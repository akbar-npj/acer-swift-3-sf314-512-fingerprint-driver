/*
 * FPC Disum (FPC2040 / Galileo) Fingerprint Driver for libfprint
 * Target Devices:
 *   - USB 10a5:a900 (Honor MagicBook X 14 / X 16 2024)
 *   - USB 10a5:e340 (Acer Swift series)
 *
 * This is a *custom* (non-image-device) driver because matching is
 * correlation-based on the clean-room BEP ridge image, not NBIS minutiae.
 * The strip sensor yields only 2-6 minutiae/frame, far below bozorth3's
 * minimum of 10, so the generic FpImageDevice path cannot work.
 *
 * Flow: capture 128x88 raw frame over USB/TLS-PSK -> clean-room BEP
 *       (128x88 -> 64x176 ridge) -> correlation matcher (best-of-N gallery).
 *
 * Reverse-engineered from the Windows driver (fpc_disum.dll) using REA & Ghidra.
 * Copyright (C) 2026
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#define FP_COMPONENT "fpc2040"

#include "drivers_api.h"
#include "fpc_protocol.h"
#include "bep_runner.h"

#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define FPC2040_NR_ENROLL_STAGES 5
#define FPC2040_BULK_IN_EP       0x81
#define FPC2040_EP_MPS           64
#define FPC2040_INNER_BUF_SIZE   65536
#define FPC2040_TPL_MAGIC        0x31435046u /* "FPC1" LE */
#define FPC2040_MATCH_THRESHOLD  550

struct _FpiDeviceFpc2040
{
  FpDevice parent;

  GUsbDevice *usb;
  guint8 ep_in;
  guint ep_mps;

  /* TLS-PSK session state */
  SSL_CTX *ssl_ctx;
  SSL *ssl;
  BIO *rbio;
  BIO *wbio;
  gboolean tls_ready;
  guint8 psk[64];
  guint psk_len;
  gboolean session_up;

  /* Inner event reassembly (events arrive either as plain framed bulk
   * packets or decrypted from the TLS stream).  Heap-allocated: GObject
   * instance sizes are limited to 64 KiB. */
  guint8 *inner_buf;
  gsize inner_len;

  /* Completed image payload for the current capture. */
  gboolean img_ready;
  guint8 *img_payload;
};

G_DECLARE_FINAL_TYPE (FpiDeviceFpc2040, fpi_device_fpc2040,
                      FPI, DEVICE_FPC2040, FpDevice)
G_DEFINE_TYPE (FpiDeviceFpc2040, fpi_device_fpc2040, FP_TYPE_DEVICE)

static const FpIdEntry id_table[] = {
  { .vid = FPC_USB_VID, .pid = FPC_USB_PID_HONOR },
  { .vid = FPC_USB_VID, .pid = FPC_USB_PID_ACER },
  { .vid = 0, .pid = 0 }
};

/* ------------------------------------------------------------------ */
/* little-endian + USB helpers                                        */
/* ------------------------------------------------------------------ */

static inline guint32
fpc_le32 (const guint8 *p)
{
  return (guint32) p[0] | ((guint32) p[1] << 8) |
         ((guint32) p[2] << 16) | ((guint32) p[3] << 24);
}

static gboolean
fpc_ctrl (FpiDeviceFpc2040 *self, gboolean out, guint8 cmd,
          guint16 val, guint16 idx, guint8 *data, gsize len,
          gsize *actual_out, GCancellable *cancellable, GError **error)
{
  gsize actual = 0;
  gboolean ok;

  ok = g_usb_device_control_transfer (
      self->usb,
      out ? G_USB_DEVICE_DIRECTION_HOST_TO_DEVICE
          : G_USB_DEVICE_DIRECTION_DEVICE_TO_HOST,
      G_USB_DEVICE_REQUEST_TYPE_VENDOR,
      G_USB_DEVICE_RECIPIENT_DEVICE,
      cmd, val, idx, data, len, &actual, 5000, cancellable, error);
  if (actual_out)
    *actual_out = actual;
  return ok;
}

static gboolean
fpc_ctrl_out (FpiDeviceFpc2040 *self, guint8 cmd, guint16 val, guint16 idx,
              guint8 *data, gsize len, GCancellable *c, GError **error)
{
  return fpc_ctrl (self, TRUE, cmd, val, idx, data, len, NULL, c, error);
}

static gboolean
fpc_ctrl_in (FpiDeviceFpc2040 *self, guint8 cmd, guint16 val, guint16 idx,
             guint8 *data, gsize len, gsize *actual,
             GCancellable *c, GError **error)
{
  gsize got = 0;

  if (!fpc_ctrl (self, FALSE, cmd, val, idx, data, len, &got, c, error))
    return FALSE;
  if (actual)
    *actual = got;
  return TRUE;
}

/* Read one complete framed packet (12-byte header + payload).
 * Returns packet length, 0 on timeout with no data, -1 on error. */
static gssize
fpc_bulk_read_event (FpiDeviceFpc2040 *self, guint8 *buf, gsize cap,
                     guint timeout, GCancellable *cancellable,
                     GError **error)
{
  gsize got = 0;

  for (;;)
    {
      if (got >= FPC_EVENT_HDR_SIZE)
        {
          guint32 want = fpc_le32 (buf + 4);

          if (want < FPC_EVENT_HDR_SIZE || want > cap)
            {
              g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                           "bad bulk frame length %u", want);
              return -1;
            }
          if (got >= want)
            return (gssize) got;
        }

      {
        gsize actual = 0;
        GError *e = NULL;

        if (!g_usb_device_bulk_transfer (self->usb, self->ep_in,
                                         buf + got, cap - got, &actual,
                                         timeout, cancellable, &e))
          {
            if (e && g_error_matches (e, G_USB_DEVICE_ERROR,
                                      G_USB_DEVICE_ERROR_TIMED_OUT))
              {
                g_error_free (e);
                if (got == 0)
                  return 0;
                continue; /* partial packet: keep waiting */
              }
            g_debug ("bulk error: %s (got=%zu)",
                     e ? e->message : "unknown", got);
            g_propagate_error (error, e);
            return -1;
          }
        if (actual == 0)
          {
            if (got == 0)
              return 0;
            continue;
          }
        got += actual;
      }
    }
}

/* ------------------------------------------------------------------ */
/* TLS-PSK                                                            */
/* ------------------------------------------------------------------ */

static void
fpc_sha256 (const void *data, size_t len, guint8 *out)
{
  unsigned int out_len = 0;
  EVP_MD_CTX *ctx = EVP_MD_CTX_new ();

  EVP_DigestInit_ex (ctx, EVP_sha256 (), NULL);
  EVP_DigestUpdate (ctx, data, len);
  EVP_DigestFinal_ex (ctx, out, &out_len);
  EVP_MD_CTX_free (ctx);
}

static gboolean
fpc_derive_psk (FpiDeviceFpc2040 *self, const guint8 *blob, gsize blob_len,
                GError **error)
{
  const struct fpc_tls_key *k = (const struct fpc_tls_key *) blob;
  const guint8 *aad, *key, *sig;
  guint8 hmac_key[32], mac[32], msg[1024];
  unsigned int mac_len = 32;
  guint8 sealing_key[32];
  EVP_CIPHER_CTX *c;
  int o1 = 0, o2 = 0;

  if (blob_len < sizeof (struct fpc_tls_key) ||
      k->magic != 0x0dec0ded ||
      (gsize) k->key_offset + k->key_len > blob_len ||
      (gsize) k->aad_offset + k->aad_len > blob_len ||
      (gsize) k->sig_offset + k->sig_len > blob_len)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                   "invalid TLS key blob");
      return FALSE;
    }

  aad = blob + k->aad_offset;
  key = blob + k->key_offset;
  sig = blob + k->sig_offset;

  if (k->aad_len < 13 || memcmp ("FPC TLS Keys", aad, 13) != 0)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                   "bad TLS key AAD");
      return FALSE;
    }

  fpc_sha256 (FPC_HMAC_KEY_STR, FPC_HMAC_KEY_LEN, hmac_key);
  if (k->aad_len + k->key_len > sizeof msg)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                   "TLS key blob too large");
      return FALSE;
    }
  memcpy (msg, aad, k->aad_len);
  memcpy (msg + k->aad_len, key, k->key_len);
  HMAC (EVP_sha256 (), hmac_key, 32, msg, k->aad_len + k->key_len,
        mac, &mac_len);
  if (k->sig_len < 32 || memcmp (mac, sig, 32) != 0)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                   "TLS key signature verification failed");
      return FALSE;
    }

  fpc_sha256 (FPC_SEALING_KEY_STR, FPC_SEALING_KEY_LEN, sealing_key);
  c = EVP_CIPHER_CTX_new ();
  EVP_CipherInit_ex (c, EVP_aes_256_cbc (), NULL, sealing_key, NULL, 0);
  EVP_CIPHER_CTX_set_padding (c, 0);
  EVP_CipherUpdate (c, self->psk, &o1, key, k->key_len);
  EVP_CipherFinal_ex (c, self->psk + o1, &o2);
  EVP_CIPHER_CTX_free (c);

  self->psk_len = (guint) (o1 + o2);
  if (self->psk_len == 0 || self->psk_len > sizeof self->psk)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                   "PSK derivation failed");
      return FALSE;
    }
  return TRUE;
}

static unsigned int
fpc_psk_cb (SSL *ssl, const char *hint, char *identity,
            unsigned int max_identity_len, unsigned char *psk,
            unsigned int max_psk_len)
{
  FpiDeviceFpc2040 *self = (FpiDeviceFpc2040 *) SSL_get_app_data (ssl);

  (void) hint;
  if (max_psk_len < self->psk_len)
    return 0;
  snprintf (identity, max_identity_len, "%s", "Disum PSK");
  memcpy (psk, self->psk, self->psk_len);
  return self->psk_len;
}

static gboolean
fpc_tls_setup (FpiDeviceFpc2040 *self, GError **error)
{
  self->ssl_ctx = SSL_CTX_new (TLS_client_method ());
  if (!self->ssl_ctx)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                   "SSL_CTX_new failed");
      return FALSE;
    }
  SSL_CTX_set_min_proto_version (self->ssl_ctx, TLS1_2_VERSION);
  SSL_CTX_set_max_proto_version (self->ssl_ctx, TLS1_2_VERSION);
  SSL_CTX_set_psk_client_callback (self->ssl_ctx, fpc_psk_cb);
  SSL_CTX_set_cipher_list (self->ssl_ctx,
                           "PSK-AES128-GCM-SHA256:PSK-AES256-GCM-SHA384:"
                           "PSK-AES128-CBC-SHA256:PSK-AES256-CBC-SHA384");

  self->ssl = SSL_new (self->ssl_ctx);
  if (!self->ssl)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                   "SSL_new failed");
      return FALSE;
    }
  self->rbio = BIO_new (BIO_s_mem ());
  self->wbio = BIO_new (BIO_s_mem ());
  BIO_set_mem_eof_return (self->rbio, -1);
  BIO_set_mem_eof_return (self->wbio, -1);
  SSL_set_bio (self->ssl, self->rbio, self->wbio);
  SSL_set_app_data (self->ssl, self);
  SSL_set_connect_state (self->ssl);
  return TRUE;
}

static gboolean
fpc_tls_flush_out (FpiDeviceFpc2040 *self, GCancellable *c, GError **error)
{
  guint8 tmp[4096];
  int pending;

  while ((pending = (int) BIO_ctrl_pending (self->wbio)) > 0)
    {
      int n = BIO_read (self->wbio, tmp, pending);
      int off;

      if (n <= 0)
        break;
      for (off = 0; off < n; )
        {
          int chunk = MIN (n - off, (int) self->ep_mps);

          if (!fpc_ctrl_out (self, CMD_TLS_DATA, 0x0001, 0x0000,
                             tmp + off, (gsize) chunk, c, error))
            return FALSE;
          off += chunk;
        }
    }
  return TRUE;
}

/* Handle one event, regardless of whether it arrived as a plain outer
 * packet or inside the TLS stream. */
static gboolean
fpc_handle_event (FpiDeviceFpc2040 *self, guint32 code,
                  const guint8 *payload, gsize len,
                  GCancellable *c, GError **error)
{
  switch (code)
    {
    case EVT_FINGER_DWN:
      g_debug ("event: finger down");
      return fpc_ctrl_out (self, CMD_GET_IMG, 0x0000, 0x0000,
                           NULL, 0, c, error);

    case EVT_IMG:
      if (len >= FPC_RAW_PAYLOAD_BYTES)
        {
          memcpy (self->img_payload, payload, FPC_RAW_PAYLOAD_BYTES);
          self->img_ready = TRUE;
          g_debug ("event: image ready");
        }
      else
        g_debug ("event: short image (%zu bytes)", len);
      return TRUE;

    default:
      return TRUE;
    }
}

/* Reassemble inner events (12-byte header: code, total len, unknown).
 * Same framing as the outer bulk packets. */
static gboolean
fpc_inner_feed (FpiDeviceFpc2040 *self, const guint8 *data, gsize len,
                GCancellable *c, GError **error)
{
  gsize off = 0;

  if (len > FPC2040_INNER_BUF_SIZE - self->inner_len)
    self->inner_len = 0;
  memcpy (self->inner_buf + self->inner_len, data, len);
  self->inner_len += len;

  while (self->inner_len - off >= FPC_EVENT_HDR_SIZE)
    {
      guint32 code = fpc_le32 (self->inner_buf + off);
      guint32 plen = fpc_le32 (self->inner_buf + off + 4);

      if (plen < FPC_EVENT_HDR_SIZE || plen > FPC2040_INNER_BUF_SIZE)
        {
          self->inner_len = 0;
          return TRUE;
        }
      if (self->inner_len - off < plen)
        break;

      g_debug ("inner: code=0x%08x plen=%u", code, plen);

      if (!fpc_handle_event (self, code,
                             self->inner_buf + off + FPC_EVENT_HDR_SIZE,
                             plen - FPC_EVENT_HDR_SIZE, c, error))
        return FALSE;

      off += plen;
    }

  if (off > 0)
    {
      memmove (self->inner_buf, self->inner_buf + off, self->inner_len - off);
      self->inner_len -= off;
    }
  return TRUE;
}

/* 1 = progress/done, 0 = want read, -1 = error */
static int
fpc_tls_pump (FpiDeviceFpc2040 *self, GCancellable *c, GError **error)
{
  if (!self->tls_ready)
    {
      int r = SSL_do_handshake (self->ssl);

      if (!fpc_tls_flush_out (self, c, error))
        return -1;
      if (r == 1)
        {
          self->tls_ready = TRUE;
          return 1;
        }
      {
        int e = SSL_get_error (self->ssl, r);

        if (e == SSL_ERROR_WANT_READ)
          return 0;
        g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                     "TLS handshake error %d", e);
        return -1;
      }
    }

  {
    guint8 tmp[8192];
    int r = SSL_read (self->ssl, tmp, sizeof tmp);

    if (!fpc_tls_flush_out (self, c, error))
      return -1;
    if (r > 0)
      {
        g_debug ("tls: decrypted %d bytes", r);
        if (!fpc_inner_feed (self, tmp, (gsize) r, c, error))
          return -1;
        return 1;
      }
    {
      int e = SSL_get_error (self->ssl, r);

      if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_ZERO_RETURN)
        return 0;
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                   "TLS read error %d", e);
      return -1;
    }
  }
}

/* ------------------------------------------------------------------ */
/* session / capture                                                  */
/* ------------------------------------------------------------------ */

static gboolean
fpc_arm (FpiDeviceFpc2040 *self, GCancellable *c, GError **error)
{
  guint8 magic[4] = { FPC_ARM_MAGIC };

  return fpc_ctrl_out (self, CMD_ARM, 0x0001, 0x0000, magic, 4, c, error);
}

static gboolean
fpc_handshake (FpiDeviceFpc2040 *self, GCancellable *c, GError **error)
{
  guint8 buf[65536];
  int i;

  for (i = 0; i < 400 && !self->tls_ready; i++)
    {
      int r = fpc_tls_pump (self, c, error);
      gssize n;

      if (r < 0)
        return FALSE;
      if (self->tls_ready)
        break;

      n = fpc_bulk_read_event (self, buf, sizeof buf, 500, c, error);
      if (n < 0)
        return FALSE;
      if (n >= FPC_EVENT_HDR_SIZE)
        {
          g_debug ("handshake[%d]: bulk n=%zd code=0x%08x", i, n,
                   fpc_le32 (buf));
          if (fpc_le32 (buf) == EVT_TLS)
            BIO_write (self->rbio, buf + FPC_EVENT_HDR_SIZE,
                       (int) (n - FPC_EVENT_HDR_SIZE));
        }
    }

  if (!self->tls_ready)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                   "TLS handshake timed out");
      return FALSE;
    }
  return TRUE;
}

static gboolean
fpc_session_start (FpiDeviceFpc2040 *self, GCancellable *c, GError **error)
{
  guint8 buf[65536];
  guint8 init_magic[4] = { FPC_INIT_MAGIC };
  guint8 keybuf[1000];
  gsize got = 0;
  gssize n;

  if (self->session_up)
    return TRUE;

  g_debug ("session: INDICATE_S_STATE");
  if (!fpc_ctrl_out (self, CMD_INDICATE_S_STATE, 0x0010, 0x0000,
                     NULL, 0, c, error))
    return FALSE;

  /* Best-effort firmware state read; failure is not fatal. */
  fpc_ctrl_in (self, GET_STATE, 0, 0, buf, 72, &got, c, NULL);
  g_debug ("session: GET_STATE returned %zu bytes", got);

  g_debug ("session: CMD_INIT");
  if (!fpc_ctrl_out (self, CMD_INIT, 0x0001, 0x0000,
                     init_magic, 4, c, error))
    return FALSE;

  n = fpc_bulk_read_event (self, buf, sizeof buf, 3000, c, error);
  g_debug ("session: init event n=%zd code=0x%08x", n,
           n >= FPC_EVENT_HDR_SIZE ? fpc_le32 (buf) : 0);
  if (n < 0)
    return FALSE;

  g_debug ("session: CMD_GET_TLS_KEY");
  if (!fpc_ctrl_in (self, CMD_GET_TLS_KEY, 0, 0, keybuf, sizeof keybuf,
                    &got, c, error))
    return FALSE;
  g_debug ("session: TLS key blob %zu bytes", got);
  if (got == 0)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                   "empty TLS key blob");
      return FALSE;
    }
  if (!fpc_derive_psk (self, keybuf, got, error))
    return FALSE;
  g_debug ("session: derived PSK (%u bytes)", self->psk_len);

  if (!fpc_tls_setup (self, error))
    return FALSE;

  g_debug ("session: CMD_TLS_INIT");
  if (!fpc_ctrl_out (self, CMD_TLS_INIT, 0x0001, 0x0000,
                     NULL, 0, c, error))
    return FALSE;

  if (!fpc_handshake (self, c, error))
    return FALSE;
  g_debug ("session: TLS handshake complete");

  if (!fpc_arm (self, c, error))
    return FALSE;
  g_debug ("session: sensor armed");

  self->session_up = TRUE;
  return TRUE;
}

static void
fpc_session_stop (FpiDeviceFpc2040 *self)
{
  if (self->usb)
    {
      guint8 disarm[4] = { FPC_DISARM_MAGIC };

      fpc_ctrl_out (self, CMD_ARM, 0x0001, 0x0000, disarm, 4, NULL, NULL);
      fpc_ctrl_out (self, CMD_ABORT, 0x0000, 0x0000, NULL, 0, NULL, NULL);
      fpc_ctrl_out (self, CMD_FINGERPRINT_SESSION_OFF, 0x0000, 0x0000,
                    NULL, 0, NULL, NULL);
    }

  if (self->ssl)
    {
      SSL_free (self->ssl);
      self->ssl = NULL;
      self->rbio = NULL;
      self->wbio = NULL;
    }
  if (self->ssl_ctx)
    {
      SSL_CTX_free (self->ssl_ctx);
      self->ssl_ctx = NULL;
    }
  self->tls_ready = FALSE;
  self->session_up = FALSE;
}

/* Capture one EVT_IMG payload ([22-byte hdr][128x88 px]). */
static gboolean
fpc_capture_frame (FpiDeviceFpc2040 *self, guint8 *payload,
                   GCancellable *c, GError **error)
{
  guint8 buf[65536];
  int i;

  if (!fpc_session_start (self, c, error))
    return FALSE;

  g_debug ("capture: waiting for image");
  self->img_ready = FALSE;
  self->inner_len = 0;

  for (i = 0; i < 4000; i++)
    {
      gssize n;
      int r;

      if (g_cancellable_is_cancelled (c))
        {
          g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_CANCELLED,
                               "cancelled");
          return FALSE;
        }

      /* Drain decrypted application data; it may carry inner events. */
      while ((r = fpc_tls_pump (self, c, error)) == 1)
        ;
      if (r < 0)
        return FALSE;
      if (self->img_ready)
        goto got_image;

      n = fpc_bulk_read_event (self, buf, sizeof buf, 1000, c, error);
      if (n < 0)
        return FALSE;
      if (n < FPC_EVENT_HDR_SIZE)
        {
          if ((i % 5) == 0)
            g_debug ("capture[%d]: bulk timeout", i);
          continue; /* timeout */
        }

      g_debug ("capture[%d]: bulk n=%zd code=0x%08x", i, n, fpc_le32 (buf));

      if (fpc_le32 (buf) == EVT_TLS)
        BIO_write (self->rbio, buf + FPC_EVENT_HDR_SIZE,
                   (int) (n - FPC_EVENT_HDR_SIZE));
      else if (!fpc_handle_event (self, fpc_le32 (buf),
                                  buf + FPC_EVENT_HDR_SIZE,
                                  (gsize) n - FPC_EVENT_HDR_SIZE,
                                  c, error))
        return FALSE;

      if (self->img_ready)
        goto got_image;
    }

  g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
               "timed out waiting for finger");
  return FALSE;

got_image:
  memcpy (payload, self->img_payload, FPC_RAW_PAYLOAD_BYTES);
  self->img_ready = FALSE;
  /* Re-arm for the next press. */
  g_usleep (20000);
  fpc_arm (self, c, NULL); /* non-fatal */
  return TRUE;
}

/* ------------------------------------------------------------------ */
/* template blob                                                      */
/* ------------------------------------------------------------------ */

static GBytes *
fpc_print_get_blob (FpPrint *print)
{
  GVariant *data = NULL, *ay = NULL;
  gconstpointer p;
  gsize len;

  g_object_get (print, "fpi-data", &data, NULL);
  if (!data)
    return NULL;
  if (!g_variant_is_of_type (data, G_VARIANT_TYPE ("(ay)")))
    {
      g_variant_unref (data);
      return NULL;
    }
  g_variant_get (data, "(@ay)", &ay);
  p = g_variant_get_fixed_array (ay, &len, 1);
  {
    GBytes *b = g_bytes_new (p, len);

    g_variant_unref (ay);
    g_variant_unref (data);
    return b;
  }
}

static void
fpc_print_set_blob (FpPrint *print, const guint8 *blob, gsize len)
{
  GVariant *ay = g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE,
                                            blob, len, 1);
  GVariant *data = g_variant_new ("(@ay)", ay);

  fpi_print_set_type (print, FPI_PRINT_RAW);
  g_object_set (print, "fpi-data", data, NULL);
}

/* ------------------------------------------------------------------ */
/* enroll                                                             */
/* ------------------------------------------------------------------ */

typedef struct
{
  FpDevice *dev;
  gint stage;
} FpcProgress;

static gboolean
fpc_progress_cb (gpointer data)
{
  FpcProgress *p = data;

  fpi_device_enroll_progress (p->dev, p->stage, NULL, NULL);
  g_object_unref (p->dev);
  g_free (p);
  return G_SOURCE_REMOVE;
}

static void
fpc_enroll_thread (GTask *task, gpointer source, gpointer task_data,
                   GCancellable *cancellable)
{
  FpiDeviceFpc2040 *self = FPI_DEVICE_FPC2040 (source);
  gsize blob_len = 8 + FPC2040_NR_ENROLL_STAGES * FPC_RIDGE_BYTES;
  guint8 *blob = g_malloc0 (blob_len);
  guint32 magic = FPC2040_TPL_MAGIC;
  guint32 n = FPC2040_NR_ENROLL_STAGES;
  int i;

  memcpy (blob + 0, &magic, 4);
  memcpy (blob + 4, &n, 4);

  for (i = 0; i < FPC2040_NR_ENROLL_STAGES; i++)
    {
      guint8 payload[FPC_RAW_PAYLOAD_BYTES];
      guint8 *ridge = blob + 8 + (gsize) i * FPC_RIDGE_BYTES;
      gchar *e = NULL;
      FpcProgress *p;

      if (g_cancellable_is_cancelled (cancellable))
        {
          g_free (blob);
          g_task_return_new_error (task, G_IO_ERROR, G_IO_ERROR_CANCELLED,
                                   "cancelled");
          return;
        }

      {
        GError *error = NULL;

        if (!fpc_capture_frame (self, payload, cancellable, &error))
          {
            g_free (blob);
            g_task_return_error (task, error);
            return;
          }
      }

      if (fpc_bep_ridge (payload, sizeof payload, ridge, &e) != 0)
        {
          g_free (blob);
          g_task_return_new_error (task, FP_DEVICE_ERROR,
                                   FP_DEVICE_ERROR_PROTO,
                                   "BEP failed: %s", e ? e : "?");
          g_free (e);
          return;
        }
      g_free (e);
      g_debug ("enroll stage %d: captured and reconstructed", i + 1);

      p = g_new0 (FpcProgress, 1);
      p->dev = g_object_ref (source);
      p->stage = i + 1;
      g_main_context_invoke (NULL, fpc_progress_cb, p);
    }

  g_task_return_pointer (task, blob, g_free);
}

static void
fpc_enroll_done (GObject *source, GAsyncResult *res, gpointer user_data)
{
  FpDevice *dev = FP_DEVICE (source);
  GError *error = NULL;
  guint8 *blob = g_task_propagate_pointer (G_TASK (res), &error);
  FpPrint *print = NULL;
  gsize blob_len = 8 + FPC2040_NR_ENROLL_STAGES * FPC_RIDGE_BYTES;

  if (!blob)
    {
      fpi_device_enroll_complete (dev, NULL, error);
      return;
    }

  fpi_device_get_enroll_data (dev, &print);
  fpc_print_set_blob (print, blob, blob_len);
  g_free (blob);

  fpi_device_enroll_complete (dev, g_object_ref (print), NULL);
}

static void
fpc_enroll (FpDevice *device)
{
  GTask *task = g_task_new (device, fpi_device_get_cancellable (device),
                            fpc_enroll_done, NULL);

  g_task_run_in_thread (task, fpc_enroll_thread);
  g_object_unref (task);
}

/* ------------------------------------------------------------------ */
/* verify / identify                                                  */
/* ------------------------------------------------------------------ */

static void
fpc_verify_thread (GTask *task, gpointer source, gpointer task_data,
                   GCancellable *cancellable)
{
  FpiDeviceFpc2040 *self = FPI_DEVICE_FPC2040 (source);
  GBytes *tpl = task_data;
  const guint8 *blob;
  gsize len;
  guint8 payload[FPC_RAW_PAYLOAD_BYTES];
  guint8 probe[FPC_RIDGE_BYTES];
  GError *error = NULL;
  gchar *e = NULL;
  guint32 n;
  int best = 0;
  guint i;

  blob = g_bytes_get_data (tpl, &len);
  if (len < 8 || fpc_le32 (blob) != FPC2040_TPL_MAGIC)
    {
      g_task_return_new_error (task, FP_DEVICE_ERROR,
                               FP_DEVICE_ERROR_DATA_INVALID,
                               "invalid template");
      return;
    }
  n = fpc_le32 (blob + 4);
  if (n == 0 || 8 + (gsize) n * FPC_RIDGE_BYTES > len)
    {
      g_task_return_new_error (task, FP_DEVICE_ERROR,
                               FP_DEVICE_ERROR_DATA_INVALID,
                               "corrupt template");
      return;
    }

  if (!fpc_capture_frame (self, payload, cancellable, &error))
    {
      g_task_return_error (task, error);
      return;
    }
  if (fpc_bep_ridge (payload, sizeof payload, probe, &e) != 0)
    {
      g_task_return_new_error (task, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                               "BEP failed: %s", e ? e : "?");
      g_free (e);
      return;
    }
  g_free (e);

  for (i = 0; i < n; i++)
    {
      int s = fpc_match_ridge (probe, blob + 8 + (gsize) i * FPC_RIDGE_BYTES);

      if (s > best)
        best = s;
    }
  g_task_return_int (task, best);
}

static void
fpc_verify_done (GObject *source, GAsyncResult *res, gpointer user_data)
{
  FpDevice *dev = FP_DEVICE (source);
  GError *error = NULL;
  gint best = g_task_propagate_int (G_TASK (res), &error);
  FpPrint *print = NULL;

  if (error)
    {
      fpi_device_verify_report (dev, FPI_MATCH_ERROR, NULL, error);
      fpi_device_verify_complete (dev, NULL);
      return;
    }

  fpi_device_get_verify_data (dev, &print);
  if (best >= FPC2040_MATCH_THRESHOLD)
    fpi_device_verify_report (dev, FPI_MATCH_SUCCESS, print, NULL);
  else
    fpi_device_verify_report (dev, FPI_MATCH_FAIL, NULL, NULL);
  fpi_device_verify_complete (dev, NULL);
}

static void
fpc_verify (FpDevice *device)
{
  FpPrint *print = NULL;
  GBytes *tpl;
  GTask *task;

  fpi_device_get_verify_data (device, &print);
  tpl = fpc_print_get_blob (print);
  if (!tpl)
    {
      fpi_device_verify_report (device, FPI_MATCH_ERROR, NULL,
                                fpi_device_error_new (FP_DEVICE_ERROR_DATA_INVALID));
      fpi_device_verify_complete (device, NULL);
      return;
    }

  task = g_task_new (device, fpi_device_get_cancellable (device),
                     fpc_verify_done, NULL);
  g_task_set_task_data (task, tpl, (GDestroyNotify) g_bytes_unref);
  g_task_run_in_thread (task, fpc_verify_thread);
  g_object_unref (task);
}

/* identify: probe against every enrolled print, report the best. */
typedef struct
{
  GPtrArray *blobs; /* GBytes*, parallel to templates */
} FpcIdentifyData;

static void
fpc_identify_data_free (gpointer p)
{
  FpcIdentifyData *d = p;

  g_ptr_array_unref (d->blobs);
  g_free (d);
}

static void
fpc_identify_thread (GTask *task, gpointer source, gpointer task_data,
                     GCancellable *cancellable)
{
  FpiDeviceFpc2040 *self = FPI_DEVICE_FPC2040 (source);
  FpcIdentifyData *d = task_data;
  guint8 payload[FPC_RAW_PAYLOAD_BYTES];
  guint8 probe[FPC_RIDGE_BYTES];
  GError *error = NULL;
  gchar *e = NULL;
  int best = 0;
  gint best_idx = -1;
  guint t;

  if (!fpc_capture_frame (self, payload, cancellable, &error))
    {
      g_task_return_error (task, error);
      return;
    }
  if (fpc_bep_ridge (payload, sizeof payload, probe, &e) != 0)
    {
      g_task_return_new_error (task, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                               "BEP failed: %s", e ? e : "?");
      g_free (e);
      return;
    }
  g_free (e);

  for (t = 0; t < d->blobs->len; t++)
    {
      GBytes *tpl = g_ptr_array_index (d->blobs, t);
      const guint8 *blob;
      gsize len;
      guint32 n;
      guint i;

      blob = g_bytes_get_data (tpl, &len);
      if (len < 8 || fpc_le32 (blob) != FPC2040_TPL_MAGIC)
        continue;
      n = fpc_le32 (blob + 4);
      if (n == 0 || 8 + (gsize) n * FPC_RIDGE_BYTES > len)
        continue;
      for (i = 0; i < n; i++)
        {
          int s = fpc_match_ridge (probe,
                                   blob + 8 + (gsize) i * FPC_RIDGE_BYTES);

          if (s > best)
            {
              best = s;
              best_idx = (gint) t;
            }
        }
    }

  g_task_return_int (task, best_idx >= 0 && best >= FPC2040_MATCH_THRESHOLD
                            ? best_idx : -1);
}

static void
fpc_identify_done (GObject *source, GAsyncResult *res, gpointer user_data)
{
  FpDevice *dev = FP_DEVICE (source);
  GError *error = NULL;
  gint idx = g_task_propagate_int (G_TASK (res), &error);
  GPtrArray *templates = NULL;

  if (error)
    {
      fpi_device_identify_report (dev, NULL, NULL, error);
      fpi_device_identify_complete (dev, NULL);
      return;
    }

  fpi_device_get_identify_data (dev, &templates);
  if (idx >= 0 && (guint) idx < templates->len)
    fpi_device_identify_report (dev, g_ptr_array_index (templates, idx),
                                NULL, NULL);
  else
    fpi_device_identify_report (dev, NULL, NULL, NULL);
  fpi_device_identify_complete (dev, NULL);
}

static void
fpc_identify (FpDevice *device)
{
  GPtrArray *templates = NULL;
  FpcIdentifyData *d;
  GTask *task;
  guint i;

  fpi_device_get_identify_data (device, &templates);

  d = g_new0 (FpcIdentifyData, 1);
  d->blobs = g_ptr_array_new_with_free_func ((GDestroyNotify) g_bytes_unref);
  for (i = 0; i < templates->len; i++)
    {
      FpPrint *print = g_ptr_array_index (templates, i);
      GBytes *b = fpc_print_get_blob (print);

      if (b)
        g_ptr_array_add (d->blobs, b);
      else
        g_ptr_array_add (d->blobs, g_bytes_new (NULL, 0));
    }

  task = g_task_new (device, fpi_device_get_cancellable (device),
                     fpc_identify_done, NULL);
  g_task_set_task_data (task, d, fpc_identify_data_free);
  g_task_run_in_thread (task, fpc_identify_thread);
  g_object_unref (task);
}

/* ------------------------------------------------------------------ */
/* open / close / probe                                               */
/* ------------------------------------------------------------------ */

static void
fpc_dev_probe (FpDevice *device)
{
  GUsbDevice *usb = fpi_device_get_usb_device (device);
  GError *error = NULL;
  g_autofree gchar *product = NULL;

  if (!g_usb_device_open (usb, &error))
    {
      fpi_device_probe_complete (device, NULL, NULL, error);
      return;
    }

  product = g_usb_device_get_string_descriptor (
      usb, g_usb_device_get_product_index (usb), NULL);

  g_usb_device_close (usb, NULL);
  fpi_device_probe_complete (device, NULL, product, NULL);
}

static gboolean
fpc_find_bulk_in (FpiDeviceFpc2040 *self, GError **error)
{
  g_autoptr(GPtrArray) interfaces = NULL;
  guint i, j;

  interfaces = g_usb_device_get_interfaces (self->usb, error);
  if (!interfaces)
    return FALSE;

  for (i = 0; i < interfaces->len; i++)
    {
      GUsbInterface *iface = g_ptr_array_index (interfaces, i);
      GPtrArray *eps = g_usb_interface_get_endpoints (iface);

      if (!eps)
        continue;

      for (j = 0; j < eps->len; j++)
        {
          GUsbEndpoint *ep = g_ptr_array_index (eps, j);

          if (g_usb_endpoint_get_direction (ep) !=
              G_USB_DEVICE_DIRECTION_DEVICE_TO_HOST)
            continue;

          self->ep_in = g_usb_endpoint_get_address (ep);
          self->ep_mps = g_usb_endpoint_get_maximum_packet_size (ep);
          if (self->ep_mps == 0)
            self->ep_mps = FPC2040_EP_MPS;
          return TRUE;
        }
    }

  g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
               "no bulk IN endpoint found");
  return FALSE;
}

static void
fpc_dev_open (FpDevice *device)
{
  FpiDeviceFpc2040 *self = FPI_DEVICE_FPC2040 (device);
  GError *error = NULL;

  self->usb = fpi_device_get_usb_device (device);
  self->ep_in = FPC2040_BULK_IN_EP;
  self->ep_mps = FPC2040_EP_MPS;
  self->session_up = FALSE;

  if (!g_usb_device_reset (self->usb, &error))
    {
      fpi_device_open_complete (device, error);
      return;
    }
  if (!g_usb_device_claim_interface (self->usb, 0, 0, &error))
    {
      fpi_device_open_complete (device, error);
      return;
    }
  if (!fpc_find_bulk_in (self, &error))
    {
      fpi_device_open_complete (device, error);
      return;
    }

  g_debug ("using bulk IN 0x%02x (mps=%u)", self->ep_in, self->ep_mps);

  fpi_device_open_complete (device, NULL);
}

static void
fpc_dev_close (FpDevice *device)
{
  FpiDeviceFpc2040 *self = FPI_DEVICE_FPC2040 (device);
  g_autoptr(GError) error = NULL;

  fpc_session_stop (self);
  if (self->usb)
    g_usb_device_release_interface (self->usb, 0, 0, &error);
  fpi_device_close_complete (device, error);
}

/* ------------------------------------------------------------------ */
/* GObject plumbing                                                   */
/* ------------------------------------------------------------------ */

static void
fpi_device_fpc2040_init (FpiDeviceFpc2040 *self)
{
  self->inner_buf = g_malloc (FPC2040_INNER_BUF_SIZE);
  self->img_payload = g_malloc (FPC_RAW_PAYLOAD_BYTES);
}

static void
fpi_device_fpc2040_finalize (GObject *object)
{
  FpiDeviceFpc2040 *self = FPI_DEVICE_FPC2040 (object);

  g_clear_pointer (&self->inner_buf, g_free);
  g_clear_pointer (&self->img_payload, g_free);

  G_OBJECT_CLASS (fpi_device_fpc2040_parent_class)->finalize (object);
}

static void
fpi_device_fpc2040_class_init (FpiDeviceFpc2040Class *klass)
{
  FpDeviceClass *dev_class = FP_DEVICE_CLASS (klass);

  G_OBJECT_CLASS (klass)->finalize = fpi_device_fpc2040_finalize;

  dev_class->id = "fpc2040";
  dev_class->full_name = "Fingerprint Cards Disum (Honor / Acer)";
  dev_class->type = FP_DEVICE_TYPE_USB;
  dev_class->id_table = id_table;
  dev_class->nr_enroll_stages = FPC2040_NR_ENROLL_STAGES;
  dev_class->scan_type = FP_SCAN_TYPE_PRESS;
  dev_class->temp_hot_seconds = -1;

  dev_class->probe = fpc_dev_probe;
  dev_class->open = fpc_dev_open;
  dev_class->close = fpc_dev_close;
  dev_class->enroll = fpc_enroll;
  dev_class->verify = fpc_verify;
  dev_class->identify = fpc_identify;

  fpi_device_class_auto_initialize_features (dev_class);
}
