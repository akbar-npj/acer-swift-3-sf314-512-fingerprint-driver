/*
 * FPC "Disum" fingerprint sensor Linux utility.
 *
 * Targets: USB 10a5:e340 (Acer Swift 3 SF314-512) and 10a5:a900 (Honor MagicBook).
 *
 * Implements the protocol actually spoken by the Windows UMDF driver
 * (fpc_disum.dll), verified against real 10a5:e340 hardware (FW 20.26.23.27):
 *
 *   1. Commands are vendor control transfers (0x40 out / 0xc0 in) on EP0.
 *   2. Events arrive on the single bulk IN endpoint, framed as a 12-byte
 *      header {code, len, unknown} (little-endian) followed by a payload.
 *   3. After CMD_INIT + CMD_GET_TLS_KEY the host derives a 32-byte PSK from the
 *      sealed key blob (HMAC-SHA256 with sha256("FPC_HMAC_KEY") to verify,
 *      AES-256-CBC with sha256("FPC_SEALING_KEY") to unseal).
 *   4. CMD_TLS_INIT then starts a TLS-PSK (TLS 1.2) session in which the HOST IS
 *      THE TLS CLIENT and the device is the server. TLS records are exchanged
 *      as: host->device via CMD_TLS_DATA control transfers, device->host as
 *      bulk packets with code EVT_TLS whose payload is a TLS record.
 *   5. The decrypted TLS stream carries a second layer of the same 12-byte
 *      framing (EVT_FINGER_DWN / EVT_IMG / ...).
 *   6. A raw capture frame is 112x88 = 9856 bytes of 8-bit grayscale.
 *
 * SPDX-License-Identifier: MIT
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <unistd.h>

#include <libusb-1.0/libusb.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "fpc_protocol.h"

static libusb_device_handle *g_devh = NULL;
static uint8_t  g_ep_bulk_in = 0;
static int      g_ep_mps = 64;
static uint16_t g_pid = 0;
static volatile int g_running = 1;
static int      g_capture_count = 0;
static int      g_target = 1;   /* number of frames to capture */
static int      g_probe = 0;    /* probe mode: ask for a no-finger image */
static int      g_sweep = 0;    /* sweep mode: try every command that might
                                 * yield a second/reference (no-finger) image */
static int      g_calib = 0;    /* calib mode: read the per-unit calibration the
                                 * vendor fetches at runtime (KPI + dead-pixel
                                 * report); g_calib==2 also probes SPI/OTP. */
/* Frame accumulator: the raw sensor output is noise dominated (single frames
 * correlate <0.4), so the vendor stacks many captures. We average here too. */
static double   g_stack[FPC_IMAGE_BYTES];

static SSL_CTX *g_ssl_ctx = NULL;
static SSL     *g_ssl = NULL;
static BIO     *g_rbio = NULL;
static BIO     *g_wbio = NULL;
static int      g_tls_ready = 0;
static int      g_armed = 0;
static unsigned char g_psk[64];
static unsigned int  g_psk_len = 0;
static const char   *g_psk_identity = "Disum PSK";

static unsigned char g_inner[1 << 20];
static size_t        g_inner_len = 0;

static void on_sigint(int s) { (void)s; g_running = 0; }

static uint32_t rd32le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void hexdump(const char *label, const uint8_t *b, int n) {
    printf("    %s (%d):", label, n);
    for (int i = 0; i < n && i < 48; i++) {
        if (i % 16 == 0) printf("\n      ");
        printf("%02x ", b[i]);
    }
    if (n > 48) printf("...");
    printf("\n");
}

static int ctrl_out(uint8_t req, uint16_t val, uint16_t idx,
                    const uint8_t *data, uint16_t len) {
    int r = libusb_control_transfer(g_devh, FPC_REQTYPE_VENDOR_OUT, req,
                                    val, idx, (unsigned char *)data, len, 5000);
    if (r < 0)
        fprintf(stderr, "[-] %s (0x%02x) OUT failed: %s\n",
                fpc_cmd_to_str(req), req, libusb_error_name(r));
    return r;
}

static int ctrl_in(uint8_t req, uint16_t val, uint16_t idx,
                   uint8_t *data, uint16_t len) {
    int r = libusb_control_transfer(g_devh, FPC_REQTYPE_VENDOR_IN, req,
                                    val, idx, data, len, 5000);
    if (r < 0)
        fprintf(stderr, "[-] %s (0x%02x) IN failed: %s\n",
                fpc_cmd_to_str(req), req, libusb_error_name(r));
    return r;
}

/* Read exactly one framed bulk packet (12-byte header + payload). */
static int bulk_read_event(uint8_t *buf, size_t cap, int timeout_ms) {
    size_t got = 0;
    for (;;) {
        if (got >= FPC_EVENT_HDR_SIZE) {
            uint32_t want = rd32le(buf + 4);
            if (want < FPC_EVENT_HDR_SIZE || want > cap) {
                fprintf(stderr, "[-] bad bulk frame length %u (got %zu)\n", want, got);
                return LIBUSB_ERROR_IO;
            }
            if (got >= want)
                return (int)got;
        }
        int xfer = 0;
        int r = libusb_bulk_transfer(g_devh, g_ep_bulk_in, buf + got,
                                     (int)(cap - got), &xfer, timeout_ms);
        if (r == LIBUSB_ERROR_TIMEOUT && got == 0)
            return LIBUSB_ERROR_TIMEOUT;
        if (r < 0)
            return r;
        got += (size_t)xfer;
    }
}

/* ------------------------- key derivation ------------------------- */

static void sha256(const void *data, size_t len, unsigned char *out) {
    unsigned int out_len = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, out, &out_len);
    EVP_MD_CTX_free(ctx);
}

static int derive_psk(const uint8_t *blob, int blob_len) {
    if (blob_len < (int)sizeof(struct fpc_tls_key)) {
        fprintf(stderr, "[-] TLS key blob too small (%d)\n", blob_len);
        return -1;
    }
    const struct fpc_tls_key *k = (const struct fpc_tls_key *)blob;
    if (k->magic != 0x0dec0ded ||
        (int)(k->key_offset + k->key_len) > blob_len ||
        (int)(k->aad_offset + k->aad_len) > blob_len ||
        (int)(k->sig_offset + k->sig_len) > blob_len) {
        fprintf(stderr, "[-] invalid TLS key blob\n");
        return -1;
    }
    const uint8_t *aad = blob + k->aad_offset;
    const uint8_t *key = blob + k->key_offset;
    const uint8_t *sig = blob + k->sig_offset;
    if (k->aad_len < 13 || memcmp("FPC TLS Keys", aad, 13) != 0) {
        fprintf(stderr, "[-] bad TLS key AAD\n");
        return -1;
    }

    unsigned char hmac_key[32], mac[32], msg[1024];
    unsigned int mac_len = 32;
    sha256(FPC_HMAC_KEY_STR, FPC_HMAC_KEY_LEN, hmac_key);
    if (k->aad_len + k->key_len > sizeof msg) return -1;
    memcpy(msg, aad, k->aad_len);
    memcpy(msg + k->aad_len, key, k->key_len);
    HMAC(EVP_sha256(), hmac_key, 32, msg, k->aad_len + k->key_len, mac, &mac_len);
    if (k->sig_len < 32 || memcmp(mac, sig, 32) != 0) {
        fprintf(stderr, "[-] TLS key signature verification FAILED\n");
        return -1;
    }
    printf("[+] TLS key signature verified\n");

    unsigned char sealing_key[32];
    sha256(FPC_SEALING_KEY_STR, FPC_SEALING_KEY_LEN, sealing_key);
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    EVP_CipherInit_ex(c, EVP_aes_256_cbc(), NULL, sealing_key, NULL, 0);
    EVP_CIPHER_CTX_set_padding(c, 0);
    int o1 = 0, o2 = 0;
    EVP_CipherUpdate(c, g_psk, &o1, key, k->key_len);
    EVP_CipherFinal_ex(c, g_psk + o1, &o2);
    EVP_CIPHER_CTX_free(c);
    g_psk_len = (unsigned int)(o1 + o2);
    if (g_psk_len == 0 || g_psk_len > sizeof g_psk) return -1;
    printf("[+] PSK derived (%u bytes)\n", g_psk_len);
    return 0;
}

/* --------------------------- TLS client --------------------------- */

static unsigned int psk_client_cb(SSL *ssl, const char *hint, char *identity,
                                  unsigned int max_identity_len,
                                  unsigned char *psk, unsigned int max_psk_len) {
    (void)ssl; (void)hint;
    if (max_psk_len < g_psk_len) return 0;
    snprintf(identity, max_identity_len, "%s", g_psk_identity);
    memcpy(psk, g_psk, g_psk_len);
    return g_psk_len;
}

static int tls_setup(void) {
    g_ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!g_ssl_ctx) return -1;
    SSL_CTX_set_min_proto_version(g_ssl_ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(g_ssl_ctx, TLS1_2_VERSION);
    SSL_CTX_set_psk_client_callback(g_ssl_ctx, psk_client_cb);
    SSL_CTX_set_cipher_list(g_ssl_ctx,
        "PSK-AES128-GCM-SHA256:PSK-AES256-GCM-SHA384:"
        "PSK-AES128-CBC-SHA256:PSK-AES256-CBC-SHA384");

    g_ssl = SSL_new(g_ssl_ctx);
    g_rbio = BIO_new(BIO_s_mem());
    g_wbio = BIO_new(BIO_s_mem());
    BIO_set_mem_eof_return(g_rbio, -1);
    BIO_set_mem_eof_return(g_wbio, -1);
    SSL_set_bio(g_ssl, g_rbio, g_wbio);
    SSL_set_connect_state(g_ssl);
    return 0;
}

static int tls_flush_out(void) {
    unsigned char tmp[4096];
    int pending;
    while ((pending = (int)BIO_ctrl_pending(g_wbio)) > 0) {
        int n = BIO_read(g_wbio, tmp, pending);
        if (n <= 0) break;
        for (int off = 0; off < n; ) {
            int chunk = n - off;
            if (chunk > g_ep_mps) chunk = g_ep_mps;
            int r = ctrl_out(CMD_TLS_DATA, 0x0001, 0x0000, tmp + off, (uint16_t)chunk);
            if (r < 0) return -1;
            off += chunk;
        }
    }
    return 0;
}

static void inner_feed(const uint8_t *data, size_t len);
static int arm_sensor(void);

static int tls_pump(void) {
    if (!g_tls_ready) {
        int r = SSL_do_handshake(g_ssl);
        if (tls_flush_out() < 0) return -1;
        if (r == 1) {
            g_tls_ready = 1;
            printf("[+] TLS handshake complete (%s)\n", SSL_get_version(g_ssl));
            return 1;
        }
        int e = SSL_get_error(g_ssl, r);
        if (e == SSL_ERROR_WANT_READ) return 0;
        fprintf(stderr, "[-] TLS handshake error %d\n", e);
        ERR_print_errors_fp(stderr);
        return -1;
    }
    unsigned char tmp[8192];
    int r = SSL_read(g_ssl, tmp, sizeof tmp);
    if (tls_flush_out() < 0) return -1;
    if (r > 0) { inner_feed(tmp, (size_t)r); return 1; }
    int e = SSL_get_error(g_ssl, r);
    if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_ZERO_RETURN) return 0;
    fprintf(stderr, "[-] TLS read error %d\n", e);
    ERR_print_errors_fp(stderr);
    return -1;
}

/* ---------------------- inner (decrypted) events ------------------- */

static void save_pgm(const uint8_t *px, size_t size, int n) {
    char name[64];
    snprintf(name, sizeof name, "acer_fingerprint_%03d.pgm", n);
    FILE *f = fopen(name, "wb");
    if (!f) { perror("fopen"); return; }
    fprintf(f, "P5\n%d %d\n255\n", FPC_SENSOR_WIDTH, FPC_SENSOR_HEIGHT);
    fwrite(px, 1, size, f);
    fclose(f);
    printf("[+] Saved %s (%zu bytes, %dx%d)\n", name, size,
           FPC_SENSOR_WIDTH, FPC_SENSOR_HEIGHT);
}

static void save_raw(const uint8_t *data, size_t size, int n) {
    char name[64];
    snprintf(name, sizeof name, "acer_fingerprint_%03d.raw", n);
    FILE *f = fopen(name, "wb");
    if (!f) return;
    fwrite(data, 1, size, f);
    fclose(f);
}

/* Average all captured frames and contrast-stretch the result. */
static void save_stack(int count) {
    if (count < 1) return;
    uint8_t px[FPC_IMAGE_BYTES];
    double lo = 1e9, hi = -1e9;
    for (size_t i = 0; i < FPC_IMAGE_BYTES; i++) {
        double v = g_stack[i] / count;
        if (v < lo) lo = v;
        if (v > hi) hi = v;
    }
    double span = (hi > lo) ? (hi - lo) : 1.0;
    for (size_t i = 0; i < FPC_IMAGE_BYTES; i++)
        px[i] = (uint8_t)((g_stack[i] / count - lo) / span * 255.0 + 0.5);

    FILE *f = fopen("acer_fingerprint_stack.pgm", "wb");
    if (!f) { perror("fopen"); return; }
    fprintf(f, "P5\n%d %d\n255\n", FPC_SENSOR_WIDTH, FPC_SENSOR_HEIGHT);
    fwrite(px, 1, FPC_IMAGE_BYTES, f);
    fclose(f);
    printf("[+] Saved acer_fingerprint_stack.pgm (%d frames averaged, %dx%d)\n",
           count, FPC_SENSOR_WIDTH, FPC_SENSOR_HEIGHT);
}

static void handle_inner_event(uint32_t code, const uint8_t *payload, size_t len) {
    printf("[<] inner event %s (0x%02x), %zu bytes\n",
           fpc_event_to_str(code), code, len);
    switch (code) {
        case EVT_ARM_RESULT:
            printf("    sensor armed, waiting for finger\n");
            break;
        case EVT_FINGER_DWN:
            printf("\n>>> FINGER DETECTED <<<\n");
            ctrl_out(CMD_GET_IMG, 0x0000, 0x0000, NULL, 0);
            break;
        case EVT_FINGER_UP:
            printf("    finger lifted\n");
            break;
        case EVT_IMG:
            if (len >= FPC_IMG_HDR_SIZE + FPC_IMAGE_BYTES) {
                g_capture_count++;
                save_raw(payload, len, g_capture_count);
                save_pgm(payload + FPC_IMG_HDR_SIZE, FPC_IMAGE_BYTES, g_capture_count);
                for (size_t i = 0; i < FPC_IMAGE_BYTES; i++)
                    g_stack[i] += payload[FPC_IMG_HDR_SIZE + i];
                /* The device yields exactly one frame per touch, so re-arm and
                 * wait for the next finger-down. Tap repeatedly to stack. */
                if (g_capture_count < g_target) {
                    usleep(20000);
                    g_armed = 0;   /* loop re-arms and waits for the next touch */
                }
            } else {
                printf("    short image payload: %zu < %d\n", len,
                       FPC_IMG_HDR_SIZE + FPC_IMAGE_BYTES);
                hexdump("payload", payload, (int)len);
            }
            break;
        case EVT_DEAD_PIXEL_REPORT: {
            printf("    dead-pixel report: %zu byte(s)\n", len);
            if (len == 0) { printf("    (no dead pixels reported)\n"); break; }
            hexdump("dp", payload, (int)len);
            for (size_t i = 0; i + 2 <= len && i < 64; i += 2)
                printf("      dp[%zu] = %u\n", i / 2,
                       (unsigned)(payload[i] | (payload[i + 1] << 8)));
            break;
        }
        case EVT_USB_LOGS:
            printf("    fw log: %.*s\n", (int)len, (const char *)payload);
            break;
        default:
            hexdump("payload", payload, (int)len);
            break;
    }
}

static void inner_feed(const uint8_t *data, size_t len) {
    if (g_inner_len + len > sizeof g_inner) g_inner_len = 0;
    memcpy(g_inner + g_inner_len, data, len);
    g_inner_len += len;

    size_t off = 0;
    while (g_inner_len - off >= FPC_EVENT_HDR_SIZE) {
        uint32_t code = rd32le(g_inner + off);
        uint32_t plen = rd32le(g_inner + off + 4);
        if (plen < FPC_EVENT_HDR_SIZE || plen > sizeof g_inner) {
            hexdump("inner (undecoded)", g_inner + off,
                    (int)(g_inner_len - off > 32 ? 32 : g_inner_len - off));
            g_inner_len = 0;
            return;
        }
        if (g_inner_len - off < plen) break;
        handle_inner_event(code, g_inner + off + FPC_EVENT_HDR_SIZE,
                           plen - FPC_EVENT_HDR_SIZE);
        off += plen;
    }
    if (off > 0) {
        memmove(g_inner, g_inner + off, g_inner_len - off);
        g_inner_len -= off;
    }
}

/* ---------------------------- device setup ------------------------- */

static int find_bulk_in(libusb_device *dev, uint8_t *ep_out, int *mps_out) {
    struct libusb_config_descriptor *cfg = NULL;
    if (libusb_get_active_config_descriptor(dev, &cfg) < 0) return -1;
    for (int i = 0; i < cfg->bNumInterfaces; i++) {
        const struct libusb_interface *ifc = &cfg->interface[i];
        for (int a = 0; a < ifc->num_altsetting; a++) {
            const struct libusb_interface_descriptor *id = &ifc->altsetting[a];
            for (int e = 0; e < id->bNumEndpoints; e++) {
                const struct libusb_endpoint_descriptor *ep = &id->endpoint[e];
                int type = ep->bmAttributes & LIBUSB_TRANSFER_TYPE_MASK;
                if (type == LIBUSB_TRANSFER_TYPE_BULK &&
                    (ep->bEndpointAddress & LIBUSB_ENDPOINT_DIR_MASK) == LIBUSB_ENDPOINT_IN) {
                    *ep_out = ep->bEndpointAddress;
                    *mps_out = ep->wMaxPacketSize;
                    libusb_free_config_descriptor(cfg);
                    return 0;
                }
            }
        }
    }
    libusb_free_config_descriptor(cfg);
    return -1;
}

static int open_device(void) {
    libusb_device_handle *h =
        libusb_open_device_with_vid_pid(NULL, FPC_USB_VID, FPC_USB_PID_ACER);
    if (h) g_pid = FPC_USB_PID_ACER;
    else {
        h = libusb_open_device_with_vid_pid(NULL, FPC_USB_VID, FPC_USB_PID_HONOR);
        if (h) g_pid = FPC_USB_PID_HONOR;
    }
    if (!h) {
        fprintf(stderr, "[-] no FPC sensor found (10a5:e340 / 10a5:a900)\n");
        return -1;
    }
    g_devh = h;
    printf("[+] opened %04x:%04x\n", FPC_USB_VID, g_pid);
    libusb_reset_device(g_devh);
    if (libusb_kernel_driver_active(g_devh, 0) == 1)
        libusb_detach_kernel_driver(g_devh, 0);
    if (libusb_claim_interface(g_devh, 0) < 0) {
        fprintf(stderr, "[-] failed to claim interface 0\n");
        return -1;
    }
    if (find_bulk_in(libusb_get_device(g_devh), &g_ep_bulk_in, &g_ep_mps) < 0) {
        fprintf(stderr, "[-] no bulk IN endpoint found\n");
        return -1;
    }
    printf("[+] bulk IN endpoint 0x%02x (mps=%d)\n", g_ep_bulk_in, g_ep_mps);
    return 0;
}

static int arm_sensor(void) {
    uint8_t magic[4] = { FPC_ARM_MAGIC };
    if (ctrl_out(CMD_ARM, 0x0001, 0x0000, magic, 4) < 0) return -1;
    g_armed = 1;
    printf("[*] sensor armed. Touch the sensor (Ctrl+C to stop).\n\n");
    return 0;
}

int main(int argc, char **argv) {
    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);
    printf("=== FPC Disum sensor utility ===\n");
    if (argc > 1) {
        if (strcmp(argv[1], "probe") == 0) {
            g_probe = 1;
            g_target = 0;
        } else if (strcmp(argv[1], "sweep") == 0) {
            g_sweep = 1;
            g_target = 0;
        } else if (strcmp(argv[1], "calib") == 0) {
            g_calib = 1;
            g_target = 0;
        } else if (strcmp(argv[1], "calib-spi") == 0) {
            g_calib = 2;
            g_target = 0;
        } else {
            g_target = atoi(argv[1]);
            if (g_target < 1) g_target = 1;
        }
    }

    if (libusb_init(NULL) < 0) { fprintf(stderr, "[-] libusb_init failed\n"); return 1; }
    SSL_library_init();
    SSL_load_error_strings();

    if (open_device() < 0) goto fail;

    uint8_t buf[65536];

    if (ctrl_out(CMD_INDICATE_S_STATE, 0x0010, 0x0000, NULL, 0) < 0) goto fail;

    int n = ctrl_in(GET_STATE, 0x0000, 0x0000, buf, 72);
    if (n >= 4) printf("[+] sensor firmware %d.%d.%d.%d\n", buf[3], buf[2], buf[1], buf[0]);

    uint8_t init_magic[4] = { FPC_INIT_MAGIC };
    if (ctrl_out(CMD_INIT, 0x0001, 0x0000, init_magic, 4) < 0) goto fail;

    n = bulk_read_event(buf, sizeof buf, 3000);
    if (n < FPC_EVENT_HDR_SIZE) {
        fprintf(stderr, "[-] no init result (%s)\n",
                n < 0 ? libusb_error_name(n) : "short");
        goto fail;
    }
    printf("[+] init result: %s, %u bytes\n", fpc_event_to_str(rd32le(buf)), rd32le(buf + 4));

    memset(buf, 0, sizeof buf);
    n = ctrl_in(CMD_GET_TLS_KEY, 0x0000, 0x0000, buf, 1000);
    if (n <= 0 || derive_psk(buf, n) < 0) goto fail;

    if (tls_setup() < 0) goto fail;
    if (ctrl_out(CMD_TLS_INIT, 0x0001, 0x0000, NULL, 0) < 0) goto fail;
    printf("[*] TLS-PSK handshake (host is TLS client)...\n");

    while (g_running) {
        /* Drive the TLS state machine first: this is what emits the
         * ClientHello after CMD_TLS_INIT, and drains decrypted app data. */
        if (!g_tls_ready) {
            int pr = tls_pump();
            if (pr < 0) break;
        } else {
            while (tls_pump() == 1) { }
        }

        if (g_probe) {
            /* Probe mode: with NO finger on the sensor, ask the device for the
             * calibration/dead-pixel image and a plain image, logging every
             * event it emits.  Goal: obtain a no-finger baseline to subtract. */
            static int ticks = 0, stage = 0;
            if (g_tls_ready) {
                ticks++;
                if (stage == 0) {
                    printf("[probe] CMD_GET_DEAD_PIXELS (finger OFF)\n");
                    ctrl_out(CMD_GET_DEAD_PIXELS, 0x0000, 0x0000, NULL, 0);
                    stage = 1; ticks = 0;
                } else if (stage == 1 && ticks >= 8) {
                    printf("[probe] CMD_GET_IMG (finger OFF)\n");
                    ctrl_out(CMD_GET_IMG, 0x0000, 0x0000, NULL, 0);
                    stage = 2; ticks = 0;
                } else if (stage == 2 && ticks >= 8) {
                    printf("[probe] CMD_REFRESH_SENSOR (finger OFF)\n");
                    ctrl_out(CMD_REFRESH_SENSOR, 0x0000, 0x0000, NULL, 0);
                    stage = 3; ticks = 0;
                } else if (stage == 3 && ticks >= 40) {
                    printf("[probe] done (no more events)\n");
                    break;
                }
            }
        }

        if (g_sweep) {
            /* Sweep mode: try every command that might yield a second /
             * reference (no-finger) image, logging every event.  No finger
             * interaction required.  Rationale: the vendor driver's FID can
             * hold one or two image buffers ("Second image does not exist")
             * and its dead-pixel test captures a no-finger image. */
            static int ticks = 0, stage = 0;
            static uint8_t kpi[64];
            if (g_tls_ready) {
                ticks++;
                if (stage == 0) {
                    printf("[sweep] stage0: CMD_GET_KPI (no finger)\n");
                    int r = ctrl_in(CMD_GET_KPI, 0x0000, 0x0000, kpi, 28);
                    if (r > 0) hexdump("kpi", kpi, r);
                    stage = 1; ticks = 0;
                } else if (stage == 1 && ticks >= 6) {
                    printf("[sweep] stage1: CMD_GET_DEAD_PIXELS\n");
                    ctrl_out(CMD_GET_DEAD_PIXELS, 0x0000, 0x0000, NULL, 0);
                    stage = 2; ticks = 0;
                } else if (stage == 2 && ticks >= 6) {
                    printf("[sweep] stage2: CMD_GET_IMG (not armed)\n");
                    ctrl_out(CMD_GET_IMG, 0x0000, 0x0000, NULL, 0);
                    stage = 3; ticks = 0;
                } else if (stage == 3 && ticks >= 6) {
                    printf("[sweep] stage3: CMD_ARM (no finger)\n");
                    arm_sensor();
                    stage = 4; ticks = 0;
                } else if (stage == 4 && ticks >= 6) {
                    printf("[sweep] stage4: CMD_GET_IMG (armed, no finger)\n");
                    ctrl_out(CMD_GET_IMG, 0x0000, 0x0000, NULL, 0);
                    stage = 5; ticks = 0;
                } else if (stage == 5 && ticks >= 6) {
                    printf("[sweep] stage5: CMD_GET_IMG again (armed)\n");
                    ctrl_out(CMD_GET_IMG, 0x0000, 0x0000, NULL, 0);
                    stage = 6; ticks = 0;
                } else if (stage == 6 && ticks >= 6) {
                    printf("[sweep] stage6: CMD_GET_KPI again\n");
                    int r = ctrl_in(CMD_GET_KPI, 0x0000, 0x0000, kpi, 28);
                    if (r > 0) hexdump("kpi", kpi, r);
                    stage = 7; ticks = 0;
                } else if (stage == 7 && ticks >= 6) {
                    printf("[sweep] stage7: CMD_REFRESH_SENSOR\n");
                    ctrl_out(CMD_REFRESH_SENSOR, 0x0000, 0x0000, NULL, 0);
                    stage = 8; ticks = 0;
                } else if (stage == 8 && ticks >= 30) {
                    printf("[sweep] done (%d images captured)\n", g_capture_count);
                    break;
                }
            }
        }

        if (g_calib) {
            /* calib mode: fetch the per-unit data the vendor driver reads at
             * runtime.  From the decrypted vendor session the only per-unit
             * commands are CMD_GET_KPI (28-byte device constant) and
             * CMD_GET_DEAD_PIXELS (-> EVT_DEAD_PIXEL_REPORT).  The real
             * calibration image lives in Windows, not on the USB bus:
             *   file      C:\Windows\System32\WinBioPlugIns\calibrationimg.pndat
             *   registry  HKLM\SOFTWARE\FPC\WBF
             * (found in FpcDisumEngine.dll / FpcSessionService.exe). */
            static int ticks = 0, stage = 0;
            static uint8_t kpi[64];
            if (g_tls_ready) {
                ticks++;
                if (stage == 0) {
                    printf("[calib] CMD_GET_KPI\n");
                    int r = ctrl_in(CMD_GET_KPI, 0x0000, 0x0000, kpi, 28);
                    if (r > 0) { printf("[calib] KPI (%d bytes):\n", r); hexdump("kpi", kpi, r); }
                    else printf("[calib] KPI read failed (%d)\n", r);
                    stage = 1; ticks = 0;
                } else if (stage == 1 && ticks >= 6) {
                    printf("[calib] CMD_GET_DEAD_PIXELS\n");
                    ctrl_out(CMD_GET_DEAD_PIXELS, 0x0000, 0x0000, NULL, 0);
                    stage = 2; ticks = 0;
                } else if (stage == 2 && ticks >= 6) {
                    if (g_calib == 2) {
                        printf("[calib] SPI/OTP probe (experimental)\n");
                        uint8_t rb[16];
                        int r = ctrl_in(CMD_PASSTHRU_FROM_SPI, 0x0000, 0x0000, rb, sizeof rb);
                        printf("[calib] CMD_PASSTHRU_FROM_SPI -> %d\n", r);
                        if (r > 0) hexdump("spi", rb, r);
                        stage = 3; ticks = 0;
                    } else {
                        printf("[calib] done\n");
                        break;
                    }
                } else if (stage == 3 && ticks >= 8) {
                    printf("[calib] done\n");
                    break;
                }
            }
        }

        if (g_tls_ready && !g_armed && !g_probe && !g_sweep && !g_calib) {
            if (arm_sensor() < 0) break;
        }
        if (!g_probe && !g_sweep && !g_calib && g_capture_count >= g_target) break;

        n = bulk_read_event(buf, sizeof buf, 500);
        if (n == LIBUSB_ERROR_TIMEOUT) continue;
        if (n < 0) { fprintf(stderr, "[-] bulk: %s\n", libusb_error_name(n)); break; }
        uint32_t code = rd32le(buf);
        if (code == EVT_TLS) {
            BIO_write(g_rbio, buf + FPC_EVENT_HDR_SIZE, n - FPC_EVENT_HDR_SIZE);
        } else {
            /* Post-handshake events (finger down / image / ...) arrive as
             * plain framed packets, not wrapped in EVT_TLS. */
            handle_inner_event(code, buf + FPC_EVENT_HDR_SIZE, n - FPC_EVENT_HDR_SIZE);
        }
    }

    save_stack(g_capture_count);

    printf("\n[*] stopping session...\n");
    uint8_t disarm[4] = { FPC_DISARM_MAGIC };
    ctrl_out(CMD_ARM, 0x0001, 0x0000, disarm, 4);
    ctrl_out(CMD_ABORT, 0x0000, 0x0000, NULL, 0);
    ctrl_out(CMD_FINGERPRINT_SESSION_OFF, 0x0000, 0x0000, NULL, 0);

    libusb_release_interface(g_devh, 0);
    libusb_close(g_devh);
    libusb_exit(NULL);
    if (g_ssl) SSL_free(g_ssl);
    if (g_ssl_ctx) SSL_CTX_free(g_ssl_ctx);
    printf("[+] done.\n");
    return g_capture_count > 0 ? 0 : 2;

fail:
    if (g_devh) { libusb_release_interface(g_devh, 0); libusb_close(g_devh); }
    libusb_exit(NULL);
    if (g_ssl) SSL_free(g_ssl);
    if (g_ssl_ctx) SSL_CTX_free(g_ssl_ctx);
    fprintf(stderr, "[-] aborted\n");
    return 1;
}
