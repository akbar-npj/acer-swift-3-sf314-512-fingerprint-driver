/*
 * bep_runner.c — BEP + matcher backend for the fpc2040 libfprint driver.
 *
 * See bep_runner.h.  Two independent pieces:
 *   - fpc_bep_ridge(): shells out to fpc_recon_native --cleanroom.
 *   - fpc_match_ridge(): links libfpc_match.a (fully standalone clean-room).
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#define _GNU_SOURCE
#include "bep_runner.h"
#include "fpc_match.h"

#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

const char *
fpc_bep_recon_bin (void)
{
  const char *e = getenv ("FPC_RECON_BIN");
  if (e && *e)
    return e;
  return "/home/shaan/native/fpc_recon_native";
}

const char *
fpc_bep_dll_path (void)
{
  const char *e = getenv ("FPC_ENCLAVE_DLL");
  if (e && *e)
    return e;
  return "/home/shaan/fp/FingerPrint_Carewe_20.26.23.27_W11x64/"
         "12b431fd-7d7e-4dd7-b87c-9ab3f9a3d01b/x64/fpc_enclave.dll";
}

int
fpc_bep_ridge (const uint8_t *raw_payload, size_t raw_len,
               uint8_t *ridge, char **err)
{
  char raw_path[] = "/tmp/fpc_raw_XXXXXX";
  char ridge_path[] = "/tmp/fpc_ridge_XXXXXX";
  gint raw_fd, ridge_fd;
  gboolean ok;
  gint status = -1;
  gchar *out = NULL, *errout = NULL;
  GError *gerr = NULL;
  gchar *argv[7];
  FILE *fp;
  size_t got;

  if (err)
    *err = NULL;

  raw_fd = g_mkstemp (raw_path);
  if (raw_fd < 0)
    {
      if (err)
        *err = g_strdup ("cannot create raw temp file");
      return -1;
    }
  ridge_fd = g_mkstemp (ridge_path);
  if (ridge_fd < 0)
    {
      close (raw_fd);
      unlink (raw_path);
      if (err)
        *err = g_strdup ("cannot create ridge temp file");
      return -1;
    }
  close (ridge_fd);
  unlink (ridge_path);

  if (write (raw_fd, raw_payload, raw_len) != (ssize_t) raw_len)
    {
      close (raw_fd);
      unlink (raw_path);
      if (err)
        *err = g_strdup ("cannot write raw temp file");
      return -1;
    }
  close (raw_fd);

  argv[0] = (gchar *) fpc_bep_recon_bin ();
  argv[1] = raw_path;
  argv[2] = ridge_path;
  argv[3] = "--cleanroom";
  argv[4] = "--dll";
  argv[5] = (gchar *) fpc_bep_dll_path ();
  argv[6] = NULL;

  ok = g_spawn_sync (NULL, argv, NULL, G_SPAWN_DEFAULT,
                     NULL, NULL, &out, &errout, &status, &gerr);

  if (!ok)
    {
      if (err)
        *err = g_strdup_printf ("spawn %s failed: %s",
                                argv[0], gerr ? gerr->message : "?");
      g_clear_error (&gerr);
      unlink (raw_path);
      g_free (out);
      g_free (errout);
      return -1;
    }

  if (!g_spawn_check_wait_status (status, &gerr))
    {
      if (err)
        *err = g_strdup_printf ("recon failed: %s (stderr: %.200s)",
                                gerr ? gerr->message : "?",
                                errout ? errout : "");
      g_clear_error (&gerr);
      unlink (raw_path);
      g_free (out);
      g_free (errout);
      return -1;
    }

  fp = fopen (ridge_path, "rb");
  if (!fp)
    {
      if (err)
        *err = g_strdup ("cannot open ridge output");
      unlink (raw_path);
      g_free (out);
      g_free (errout);
      return -1;
    }
  got = fread (ridge, 1, FPC_RIDGE_BYTES, fp);
  fclose (fp);
  unlink (raw_path);
  unlink (ridge_path);
  g_free (out);
  g_free (errout);

  if (got != FPC_RIDGE_BYTES)
    {
      if (err)
        *err = g_strdup_printf ("short ridge output (%zu/%d)",
                                got, FPC_RIDGE_BYTES);
      return -1;
    }
  return 0;
}

int
fpc_match_ridge (const uint8_t *a, const uint8_t *b)
{
  fpc_tpl ta, tb;

  if (fpc_tpl_build (a, FPC_RIDGE_W, FPC_RIDGE_H, &ta) != 0)
    return 0;
  if (fpc_tpl_build (b, FPC_RIDGE_W, FPC_RIDGE_H, &tb) != 0)
    return 0;
  return fpc_tpl_match (&ta, &tb);
}
