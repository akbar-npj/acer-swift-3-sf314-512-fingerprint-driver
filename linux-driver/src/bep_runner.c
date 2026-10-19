/*
 * bep_runner.c — BEP + matcher backend for the fpc2040 libfprint driver.
 *
 * See bep_runner.h.  Both halves are fully standalone clean-room code:
 *   - fpc_bep_ridge(): cr_bep_run_frame() from libfpcbep.
 *   - fpc_match_ridge(): libfpc_match.
 *
 * No vendor DLL, no subprocess, no temporary files.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#define _GNU_SOURCE
#include "bep_runner.h"
#include "fpc_match.h"
#include "fpc_bep_template.h"

#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
fpc_bep_ridge (const uint8_t *raw_payload, size_t raw_len,
               uint8_t *ridge, char **err)
{
  const uint8_t *hdr = NULL;
  const uint8_t *pix;
  int rc;

  if (err)
    *err = NULL;

  if (raw_payload == NULL || ridge == NULL)
    {
      if (err)
        *err = g_strdup ("null buffer");
      return -1;
    }

  if (raw_len == FPC_RAW_PAYLOAD_BYTES)
    {
      hdr = raw_payload;
      pix = raw_payload + FPC_IMG_HDR_BYTES;
    }
  else if (raw_len == FPC_RAW_BYTES)
    {
      pix = raw_payload;
    }
  else
    {
      if (err)
        *err = g_strdup_printf ("unexpected frame length %zu", raw_len);
      return -1;
    }

  rc = cr_bep_run_frame (hdr, pix, ridge);
  if (rc != 0)
    {
      if (err)
        *err = g_strdup_printf ("cr_bep_run_frame failed (%d)", rc);
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
