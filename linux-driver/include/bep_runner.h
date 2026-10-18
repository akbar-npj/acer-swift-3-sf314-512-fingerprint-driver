/*
 * bep_runner.h — BEP + matcher backend for the fpc2040 libfprint driver.
 *
 * The driver captures a raw 128x88 contact frame.  The clean-room BEP turns
 * it into a 64x176 ridge image, and the correlation matcher compares ridges.
 *
 * The BEP backend is deliberately isolated behind fpc_bep_ridge() so it can be
 * swapped without touching the driver.  The current implementation shells out
 * to the validated `fpc_recon_native --cleanroom` (which still needs the
 * vendor DLL for enclave bootstrap + static tables).  A future implementation
 * will link libfpcbep.a directly and remove that dependency.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#ifndef FPC_BEP_RUNNER_H
#define FPC_BEP_RUNNER_H

#include <stdint.h>
#include <stddef.h>

#define FPC_RAW_W             128
#define FPC_RAW_H             88
#define FPC_RAW_BYTES         (FPC_RAW_W * FPC_RAW_H)          /* 11264 */
#define FPC_IMG_HDR_BYTES     22
#define FPC_RAW_PAYLOAD_BYTES (FPC_IMG_HDR_BYTES + FPC_RAW_BYTES) /* 11286 */

#define FPC_RIDGE_W           64
#define FPC_RIDGE_H           176
#define FPC_RIDGE_BYTES       (FPC_RIDGE_W * FPC_RIDGE_H)      /* 11264 */

/* Convert a captured EVT_IMG payload ([22-byte hdr][128x88 px]) into a
 * 64x176 ridge image.  Returns 0 on success, -1 on failure (err set). */
int fpc_bep_ridge (const uint8_t *raw_payload, size_t raw_len,
                   uint8_t *ridge, char **err);

/* Correlation match of two 64x176 ridge images, 0..1000 (>= 550 = same). */
int fpc_match_ridge (const uint8_t *a, const uint8_t *b);

/* Backend paths (env overrides: FPC_RECON_BIN, FPC_ENCLAVE_DLL). */
const char *fpc_bep_recon_bin (void);
const char *fpc_bep_dll_path (void);

#endif /* FPC_BEP_RUNNER_H */
