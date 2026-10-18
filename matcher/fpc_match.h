/*
 * fpc_match.h — host-side matcher for FPC 2040 (Disum/Swift21) ridge images.
 *
 * The sensor is a small strip (64x176 px, ~3.2 x 8.8 mm).  A single frame holds
 * only ~5-8 ridges across, which yields far too few minutiae for NBIS/bozorth
 * (typically 2-6, below MIN_COMPUTABLE_BOZORTH_MINUTIAE = 10).  FPC's own
 * matcher is correlation based; this is the clean-room equivalent:
 *
 *   1. band-pass the reconstructed ridge image (remove shading, keep ridges),
 *   2. local contrast normalisation so wet/dry regions weigh the same,
 *   3. masked, rotation-searched normalised cross-correlation.
 *
 * Scores are 0..1000.  Empirically (see MATCHING.md) genuine same-finger
 * pairs across sessions score 700-900, impostors 200-450.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#ifndef FPC_MATCH_H
#define FPC_MATCH_H

#include <stdint.h>
#include <stddef.h>

#define FPC_TPL_W 64
#define FPC_TPL_H 176
#define FPC_TPL_PIXELS (FPC_TPL_W * FPC_TPL_H)

/* A preprocessed image ready for matching.  Keep it small enough to serialise
 * into FpPrint data: 11264 (z) + 1408 (mask) + header ~= 12.7 KiB. */
typedef struct {
    uint8_t  w, h;
    uint8_t  coverage;          /* percent of pixels with usable ridge signal */
    int8_t   z[FPC_TPL_PIXELS]; /* band-passed, locally normalised, ~[-127,127] */
    uint8_t  mask[(FPC_TPL_PIXELS + 7) / 8];
} fpc_tpl;

/* Build a template from an 8-bit grayscale ridge image (row-major, w*h).
 * Returns 0 on success, -1 if the image has no usable ridge area. */
int fpc_tpl_build(const uint8_t *img, int w, int h, fpc_tpl *out);

/* Compare two templates.  Returns 0..1000 (1000 = identical).
 * Typical runtime on a 64x176 pair: ~3 ms on one x86-64 core. */
int fpc_tpl_match(const fpc_tpl *a, const fpc_tpl *b);

/* Best score of @probe against a gallery, plus the index of the best entry. */
int fpc_tpl_match_gallery(const fpc_tpl *probe, const fpc_tpl *gallery,
                          int n, int *best_index);

/* Default accept threshold.  Tuned on the 2026-10 capture corpus:
 * genuine cross-session min 490 (median 750), impostor max 490.  With a
 * 5-template gallery the genuine minimum rises to ~790. */
#define FPC_MATCH_THRESHOLD 550

#endif /* FPC_MATCH_H */
