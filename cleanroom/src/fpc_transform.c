/*
 * fpc_transform.c — clean-room reimplementation of two image-transform leaves
 * from the reachable BEP tree.  Derived from disassembly of fpc_enclave.dll;
 * see MAP.md.
 *
 *   0x18002ca30  cr_affine_sample_u8 — Q15 bilinear resample of a byte image
 *                                     over an affine grid.
 *   0x18000ee70  cr_polyphase_fir4   — 4-phase FIR over interleaved bytes.
 */
#include "fpc_bep.h"

/* 0x18002ca30 — resample `src` into `dst` with Q15 fixed-point bilinear
 * interpolation.  For each output pixel (col,row):
 *     x = s->x_org + row*s->x_row + col*s->x_col     (Q15)
 *     y = s->y_org + row*s->y_row + col*s->y_col     (Q15)
 *     xi = x>>15, xf = x&0x7fff, yi = y>>15, yf = y&0x7fff
 *     idx = yi*src->a + xi
 *     w00 = ((0x8000-xf)*(0x8000-yf))>>15, w10 = ((0x8000-yf)*xf)>>15
 *     w01 = ((0x8000-xf)*yf)>>15,        w11 = (xf*yf)>>15
 *     out = (int8_t)((w00*src[idx] + w01*src[idx+stride]
 *                    + w10*src[idx+1] + w11*src[idx+stride+1]) >> 15)
 * All weights are 32-bit signed; the source window origin is
 * src->data + (src->offy*src->a + src->offx) and the destination origin is
 * dst->data + (dst->offy*dst->a + dst->offx).  dst->w x dst->h pixels. */
void cr_affine_sample_u8(cr_image *dst, const cr_image *src,
                         const cr_affine_map *s)
{
    int sstride = src->a;
    int dstride = dst->a;
    const uint8_t *sbase = (const uint8_t *)src->data
        + ((long long)src->offy * sstride + src->offx);
    uint8_t *dbase = (uint8_t *)dst->data
        + ((long long)dstride * dst->offy + dst->offx);
    int h = dst->h;
    int w = dst->w;

    if (h <= 0)
        return;

    int x = s->x_org;
    int y = s->y_org;
    int rowoff = 0;
    int ri = 0;

    do {
        if (w > 0) {
            uint8_t *dp = dbase + rowoff;
            int xx = x, yy = y;
            do {
                int xi = xx >> 15;
                int xf = xx & 0x7fff;
                int yi = yy >> 15;
                int yf = yy & 0x7fff;
                int idx = yi * sstride + xi;
                int w00 = ((0x8000 - xf) * (0x8000 - yf)) >> 15;
                int w10 = ((0x8000 - yf) * xf) >> 15;
                int w01 = ((0x8000 - xf) * yf) >> 15;
                int w11 = (xf * yf) >> 15;
                int v = w00 * sbase[idx]
                      + w01 * sbase[idx + sstride]
                      + w10 * sbase[idx + 1]
                      + w11 * sbase[idx + sstride + 1];
                xx += s->x_col;
                yy += s->y_col;
                *dp = (uint8_t)(int8_t)(v >> 15);
                dp++;
            } while (dp != dbase + rowoff + w);
        }
        ri++;
        x += s->x_row;
        rowoff += dstride;
        y += s->y_row;
    } while (ri != h);
}

/* 0x18000ee70 — 4-phase FIR.  The input is treated as a stream of 4-byte
 * groups; for each group at byte offset 4*p the four output bytes are
 *     out[4p+r] = (int8_t)((0x4000 + sum_{j=0}^{2*iters} in[4p+r+j]*coef[j]) >> 15)
 * where iters = ((unsigned)(ncoef-2) >> 1) + 1.  `nbytes` is the input length
 * (processed in groups of 4; a value <= 3 is a no-op); `ncoef` is the number of
 * int16 coefficients.  The accumulator arithmetic is 32-bit signed. */
void cr_polyphase_fir4(uint8_t *out, const uint8_t *in, const int16_t *coef,
                       int nbytes, int ncoef)
{
    if (nbytes <= 3)
        return;

    const uint8_t *end = in + (size_t)((uint32_t)(nbytes - 4) >> 2) * 4 + 4;

    do {
        int a0 = in[0] * coef[0];
        int a1 = in[1] * coef[0];
        int a2 = in[2] * coef[0];
        int a3 = in[3] * coef[0];

        if (ncoef > 1) {
            int iters = (int)(((uint32_t)(ncoef - 2) >> 1) + 1);
            int A = in[1], B = in[2], C = in[3];
            for (int k = 1; k <= iters; k++) {
                int c1 = coef[2 * k - 1];
                int c2 = coef[2 * k];
                int N = in[2 * k + 2];
                int M = in[2 * k + 3];
                a0 += A * c1 + B * c2;
                a1 += B * c1 + C * c2;
                a2 += C * c1 + N * c2;
                a3 += N * c1 + M * c2;
                A = C; B = N; C = M;
            }
        }

        out[0] = (uint8_t)(int8_t)((a0 + 0x4000) >> 15);
        out[1] = (uint8_t)(int8_t)((a1 + 0x4000) >> 15);
        out[2] = (uint8_t)(int8_t)((a2 + 0x4000) >> 15);
        out[3] = (uint8_t)(int8_t)((a3 + 0x4000) >> 15);

        in += 4;
        out += 4;
    } while (end != in);
}
