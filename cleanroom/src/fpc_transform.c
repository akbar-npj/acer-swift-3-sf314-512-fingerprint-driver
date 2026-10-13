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

/* 0x180044b10 — bilinear "splat" of 16 weighted points into two float buffers.
 * `w[16]` and `alpha[16]` are per-point weights; `x0`/`y0` are both the start
 * coordinate AND the per-step increment (x_k = x0*(k+1), y_k = y0*(k+1)); the
 * float position is scaled by `scale`.  For each point the four bilinear taps
 * are accumulated into `bufB` (weight only) and `bufA` (weight*alpha), both
 * laid out with a 17-float row stride:
 *     xi = (int)x, xf = x - (float)(int)x, yi = (int)y - (y0 < 0), yf = y - (float)yi
 *     wf = w[k]*scale
 *     w00 = ((1-xf)*(1-yf))*wf   -> idx
 *     w10 = ((1-yf)*xf)*wf       -> idx+1
 *     w01 = ((1-xf)*yf)*wf       -> idx+17
 *     w11 = (xf*yf)*wf           -> idx+18
 * All arithmetic is single precision in exactly this order (built with
 * -ffp-contract=off). */
void cr_splat_bilinear(const float *w, float *bufA, float *bufB,
                       const float *alpha, float x0, float y0, float scale)
{
    float x = x0;
    float y = y0;
    int negy = (y0 < 0.0f) ? 1 : 0;

    for (int k = 0; k < 16; k++) {
        int xi = (int)x;
        int yi = (int)y - negy;
        float wf = w[k] * scale;
        float xf = x - (float)(int)x;
        float yf = y - (float)yi;
        int idx = yi * 17 + xi;
        float w00 = (1.0f - xf) * (1.0f - yf) * wf;
        float w10 = (1.0f - yf) * xf * wf;
        float w01 = (1.0f - xf) * yf * wf;
        float w11 = xf * yf * wf;

        bufB[idx]      += w00;
        bufA[idx]       = w00 * alpha[k] + bufA[idx];
        bufB[idx + 1]  += w10;
        bufA[idx + 1]   = w10 * alpha[k] + bufA[idx + 1];
        bufB[idx + 17] += w01;
        bufA[idx + 17]  = w01 * alpha[k] + bufA[idx + 17];
        bufB[idx + 18] += w11;
        bufA[idx + 18]  = w11 * alpha[k] + bufA[idx + 18];

        x += x0;
        y += y0;
    }
}

/* 0x1800169b0 — 8-neighbour 3x3 Laplacian of a single row.  out[i] is the
 * Laplacian centred on C[i+1]:
 *     8*C[i+1] - (A[i]+A[i+1]+A[i+2] + C[i]+C[i+2] + B[i]+B[i+1]+B[i+2])
 * where C is the centre row and A/B the neighbouring rows.  The vendor writes
 * it as a two-pass 4-wide vectorised loop: pass 1 covers the bulk columns
 * [0, w-4), pass 2 the tail [w-4, w) (with an output-pointer adjustment of
 * -((-w)&3) shorts so the last window lands flush at column w).  Arithmetic is
 * 32-bit; the stored value is the low 16 bits. */
void cr_laplacian_3x3(int16_t *out, const int16_t *A, const int16_t *C,
                      const int16_t *B, int w)
{
    int pass = 2;
    int start = 0;
    int end = w - 4;
    int outadj = -((-w) & 3);
    int16_t *op = out;

    do {
        if (start < end) {
            int iters = ((end - 1 - start) >> 2) + 1;
            const int16_t *a = A + start;
            const int16_t *c = C + start;
            const int16_t *b = B + start;
            for (int k = 0; k < iters; k++) {
                for (int r = 0; r < 4; r++) {
                    op[k * 4 + r] = (int16_t)(8 * c[r + 1]
                        - (a[r] + a[r + 1] + a[r + 2]
                         + c[r] + c[r + 2]
                         + b[r] + b[r + 1] + b[r + 2]));
                }
                a += 4; c += 4; b += 4;
            }
            op += iters * 4;
        }
        op += outadj;
        if (pass == 1)
            break;
        pass = 1;
        start = w - 4;
        end = w;
    } while (1);
}
