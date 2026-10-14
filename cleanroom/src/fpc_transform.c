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

/* 0x18001fd10 — Q15 bilinear warp of an int16 image with ldexp-scaled steps.
 *   void fn(cr_image *dst, const cr_image *src, const float *coef, uint32_t _)
 *
 * `coef` holds {x_col, x_row, x_org, y_col, y_row, y_org} as floats (the same
 * layout as cr_affine_map).  The vendor scales each axis by
 *     sx = (2*src->w - 2) * 2^-24 ,  sy = (2*src->h - 2) * 2^-24
 * (built with cr_ldexpf), truncates the six quotients toward zero to ints and
 * uses them as the Q15 grid steps:
 *     x = x_org + row*x_row + col*x_col   (likewise y)
 * Each 32-bit coordinate is first reduced to its low 24 bits, folded into a
 * triangle (v > 0x7fffff -> 0xffffff - v) and then shifted right 9 and scaled
 * by (2*n - 2) to split into an integer part (>>15) and a 15-bit fraction.
 * The source window origin is src->data + (src->offy*src->a + src->offx) with
 * row stride src->a; the destination is dst->w x dst->h int16 starting at
 * dst->data + (dst->offy*dst->a + dst->offx).  A non-positive dst->h is a
 * no-op; a non-positive dst->w skips the inner loop (as in the vendor). */
void cr_warp_bilinear_q15(cr_image *dst, const cr_image *src,
                          const float *coef)
{
    int dw = dst->w, dh = dst->h;
    int sstride = src->a;
    const int16_t *sbase = (const int16_t *)src->data
        + ((long long)src->offy * sstride + src->offx);
    int16_t *dbase = (int16_t *)dst->data
        + ((long long)dst->offy * dst->a + dst->offx);

    float sx = cr_ldexpf((float)(2 * src->w - 2), -24);
    float sy = cr_ldexpf((float)(2 * src->h - 2), -24);
    int xscale = 2 * src->w - 2;
    int yscale = 2 * src->h - 2;

    int xcol = (int)(coef[0] / sx);
    int xrow = (int)(coef[1] / sx);
    int x0   = (int)(coef[2] / sx);
    int ycol = (int)(coef[3] / sy);
    int yrow = (int)(coef[4] / sy);
    int y0   = (int)(coef[5] / sy);

    if (dh <= 0)
        return;

    int ri = 0;
    int rowoff = 0;
    do {
        if (dw > 0) {
            int16_t *dp = dbase + rowoff;
            int x = x0, y = y0;
            do {
                int xm = x & 0xffffff;
                int xv = xm;
                if (xv > 0x7fffff) xv = 0xffffff - xv;
                xv = (xv >> 9) * xscale;
                int xf = xv & 0x7fff, xi = xv >> 15;

                int ym = y & 0xffffff;
                int yv = ym;
                if (yv > 0x7fffff) yv = 0xffffff - yv;
                yv = (yv >> 9) * yscale;
                int yf = yv & 0x7fff, yi = yv >> 15;

                int idx = yi * sstride + xi;
                int w00 = ((0x8000 - xf) * (0x8000 - yf)) >> 15;
                int w10 = ((0x8000 - yf) * xf) >> 15;
                int w01 = ((0x8000 - xf) * yf) >> 15;
                int w11 = (xf * yf) >> 15;
                int v = w00 * sbase[idx]
                      + w01 * sbase[idx + sstride]
                      + w10 * sbase[idx + 1]
                      + w11 * sbase[idx + sstride + 1];
                x = xm + xcol;
                y = ym + ycol;
                *dp = (int16_t)(v >> 15);
                dp++;
            } while (dp != dbase + rowoff + dw);
        }
        ri++;
        x0 += xrow;
        rowoff += dw;
        y0 += yrow;
    } while (ri != dh);
}

/* ------------------------------------------------------------------------ *
 * 0x180018000 — downscale an s16 image (a1) and a u8 image (a2) together.
 *   int fn(cr_image *a1, cr_image *a2, int a3, int a4)
 *
 * a1/a2 must both be a1->w x a1->h with a1->w > a3 and a1->h > a4, else 0x69.
 * Computes s = min((float)w/(float)a3, (float)h/(float)a4) (the SSE MINSS
 * operand order) and the affine coefficient vector
 *   coef = { s, 0, (w - a3*s)*0.5, 0, s, (h - a4*s)*0.5 }
 * then:
 *   - allocates an s16 image d16 (w x h) and a u8 image d8 (w x h);
 *   - cr_copy_u16_shl_guarded(&d16, a1, 0)   (a1 -> d16)
 *   - cr_image_copy_u8(&d8, a2)              (a2 -> d8)
 *   - cr_image_set(a1, a1->data, a3, a4) and cr_image_set(a2, a2->data, a3, a4)
 *     (rewrite both descriptors to the target size, keeping their buffers);
 *   - cr_warp_bilinear_q15(a1, &d16, coef) and
 *     cr_affine_sample_u8_nn(a2, &d8, coef, 0);
 *   - frees d16 and d8.
 * Any failure frees what has been allocated and returns the first error.
 * ------------------------------------------------------------------------ */
int cr_resize_pair_18000(cr_image *a1, cr_image *a2, int a3, int a4)
{
    int w = a1->w, h = a1->h;
    if (w <= a3)
        return 0x69;
    if (h <= a4)
        return 0x69;

    float sw = (float)w / (float)a3;
    float sh = (float)h / (float)a4;
    float s  = (sw < sh) ? sw : sh;

    float coef[6];
    coef[0] = s;
    coef[1] = 0.0f;
    coef[2] = ((float)w - (float)a3 * s) * 0.5f;
    coef[3] = 0.0f;
    coef[4] = s;
    coef[5] = ((float)h - (float)a4 * s) * 0.5f;

    cr_image d16, d8;
    int r = cr_image_alloc_s16((int *)&d16, w, h);
    if (r != 0)
        return r;
    r = cr_image_alloc_u8((int *)&d8, w, h);
    if (r != 0) {
        cr_cleanup_ptr8_clear(&d16);
        return r;
    }

    r = cr_copy_u16_shl_guarded(&d16, a1, 0);
    if (r == 0)
        r = (int)cr_image_copy_u8(&d8, a2);
    if (r == 0)
        r = (int)cr_image_set(a1, a1->data, a3, a4);
    if (r == 0)
        r = (int)cr_image_set(a2, a2->data, a3, a4);
    if (r == 0) {
        cr_warp_bilinear_q15(a1, &d16, coef);
        cr_affine_sample_u8_nn(a2, &d8, coef, 0);
    }
    cr_cleanup_ptr8_clear(&d16);
    cr_cleanup_ptr8_a(&d8);
    return r;
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

/* 7-tap edge-clamped FIR along one 1-D signal.  `base` points at sample 0;
 * samples are `base[j*stride]`, outputs `out[j*stride]` for j=0..n-1.  The taps
 * are clamped to the signal (left edge repeats base[0], right edge repeats
 * base[(n-1)*stride]).  Mirrors the vendor's two-loop split: a rolling-history
 * loop for j=0..n-5 and a second loop for the last four samples whose newest
 * tap is pinned at the end; n<5 takes only the second loop.  32-bit wrapping
 * arithmetic, arithmetic `>>15`. */
static void fir7_1d(int16_t *out, const int16_t *base, int n, int stride,
                    const int16_t *coef)
{
    const int16_t *p = base + 3 * stride;         /* &x[3] */
    int i8 = p[-3 * stride], i7 = p[-2 * stride], i16v = p[-stride];
    int i9 = 0, i5 = 0, i17 = 0, i10 = 0, i18 = 0;
    int16_t *po;
    const int16_t *ps20;
    int start, end;

    if (n < 5) {
        i9 = 0;
        po = out;
        ps20 = p;
        i10 = i8; i17 = i8; i5 = i8;
        start = 0; end = n;
    } else {
        int m = n - 5;
        i9 = i8; i18 = i7; i10 = i8; i17 = i8;
        for (int j = 0; j <= m; j++) {
            i5 = i17; i17 = i10; i10 = i8; i7 = i16v; i8 = i18;
            i16v = p[j * stride];
            out[j * stride] = (int16_t)((int32_t)((uint32_t)coef[6] * (uint32_t)i16v
                                                + (uint32_t)coef[4] * (uint32_t)i8
                                                + (uint32_t)coef[2] * (uint32_t)i17
                                                + (uint32_t)coef[0] * (uint32_t)i9
                                                + (uint32_t)coef[1] * (uint32_t)i5
                                                + (uint32_t)coef[3] * (uint32_t)i10
                                                + (uint32_t)coef[5] * (uint32_t)i7) >> 15);
            i9 = i5; i18 = i7;
        }
        po = out + (m + 1) * stride;
        ps20 = p + (m + 1) * stride;
        start = n - 4; end = n;
    }

    for (int j = start; j < end; j++) {
        i18 = i17; i17 = i10; i10 = i8;
        int16_t sv = *ps20;
        *po = (int16_t)((int32_t)((uint32_t)coef[6] * (uint32_t)(int32_t)sv
                                + (uint32_t)coef[5] * (uint32_t)i16v
                                + (uint32_t)coef[3] * (uint32_t)i10
                                + (uint32_t)coef[1] * (uint32_t)i18
                                + (uint32_t)coef[0] * (uint32_t)i5
                                + (uint32_t)coef[2] * (uint32_t)i17
                                + (uint32_t)coef[4] * (uint32_t)i7) >> 15);
        po += stride;
        i8 = i7; i7 = i16v; i5 = i18; i16v = sv;
    }
}

/* shared canonical-descriptor guard for the two 7-tap FIR twins */
static int fir7_guard(const cr_image *dst, const cr_image *src)
{
    return !(src->a == src->w && src->b == src->h && src->offx == 0 && src->offy == 0 &&
             dst->a == src->a && dst->b == src->b &&
             dst->a == dst->w && dst->b == dst->h && dst->offx == 0 && dst->offy == 0);
}

/* 0x180020d80 — 7-tap int16 FIR applied to every row of `src`, writing `dst`.
 * Both descriptors must be canonical (a==w, b==h, offx==offy==0) and share the
 * same (a,b) pair, else the function returns 0x69.  For each row:
 *     out[j] = (int16_t)((sum_{k=0..6} coef[k] * x[j-3+k]) >> 15)
 * with the taps clamped to the row (left edge repeats x[0], right edge repeats
 * x[w-1]).  See fir7_1d for the loop split. */
int cr_fir7_s16(cr_image *dst, const cr_image *src, const int16_t *coef)
{
    if (fir7_guard(dst, src))
        return 0x69;

    int w = src->w;
    int h = src->h;
    if (h <= 0)
        return 0;

    int stride = src->a;
    const int16_t *s = (const int16_t *)src->data;
    int16_t *d = (int16_t *)dst->data;

    for (int row = 0; row < h; row++)
        fir7_1d(d + row * stride, s + row * stride, w, 1, coef);

    return 0;
}

/* 0x18001c280 — the column-wise (vertical) twin of cr_fir7_s16: the same
 * 7-tap edge-clamped FIR, but run down each of the `w` columns (each `h`
 * samples long, step `a`) instead of across each row.  Same guard. */
int cr_fir7_s16_col(cr_image *dst, const cr_image *src, const int16_t *coef)
{
    if (fir7_guard(dst, src))
        return 0x69;

    int w = src->w;
    int h = src->h;
    if (w <= 0)
        return 0;

    int stride = src->a;
    const int16_t *s = (const int16_t *)src->data;
    int16_t *d = (int16_t *)dst->data;

    for (int col = 0; col < w; col++)
        fir7_1d(d + col, s + col, h, stride, coef);

    return 0;
}

/* 0x18000d8e0 — masked per-column mean correction.  `cfg[9]` is a mode byte:
 * 0 returns 0, 2 runs the correction, anything else returns 0x69.  For mode 2,
 * `r0 = cfg[0xc]`, `r1 = cfg[0x10] + r0`; it requires `r1 <= img->w` and
 * `img->h > 29`, else 0x69.  A "global" mean is taken over the set bits of
 * bitmap rows `bm->offy + r0 .. r1-1`, columns `bm->offx .. offx+h-1`, sampling
 * image column `row` (i.e. `img->data[row + k*img->w]`).  Then for every image
 * column `col` in `[0, img->w)` a local mean is taken over bitmap row
 * `bm->offy + col` (same column span), and — if that row has any set bit —
 * every pixel of the column is replaced by `clamp((int)(p + global - local),
 * 0, 255)`.  All sums are 32-bit; the division/addition is single precision in
 * exactly this order (built with -ffp-contract=off). */
int cr_bitmap_mean_correct(cr_image *img, const cr_image *bm,
                           const uint8_t *cfg)
{
    if (cfg[9] == 0)
        return 0;
    if (cfg[9] != 2)
        return 0x69;

    int w = img->w;
    int h = img->h;
    int r0 = *(const int *)(cfg + 0xc);
    int r1 = *(const int *)(cfg + 0x10) + r0;
    if (r1 > w || h <= 0x1d)
        return 0x69;

    const uint8_t *idata = (const uint8_t *)img->data;
    const uint32_t *bdata = (const uint32_t *)bm->data;
    int a = bm->a;
    int offx = bm->offx, offy = bm->offy;

    uint32_t gsum = 0;
    int gcnt = 0;

    if (r0 < r1) {
        int y = r0;
        int base = (offy + r0) * a;
        do {
            int bit = offx + base;
            int idx = y;
            do {
                if ((bdata[bit >> 5] >> ((bit - base) & 0x1f)) & 1) {
                    gcnt++;
                    gsum += idata[idx];
                }
                bit++;
                idx += w;
            } while (h + offx + base != bit);
            y++;
            base += a;
        } while (r1 != y);
    }

    if (gcnt != 0) {
        for (int col = 0; col < w; col++) {
            uint32_t lsum = 0;
            int lcnt = 0;
            int base = (offy + col) * a;
            int bit = offx + base;
            int idx = col;
            do {
                if ((bdata[bit >> 5] >> ((bit - base) & 0x1f)) & 1) {
                    lcnt++;
                    lsum += idata[idx];
                }
                bit++;
                idx += w;
            } while (h + offx + base != bit);

            if (lcnt != 0) {
                float gmean = (float)(int)gsum / (float)gcnt;
                float lmean = (float)(int)lsum / (float)lcnt;
                for (int k = 0; k < h; k++) {
                    uint8_t *p = (uint8_t *)img->data + (w * k + col);
                    int v = (int)((float)*p + (gmean - lmean));
                    uint8_t b;
                    if (v < 255) {
                        b = (uint8_t)v;
                        if (v < 1)
                            b = 0;
                    } else {
                        b = 255;
                    }
                    *p = b;
                }
            }
        }
    }
    return 0;
}

/* 0x180043db0 — bit-packed sign signature of a small filter bank.  `cfg[0x10]`
 * is a 16-byte-aligned matrix pointer (`cfg[4]` = window size `m`, `cfg[8]` =
 * signed byte `b8`, output count `n = b8/2`); `*inpp` is the input window.
 * NULL matrix -> 0x69, misaligned -> 1, n <= 0 -> 0.  For each matrix row i the
 * window (m*m bytes) is scanned forward and backward; each matrix entry is 16
 * bytes = 8 int16, split lo = entries 0..3 and hi = 4..7 (sign-extended to
 * int32).  Four 4-lane dot products are accumulated in 32-bit SIMD:
 *     A = Σ lo*in[k],  B = Σ hi*in[k],  C = Σ lo*in[m*m-1-k],  D = Σ hi*in[...]
 * then `out[i] = pack(A,B)` and `out[i+n] = pack(C,D)`, where
 * `pack(P,Q) = Σ_l (P[l]>0 ? 1<<l : 0) | (Q[l]>0 ? 0x10<<l : 0)` (a signed
 * per-lane greater-than-zero test, packed as two nibbles).  The matrix entry
 * stride is `b8*8` bytes and the row stride 16. */
int cr_signpack_dot(uint8_t *out, const void *const *inpp, const uint8_t *cfg)
{
    const uint8_t *mat = *(const uint8_t *const *)(cfg + 0x10);
    if (mat == NULL)
        return 0x69;
    if (((uintptr_t)mat & 0xf) != 0)
        return 1;

    int n = (int8_t)cfg[8] / 2;
    if (n <= 0)
        return 0;

    int m = *(const int *)(cfg + 4);
    int nwin = m * m;
    const uint8_t *input = (const uint8_t *)*inpp;
    long long estride = (long long)(int8_t)cfg[8] * 8;

    for (int i = 0; i < n; i++) {
        uint32_t A[4] = {0, 0, 0, 0}, B[4] = {0, 0, 0, 0};
        uint32_t C[4] = {0, 0, 0, 0}, D[4] = {0, 0, 0, 0};
        const uint8_t *mrow = mat + i * 16;

        for (int k = 0; k < nwin; k++) {
            uint32_t fwd = input[k];
            uint32_t back = input[nwin - 1 - k];
            const int16_t *vec = (const int16_t *)(mrow + (long long)k * estride);
            for (int l = 0; l < 4; l++) {
                A[l] += (uint32_t)vec[l] * fwd;
                B[l] += (uint32_t)vec[4 + l] * fwd;
                C[l] += (uint32_t)vec[l] * back;
                D[l] += (uint32_t)vec[4 + l] * back;
            }
        }

        uint8_t lo = 0, hi = 0;
        for (int l = 0; l < 4; l++) {
            if ((int32_t)A[l] > 0) lo |= (uint8_t)(1u << l);
            if ((int32_t)B[l] > 0) lo |= (uint8_t)(0x10u << l);
            if ((int32_t)C[l] > 0) hi |= (uint8_t)(1u << l);
            if ((int32_t)D[l] > 0) hi |= (uint8_t)(0x10u << l);
        }
        out[i] = lo;
        out[i + n] = hi;
    }
    return 0;
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

/* 0x18000fd90 — blit a source bitmap into a destination bitmap at bit column
 * `bitoff` and row `rowoff`, shifting the source bits LEFT by (bitoff & 31).
 * `src`/`dst` descriptors must have offx==offy==0 and `src->a <= dst->a`, else
 * 0x69.  The source row length is `src->a` bits (word-aligned, so `src->a>>5`
 * words per row) and `src->h` rows are copied; the destination row stride is
 * `dst->a` bits.  When the bit offset is word-aligned the rows are copied
 * verbatim; otherwise the first destination word keeps its low bits and takes
 * `src[0]<<s`, each following word is `(src[k]<<s)|(src[k-1]>>(32-s))`, and —
 * only when `dst->a > src->a` — one carry word is written past the end. */
int cr_bitmap_copy_shift(cr_image *dst, const cr_image *src,
                         uint32_t bitoff, int rowoff)
{
    if (src->offx != 0 || src->offy != 0)
        return 0x69;
    if (dst->offx != 0 || dst->offy != 0)
        return 0x69;
    if (dst->a < src->a)
        return 0x69;

    int src_words = src->a >> 5;
    int dst_words = dst->a >> 5;
    int wordoff   = (int)(bitoff >> 5);
    int s         = (int)(bitoff & 0x1f);
    int h         = src->h;

    uint32_t *d = (uint32_t *)dst->data;
    const uint32_t *sd = (const uint32_t *)src->data;

    if (s == 0) {
        if (h <= 0)
            return 0;
        int dw = wordoff + rowoff * dst_words;
        for (int row = 0; row < h; row++) {
            for (int k = 0; k < src_words; k++)
                d[dw + k] = sd[row * src_words + k];
            dw += dst_words;
        }
        return 0;
    }

    if (h <= 0)
        return 0;
    int last  = src_words - 1;
    int i9    = (last > 0) ? last : 0;
    int carry = 32 - s;
    int dbase = wordoff + rowoff * dst_words;

    for (int row = 0; row < h; row++) {
        uint32_t *pd = d + dbase + row * dst_words;
        const uint32_t *ps = sd + row * src_words;
        pd[0] = ((pd[0] << s) >> s) | (ps[0] << s);
        for (int k = 1; k < src_words; k++)
            pd[k] = (ps[k] << s) | (ps[k - 1] >> carry);
        if (dst->a > src->a) {
            uint32_t *pc = pd + i9 + 1;
            *pc = (ps[i9] >> carry) | ((*pc >> s) << s);
        }
    }
    return 0;
}

/* 0x18003e590 — extract a bitmap window from `src` into `dst`, shifting the
 * source bits RIGHT by (src->offx & 31).  The window starts at bit column
 * `src->offx` and row `src->offy` of the source and is `dst->a` bits wide and
 * `dst->h` rows tall; the last destination word is masked to the destination's
 * valid width (`0xffffffff >> ((dst->a - dst->w) & 31)`).  `dst` must have
 * offx==offy==0 and `src->a >= dst->a`, else 0x69.  When the bit offset is
 * word-aligned the words are copied verbatim; otherwise each destination word
 * is `(src[k+1] << (32-s)) | (src[k] >> s)` and the final word additionally
 * takes a carry from `src[dst_words]` when `src->a > dst->a`. */
int cr_bitmap_extract_shift(cr_image *dst, const cr_image *src)
{
    if (dst->offx != 0 || dst->offy != 0)
        return 0x69;
    if (src->a < dst->a)
        return 0x69;

    int src_words = src->a >> 5;
    int dst_words = dst->a >> 5;
    uint32_t mask = 0xffffffffu >> ((dst->a - dst->w) & 0x1f);
    int s   = src->offx & 0x1f;
    int sob = src->offx >> 5;
    int h   = dst->h;

    uint32_t *d = (uint32_t *)dst->data;
    const uint32_t *sd = (const uint32_t *)src->data;

    if (s == 0) {
        if (h <= 0)
            return 0;
        for (int row = 0; row < h; row++) {
            const uint32_t *ps = sd + sob + (src->offy + row) * src_words;
            uint32_t *pd = d + row * dst_words;
            for (int k = 0; k < dst_words - 1; k++)
                pd[k] = ps[k];
            pd[dst_words - 1] = ps[dst_words - 1] & mask;
        }
        return 0;
    }

    if (h <= 0)
        return 0;
    for (int row = 0; row < h; row++) {
        const uint32_t *ps = sd + sob + (src->offy + row) * src_words;
        uint32_t *pd = d + row * dst_words;
        for (int k = 0; k < dst_words - 1; k++)
            pd[k] = (ps[k + 1] << (32 - s)) | (ps[k] >> s);
        uint32_t last = ps[dst_words - 1] >> s;
        if (src->a > dst->a)
            last |= ps[dst_words] << (32 - s);
        pd[dst_words - 1] = last & mask;
    }
    return 0;
}

/* 0x180024200 — in-place row permutation of a byte matrix.  `data` is `n`
 * rows of `stride` bytes and `perm` is an array of 8-byte entries (only the
 * first int of each is read/written) giving, for each destination row j, the
 * source row `perm[j]` (so the net effect is `row[j] = old_row[perm[j]]`).  The
 * vendor walks each permutation cycle, shifting rows backwards, and marks
 * visited entries with a temporary `+0x4000000` flag which is stripped from
 * every entry again at the end.  `stride` must be < 0x41 (i.e. <= 64) else it
 * returns 0x69; `stride <= 0` moves no data but still walks the cycles. */
int cr_permute_rows(uint8_t *data, int32_t *perm, int n, int stride)
{
    uint8_t tmp[64];

    if (stride >= 0x41)
        return 0x69;

    if (n > 0) {
        int last = stride - 1;
        int iv1 = 0, iv12 = 0;
        int32_t *pv13 = perm;

        for (;;) {
            int iv9 = *pv13;
            if (iv9 < 0x4000000) {
                int32_t *pv10 = pv13;
                int iv2 = iv9;
                int iv_1 = iv1;
                int copy = 0;

                if (stride >= 1) {
                    for (int k = 0; k < stride; k++)
                        tmp[k] = data[iv12 + k];
                    copy = 1;
                }

                if (iv9 != iv1) {
                    do {
                        iv9 = iv2;
                        if (stride > 0) {
                            long long l6 = (long long)stride * iv9;
                            uint8_t *p7 = data + l6;
                            uint8_t *p8;
                            do {
                                p8 = p7 + 1;
                                p7[(long long)stride * iv_1 - l6] = *p7;
                                p7 = p8;
                            } while (p8 != data + 1 + (size_t)last + l6);
                        }
                        perm[iv_1 * 2] += 0x4000000;
                        pv10 = perm + iv9 * 2;
                        iv2 = *pv10;
                        iv_1 = iv9;
                    } while (*pv10 != iv1);

                    if (stride < 1) {
                        *pv10 += 0x4000000;
                        goto next_row;
                    }
                }

                if (copy)
                    for (int k = 0; k < stride; k++)
                        data[iv9 * stride + k] = tmp[k];

                *pv10 += 0x4000000;
            }
next_row:
            iv1++;
            pv13 += 2;
            iv12 += stride;
            if (n == iv1)
                break;
        }

        {
            int32_t *e = perm + (n - 1) * 2 + 2;
            int32_t *p = perm;
            do {
                *p += -0x4000000;
                p += 2;
            } while (e != p);
        }
    }
    return 0;
}

/* ------------------------------------------------------------------------ *
 * 0x180032830 — 15x15 separable box filter on an int16 image (divide by 15).
 *   Args (ms_abi): rcx = base (int16*), edx = width W, r8d = height H.
 *   `out = (sum*0x1111 + 0x8000) >> 16` approximates `sum / 15` (0x1111*15 =
 *   0xFFFF).  Four in-place passes:
 *     1. horizontal 15-tap running sum -> cols 0..W-15 of every row;
 *     2. vertical 15-tap running sum   -> rows 7..H-8, cols 7..W-8
 *        (the pass reads columns W-15..0 and writes 7 cols/rows to the right);
 *     3. horizontal edge replication: for rows 7..H-8 copy col 7 into cols
 *        0..6 and col W-8 into cols W-7..W-1;
 *     4. vertical edge replication: for every column copy row 7 into rows
 *        0..6 and row H-8 into rows H-7..H-1.
 *   The result is an order-dependent in-place transform; the transcription
 *   below preserves the exact pointer walk of each pass.
 * ------------------------------------------------------------------------ */
static int16_t cr_div15_s16(int32_t sum)
{
    uint32_t t = (uint32_t)sum * 0x1111u + 0x8000u;
    return (int16_t)(t >> 16);
}

void cr_boxsum15_s16(int16_t *base, int W, int H)
{
    int rem = W - 15;

    /* pass 1: horizontal 15-tap box sum */
    if (H > 0) {
        int16_t *p = base + 1;
        int rows = 0;
        do {
            int prev = p[-1];
            int32_t sum = prev;
            int16_t *q = p;
            do {
                sum += *q;
                q++;
            } while (p + 0xe != q);
            if (rem > 0) {
                int16_t *r = p - 1;
                while (1) {
                    int16_t *r2 = r + 1;
                    int32_t v = sum * 0x1111;
                    sum = sum - (prev - r[0xf]);
                    *r = (int16_t)((uint32_t)(v + 0x8000) >> 16);
                    if (p + (W - 0x10) == r2) break;
                    prev = *r2;
                    r = r2;
                }
            }
            rows++;
            p[(W - 0xe) - 2] = cr_div15_s16(sum);
            p = p + W;
        } while (H != rows);
    }

    /* pass 2: vertical 15-tap box sum */
    if (rem >= 0) {
        long long st = W;
        int16_t *p = base + (rem + W);      /* row 1, col W-15 */
        int16_t *end = base + (W - 1);
        int16_t *q2;
        do {
            int prev = p[-st];
            int32_t sum = prev;
            int16_t *q = p;
            int cnt = 0xe;
            do {
                sum += *q;
                q += st;
                cnt--;
            } while (cnt != 0);
            int i;
            if (H < 0x10) {
                i = 7;
            } else {
                q = p;
                i = 0;
                while (1) {
                    int32_t v = sum * 0x1111;
                    sum = sum - (prev - q[W * 0xf - st]);
                    q[(W + 1) * 7 - st] =
                        (int16_t)((uint32_t)(v + 0x8000) >> 16);
                    if (i + 1 == H - 0xf) break;
                    prev = *q;
                    q = q + st;
                    i++;
                }
                i = i + 8;
            }
            q2 = p - 1;
            p[(i * W + 7) - st] = cr_div15_s16(sum);
            p = q2;
        } while (end != q2);
    }

    /* pass 3: horizontal edge replication over rows 7..H-8 */
    if (H > 0xe) {
        int16_t *r9  = base + 7 * W + 7;    /* row 7, col 7 */
        int16_t *r11 = base + 8 * W - 8;    /* row 7, col W-8 */
        for (int r = 7; r != H - 7; r++) {
            int16_t *dst = r9 - 7;          /* row r, col 0 */
            int16_t left  = *r9;
            int16_t right = *r11;
            for (int c = 0; c < 7; c++)
                dst[c] = left;
            for (int c = 0; c < 7; c++)
                dst[W - 7 + c] = right;
            r9 += W;
            r11 += W;
        }
    }

    /* pass 4: vertical edge replication over every column */
    if (W > 0) {
        int16_t *r9  = base + 7 * W;        /* row 7, col 0 */
        int16_t *r10 = base + (H - 8) * W;  /* row H-8, col 0 */
        int16_t *stop = base + 8 * W;       /* row 8, col 0 */
        for (; r9 != stop; r9++, r10++) {
            int16_t top = *r9;
            int16_t bot = *r10;
            int16_t *dst = r9 - 7 * W;      /* row 0, col c */
            for (int c = 0; c < 7; c++)
                dst[c * W] = top;
            for (int c = 0; c < 7; c++)
                dst[(H - 7 + c) * W] = bot;
        }
    }
}

/* ------------------------------------------------------------------------ *
 * 0x18001aaa0 — the byte twin of cr_boxsum15_s16 (15x15 separable box filter,
 *   divide by 15).  Same four in-place passes (horizontal running sum,
 *   vertical running sum, horizontal edge replication, vertical edge
 *   replication) but the samples are bytes and the rounding constant is
 *   0x800 (sums are at most 15*255).  Args (ms_abi): rcx = base, edx = W,
 *   r8d = H.
 * ------------------------------------------------------------------------ */
static uint8_t cr_div15_u8(int32_t sum)
{
    uint32_t t = (uint32_t)sum * 0x1111u + 0x800u;
    return (uint8_t)(t >> 16);
}

void cr_boxsum15_u8(uint8_t *base, int W, int H)
{
    int rem = W - 15;

    /* pass 1: horizontal 15-tap box sum */
    if (H > 0) {
        uint8_t *p = base + 1;
        int rows = 0;
        do {
            int prev = p[-1];
            int32_t sum = prev;
            uint8_t *q = p;
            do {
                sum += *q;
                q++;
            } while (p + 0xe != q);
            if (rem > 0) {
                uint8_t *r = p - 1;
                while (1) {
                    uint8_t *r2 = r + 1;
                    int32_t v = sum * 0x1111;
                    sum = sum - (prev - r[0xf]);
                    *r = (uint8_t)((uint32_t)(v + 0x800) >> 16);
                    if (p + (W - 0x10) == r2) break;
                    prev = *r2;
                    r = r2;
                }
            }
            rows++;
            p[(W - 0xe) - 2] = cr_div15_u8(sum);
            p = p + W;
        } while (H != rows);
    }

    /* pass 2: vertical 15-tap box sum */
    if (rem >= 0) {
        long long st = W;
        uint8_t *p = base + (rem + W);      /* row 1, col W-15 */
        uint8_t *end = base + (W - 1);
        uint8_t *q2;
        do {
            int prev = p[-st];
            int32_t sum = prev;
            uint8_t *q = p;
            int cnt = 0xe;
            do {
                sum += *q;
                q += st;
                cnt--;
            } while (cnt != 0);
            int i;
            if (H < 0x10) {
                i = 7;
            } else {
                q = p;
                i = 0;
                while (1) {
                    int32_t v = sum * 0x1111;
                    sum = sum - (prev - q[W * 0xf - st]);
                    q[(W + 1) * 7 - st] =
                        (uint8_t)((uint32_t)(v + 0x800) >> 16);
                    if (i + 1 == H - 0xf) break;
                    prev = *q;
                    q = q + st;
                    i++;
                }
                i = i + 8;
            }
            q2 = p - 1;
            p[(i * W + 7) - st] = cr_div15_u8(sum);
            p = q2;
        } while (end != q2);
    }

    /* pass 3: horizontal edge replication over rows 7..H-8 */
    if (H > 0xe) {
        uint8_t *r9  = base + 7 * W + 7;    /* row 7, col 7 */
        uint8_t *r11 = base + 8 * W - 8;    /* row 7, col W-8 */
        for (int r = 7; r != H - 7; r++) {
            uint8_t *dst = r9 - 7;          /* row r, col 0 */
            uint8_t left  = *r9;
            uint8_t right = *r11;
            for (int c = 0; c < 7; c++)
                dst[c] = left;
            for (int c = 0; c < 7; c++)
                dst[W - 7 + c] = right;
            r9 += W;
            r11 += W;
        }
    }

    /* pass 4: vertical edge replication over every column */
    if (W > 0) {
        uint8_t *r9  = base + 7 * W;        /* row 7, col 0 */
        uint8_t *r10 = base + (H - 8) * W;  /* row H-8, col 0 */
        uint8_t *stop = base + 8 * W;       /* row 8, col 0 */
        for (; r9 != stop; r9++, r10++) {
            uint8_t top = *r9;
            uint8_t bot = *r10;
            uint8_t *dst = r9 - 7 * W;      /* row 0, col c */
            for (int c = 0; c < 7; c++)
                dst[c * W] = top;
            for (int c = 0; c < 7; c++)
                dst[(H - 7 + c) * W] = bot;
        }
    }
}

/* ------------------------------------------------------------------------ *
 * 0x18003ecc0 — widen a byte row to int16 with reflect-101 padding, then run
 *   an m-tap symmetric FIR (divide by 512, round with +0x100).
 *   Args (ms_abi): rcx = out (int16*), rdx = scratch (uint16*), r8 = in (u8*),
 *   r9 = coef (int16*), [rsp+0x20] = n (input length), [rsp+0x28] = m (taps).
 *   scratch (length n + 2*pad, pad = m>>1) is filled as
 *       scratch[pad + i]      = in[i]              (i in [0,n))
 *       scratch[pad - 1 - j]  = in[j + 1]          (left  reflect-101)
 *       scratch[pad + n + j]  = in[n - 2 - j]      (right reflect-101)
 *   and then out[i] = (int16)((Σ_{k<taps_i} coef[k]*scratch[i+k] + 0x100) >> 9).
 *
 *   The vendor splits the output into a 4-wide unrolled region (i < bound,
 *   bound = 4 + 4*((n-4)>>2), 0 when n<=3) and a scalar tail (i >= bound).
 *   The unrolled region consumes 2P+1 taps with P = 1 + ((m-2)>>1) — i.e. m
 *   taps for ODD m (the only case the public entry FUN_180021700 admits, via
 *   `if ((m & 1) == 0) return 1;`) but m+1 taps for EVEN m (it reads coef[m]).
 *   The tail always consumes exactly m taps.  Both regions are reproduced
 *   verbatim below so parity holds for every m the other callers may pass.
 * ------------------------------------------------------------------------ */
void cr_u8_expand_convolve(int16_t *out, uint16_t *scratch, const uint8_t *in,
                           const int16_t *coef, int n, int m)
{
    int pad = m >> 1;

    if (n > 0)
        for (int i = 0; i < n; i++)
            scratch[pad + i] = in[i];
    if (pad > 0)
        for (int j = 0; j < pad; j++) {
            scratch[j] = in[pad - j];
            scratch[pad + n + j] = in[n - 2 - j];
        }

    int unrolled_taps = 3 + 2 * ((m - 2) >> 1);   /* m for odd m, m+1 for even */
    int bound = (n > 3) ? 4 + 4 * ((n - 4) >> 2) : 0;

    for (int i = 0; i < n; i++) {
        int taps = (i < bound) ? unrolled_taps : m;
        int32_t acc = 0;
        for (int k = 0; k < taps; k++)
            acc += (int32_t)coef[k] * (int32_t)(int16_t)scratch[i + k];
        out[i] = (int16_t)((acc + 0x100) >> 9);
    }
}

/* ------------------------------------------------------------------------ *
 * 0x180043120 — 16-point bilinear splat followed by an affine accumulation.
 *
 *   void fn(const float *pts, const float *alpha, float p3, float p4,
 *           float *bufA, float *bufB, float beta, int k);
 *
 * Both float buffers use a 17-float row stride.  First cr_splat_bilinear is run
 * from the (k+17)*17 offset with (x0,y0) = (±p3, ∓p4) (sign chosen so p3 >= 0
 * maps to x0 = p3) and scale = 1 - p4*p4.  Then, for i = 0..15, a point at
 * (fx, fy) = (p3*(i+0.5), p4*(i+0.5)) is splatted with the four bilinear
 * weights scaled by pts[i]*p4*p4: the raw weights accumulate into bufB and the
 * beta-scaled weights into bufA.  ix = floor(fx) (via the vendor's truncate-
 * then-correct-on-negative form), iy = (int)fy.
 * ------------------------------------------------------------------------ */
void cr_splat_accum16(const float *pts, const float *alpha,
                      float p3, float p4, float *bufA, float *bufB,
                      float beta, int k)
{
    long long base = (long long)(k + 17) * 17;
    float p4sq = p4 * p4;                /* vendor precomputes p4*p4 once */
    float scale = 1.0f - p4sq;

    if (p3 < 0.0f)
        cr_splat_bilinear(pts, bufA + base, bufB + base, alpha, -p3, p4, scale);
    else
        cr_splat_bilinear(pts, bufA + base, bufB + base, alpha, p3, -p4, scale);

    float fx = p3 * 0.5f;
    float fy = p4 * 0.5f;
    int   neg = (p3 < 0.0f) ? 1 : 0;

    for (int i = 0; i < 16; i++) {
        int   ix = (int)fx - neg;
        int   iy = (int)fy;
        long long off = base + (long long)ix * 17 + iy;
        float fyr = fy - (float)iy;
        float fxr = fx - (float)ix;
        float a = pts[i] * p4sq;
        float w00 = (1.0f - fyr) * (1.0f - fxr) * a;
        float w01 = (1.0f - fxr) * fyr * a;
        float w10 = (1.0f - fyr) * fxr * a;
        float w11 = fyr * fxr * a;

        bufB[off]      += w00;
        bufA[off]       = w00 * beta + bufA[off];
        bufB[off + 1]  += w01;
        bufA[off + 1]   = w01 * beta + bufA[off + 1];
        bufB[off + 17] += w10;
        bufA[off + 17]  = w10 * beta + bufA[off + 17];
        bufB[off + 18] += w11;
        bufA[off + 18]  = w11 * beta + bufA[off + 18];

        fx += p3;
        fy += p4;
    }
}

/* ------------------------------------------------------------------------ *
 * 0x180021700 — streaming-FIR context initialiser + ring prefetch.
 *   int fn(cr_fir_row_ctx *ctx, const cr_image *img, float sigma, int n, int flag)
 *
 * Validates a square, offset-free image with w == a, h == b, w >= n, h >= n,
 * an odd tap count n > 2 and (flag & 0xff) == 0, else returns 1.
 * Zeroes the 32-byte ctx, then allocates
 *   size = 2*n*(w+2) + 2*(w+n-1)
 * bytes and lays the workspace out as
 *   +0        int16 coef[n] (+ mirror copy coef[n..2n-2] = coef[0..n-2])
 *   +4n       int16 ring[n rows of width w]
 *   +2n*(w+2) uint16 scratch for cr_u8_expand_convolve
 * setting ctx->{n,row=-1,base,coef_off=0,out_off=4n,scratch_off=2n*(w+2)}.
 * The ring is pre-filled: rows n/2..n-1 receive the horizontal FIR of source
 * rows 0..n/2, and rows 0..n/2-1 are the vertical mirror of rows n-1..n/2+1.
 * Returns 0 on success.
 * ------------------------------------------------------------------------ */
int cr_fir_ctx_init(cr_fir_row_ctx *ctx, const cr_image *img, float sigma,
                    int n, int flag)
{
    if (!(img->a == img->w && img->b == img->h))
        return 1;
    if (img->offx != 0 || img->offy != 0)
        return 1;
    if (n <= 2)
        return 1;
    if ((n & 1) == 0)
        return 1;
    if (img->w < n)
        return 1;
    if (img->h < n)
        return 1;
    if ((flag & 0xff) != 0)
        return 1;

    int w = img->w;
    cr_fill(ctx, 0, 0x20);

    int size32 = 2 * n * (w + 2) + 2 * (w + n - 1);
    size_t size = (size_t)(intptr_t)size32;
    int r = cr_malloc_aligned16(&ctx->base, size);
    if (r != 0)
        return r;

    uint8_t  *base = (uint8_t *)ctx->base;
    int16_t  *coef = (int16_t *)base;                 /* coef_off = 0        */
    int16_t  *ring = (int16_t *)(base + 4 * n);       /* out_off  = 4n       */
    uint16_t *scr  = (uint16_t *)(base + 2 * n * (w + 2));

    ctx->n           = n;
    ctx->row         = -1;
    ctx->coef_off    = 0;
    ctx->out_off     = 4 * n;
    ctx->scratch_off = 2 * n * (w + 2);

    cr_gaussian_window_q15(coef, sigma, n);
    for (int i = 0; i < n - 1; i++)
        coef[n + i] = coef[i];

    int h = n >> 1;
    for (int i = 0; i <= h; i++) {
        cr_u8_expand_convolve(ring + (size_t)(h + i) * w, scr,
                              (const uint8_t *)img->data + (size_t)i * w,
                              coef, w, n);
    }
    for (int k = 0; k < h; k++) {
        int16_t *src = ring + (size_t)(n - 1 - k) * w;
        int16_t *dst = ring + (size_t)k * w;
        for (int j = 0; j < w; j++)
            dst[j] = src[j];
    }
    return 0;
}

/* ------------------------------------------------------------------------ *
 * 0x18003a6b0 — byte-output streaming-FIR context initialiser + ring prefetch.
 *   int fn(cr_fir_row_ctx *ctx, const cr_image *img, float sigma, int n, int flag)
 *
 * Sibling of 0x180021700 for the u8 ring (cr_row_fir_i8).  Validates a square,
 * offset-free image (a==w, b==h, offsets 0), an odd tap count n > 2, w a
 * multiple of 4, w >= n, h >= n and (flag & 0xff) == 0, else returns 1.
 * Allocates size = w*n + 4n + w + n - 1 and lays the workspace out as
 *   +0        int16 coef[n] (+ mirror copy coef[n..2n-2] = coef[0..n-2])
 *   +4n       u8 ring[n rows of width w]
 *   +wn+4n    u8 scratch for cr_mirror_extend_fir (w+n-1 bytes)
 * setting ctx->{n,row=-1,base,coef_off=0,out_off=4n,scratch_off=wn+4n}.  The
 * ring rows n/2..n-1 receive the mirror-extended polyphase FIR of source rows
 * 0..n/2, and rows 0..n/2-1 are the vertical (byte) mirror of rows n-1..n/2+1.
 * Returns 0 on success.
 * ------------------------------------------------------------------------ */
int cr_fir_ctx_init_i8(cr_fir_row_ctx *ctx, const cr_image *img, float sigma,
                       int n, int flag)
{
    if (!(img->a == img->w && img->b == img->h))
        return 1;
    if (img->offx != 0 || img->offy != 0)
        return 1;
    if (n <= 2)
        return 1;
    if ((n & 1) == 0)
        return 1;
    if ((img->w & 3) != 0)
        return 1;
    if (img->w < n)
        return 1;
    if (img->h < n)
        return 1;
    if ((flag & 0xff) != 0)
        return 1;

    int w = img->w;
    cr_fill(ctx, 0, 0x20);

    int size32 = w * n + 4 * n + w + n - 1;
    size_t size = (size_t)(intptr_t)size32;
    int r = cr_malloc_aligned16(&ctx->base, size);
    if (r != 0)
        return r;

    uint8_t  *base = (uint8_t *)ctx->base;
    int16_t  *coef = (int16_t *)base;                 /* coef_off = 0        */
    uint8_t  *ring = base + 4 * n;                    /* out_off  = 4n       */
    uint8_t  *scr  = base + w * n + 4 * n;

    ctx->n           = n;
    ctx->row         = -1;
    ctx->coef_off    = 0;
    ctx->out_off     = 4 * n;
    ctx->scratch_off = w * n + 4 * n;

    cr_gaussian_window_q15(coef, sigma, n);
    for (int i = 0; i < n - 1; i++)
        coef[n + i] = coef[i];

    int h = n >> 1;
    for (int i = 0; i <= h; i++) {
        cr_mirror_extend_fir(ring + (size_t)(h + i) * w, scr,
                             (const uint8_t *)img->data + (size_t)i * w,
                             coef, w, n);
    }
    for (int k = 0; k < h; k++) {
        uint8_t *src = ring + (size_t)(n - 1 - k) * w;
        uint8_t *dst = ring + (size_t)k * w;
        for (int j = 0; j < w; j++)
            dst[j] = src[j];
    }
    return 0;
}

/* ------------------------------------------------------------------------ *
 * 0x18002af00 / 0x180010440 — streaming vertical FIR, one output row per call.
 *
 *   int fn(<i16|i8> *out, cr_fir_row_ctx *ctx, const cr_image *img, int target);
 *
 * No-op returning 1 unless target == ctx->row + 1; otherwise advances ctx->row
 * and emits output row target-1:
 *   rr = (target-1) % n  is the ring slot.  Source row target-1 + n/2 is
 *   widened and horizontally FIR'd into ring row rr by cr_u8_expand_convolve
 *   (coef = the shared int16 array); past the bottom edge the slot is filled by
 *   mirroring ring row (((2h - (target-1+n/2) - (n/2) - 3) % n) * w).
 *   The vertical n-tap Q15 FIR then reads the coefficient array linearly from
 *   the rotation offset (n-1-rr)%n and the ring rows at stride w:
 *       acc = Σ_{k<n} coef[rot+k] * ring[k*w + col]
 *   i16 output:  out[col] = (int16)((acc + 0x4000) >> 15)
 *   i8  output:  out[col] = (int8_t)((acc + 0x104000) >> 21)
 * The i16 variant only emits the 4*((w-4)>>2)+4 unrolled columns (no tail, so
 * w must be a multiple of 4); the i8 variant additionally emits the tail
 * columns j = 4*((w-4)>>2)+4 .. w-1. */
static int cr_row_fir(int is_i8, void *out, cr_fir_row_ctx *ctx,
                      const cr_image *img, int target)
{
    int row = ctx->row;
    int r1  = row + 1;
    if (r1 != target)
        return 1;

    int n = ctx->n;
    ctx->row = r1;

    int16_t  *coef = (int16_t *)((uint8_t *)ctx->base + ctx->coef_off);
    int16_t  *ring = (int16_t *)((uint8_t *)ctx->base + ctx->out_off);
    uint16_t *scr  = (uint16_t *)((uint8_t *)ctx->base + ctx->scratch_off);
    int w = img->w, h = img->h;
    int rr = row % n;

    if (r1 > 0) {
        int srcrow = r1 + (n >> 1);
        if (srcrow < h) {
            cr_u8_expand_convolve(ring + w * rr, scr,
                                  (const uint8_t *)img->data
                                      + (long long)srcrow * w,
                                  coef, w, n);
        } else if (w > 0) {
            int lv = ((h * 2 - (srcrow + 3 + (n >> 1))) % n) * w;
            int16_t *p = ring + lv;
            do {
                p[w * rr - lv] = *p;
                p++;
            } while (ring + (w - 1) + lv + 1 != p);
        }
    }

    int16_t *cr_  = coef + ((n - rr - 1) % n);
    int done = 0;

    if (w > 3) {
        int16_t *rp0 = ring;
        int16_t *end = ring + ((w - 4) >> 2) * 4 + 4;
        do {
            int c0 = cr_[0];
            int a0 = rp0[0] * c0, a1 = rp0[1] * c0;
            int a2 = rp0[2] * c0, a3 = rp0[3] * c0;
            if (n > 1) {
                const int16_t *cp = cr_ + 1;
                const int16_t *rp = rp0;
                do {
                    int ck;
                    rp += w;
                    ck = *cp++;
                    a0 += rp[0] * ck;
                    a1 += rp[1] * ck;
                    a2 += rp[2] * ck;
                    a3 += rp[3] * ck;
                } while (cr_ + (n - 2) + 2 != cp);
            }
            rp0 += 4;
            if (is_i8) {
                uint8_t *po = (uint8_t *)out + done;
                po[0] = (uint8_t)((a0 + 0x104000) >> 21);
                po[1] = (uint8_t)((a1 + 0x104000) >> 21);
                po[2] = (uint8_t)((a2 + 0x104000) >> 21);
                po[3] = (uint8_t)((a3 + 0x104000) >> 21);
            } else {
                int16_t *po = (int16_t *)out + done;
                po[0] = (int16_t)((a0 + 0x4000) >> 15);
                po[1] = (int16_t)((a1 + 0x4000) >> 15);
                po[2] = (int16_t)((a2 + 0x4000) >> 15);
                po[3] = (int16_t)((a3 + 0x4000) >> 15);
            }
            done += 4;
        } while (end != rp0);
    }

    if (!is_i8)
        return 0;                       /* the int16 variant has no tail */

    for (int j = done; j < w; j++) {
        int a = cr_[0] * ring[j];
        if (n > 1) {
            const int16_t *cp = cr_ + 1;
            const int16_t *rp = ring + w + j;
            do {
                a += rp[0] * (*cp++);
                rp += w;
            } while (cr_ + (n - 2) + 2 != cp);
        }
        ((uint8_t *)out)[j] = (uint8_t)((a + 0x104000) >> 21);
    }
    return 0;
}

int cr_row_fir_i16(int16_t *out, cr_fir_row_ctx *ctx,
                   const cr_image *img, int target)
{
    return cr_row_fir(0, out, ctx, img, target);
}

int cr_row_fir_i8(uint8_t *out, cr_fir_row_ctx *ctx,
                  const cr_image *img, int target)
{
    return cr_row_fir(1, out, ctx, img, target);
}

/* ------------------------------------------------------------------------ *
 * 0x18003b110 — a third streaming vertical-FIR variant: same ring/rotation
 * contract as cr_row_fir_* but the ring row is filled by cr_mirror_extend_fir
 * and the vertical pass is the 4-wide cr_vfir4_u8.
 *   int fn(uint8_t *out, cr_fir_row_ctx *ctx, const cr_image *img, int target):
 *     if (ctx->row+1 != target) return 1;
 *     rr = ctx->row % n; ctx->row = target;
 *     if (target > 0) {
 *       srcrow = target + n/2;
 *       if (srcrow < h) cr_mirror_extend_fir(ring + w*rr, scratch,
 *                                            img->data + srcrow*w, coef, w, n);
 *       else if (w > 0) mirror ring row rem=(2h-srcrow-n/2-3)%n into ring row rr;
 *     }
 *     cr_vfir4_u8(out, ring, coef + (n-rr-1)%n, w, n);
 *     return 0;
 * ------------------------------------------------------------------------ */
int cr_row_fir_vfir(uint8_t *out, cr_fir_row_ctx *ctx,
                    const cr_image *img, int target)
{
    int row = ctx->row;
    int r1  = row + 1;
    if (r1 != target)
        return 1;

    int n = ctx->n;
    ctx->row = r1;

    int16_t *coef = (int16_t *)((uint8_t *)ctx->base + ctx->coef_off);
    uint8_t *ring = (uint8_t *)ctx->base + ctx->out_off;
    uint8_t *scr  = (uint8_t *)ctx->base + ctx->scratch_off;
    int w = img->w, h = img->h;
    int rr = row % n;

    if (r1 > 0) {
        int srcrow = r1 + (n >> 1);
        if (srcrow < h) {
            cr_mirror_extend_fir(ring + (size_t)w * rr, scr,
                                 (const uint8_t *)img->data
                                     + (long long)srcrow * w,
                                 coef, w, n);
        } else if (w > 0) {
            long long lv = (long long)(((h * 2 - (srcrow + 3 + (n >> 1))) % n)
                                       * w);
            uint8_t *p = ring + lv;
            do {
                uint8_t *q = p + 1;
                p[(long long)(int)((uint32_t)w * (uint32_t)rr) - lv] = *p;
                p = q;
            } while (p != ring + lv + (w - 1) + 1);
        }
    }

    cr_vfir4_u8(out, ring, coef + ((n - rr) - 1) % n, w, n);
    return 0;
}

/* ------------------------------------------------------------------------ *
 * 0x180019080 — two-scale (n=9 / n=15) band-pass difference, byte output.
 *   int fn(cr_image *out, const cr_image *in, const cr_bandpass_cfg *cfg)
 *
 * Builds an n=9 and an n=15 FIR context (cr_fir_ctx_init_i8 from cfg->sigma9 /
 * cfg->sigma15 and the sign-extended cfg->flag) then streams both over every
 * source row with cr_row_fir_vfir into buf1 / buf2.  For each row it stores the
 * normalised difference of the two filtered rows into out->data:
 *     d = (int16_t)(buf1[col] - buf2[col]);
 *     maxd = max |d| over the row;   scale = maxd ? 0x1fc00 / maxd : 0x400;
 *     out[row*w + col] = (uint8_t)((d * scale) >> 10);
 * buf3[row] holds each row's maxd and maxall the global maximum.  When maxall
 * is non-zero a second pass re-scales every output byte row by row:
 *     s2 = buf3[row] ? (buf3[row] << 10) / maxall : 0x400;
 *     out[...] = (uint8_t)((((int8_t)out[...] * s2) >> 10) + 128);
 * Workspace (buf1 = out->w bytes, buf2 = out->w bytes, buf3 = out->h int16) is
 * freed in reverse order on every exit path.
 * ------------------------------------------------------------------------ */
int cr_bandpass_diff_i8(cr_image *out, const cr_image *in,
                        const cr_bandpass_cfg *cfg)
{
    cr_fir_row_ctx ctx9, ctx15;
    int r;

    r = cr_fir_ctx_init_i8(&ctx9, in, cfg->sigma9, 9, (int)(int8_t)cfg->flag);
    if (r != 0)
        return r;

    r = cr_fir_ctx_init_i8(&ctx15, in, cfg->sigma15, 15,
                           (int)(int8_t)cfg->flag);
    if (r != 0) {
        cr_free_slot8(&ctx9);
        return r;
    }

    uint8_t *buf1 = NULL, *buf2 = NULL;
    int16_t *buf3 = NULL;

    r = cr_malloc_aligned16((void **)&buf1, (size_t)(intptr_t)out->w);
    if (r != 0) {
        cr_free_slot8(&ctx9);
        cr_free_slot8(&ctx15);
        return r;
    }
    r = cr_malloc_aligned16((void **)&buf2, (size_t)(intptr_t)out->w);
    if (r != 0) {
        cr_free_slot8(&ctx9);
        cr_free_slot8(&ctx15);
        cr_sized_free((void **)&buf1);
        return r;
    }
    r = cr_malloc_aligned16((void **)&buf3, (size_t)((intptr_t)out->h * 2));
    if (r != 0) {
        cr_free_slot8(&ctx9);
        cr_free_slot8(&ctx15);
        cr_sized_free((void **)&buf1);
        cr_sized_free((void **)&buf2);
        return r;
    }

    int w = in->w;
    int h = in->h;
    int maxall = 0;

    if (h > 0) {
        uint8_t *od = (uint8_t *)out->data;
        for (int row = 0; row < h; row++, od += w) {
            r = cr_row_fir_vfir(buf1, &ctx9, in, row);
            if (r == 0)
                r = cr_row_fir_vfir(buf2, &ctx15, in, row);
            if (r != 0) {
                cr_free_slot8(&ctx9);
                cr_free_slot8(&ctx15);
                cr_sized_free((void **)&buf1);
                cr_sized_free((void **)&buf2);
                cr_sized_free((void **)&buf3);
                return r;
            }

            int maxd = 0;
            for (int col = 0; col < w; col++) {
                int d = (int)buf1[col] - (int)buf2[col];
                if (d < 0) d = -d;
                if (maxd < d) maxd = d;
            }
            buf3[row] = (int16_t)maxd;
            if (maxall < maxd) maxall = maxd;

            int scale = 0x400;
            if (maxd != 0) scale = 0x1fc00 / maxd;
            for (int col = 0; col < w; col++) {
                int d = (int16_t)((int)buf1[col] - (int)buf2[col]);
                od[col] = (uint8_t)((int32_t)((uint32_t)d * (uint32_t)scale)
                                    >> 10);
            }
        }
    }

    if (maxall != 0) {
        uint8_t *od = (uint8_t *)out->data;
        for (int row = 0, coloff = 0; row < h; row++, coloff += w) {
            int md = buf3[row];
            int s2 = 0x400;
            if (md != 0) s2 = (int)((int64_t)md << 10) / maxall;
            for (int col = 0; col < w; col++) {
                int v = (int8_t)od[coloff + col];
                v = (int32_t)((uint32_t)v * (uint32_t)s2) >> 10;
                v += 128;
                od[coloff + col] = (uint8_t)v;
            }
        }
    }

    cr_free_slot8(&ctx9);
    cr_free_slot8(&ctx15);
    cr_sized_free((void **)&buf1);
    cr_sized_free((void **)&buf2);
    cr_sized_free((void **)&buf3);
    return 0;
}

/* ------------------------------------------------------------------------ *
 * 0x18003e7a0 — bilinear orientation-field sampler.
 *   int fn(const cr_angle_field *d, int px, int py):
 *     Each byte of the field is an angle phase; the (cos,sin) vector is
 *     cr_sincos(byte).  Sample at Q6 position (px-d->ox, py-d->oy), bilinearly
 *     interpolate the (sin,cos) vectors with Q6 weights, then return
 *     (cr_atan2_fixed(sin_i, cos_i) + 0x400000) >> 23.
 *
 *   The four corners are clamped to the field: x0=clamp(fx,0,w-1),
 *   x1=clamp(fx+1,0,w-1), y0/y1 likewise.  The byte is read sign-extended
 *   (signed char) before being handed to cr_sincos as a phase.
 * ------------------------------------------------------------------------ */
int cr_bilinear_angle_sample(const cr_angle_field *d, int px, int py)
{
    uint32_t      ux   = (uint32_t)(px - d->ox);
    uint32_t      uy   = (uint32_t)(py - d->oy);
    int           w    = d->img.w;
    const int8_t *data = (const int8_t *)d->img.data;

    int      fxb = (int)ux >> 6;
    uint32_t fx  = ux & 0x3fu;
    int      fyb = (int)uy >> 6;
    uint32_t fy  = uy & 0x3fu;

    int xmax = w - 1;
    int ymax = d->img.h - 1;

    int x0 = fxb < 0 ? 0 : fxb;
    if (xmax <= x0) x0 = xmax;
    int y0 = fyb < 0 ? 0 : fyb;
    if (ymax <= y0) y0 = ymax;

    int x1 = fxb + 1;
    if (x1 < 0) x1 = 0;
    if (x1 < xmax) xmax = x1;              /* xmax now holds x1 */
    int x1v = xmax;

    int y1 = fyb + 1;
    if (y1 < 0) y1 = 0;
    if (ymax <= y1) y1 = ymax;

    int32_t cTL, sTL, cTR, sTR, cBL, sBL, cBR, sBR;
    cr_sincos(&cTL, &sTL, (uint32_t)(int32_t)data[y0 * w + x0]);
    cr_sincos(&cTR, &sTR, (uint32_t)(int32_t)data[y0 * w + x1v]);
    cr_sincos(&cBL, &sBL, (uint32_t)(int32_t)data[x0 + y1 * w]);
    cr_sincos(&cBR, &sBR, (uint32_t)(int32_t)data[y1 * w + x1v]);

    int32_t w00 = (int32_t)(0x40 - fx) * (int32_t)(0x40 - fy);
    int32_t w10 = (int32_t)(0x40 - fy) * (int32_t)fx;
    int32_t w01 = (int32_t)(0x40 - fx) * (int32_t)fy;
    int32_t w11 = (int32_t)(fx * fy);

    int32_t sin_i = (sBL * w01 + w00 * sTL + w10 * sTR + 0x8000 + sBR * w11) >> 12;
    int32_t cos_i = (cTL * w00 + cTR * w10 + cBL * w01 + 0x8000 + cBR * w11) >> 12;

    int ang = cr_atan2_fixed(sin_i, cos_i);
    return (ang + 0x400000) >> 23;
}
