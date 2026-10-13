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
