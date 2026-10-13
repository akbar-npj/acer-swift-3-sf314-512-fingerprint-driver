/*
 * fpc_filter.c — clean-room reimplementation of 0x18000fb20, a vertical FIR
 * filter that processes four columns at a time.  Derived from disassembly of
 * fpc_enclave.dll; the RVA <-> cr_ map is in MAP.md.
 *
 * Layout: `in` is row-major with row stride `n`; the kernel `coeff` has `m`
 * int16 taps.  For each group of 4 columns at offset `g*4` (g = 0..), and each
 * of the 4 columns j:
 *
 *     out[g*4 + j] = (int8_t)(( sum_{k=0..m-1} in[k*n + g*4 + j] * coeff[k]
 *                              + 0x4000 ) >> 15)
 *
 * i.e. a fixed-point (Q15) vertical filter, saturating into a byte by the
 * truncating 8-bit store.  `n <= 3` is a no-op.  The number of output groups is
 * ((n-4)>>2)+1, so trailing columns that do not fill a group are left alone.
 */
#include "fpc_bep.h"
#include <string.h>

static float f32_from_bits(uint32_t b)
{
    float f;
    memcpy(&f, &b, sizeof f);
    return f;
}

void cr_vfir4_u8(uint8_t *out, const uint8_t *in, const int16_t *coeff,
                 int n, int m)
{
    if (n <= 3)
        return;

    const uint8_t *in_end = in + ((n - 4) >> 2) * 4 + 4;

    for (const uint8_t *p = in; p != in_end; p += 4) {
        int32_t s0 = (int32_t)p[0] * coeff[0];
        int32_t s1 = (int32_t)p[1] * coeff[0];
        int32_t s2 = (int32_t)p[2] * coeff[0];
        int32_t s3 = (int32_t)p[3] * coeff[0];

        if (m > 1) {
            const uint8_t *q = p + n;
            for (int k = 1; k < m; k++) {
                int32_t c = coeff[k];
                s0 += (int32_t)q[0] * c;
                s1 += (int32_t)q[1] * c;
                s2 += (int32_t)q[2] * c;
                s3 += (int32_t)q[3] * c;
                q += n;
            }
        }

        out[0] = (uint8_t)((s0 + 0x4000) >> 15);
        out[1] = (uint8_t)((s1 + 0x4000) >> 15);
        out[2] = (uint8_t)((s2 + 0x4000) >> 15);
        out[3] = (uint8_t)((s3 + 0x4000) >> 15);
        out += 4;
    }
}

/* 0x18002cc00 — horizontal box blur of a float image, or a plain copy when the
 * window width `win` is even.  `*dst_ref` is the destination float buffer; `src`
 * is a float image with `nrows` rows and `ncols` columns stored column-major
 * (column stride == nrows).  For odd `win`, each output pixel is the mean of
 * `win` horizontally-consecutive input pixels centred on it, with clamp-to-edge
 * (`lo = -(win-1)/2`; sample columns clamp(j) into [0,ncols-1]).  The mean is a
 * running float sum divided once by (float)win. */
void cr_box_blur_h_f32(void *dst_ref, const float *src, int nrows, int ncols,
                       int win)
{
    float *dst = *(float **)dst_ref;

    if (!(win & 1)) {
        int total = nrows * ncols;
        if (total > 0)
            for (int i = 0; i < total; i++)
                dst[i] = src[i];
        return;
    }

    if (nrows <= 0)
        return;

    int lo = -((win - 1) / 2);   /* C truncation matches the vendor's signed /2 */
    int last = ncols - 1;

    for (int i = 0; i < nrows; i++) {
        if (ncols <= 0)
            continue;
        for (int j = lo; j < lo + ncols; j++) {
            float sum = 0.0f;
            for (int k = j; k != j + win; k++) {
                int c = k;
                if (c < 0) c = 0;
                if (c > last) c = last;
                sum += src[c * nrows + i];
            }
            dst[(j - lo) * nrows + i] = sum / (float)win;
        }
    }
}

/* ------------------------------------------------------------------------ *
 * 0x180043a50 — 9-tap triangular (Bartlett) filter along the 9 lines of an
 *   n x 9 float buffer (row stride 9).
 *
 *   Each of the 9 lines (elements t, t+9, t+18, ...) is filtered
 *   independently with a triangular window of weights [1,2,3,4,5,4,3,2,1],
 *   via the sliding-window recurrence
 *       out[r] = out[r-1] - sum_{i=r-5}^{r-1} c[i] + sum_{i=r}^{r+4} c[i]
 *   where c[k] = in[t + 9k].  Rows 0..4 use a triangular warm-up (the
 *   out-of-range taps contribute 0) and the last four rows use the same
 *   recurrence with the out-of-range "add" taps dropped.
 *
 *   Args (ms_abi): rcx = in (float*), rdx = out (float*), r8d = n (rows).
 *   The buffer holds 9*n floats; the vendor assumes n >= 9 (no guard).  The
 *   float operation order is transcribed verbatim for bit-for-bit parity.
 * ------------------------------------------------------------------------ */
void cr_tri9_filter(float *in, float *out, int n)
{
    const float c5 = 5.0f, c4 = 4.0f, c3 = 3.0f;
    int n4 = n - 4;
    float *r9 = in + n4 * 9 - 45;

    for (int t = 0; t < 9; t++) {
        float *c = in + t;
        float *o = out + t;
        float acc;

        /* rows 0..4: triangular warm-up */
        acc  = c[9] * c4;
        acc += c[0] * c5;
        acc += c[18] * c3;
        acc += c[27] + c[27];
        acc += c[36];
        o[0] = acc;
        acc -= c[0];
        acc += c[9]; acc += c[18]; acc += c[27]; acc += c[36]; acc += c[45];
        o[9] = acc;
        acc -= c[0]; acc -= c[9];
        acc += c[18]; acc += c[27]; acc += c[36]; acc += c[45]; acc += c[54];
        o[18] = acc;
        acc -= c[0]; acc -= c[9]; acc -= c[18];
        acc += c[27]; acc += c[36]; acc += c[45]; acc += c[54]; acc += c[63];
        o[27] = acc;
        acc -= c[0]; acc -= c[9]; acc -= c[18]; acc -= c[27];
        acc += c[36]; acc += c[45]; acc += c[54]; acc += c[63]; acc += c[72];
        o[36] = acc;

        /* rows 5..n-5: full sliding-window recurrence */
        if (n4 > 5) {
            float *rs = r9 + t;          /* termination pointer */
            float *ra = c;               /* advances by 9 per row */
            float *rg = o;               /* advances by 9 per row */
            do {
                acc = rg[36];
                ra += 9;
                acc -= ra[-9]; acc -= ra[0]; acc -= ra[9];
                acc -= ra[18]; acc -= ra[27];
                acc += ra[36]; acc += ra[45]; acc += ra[54];
                acc += ra[63]; acc += ra[72];
                rg += 9;
                rg[36] = acc;
            } while (rs != ra);
        }

        /* rows n-4..n-1: recurrence with truncated "add" taps */
        acc = out[9 * (n - 4) + t - 9];
        {
            float *q = r9 + t;
            acc -= q[0];
            q += 1;
            acc -= q[8]; acc -= q[17]; acc -= q[26]; acc -= q[35];
            acc += q[44]; acc += q[53]; acc += q[62]; acc += q[71];
        }
        out[9 * (n - 4) + t] = acc;

        acc = out[9 * (n - 3) + t - 9];
        {
            float *q = in + 9 * (n - 3) + t + 1;
            acc -= q[-46]; acc -= q[-37]; acc -= q[-28];
            acc -= q[-19]; acc -= q[-10];
            acc += q[-1]; acc += q[8]; acc += q[17];
        }
        out[9 * (n - 3) + t] = acc;

        acc = out[9 * (n - 2) + t - 9];
        {
            float *q = in + 9 * (n - 2) + t + 1;
            acc -= q[-46]; acc -= q[-37]; acc -= q[-28];
            acc -= q[-19]; acc -= q[-10];
            acc += q[-1]; acc += q[8];
        }
        out[9 * (n - 2) + t] = acc;

        acc = out[9 * (n - 1) + t - 9];
        {
            float *q = in + 9 * (n - 1) + t + 1;
            acc -= q[-46]; acc -= q[-37]; acc -= q[-28];
            acc -= q[-19]; acc -= q[-10];
            acc += q[-1];
        }
        out[9 * (n - 1) + t] = acc;
    }
}

/* BORDER_REFLECT_101 index fold (period 2*(n-1)); single-fold is enough when
 * the caller's range stays within one period, but the fixed-tap variant below
 * can exceed it for small n, so fold periodically. */
static int refl101(int i, int n)
{
    if (n <= 1)
        return 0;
    int period = 2 * (n - 1);
    i %= period;
    if (i < 0) i += period;
    if (i >= n) i = period - i;
    return i;
}

/* Shared core for the reflect-101-padded int16 FIR leaves (0x180030fc0
 * column-wise, 0x180040560 row-wise, 0x180033b40 fixed 7-tap).  Filters `n`
 * gathered samples:
 *   dst[j*dstride] = (int16)(( Σ_{k=0}^{K-1} coef[k]*buf[refl101(j-H+k,n)]
 *                              + 0x4000 ) >> 15)
 * The accumulation is integer and order-independent, so the vendor's split into
 * a descending "left" pass, a plain middle pass and a descending "right" pass is
 * bit-identical to this closed form. */
static void fir_reflect_line(int16_t *dst, int dstride, const int16_t *buf,
                             const int16_t *coef, int K, int H, int n)
{
    for (int j = 0; j < n; j++) {
        uint32_t s = 0;
        for (int k = 0; k < K; k++)
            s += (uint32_t)((int32_t)coef[k] * (int32_t)buf[refl101(j - H + k, n)]);
        dst[j * dstride] = (int16_t)((int32_t)(s + 0x4000u) >> 15);
    }
}

/* ------------------------------------------------------------------------ *
 * 0x180030fc0 (.isra.6) — reflect-101-padded int16 FIR down each column.
 *
 *   Args (ms_abi): rcx = out (int16*), rdx = in (int16*), r8 = coef (int16*),
 *   r9d = p4 (kernel length request), [rsp+0x20] = W (row length / stride),
 *   [rsp+0x28] = L (column length).
 *
 *   For each column c (0..W-1) the L samples buf[i] = in[c + i*W] are gathered
 *   and correlated with the kernel:
 *       K = clamp(p4, 0, L-1);  H = K >> 1;
 *       out[c + j*W] = (int16)(( Σ_{k=0}^{K-1} coef[k]*buf[refl(j-H+k)]
 *                                + 0x4000 ) >> 15)        for j = 0..L-1
 *   with BORDER_REFLECT_101 padding.
 *   The vendor uses a 256-short stack buffer, so L must be <= 256.
 *   Returns 0; a non-positive W makes it a no-op.
 * ------------------------------------------------------------------------ */
int cr_fir_reflect(int16_t *out, const int16_t *in, const int16_t *coef,
                   int p4, int W, int L)
{
    int K = p4;
    if (K < 0) K = 0;
    if (K > L - 1) K = L - 1;
    int H = K >> 1;

    if (W <= 0)
        return 0;

    int16_t buf[256];
    for (int c = 0; c < W; c++) {
        for (int i = 0; i < L; i++)
            buf[i] = in[c + i * W];
        fir_reflect_line(out + c, W, buf, coef, K, H, L);
    }
    return 0;
}

/* ------------------------------------------------------------------------ *
 * 0x180040560 — the row-wise twin of 0x180030fc0: the same reflect-101 FIR but
 *   applied along contiguous rows (stride 1) and run over R rows.
 *
 *   Args (ms_abi): rcx = out (int16*), rdx = in (int16*), r8 = coef (int16*),
 *   r9d = p4 (kernel length request), [rsp+0x20] = W (row length),
 *   [rsp+0x28] = R (row count).
 *
 *   For each row r (0..R-1), with buf[i] = in[r*W + i]:
 *       K = clamp(p4, 0, W-1);  H = K >> 1;
 *       out[r*W + j] = (int16)(( Σ_{k=0}^{K-1} coef[k]*buf[refl(j-H+k)]
 *                                + 0x4000 ) >> 15)        for j = 0..W-1
 *   Returns 0; a non-positive R makes it a no-op.
 * ------------------------------------------------------------------------ */
int cr_fir_reflect_rows(int16_t *out, const int16_t *in, const int16_t *coef,
                        int p4, int W, int R)
{
    int K = p4;
    if (K < 0) K = 0;
    if (K > W - 1) K = W - 1;
    int H = K >> 1;

    if (R <= 0)
        return 0;

    int16_t buf[256];
    for (int r = 0; r < R; r++) {
        for (int i = 0; i < W; i++)
            buf[i] = in[r * W + i];
        fir_reflect_line(out + r * W, 1, buf, coef, K, H, W);
    }
    return 0;
}

/* ------------------------------------------------------------------------ *
 * 0x180033b40 — fixed 7-tap reflect-101 FIR down each row.
 *
 *   Args (ms_abi): rcx = out (int16*), rdx = in (int16*), r8 = coef (int16*),
 *   r9d = W (row length), [rsp+0x20] = R (row count).
 *
 *   For each row r (0..R-1):
 *       out[r*W + j] = (int16)(( Σ_{k=0}^{6} coef[k]*in[r*W + refl101(j-3+k,W)]
 *                                + 0x4000 ) >> 15)        for j = 0..W-1
 *   i.e. the same reflect-101 FIR as the two leaves above but with a fixed
 *   7-tap kernel (centre H=3).  The vendor unrolls it two outputs at a time
 *   with a parity-dependent tail; since the accumulation is integer and
 *   order-independent the closed form is bit-identical.
 *
 *   NOTE: the kernel is fixed at K=7 (the twins clamp K to n-1), so the
 *   window spans more than one BORDER_REFLECT_101 period when W < 4.  In that
 *   degenerate case the vendor's single-fold edge passes overlap and read into
 *   the neighbouring row (verified with an index-map probe); the closed form
 *   below is the well-defined reflect-101 and matches the vendor for all
 *   W >= 4, the domain in which a 7-tap reflected filter is meaningful.
 * ------------------------------------------------------------------------ */
void cr_fir7_reflect(int16_t *out, const int16_t *in, const int16_t *coef,
                     int W, int R)
{
    if (R <= 0)
        return;
    for (int r = 0; r < R; r++)
        fir_reflect_line(out + r * W, 1, in + r * W, coef, 7, 3, W);
}

/* ------------------------------------------------------------------------ *
 * 0x1800433b0 — fixed 7-tap reflect-101 FIR down each column of a tall image.
 *
 *   Args (ms_abi): rcx = out (int16*), rdx = in (int16*), r8 = coef (int16*),
 *   r9d = n (row stride AND column count), [rsp+0x20] = sel (line length).
 *
 *   For each column c (0..n-1) the `sel` samples buf[i] = in[c + i*n] are
 *   gathered and correlated with the fixed 7-tap kernel (centre H=3):
 *       out[c + j*n] = (int16)(( Σ_{k=0}^{6} coef[k]*buf[refl101(j-3+k,sel)]
 *                                + 0x4000 ) >> 15)        for j = 0..sel-1
 *
 *   This is the column-wise twin of cr_fir7_reflect above (same fixed 7-tap
 *   reflect-101 kernel) but with the line running down columns of stride n
 *   rather than along contiguous rows.  The vendor keeps a folded/rotating
 *   7-short sliding window and emits two outputs per iteration plus a
 *   parity-dependent tail; because the accumulation is integer and
 *   order-independent the closed form below is bit-identical.
 *
 *   NOTE: as with cr_fir7_reflect, a 7-tap window spans more than one
 *   BORDER_REFLECT_101 period when sel < 4, where the vendor's single-fold edge
 *   passes overlap and read the neighbouring column.  The closed form is the
 *   well-defined reflect-101 and matches the vendor for all sel >= 4, the
 *   domain in which a 7-tap reflected filter is meaningful.
 * ------------------------------------------------------------------------ */
void cr_vfir7_cols(int16_t *out, const int16_t *in, const int16_t *coef,
                   int n, int sel)
{
    if (n <= 0)
        return;
    for (int c = 0; c < n; c++) {
        for (int j = 0; j < sel; j++) {
            uint32_t s = 0;
            for (int k = 0; k < 7; k++)
                s += (uint32_t)((int32_t)coef[k]
                                * (int32_t)in[c + refl101(j - 3 + k, sel) * n]);
            out[c + j * n] = (int16_t)((int32_t)(s + 0x4000u) >> 15);
        }
    }
}

/* ------------------------------------------------------------------------ *
 * 0x18002e6a0 — separable 11x11 int16 FIR, one output row.
 *
 *   Args (ms_abi): rcx = out (int16*), rdx = in (uint8_t*), r8 = coef (int16*),
 *   r9d = w (output width), [rsp+0x20] = s (input row stride in bytes).
 *
 *   Two passes, with the (w+10)-short intermediate held in `out` in place:
 *     pass 1 (vertical):   mid[j] = (Σ_{d=-5..5} K[j][d]*in[(j-5)+d*s]) >> 12
 *     pass 2 (horizontal): out[i] = (Σ_{k=0..10} coef[k]*mid[i+k]) >> 12
 *   for j = 0..w+9 and i = 0..w-1.  `in` is read as *bytes* (zero-extended).
 *
 *   Pass 1 has two code paths: the 4-wide-unrolled bulk (j < (w+10)&~3) uses
 *   the *symmetric* kernel K[d] = coef[5-|d|] (the vendor only reads
 *   coef[0..5] there), while the scalar tail (j >= (w+10)&~3) reads the full
 *   11-tap coef[0..10] with K[d] = coef[d+5].  The two coincide for a symmetric
 *   kernel; the rewrite reproduces both so arbitrary coefficients match.
 *   Pass 2 accumulates in wrapping 32-bit (coef*mid can exceed int32) and there
 *   is no rounding bias — just an arithmetic >>12, in both passes.
 * ------------------------------------------------------------------------ */
void cr_sep11_row(int16_t *out, const uint8_t *in, const int16_t *coef,
                  int w, int s)
{
    int bulk = (w + 10) & ~3;
    if (bulk > 0) {
        for (int j = 0; j < bulk; j++) {
            int acc = 0;
            for (int d = -5; d <= 5; d++)
                acc += (int)coef[5 - (d < 0 ? -d : d)]
                       * (int)in[(j - 5) + d * s];
            out[j] = (int16_t)(acc >> 12);
        }
    }
    if (bulk <= w + 9) {
        for (int j = bulk; j <= w + 9; j++) {
            int acc = 0;
            for (int k = 0; k <= 10; k++)
                acc += (int)coef[k] * (int)in[(j - 5) + (k - 5) * s];
            out[j] = (int16_t)(acc >> 12);
        }
    }
    for (int i = 0; i < w; i++) {
        uint32_t acc = 0;
        for (int k = 0; k <= 10; k++)
            acc += (uint32_t)((int32_t)coef[k] * (int32_t)out[i + k]);
        out[i] = (int16_t)((int32_t)acc >> 12);
    }
}

/* ------------------------------------------------------------------------ *
 * 0x180038ac0 — per-pixel kernel-bank 2D correlation.
 *
 *   Args (ms_abi): rcx = out (int32*), rdx = in (int16*), r8 = kbank (int16*),
 *   r9 = selarr (int16*), [rsp+0x28] = unused (8 bytes), [rsp+0x30] = ow,
 *   [rsp+0x38] = oh, [rsp+0x40] = iw (input row stride), [rsp+0x48] = ih,
 *   [rsp+0x50] = K.  NOTE: the unused 8-byte 5th argument is load-bearing for
 *   the stack layout — it must stay in the signature.
 *
 *   For each output pixel (r,c), sel = selarr[r*ow + c] picks a KxK kernel from
 *   the bank, and the KxK input window at top-left (r,c) is correlated with it:
 *       out[r*ow + c] = Σ_{ky,kx} in[(r+ky)*iw + c+kx] * kbank[sel*K*K + ky*K + kx]
 *
 *   Guards: `iw < ow-1+K` or `ih < oh-1+K` → 1.  The K==15 and K==7 paths add
 *   `iw <= ow+13` / `ih <= oh+13` (resp. +5) → 0x69, and K==17 adds `iw <= ow+15`
 *   → 1; all four are unreachable once the initial guards pass (same bound), but
 *   they are reproduced verbatim.  K < 1 writes all-zero outputs.  Returns 0.
 *
 *   The vendor has 4-wide-unrolled specialised bodies for K=15, 17 and 7 (same
 *   integer accumulation, so bit-identical to the closed form) plus a general
 *   KxK body.  The accumulation is wrapping 32-bit (coef*coef can exceed int32).
 * ------------------------------------------------------------------------ */
int cr_corr_kbank(int32_t *out, const int16_t *in, const int16_t *kbank,
                  const int16_t *selarr, long long unused,
                  int ow, int oh, int iw, int ih, int K)
{
    if (iw < ow - 1 + K) return 1;
    if (ih < oh - 1 + K) return 1;
    if (K == 15) {
        if (iw <= ow + 13) return 0x69;
        if (ih <= oh + 13) return 0x69;
    } else if (K == 17) {
        if (iw <= ow + 15) return 1;
        if (ih <= oh + 15) return 1;
    } else if (K == 7) {
        if (iw <= ow + 5) return 0x69;
        if (ih <= oh + 5) return 0x69;
    }
    if (oh > 0) {
        for (int r = 0; r < oh; r++) {
            for (int c = 0; c < ow; c++) {
                uint32_t acc = 0;
                if (K >= 1) {
                    int sel = selarr[r * ow + c];
                    const int16_t *kb = kbank + (long long)sel * K * K;
                    for (int ky = 0; ky < K; ky++)
                        for (int kx = 0; kx < K; kx++)
                            acc += (uint32_t)((int32_t)in[(r + ky) * iw + c + kx]
                                              * (int32_t)kb[ky * K + kx]);
                }
                out[r * ow + c] = (int32_t)acc;
            }
        }
    }
    return 0;
}

/* ------------------------------------------------------------------------ *
 * 0x18002c600 — in-place separable box mean over a float image.
 *
 *   Args (ms_abi): rcx = dst descriptor, rdx = src descriptor, r8d = mode.
 *   Descriptor: +0x08 = float *data, +0x10 = w (uint), +0x14 = h (uint).
 *   Both w and h must be even, else returns 0x69.
 *
 *   mode == 3 : 3x3 box mean   (multiply by 0x3de38e39 ~= 1/9)
 *   mode != 3 : 5x5 box mean   (multiply by 0x3d23d70a ~= 0.04)
 *
 *   Two passes — horizontal then vertical — each a clamp-to-edge box sum
 *   accumulated left-to-right (ascending index) and the vertical result then
 *   multiplied by the 1/k^2 constant.  The vendor runs both passes in place,
 *   reading ahead and keeping the already-overwritten samples in shift
 *   registers; we reproduce that with a two-deep history per line so the
 *   result is identical whether or not dst == src.  Verified against the
 *   vendor's impulse response (separable clamp box) and random floats.
 * ------------------------------------------------------------------------ */
int cr_box_mean_f32(void *img1, void *img2, int mode)
{
    uint32_t w = *(uint32_t *)((char *)img2 + 0x10);
    uint32_t h = *(uint32_t *)((char *)img2 + 0x14);

    if ((w & 1u) || (h & 1u))
        return 0x69;

    float *dst = *(float **)((char *)img1 + 8);
    const float *src = *(const float **)((char *)img2 + 8);

    int r = (mode == 3) ? 1 : 2;
    float c = (mode == 3) ? f32_from_bits(0x3de38e39u)
                          : f32_from_bits(0x3d23d70au);

    if (w == 0 || h == 0)
        return 0;

    /* pass 1 — horizontal box sum (undivided), in place */
    for (uint32_t i = 0; i < h; i++) {
        float *row = dst + (size_t)i * w;
        const float *s = src + (size_t)i * w;
        float p1 = s[0], p2 = s[0];      /* original s[j-1], s[j-2] */
        for (uint32_t j = 0; j < w; j++) {
            float oj = s[j];
            float acc;
            int t0 = (int)j - r;
            if (t0 < 0) t0 = 0;
            if (t0 < (int)j) {
                int d = (int)j - t0;
                acc = (d == 1) ? p1 : p2;
            } else {
                acc = s[t0];
            }
            for (int t = (int)j - r + 1; t <= (int)j + r; t++) {
                int idx = t;
                if (idx < 0) idx = 0;
                if (idx > (int)w - 1) idx = (int)w - 1;
                float v;
                if (idx < (int)j) {
                    int d = (int)j - idx;
                    v = (d == 1) ? p1 : p2;
                } else {
                    v = s[idx];
                }
                acc += v;
            }
            row[j] = acc;
            p2 = p1;
            p1 = oj;
        }
    }

    /* pass 2 — vertical box sum, times the 1/k^2 constant, in place */
    for (uint32_t j = 0; j < w; j++) {
        float p1 = dst[j], p2 = dst[j];  /* original dst[i-1][j], dst[i-2][j] */
        for (uint32_t i = 0; i < h; i++) {
            float oj = dst[(size_t)i * w + j];
            float acc;
            int t0 = (int)i - r;
            if (t0 < 0) t0 = 0;
            if (t0 < (int)i) {
                int d = (int)i - t0;
                acc = (d == 1) ? p1 : p2;
            } else {
                acc = dst[(size_t)t0 * w + j];
            }
            for (int t = (int)i - r + 1; t <= (int)i + r; t++) {
                int idx = t;
                if (idx < 0) idx = 0;
                if (idx > (int)h - 1) idx = (int)h - 1;
                float v;
                if (idx < (int)i) {
                    int d = (int)i - idx;
                    v = (d == 1) ? p1 : p2;
                } else {
                    v = dst[(size_t)idx * w + j];
                }
                acc += v;
            }
            dst[(size_t)i * w + j] = acc * c;
            p2 = p1;
            p1 = oj;
        }
    }

    return 0;
}

/* ------------------------------------------------------------------------ *
 * 0x180030ea0 — per-sample running average with a saturation counter.
 *   void fn(int16_t *cnt, int16_t *dst, const int16_t *src, int n,
 *           float k, const int16_t *limit):
 *     for i in 0..n-1:
 *       s = src[i];
 *       if (s < 0xfa) {                       // signed 16-bit
 *         c = cnt[i];
 *         if (c < *limit) { c++; cnt[i]=c; s=src[i]; }
 *         ce = (int)c;                        // sign-extended
 *         v = ((dst[i]*2^-6 * (ce-1)) + s*k) / ce * 64;
 *         r = cr_roundf_to_int(v); if (r > 0x7fff) r = 0x7fff;
 *         dst[i] = r;
 *       }
 * ------------------------------------------------------------------------ */
void cr_running_avg(int16_t *cnt, int16_t *dst, const int16_t *src,
                    int n, float k, const int16_t *limit)
{
    for (int i = 0; i < n; i++) {
        int16_t s = src[i];
        if (s < 0xfa) {
            int16_t c = cnt[i];
            if (c < *limit) {
                c = (int16_t)(c + 1);
                cnt[i] = c;
                s = src[i];
            }
            int ce = (int)c;
            float v = ((((float)(int)dst[i] * 0x1p-6f) * ((float)ce - 1.0f)) +
                       ((float)(int)s * k)) / (float)ce * 64.0f;
            int r = cr_roundf_to_int(v);
            if (r > 0x7fff)
                r = 0x7fff;
            dst[i] = (int16_t)r;
        }
    }
}

/* ------------------------------------------------------------------------ *
 * 0x1800335e0 — moving average (box filter) of a float signal with edge
 * replication.
 *   void fn(float *out, const float *in, int n, uint32_t w):
 *     if ((int)w < 2) { copy in->out (n elements); return; }
 *     half = cr_lroundf((float)w * 0.5f);
 *     sum = Σ_{j<w} in[j]; inv = 1.0f/(float)w;
 *     out[0..half-1] = sum*inv;
 *     iVar3 = (n - half) - ((w even) ? 1 : 0);
 *     sliding: out[half..iVar3] = (in[k] - in[k-w])*inv + out[k-1];
 *     edge: out[iVar3+1..n-1] = out[iVar3];
 * ------------------------------------------------------------------------ */
void cr_box_mean_edge(float *out, const float *in, int n, uint32_t w)
{
    int half = cr_lroundf((float)(int)w * 0.5f);
    if ((int)w < 2) {
        if (n > 0)
            for (int k = 0; k < n; k++)
                out[k] = in[k];
        return;
    }
    float sum = 0.0f;
    for (uint32_t j = 0; j < w; j++)
        sum += in[j];
    float inv = 1.0f / (float)(int)w;
    for (int j = 0; j < half; j++)
        out[j] = sum * inv;
    int iVar3 = (n - half) - ((w & 1u) == 0 ? 1 : 0);
    if (half <= iVar3) {
        const float *p2 = in + w;
        float       *p6 = out + half - 1;
        const float *endp = in + (unsigned)(iVar3 - half) + w + 1;
        do {
            p6[1] = (*p2 - p2[-(ptrdiff_t)w]) * inv + p6[0];
            p2 = p2 + 1;
            p6 = p6 + 1;
        } while (p2 != endp);
    }
    int start = iVar3 + 1;
    if (start < n) {
        float *p2 = out + start;
        float *endp = out + (unsigned)((n - 2) - iVar3) + start + 1;
        do {
            float *p6 = p2 + 1;
            *p2 = p2[-1];
            p2 = p6;
        } while (p2 != endp);
    }
}
