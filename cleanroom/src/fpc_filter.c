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
#include <stdlib.h>

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
    if (n <= 0 || sel <= 0)
        return;
    /* This is called in-place by cr_gauss_fir7_apply (out == in == a_data).  A
     * naive closed form that re-reads `in` for every output would, after an
     * output overwrites position r, let later outputs read the *overwritten*
     * value of r (as their -3/-2/-1 tap).  The vendor instead holds each input
     * in a sliding register window, i.e. it reads every input exactly once,
     * before any output overwrites it.  Replicate that by snapshotting each
     * column into a temp buffer first; this is bit-identical and in-place-safe. */
    int16_t *buf = malloc((size_t)sel * sizeof(int16_t));
    if (!buf)
        return;
    for (int c = 0; c < n; c++) {
        for (int j = 0; j < sel; j++)
            buf[j] = in[c + (size_t)j * n];
        fir_reflect_line(out + c, n, buf, coef, 7, 3, sel);
    }
    free(buf);
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

/* ------------------------------------------------------------------------ *
 * 0x180037ac0 — ridge gain normalisation of a u8 image.
 *   int fn(cr_image *img):  guard (w & 7) != 0 -> 0x69.
 *   Phase 1: acc[k] += (0xff - p) for every pixel whose column % 8 == k
 *            (w is a multiple of 8, so the vendor's running counter == col%8).
 *   Phase 2: u4 = (acc[7]+acc[0])*3, u14 = acc[1..6];
 *            gain = (u14 << sh) / ((u4 << sh) >> 15), sh = min(clz(u4)-1,
 *            clz(u14)-1) & 31, default 0x8000 when u4 <= 0.  Then, per group of
 *            8 columns, only lanes 0 and 7 are rewritten:
 *            v = ((0xff - p) * gain) >> 15; p = ~v (clamped to 0 when v>=0xff).
 * ------------------------------------------------------------------------ */
int cr_gain_normalize_u8(cr_image *img)
{
    uint32_t w = (uint32_t)img->w;
    if ((w & 7u) != 0)
        return 0x69;
    int h = img->h;
    uint8_t *data = (uint8_t *)img->data;
    int acc[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
    if (h > 0) {
        for (int row = 0; row < h; row++) {
            uint8_t *p = data + (size_t)row * w;
            if ((int)w > 0) {
                for (uint32_t col = 0; col < w; col++)
                    acc[col & 7u] += 0xff - (int)p[col];
            }
        }
        uint32_t u4 = (uint32_t)(acc[7] + acc[0]) * 3u;
        int gain = 0x8000;
        if ((int)u4 > 0) {
            uint32_t u14 = (uint32_t)(acc[2] + acc[1] + acc[3] +
                                      acc[4] + acc[5] + acc[6]);
            int c1 = (int)cr_clz_or32(u4) - 1;
            int c2 = (int)cr_clz_or32(u14) - 1;
            int sh = (c1 < c2) ? c1 : c2;
            unsigned shu = (unsigned)sh & 0x1fu;
            gain = (int)((uint32_t)u14 << shu) /
                   ((int)((uint32_t)u4 << shu) >> 15);
        }
        if ((int)w > 0) {
            int w8 = (int)((w - 1u) >> 3) + 1;
            for (int row = 0; row < h; row++) {
                uint8_t *base = data + (size_t)row * w;
                for (int k = 0; k < w8; k++) {
                    uint8_t *p = base + k * 8;
                    int v = (int)((uint32_t)(0xff - (int)p[0]) *
                                  (uint32_t)gain) >> 15;
                    uint8_t r = (uint8_t)~v;
                    if (v >= 0xff)
                        r = 0;
                    p[0] = r;
                    v = (int)((uint32_t)(0xff - (int)p[7]) *
                              (uint32_t)gain) >> 15;
                    r = (uint8_t)~v;
                    if (v >= 0xff)
                        r = 0;
                    p[7] = r;
                }
            }
        }
    }
    return 0;
}

/* ------------------------------------------------------------------------ *
 * 0x1800175b0 — int16 twin of cr_gain_normalize_u8.
 *   Base 0x3fc0, shift 12, default gain 0x1000, and u4 = acc[1..6] / 3
 *   (signed division).  Phase 2 writes lanes 0 and 7 of each 8-sample group:
 *   v = ((0x3fc0 - p) * gain) >> 12; p = (int16)(0x3fc0 - v), clamped to 0
 *   when v >= 0x3fc0.
 * ------------------------------------------------------------------------ */
int cr_gain_normalize_s16(cr_image *img)
{
    uint32_t w = (uint32_t)img->w;
    if ((w & 7u) != 0)
        return 0x69;
    int h = img->h;
    int16_t *data = (int16_t *)img->data;
    int acc[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
    if (h > 0) {
        for (int row = 0; row < h; row++) {
            int16_t *p = data + (size_t)row * w;
            if ((int)w > 0) {
                for (uint32_t col = 0; col < w; col++)
                    acc[col & 7u] += 0x3fc0 - (int)p[col];
            }
        }
        uint32_t u5 = (uint32_t)(acc[7] + acc[0]);
        int gain = 0x1000;
        if ((int)u5 > 0) {
            uint32_t u4 = (uint32_t)((acc[2] + acc[1] + acc[3] +
                                      acc[4] + acc[5] + acc[6]) / 3);
            int c1 = (int)cr_clz_or32(u5) - 1;
            int c2 = (int)cr_clz_or32(u4) - 1;
            int sh = (c1 < c2) ? c1 : c2;
            unsigned shu = (unsigned)sh & 0x1fu;
            gain = (int)((uint32_t)u4 << shu) /
                   ((int)((uint32_t)u5 << shu) >> 12);
        }
        if ((int)w > 0) {
            int w8 = (int)((w - 1u) >> 3) + 1;
            for (int row = 0; row < h; row++) {
                int16_t *base = data + (size_t)row * w;
                for (int k = 0; k < w8; k++) {
                    int16_t *p = base + k * 8;
                    int v = (int)((uint32_t)(0x3fc0 - (int)p[0]) *
                                  (uint32_t)gain) >> 12;
                    int r = 0x3fc0 - v;
                    if (v >= 0x3fc0)
                        r = 0;
                    p[0] = (int16_t)r;
                    v = (int)((uint32_t)(0x3fc0 - (int)p[7]) *
                              (uint32_t)gain) >> 12;
                    r = 0x3fc0 - v;
                    if (v >= 0x3fc0)
                        r = 0;
                    p[7] = (int16_t)r;
                }
            }
        }
    }
    return 0;
}

/* ------------------------------------------------------------------------ *
 * 0x180040ea0 — weighted running average with saturation state.
 *   void fn(int16_t *state, int16_t **dstp, const cr_image *img,
 *           const uint8_t **srcp, float k, const int16_t *limit):
 *     n = img->w * img->h;  for each i:
 *       fs = src[i]/255;  f5 = state[i]*2^-4 + fs;
 *       f4 = (limit < f5) ? limit : f5;               // MINSS
 *       if (f4 > 0) {
 *         state[i] = roundf(f4*16);
 *         dst[i] = roundf(((dst[i]*2^-6 * (f4-fs)) + fs*(img[i]*k)) / f4 * 64),
 *                  clamped to 0x7fff;
 *       }
 * ------------------------------------------------------------------------ */
void cr_weighted_running_avg(int16_t *state, int16_t **dstp,
                             const cr_image *img, const uint8_t **srcp,
                             float k, const int16_t *limit)
{
    int16_t *dst = *dstp;
    const uint8_t *src = *srcp;
    const uint8_t *imgdata = (const uint8_t *)img->data;
    int n = img->w * img->h;
    if (n <= 0)
        return;
    float lf = (float)(int)*limit;
    for (int i = 0; i < n; i++) {
        float fs = (float)src[i] / 255.0f;
        float f5 = (float)(int)state[i] * 0.0625f + fs;
        float f4 = (lf < f5) ? lf : f5;
        if (f4 > 0.0f) {
            state[i] = (int16_t)cr_roundf_to_int(f4 * 16.0f);
            float a = (float)(int)dst[i] * 0.015625f;
            float b = a * (f4 - fs);
            float c = (float)(int)imgdata[i] * k;
            float d = fs * c;
            int t = cr_roundf_to_int(((b + d) / f4) * 64.0f);
            if (t > 0x7fff)
                t = 0x7fff;
            dst[i] = (int16_t)t;
        }
    }
}

/* ------------------------------------------------------------------------ *
 * 0x18001a510 — mirror-extend a source row, then run a 4-phase polyphase FIR.
 *   int fn(uint8_t *out, uint8_t *dst, const uint8_t *src,
 *          const int16_t *coef, int n, int ncoef):
 *   `h = ncoef >> 1` is the border width.  The source row (n bytes) is placed
 *   at dst[h .. h+n), the h bytes on each side are mirror-filled:
 *       dst[j]        = src[h - j]          for j in [0, h)
 *       dst[n+h+j]    = src[n - 2 - j]      for j in [0, h)
 *   and finally cr_polyphase_fir4(out, dst, coef, n, ncoef) is applied.  The
 *   vendor has fast 4-at-a-time paths when ncoef is 9 or 15 and n % 4 == 0,
 *   but they produce exactly the same bytes as the generic loops.  Returns 0.
 * ------------------------------------------------------------------------ */
int cr_mirror_extend_fir(uint8_t *out, uint8_t *dst, const uint8_t *src,
                         const int16_t *coef, int n, int ncoef)
{
    int h = ncoef >> 1;
    if (n > 0)
        for (int i = 0; i < n; i++)
            dst[h + i] = src[i];
    if (h > 0)
        for (int j = 0; j < h; j++) {
            dst[j] = src[h - j];
            dst[n + h + j] = src[n - 2 - j];
        }
    cr_polyphase_fir4(out, dst, coef, n, ncoef);
    return 0;
}

/* ------------------------------------------------------------------------ *
 * 0x180041140 — masked inpainting from box means, then mask -> image apply.
 *   void fn(cr_image *mask, cr_image *img, uint8_t and_mask, int apply):
 *   Pass 1 (only when h > 0): for every pixel whose mask byte has bit0 or bit4
 *   set, try to fill img->data[idx] with the mean of the surrounding masked
 *   box: first with a 3x3 box (win 3, any positive count), and if that fails
 *   with a 5x5 box (win 5, count > 5).  On success the mask byte becomes 8.
 *   Pass 2: any mask byte with bit3 set is rewritten to 2; then, when `apply`,
 *   a pixel whose (updated) mask has bit0 set gets img 0.0f and one whose mask
 *   has bit4 set gets img 255.0f.
 * ------------------------------------------------------------------------ */
void cr_inpaint_masked_box(cr_image *mask, cr_image *img,
                           uint8_t and_mask, int apply)
{
    int w = mask->w, h = mask->h;
    uint8_t *m = (uint8_t *)mask->data;
    float   *d = (float *)img->data;

    if (h > 0) {
        for (int r = 0; r < h; r++) {
            int rowbase = r * w;
            for (int c = 0; c < w; c++) {
                int idx = rowbase + c;
                uint8_t b = m[idx];
                if ((b & 0x11) == 0)
                    continue;
                int cnt;
                float sum;
                cr_masked_box_sum(&cnt, &sum, img, mask, and_mask, 3, idx);
                if (cnt > 0) {
                    d[idx] = sum / (float)cnt;
                    m[idx] = 8;
                }
                if (m[idx] != 8) {
                    cr_masked_box_sum(&cnt, &sum, img, mask, and_mask, 5, idx);
                    if (cnt > 0 && cnt > 5) {
                        d[idx] = sum / (float)cnt;
                        m[idx] = 8;
                    }
                }
            }
        }
        for (int r = 0; r < h; r++) {
            int rowbase = r * w;
            for (int c = 0; c < w; c++) {
                int idx = rowbase + c;
                if (m[idx] & 8)
                    m[idx] = 2;
                if (apply) {
                    uint8_t b = m[idx];
                    if (b & 1)
                        d[idx] = 0.0f;
                    else if (b & 0x10)
                        d[idx] = 255.0f;
                }
            }
        }
    }
}

/* ------------------------------------------------------------------------ *
 * 0x18003af20 — inpaint a list of pixels by a growing masked box mean.
 *
 *   void fn(cr_image *img, cr_image *mask, const uint16_t *count,
 *           const uint16_t *const *indices);
 *
 * For each of the *count u16 linear indices `(*indices)[i]` whose mask byte
 * has bit 2 set, walk the window sizes 3, 5, 7 (stopping at a per-pixel cap of
 * 5 for interior pixels that are not near the right border, 7 otherwise) and
 * call cr_masked_box_sum with and-mask 0x13.  Accept the first window whose
 * count exceeds a floor of 5 (only for win == 5 interior-non-right) or 0:
 * write the mean into the float image and mark the mask byte 8.  The walk
 * stops early once the pixel is marked 8.
 * ------------------------------------------------------------------------ */
void cr_inpaint_index_list(cr_image *img, cr_image *mask,
                           const uint16_t *count,
                           const uint16_t *const *indices)
{
    float   *idata = (float *)img->data;
    uint8_t *mdata = (uint8_t *)mask->data;
    int w = img->w, h = img->h;
    int n = (int)*count;

    if (n == 0)
        return;

    for (int i = 0; i < n; i++) {
        uint16_t idx = (*indices)[i];
        if (!(mdata[idx] & 4))
            continue;

        int row = (int)((long long)idx / w);
        int col;
        int maxwin, right;

        if (row < 2 || h - 2 <= row || (col = (int)((long long)idx % w)) < 2) {
            maxwin = 7;
            right  = 1;
        } else {
            right  = (w - 2 <= col);
            maxwin = 5 + 2 * right;
        }

        int win = 3;
        while (mdata[idx] != 8) {
            int   cnt;
            float sum;
            cr_masked_box_sum(&cnt, &sum, img, mask, 0x13, win, idx);
            int need = (win == 5 && !right) ? 5 : 0;
            if (need < cnt) {
                idata[idx] = sum / (float)cnt;
                mdata[idx] = 8;
            }
            win += 2;
            if (maxwin < win)
                break;
        }
    }
}

/* ------------------------------------------------------------------------ *
 * 0x180026b30 — two separable 3-tap FIR products from one int16 source image.
 * Template taps: rows/cols use {0x4000, 0, 0xc000} (derivative) and
 * {0x4000, 0x4000, 0x4000} (smoothing).
 *   uint32_t fn(cr_image *A, cr_image *B, const cr_image *src):
 *     if (!(w in [4,0x100])) return 1;
 *     r = fir_rows(A, src, coef,   3, w, h); if (r) return r;
 *     if (!(h in [4,0x100])) return 0x69;
 *     r = fir_cols(A, A,   coef+3, 3, w, h); if (r) return r;
 *     if (!(h in [4,0x100])) return 0x69;
 *     r = fir_cols(B, src, coef,   3, w, h); if (r) return r;
 *     if (!(w in [4,0x100])) return 1;
 *     return fir_rows(B, B, coef+3, 3, w, h);
 *   "x in [4,0x100]" is the vendor's `(uint32_t)(x-4) < 0xfd` guard.
 * ------------------------------------------------------------------------ */
uint32_t cr_sep_fir_pair(cr_image *A, cr_image *B, const cr_image *src)
{
    int16_t coef[6];
    coef[0] = 0x4000;
    coef[1] = 0;
    coef[2] = (int16_t)0xc000;
    coef[3] = 0x4000;
    coef[4] = 0x4000;
    coef[5] = 0x4000;

    int w = src->w, h = src->h;
    if ((uint32_t)(w - 4) < 0xfd) {
        int16_t *sd = (int16_t *)src->data;
        int16_t *Ad = (int16_t *)A->data;
        int r = cr_fir_reflect_rows(Ad, sd, coef, 3, w, h);
        if (r != 0)
            return (uint32_t)r;
        if ((uint32_t)(h - 4) < 0xfd) {
            r = cr_fir_reflect(Ad, Ad, coef + 3, 3, w, h);
            if (r != 0)
                return (uint32_t)r;
            if ((uint32_t)(h - 4) < 0xfd) {
                int16_t *Bd = (int16_t *)B->data;
                r = cr_fir_reflect(Bd, sd, coef, 3, w, h);
                if (r != 0)
                    return (uint32_t)r;
                if ((uint32_t)(w - 4) < 0xfd)
                    return (uint32_t)cr_fir_reflect_rows(Bd, Bd, coef + 3,
                                                         3, w, h);
                return 1;
            }
        }
        return 0x69;
    }
    return 1;
}

/* ------------------------------------------------------------------------ *
 * 0x1800345f0 — Q15 Gaussian window generator.
 *   void fn(int16_t *out, float sigma, int n):
 *     q = -0.5f / (sigma*sigma);  c = (float)(n-1) * 0.5f;
 *     sum = 0; for i<n: sum += expf(((float)i - c) * q * ((float)i - c));
 *     for k<n:  v = round( (expf(((float)k - c) * q * ((float)k - c)) * 32768)
 *                          / sum );
 *               out[k] = clamp(v, -32768, 32767);
 *   The multiply is grouped (t*q)*t exactly as the vendor emits it.
 * ------------------------------------------------------------------------ */
void cr_gaussian_window_q15(int16_t *out, float sigma, int n)
{
    float q = -0.5f / (sigma * sigma);

    if (n > 0) {
        float c   = (float)(int)((unsigned)n - 1) * 0.5f;
        float sum = 0.0f;

        for (int i = 0; i < n; i++) {
            float t = (float)i - c;
            sum += cr_expf(t * q * t);
        }

        for (int k = 0; k < n; k++) {
            float t = (float)k - c;
            float v = cr_expf(t * q * t);
            int   r = cr_roundf_to_int((v * 32768.0f) / sum);

            if (r >= 0x7fff)       out[k] = (int16_t)0x7fff;
            else if (r <= -0x8000) out[k] = (int16_t)0x8000;
            else                   out[k] = (int16_t)r;
        }
    }
}

/* ------------------------------------------------------------------------ *
 * 0x180018a10 — Q15 Gaussian / 1st-derivative / 2nd-derivative windows.
 *   void fn(int16_t *g, int16_t *dg, int16_t *d2g, float sigma, int n):
 *     q = -0.5f/(sigma*sigma);  c = (float)(n-1)*0.5f;
 *     sum = 0; for i<n: t = (float)i - c; sum += expf(t*q*t);
 *     for k<n:
 *       u  = (float)k - c;
 *       e  = expf(q*u*u);            // note: q*u*u here (vs t*q*t above)
 *       u2 = (u+u)*q;                // 2u*q
 *       g  = e*u2;                   // derivative factor
 *       g[k]  = (int16_t)round((e * 32768) / sum);
 *       dg[k] = (int16_t)round((g * 32768) / sum);
 *       d2g[k]= (int16_t)round(((u2*g + (q+q)*e) * 32768) / sum);
 *   Grouping is preserved verbatim: pass 1 uses (t*q)*t, pass 2 uses
 *   (q*u)*u, and d2g uses ((u2*g) + ((q+q)*e)) * 32768.
 * ------------------------------------------------------------------------ */
void cr_gaussian_deriv_windows_q15(int16_t *g, int16_t *dg, int16_t *d2g,
                                   float sigma, int n)
{
    float q = -0.5f / (sigma * sigma);
    float c = (float)(int)((unsigned)n - 1) * 0.5f;

    float sum = 0.0f;
    for (int i = 0; i < n; i++) {
        float t = (float)i - c;
        sum += cr_expf(t * q * t);
    }

    for (int k = 0; k < n; k++) {
        float u  = (float)k - c;
        float e  = cr_expf(q * u * u);
        float u2 = (u + u) * q;
        float d  = e * u2;

        g[k]   = (int16_t)cr_roundf_to_int((e * 32768.0f) / sum);
        dg[k]  = (int16_t)cr_roundf_to_int((d * 32768.0f) / sum);
        d2g[k] = (int16_t)cr_roundf_to_int(((u2 * d + (q + q) * e) * 32768.0f) / sum);
    }
}

/* ------------------------------------------------------------------------ *
 * 0x180034740 — separable 7-tap Gaussian blur of two int16 images.
 *   int fn(cr_image *a, cr_image *b, float sigma):
 *     int16_t coef[7]; cr_gaussian_window_q15(coef, sigma, 7);
 *     r = cr_fir7_s16(a,a,coef);     if (r) return r;
 *     r = cr_fir7_s16_col(a,a,coef); if (r) return r;
 *     r = cr_fir7_s16(b,b,coef);     if (r) return r;
 *     return cr_fir7_s16_col(b,b,coef);
 *   Both images are filtered in place (row pass then column pass); the
 *   short-circuit means a guard failure on `a` skips `b` entirely.  The
 *   status of the first failing pass is returned (0 if all four run).
 * ------------------------------------------------------------------------ */
int cr_gauss_blur7_pair(cr_image *a, cr_image *b, float sigma)
{
    int16_t coef[7];
    cr_gaussian_window_q15(coef, sigma, 7);

    int r = cr_fir7_s16(a, a, coef);
    if (r != 0)
        return r;
    r = cr_fir7_s16_col(a, a, coef);
    if (r != 0)
        return r;
    r = cr_fir7_s16(b, b, coef);
    if (r != 0)
        return r;
    return cr_fir7_s16_col(b, b, coef);
}

/* ------------------------------------------------------------------------ *
 * 0x18002b930 — separable blur pair using a 15-tap Gaussian / derivative
 * window.  Builds g (Gaussian) and dg (derivative) via
 * cr_gaussian_deriv_windows_q15, then for the source image (dims from
 * src->w/src->h) writes two blurred outputs:
 *   o1 = rows(dg) then cols(g)
 *   o2 = rows(g) then cols(dg)
 * Both row passes read from the *same* source data.  Out-of-range dims
 * return 0x69 (h out of range) or 1 (w out of range); an alloc/guard
 * failure short-circuits.
 * ------------------------------------------------------------------------ */
uint32_t cr_gauss_deriv_blur_pair(cr_image *o1, cr_image *o2,
                                  const cr_image *src, float sigma)
{
    int16_t g[16], dg[16], d2g[20];
    uint32_t r;
    /* Vendor returns early if the window build fails; our implementation is a
     * pure expf computation and cannot fail, so we always continue. */
    cr_gaussian_deriv_windows_q15(g, dg, d2g, sigma, 15);

    int w = src->w, h = src->h;
    if ((uint32_t)(w - 0x10) < 0xf1) {
        int16_t *o1d  = (int16_t *)o1->data;
        int16_t *srcd = (int16_t *)src->data;
        r = cr_fir_reflect_rows(o1d, srcd, dg, 15, w, h);
        if ((int)r != 0)
            return r;
        if ((uint32_t)(h - 0x10) < 0xf1) {
            r = cr_fir_reflect(o1d, o1d, g, 15, w, h);
            if ((int)r != 0)
                return r;
            if (0xf0 < (uint32_t)(w - 0x10))
                return 1;
            int16_t *o2d = (int16_t *)o2->data;
            r = cr_fir_reflect_rows(o2d, srcd, g, 15, w, h);
            if ((int)r != 0)
                return r;
            if ((uint32_t)(h - 0x10) < 0xf1)
                return cr_fir_reflect(o2d, o2d, dg, 15, w, h);
        }
        return 0x69;
    }
    return 1;
}

/* ------------------------------------------------------------------------ *
 * 0x18003eb00 — three-image Gaussian/derivative filter dispatcher.
 *   int fn(void *p1, void *p2, const void *p3, float sigma)
 *
 * Validates the three descriptors (each: the tag word at +0 must equal the
 * w/h word at +0x10, and the origin word at +0x18 must be zero).  If p3's w
 * is 8-aligned, builds a fresh 15-tap Gaussian/derivative window and runs four
 * guarded reflect FIR passes — p1 = rows(dg) then cols(g), p2 = rows(g) then
 * cols(dg), both reading the shared p3 source (the vendor's p2 row call reuses
 * r8 left holding g).  Otherwise it delegates to cr_gauss_deriv_blur_pair.
 * A sigma below 0.72 returns 0x69 first.
 * ------------------------------------------------------------------------ */
int cr_gauss_deriv_3img(void *a1, void *a2, void *a3, float sigma)
{
    uint8_t *p1 = (uint8_t *)a1, *p2 = (uint8_t *)a2, *p3 = (uint8_t *)a3;

    if (*(uint64_t *)(p1 + 0x00) != *(uint64_t *)(p1 + 0x10)) return 0x69;
    if (*(uint64_t *)(p1 + 0x18) != 0)                         return 0x69;
    if (*(uint64_t *)(p2 + 0x00) != *(uint64_t *)(p2 + 0x10)) return 0x69;
    if (*(uint64_t *)(p2 + 0x18) != 0)                         return 0x69;
    if (*(uint64_t *)(p3 + 0x00) != *(uint64_t *)(p3 + 0x10)) return 0x69;
    if (*(uint64_t *)(p3 + 0x18) != 0)                         return 0x69;

    if ((*(uint8_t *)(p3 + 0x10) & 7) != 0) {
        if (0.72f > sigma)
            return 0x69;
        return (int)cr_gauss_deriv_blur_pair((cr_image *)p1, (cr_image *)p2,
                                             (const cr_image *)p3, sigma);
    }
    if (0.72f > sigma)
        return 0x69;

    int16_t g[16], dg[16], d2g[16];
    cr_gaussian_deriv_windows_q15(g, dg, d2g, sigma, 15);

    int w = *(int *)(p3 + 0x10);
    int h = *(int *)(p3 + 0x14);
    int16_t *p1d = *(int16_t **)(p1 + 8);
    int16_t *p2d = *(int16_t **)(p2 + 8);
    int16_t *p3d = *(int16_t **)(p3 + 8);
    int r;

    r = cr_fir_reflect_rows_guarded(p1d, p3d, dg, 15, w, h);
    if (r) return r;
    r = cr_fir_reflect_guarded(p1d, p1d, g, 15, w, h);
    if (r) return r;
    r = cr_fir_reflect_rows_guarded(p2d, p3d, g, 15, w, h);
    if (r) return r;
    r = cr_fir_reflect_guarded(p2d, p2d, dg, 15, w, h);
    if (r) return r;
    return 0;
}

/* ------------------------------------------------------------------------ *
 * 0x18002f770 — three-output Gaussian-derivative triple from one source.
 *   int fn(void *o1, void *o2, void *o3, void *src, float sigma)
 *
 * Builds the 15-tap Gaussian derivative windows (g, dg, d2g) from sigma, then
 * fills the three output int16 images from the source `src`:
 *     o1 = cols(g)   o rows(d2g) o src
 *     o2 = cols(dg)  o rows(dg)  o src
 *     o3 = cols(d2g) o rows(g)   o src
 * Each stage validates the source width/height (must be in [16,256], else 1)
 * after the windows (return its status) and before the column pass (else 0x69).
 * The vendor leaves r8 holding the window pointer across the row pass (the
 * reflect helpers do not write r8), so the o3 row pass uses g and the o2 column
 * pass uses dg. */
int cr_gauss_deriv_triple(void *a1, void *a2, void *a3, void *a4, float sigma)
{
    uint8_t *p1 = (uint8_t *)a1, *p2 = (uint8_t *)a2,
            *p3 = (uint8_t *)a3, *p4 = (uint8_t *)a4;
    int16_t g[16], dg[16], d2g[16];
    int r;

    cr_gaussian_deriv_windows_q15(g, dg, d2g, sigma, 15);

    if ((unsigned)(*(int *)(p4 + 0x10) - 0x10) > 0xf0u) return 1;

    int16_t *src = *(int16_t **)(p4 + 8);
    int     w = *(int *)(p4 + 0x10);
    int     h = *(int *)(p4 + 0x14);

    r = cr_fir_reflect_rows(*(int16_t **)(p1 + 8), src, d2g, 15, w, h);
    if (r) return r;
    if ((unsigned)(h - 0x10) > 0xf0u) return 0x69;
    r = cr_fir_reflect(*(int16_t **)(p1 + 8), *(int16_t **)(p1 + 8), g, 15, w, h);
    if (r) return r;

    if ((unsigned)(w - 0x10) > 0xf0u) return 1;
    r = cr_fir_reflect_rows(*(int16_t **)(p3 + 8), src, g, 15, w, h);
    if (r) return r;
    if ((unsigned)(h - 0x10) > 0xf0u) return 0x69;
    r = cr_fir_reflect(*(int16_t **)(p3 + 8), *(int16_t **)(p3 + 8), d2g, 15, w, h);
    if (r) return r;

    if ((unsigned)(w - 0x10) > 0xf0u) return 1;
    r = cr_fir_reflect_rows(*(int16_t **)(p2 + 8), src, dg, 15, w, h);
    if (r) return r;
    if ((unsigned)(h - 0x10) > 0xf0u) return 0x69;
    r = cr_fir_reflect(*(int16_t **)(p2 + 8), *(int16_t **)(p2 + 8), dg, 15, w, h);
    return r;
}

/* ------------------------------------------------------------------------ *
 * 0x180030070 — validated 3-output Gaussian-derivative triple.
 *   int fn(cr_image *o1, cr_image *o2, cr_image *o3, const cr_image *src,
 *          float sigma)
 *
 * All four descriptors must be canonical (the tag word at +0 equals the w/h
 * word at +0x10, and the origin word at +0x18 is zero), else 0x69.  A sigma
 * below 0.72 also returns 0x69.
 *
 * If src->w is NOT 8-aligned it delegates to cr_gauss_deriv_triple (which
 * uses the unguarded reflect helpers).  When src->w IS 8-aligned it runs the
 * six guarded reflect passes itself, mirroring the triple's pass order:
 *     o1 = cols(g)   o rows(d2g) o src
 *     o3 = cols(d2g) o rows(g)   o src   (row call reuses r8 left holding g)
 *     o2 = cols(dg)  o rows(dg)  o src   (col call reuses r8 left holding dg)
 * Each pass short-circuits on its (nonzero) status, which is returned.
 * ------------------------------------------------------------------------ */
int cr_gauss_deriv_triple_guarded(void *a1, void *a2, void *a3,
                                  const void *a4, float sigma)
{
    uint8_t *p1 = (uint8_t *)a1, *p2 = (uint8_t *)a2,
            *p3 = (uint8_t *)a3, *p4 = (uint8_t *)a4;

    if (*(uint64_t *)(p1 + 0x00) != *(uint64_t *)(p1 + 0x10)) return 0x69;
    if (*(uint64_t *)(p1 + 0x18) != 0)                         return 0x69;
    if (*(uint64_t *)(p2 + 0x00) != *(uint64_t *)(p2 + 0x10)) return 0x69;
    if (*(uint64_t *)(p2 + 0x18) != 0)                         return 0x69;
    if (*(uint64_t *)(p3 + 0x00) != *(uint64_t *)(p3 + 0x10)) return 0x69;
    if (*(uint64_t *)(p3 + 0x18) != 0)                         return 0x69;
    if (*(uint64_t *)(p4 + 0x00) != *(uint64_t *)(p4 + 0x10)) return 0x69;
    if (*(uint64_t *)(p4 + 0x18) != 0)                         return 0x69;

    if ((*(uint8_t *)(p4 + 0x10) & 7) != 0) {
        if (0.72f > sigma)
            return 0x69;
        return cr_gauss_deriv_triple(a1, a2, a3, (void *)a4, sigma);
    }
    if (0.72f > sigma)
        return 0x69;

    int16_t g[16], dg[16], d2g[16];
    cr_gaussian_deriv_windows_q15(g, dg, d2g, sigma, 15);

    int w = *(int *)(p4 + 0x10);
    int h = *(int *)(p4 + 0x14);
    int16_t *p1d = *(int16_t **)(p1 + 8);
    int16_t *p2d = *(int16_t **)(p2 + 8);
    int16_t *p3d = *(int16_t **)(p3 + 8);
    const int16_t *p4d = *(const int16_t **)(p4 + 8);
    int r;

    r = cr_fir_reflect_rows_guarded(p1d, p4d, d2g, 15, w, h); if (r) return r;
    r = cr_fir_reflect_guarded(p1d, p1d, g, 15, w, h);       if (r) return r;
    r = cr_fir_reflect_rows_guarded(p3d, p4d, g, 15, w, h);   if (r) return r;
    r = cr_fir_reflect_guarded(p3d, p3d, d2g, 15, w, h);     if (r) return r;
    r = cr_fir_reflect_rows_guarded(p2d, p4d, dg, 15, w, h);  if (r) return r;
    r = cr_fir_reflect_guarded(p2d, p2d, dg, 15, w, h);      if (r) return r;
    return r;
}

/* ------------------------------------------------------------------------ *
 * 0x1800256e0 — n*n box median filter over an 8-bit image, borders clamped.
 *   uint32_t fn(cr_image *out, cr_image *src, uint16_t n):
 *     scratch = cr_malloc_aligned16(n*n);
 *     for each output pixel (orow,orow-col): gather the n*n source window
 *       centred on (ocol,orow) with clamped indices into scratch, then run
 *       (n*n+1)>>1 forward bubble-sort passes and emit scratch[(n*n-1)/2].
 *     cr_sized_free(scratch).
 * ------------------------------------------------------------------------ */
uint32_t cr_box_median_u8(cr_image *out, const cr_image *src, uint16_t n)
{
    void   *scratch = NULL;
    uint32_t r = cr_malloc_aligned16(&scratch, (size_t)n * (size_t)n);
    if (r == 0) {
        int      w  = src->w, h = src->h;
        uint8_t *sd = (uint8_t *)src->data;
        uint8_t *od = (uint8_t *)out->data;
        int      nn = (int)n * (int)n;

        if (h > 0) {
            int iVar17 = -((int)(n - 1) / 2);
            int orow   = 0;
            do {
                if (w > 0) {
                    int ocol = 0;
                    do {
                        if (n != 0) {
                            int wr = 0;
                            do {
                                int srow = iVar17 + orow + wr;
                                if (srow < 0)      srow = 0;
                                if (srow > h - 1)  srow = h - 1;
                                int wc = 0;
                                do {
                                    int scol = iVar17 + ocol + wc;
                                    if (scol < 0)      scol = 0;
                                    if (scol > w - 1)  scol = w - 1;
                                    ((uint8_t *)scratch)[wr * n + wc] =
                                        sd[scol + srow * w];
                                    wc++;
                                } while (wc != (int)n);
                                wr++;
                            } while (wr != (int)n);
                        }
                        int passes = (nn + 1) >> 1;
                        while (passes-- > 0) {
                            if (nn > 1) {
                                int k = 0;
                                do {
                                    uint8_t b3 = ((uint8_t *)scratch)[k];
                                    uint8_t b2 = ((uint8_t *)scratch)[k + 1];
                                    if (b3 < b2) {
                                        ((uint8_t *)scratch)[k]     = b2;
                                        ((uint8_t *)scratch)[k + 1] = b3;
                                    }
                                    k++;
                                } while (k != nn - 1);
                            }
                        }
                        od[orow * w + ocol] =
                            ((uint8_t *)scratch)[(nn - 1) / 2];
                        ocol++;
                    } while (ocol != w);
                }
                orow++;
            } while (orow != h);
        }
        cr_sized_free(&scratch);
    }
    return r;
}

/* ---- batch 66: Gaussian-windowed 2-pass reflect FIR orchestrator ---------
 * 0x18002f620 — validates two "self-linked" descriptors (p[0]==p[0x10],
 * p[0x18]==0), builds a 15-tap Q15 Gaussian window from `sigma`, then runs a
 * row pass (fir_reflect_rows) followed by a column pass (fir_reflect) over the
 * int16 data at p1[0x8] (out) using p2[0x8] (in) and the dimensions p2[0x10]
 * (W) / p2[0x14] (R).  When the descriptor pointer p2[0x10] is 16-byte
 * aligned the *guarded* FIR variants are used, otherwise the plain variants.
 * Transcribed directly from the disassembly. */
int cr_gaussian_fir_2pass(void *a1, void *a2, float sigma)
{
    uint8_t *p1 = (uint8_t *)a1, *p2 = (uint8_t *)a2;
    if (*(void **)(p1 + 0)    != *(void **)(p1 + 0x10)) return 0x69;
    if (*(void **)(p1 + 0x18) != NULL)                   return 0x69;
    if (*(void **)(p2 + 0)    != *(void **)(p2 + 0x10)) return 0x69;
    if (*(void **)(p2 + 0x18) != NULL)                   return 0x69;

    int16_t coef[16];
    cr_gaussian_window_q15(coef, sigma, 15);

    int W = *(int *)(p2 + 0x10);
    int R = *(int *)(p2 + 0x14);
    int16_t *out = *(int16_t **)(p1 + 0x8);
    int16_t *in  = *(int16_t **)(p2 + 0x8);

    if (((uintptr_t)*(void **)(p2 + 0x10) & 7u) != 0) {
        /* unaligned descriptor -> plain (unguarded) FIR variants */
        if ((W - 0x10) > 0xf0) return 1;
        int r = cr_fir_reflect_rows(out, in, coef, 15, W, R);
        if (r) return r;
        if ((R - 0x10) > 0xf0) return 0x69;
        return cr_fir_reflect(out, out, coef, 15, W, R);
    } else {
        int r = cr_fir_reflect_rows_guarded(out, in, coef, 15, W, R);
        if (r) return r;
        return cr_fir_reflect_guarded(out, out, coef, 15, W, R);
    }
}

/* ---- batch 66: feature/quality check (0x180048ab0) -----------------------
 * Validates nothing (no early return on inputs); computes a running temporal
 * average of p1[0x10] into one of two (cnt,dst) buffer pairs — selected by
 * whether 0.5*p1[0x40] is a non-integer — then a Pearson correlation over
 * p1[0x10]/p1[0x28].  When the correlation passes it raises the flag byte at
 * p1[0x08].  Return value is always 0.  Transcribed from disassembly.
 *   fn(p1, k, p3): MS-x64 assigns registers by argument POSITION, so the
 *   vendor's real signature is (void *p1, float k, void *p3) — arg2 (float)
 *   lands in xmm1, arg3 (ptr) in r8: rcx=p1, xmm1=k, r8=p3. */
int cr_feature_qualify(void *a1, void *a3, float k)
{
    uint8_t *p1 = (uint8_t *)a1, *p3 = (uint8_t *)a3;
    int a60 = *(int *)(p1 + 0x60);
    int a64 = *(int *)(p1 + 0x64);
    int r9  = a64 * a60;
    int cnt = (r9 >= 0) ? (r9 >> 4) : ((r9 + 15) >> 4);

    float x   = (float)*(int *)(p1 + 0x40) * 0.5f;
    float ipart;
    float frac = cr_modff(x, &ipart);

    int16_t *src   = *(int16_t **)(p1 + 0x10);
    int16_t *dstA  = *(int16_t **)(p1 + 0x20);
    int16_t *cntA  = *(int16_t **)(p1 + 0x30);
    int16_t *dstB  = *(int16_t **)(p1 + 0x28);
    int16_t *cntB  = *(int16_t **)(p1 + 0x38);
    /* the vendor passes the *address* p3+0x24 (a single int16 limit value),
     * it does not dereference it here */
    int16_t *limit = (int16_t *)(p3 + 0x24);

    if (frac > 0.0f) {
        cr_running_avg(cntA, dstA, src, cnt, k, limit);
    } else {
        cr_running_avg(cntB, dstB, src, cnt, k, limit);
    }

    /* vendor: trunc(a60/4) and trunc(a64/4) — cmovns picks v (not v+3) when
     * v >= 0, then sar 2 (round toward zero for both signs) */
    int    width  = (a60 >= 0) ? (a60 >> 2) : ((a60 + 3) >> 2);
    int    height = (a64 >= 0) ? (a64 >> 2) : ((a64 + 3) >> 2);
    float  out_corr;
    int    out_valid;
    cr_corr_coeff(&out_corr, &out_valid, dstA, dstB,
                  width, height, 0x7fff,
                  *(int *)(p3 + 0x10), *(int *)(p3 + 0x14));
    if (out_valid != 1)                    return 0;
    if (out_corr <= *(float *)(p3 + 0x28)) return 0;
    if (*(int *)(p1 + 0x40) <= 20)         return 0;
    *(uint8_t *)(p1 + 8) = 1;
    return 0;
}
