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
 *   with BORDER_REFLECT_101 padding: refl(i) = -i for i<0, 2*(L-1)-i for
 *   i>=L, else i.  (The vendor splits this into a descending "left" pass, a
 *   plain middle pass and a descending "right" pass; since the accumulation is
 *   integer and order-independent, the closed form is bit-identical.)
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
        for (int j = 0; j < L; j++) {
            uint32_t s = 0;
            for (int k = 0; k < K; k++) {
                int idx = j - H + k;
                if (idx < 0) idx = -idx;
                else if (idx >= L) idx = 2 * (L - 1) - idx;
                s += (uint32_t)((int32_t)coef[k] * (int32_t)buf[idx]);
            }
            out[c + j * W] = (int16_t)((int32_t)(s + 0x4000u) >> 15);
        }
    }
    return 0;
}
