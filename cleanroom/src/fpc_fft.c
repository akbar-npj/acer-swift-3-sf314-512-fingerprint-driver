/*
 * fpc_fft.c — clean-room reimplementation of the vendor hybrid radix-4/radix-2
 * FFT (forward 0x18003d490, inverse 0x1800244a0).
 *
 * Transcribed directly from the x86-64 disassembly of fpc_enclave.dll.  The
 * vendor does a radix-4 first stage fused with the bit-reversal permutation,
 * then radix-2 stages driven by a precomputed unit-circle twiddle table.  The
 * bit-reversal and twiddle tables are embedded verbatim from .rdata in
 * fpc_fft_tables.h so the float results are bit-identical.  Build with
 * -ffp-contract=off (no FMA fusion) for exact match.
 *
 * Bit-exact transcription notes (verified against procedure_assembly):
 *  - First stage writes a contiguous 8-float block per iteration of the
 *    bit-reversal table (4 int16 indices r0..r3).  The 8 outputs are the
 *    specific vendor combination below, NOT a textbook 4-point DFT.
 *  - In the radix-2 butterfly the twiddle (cos,sin) is applied to operand b;
 *    new_a = a + W*b, new_b = a - W*b where W = cos + i*sin for forward and
 *    cos - i*sin for inverse.  Column 0 uses the identity twiddle (1,0).
 */
#include "fpc_bep.h"
#include "fpc_fft_tables.h"

static inline int cr_fft_pow2_ok(uint32_t n) {
    /* n must be in [8,256] and a power of two (matches disasm guard) */
    if (n - 8u >= 0xf9u) return 0;          /* n < 8 or n > 256 */
    int t = cr_hi_bit_index(n);
    return (((uint32_t)1u << (t & 0x1f)) == n);
}

/* radix-2 stages; dir = +1 forward, -1 inverse (sign of the twiddle's sine) */
static void cr_fft_stages(float *x, uint32_t n, int dir) {
    uint32_t nn = n;
    int iVar2 = 4;
    int iVar11 = 0x200;
    do {
        int iVar1 = iVar2 * 2;
        int iVar9 = (int)(nn >> 3);
        int iVar10 = 0;
        int stride = iVar2 * 4;            /* floats between butterflies in a column */
        const float *tw = cr_fft_twiddle + iVar11;
        float cosv = 1.0f, sinv = 0.0f;    /* twiddle for column 0 (W^0 = 1+0i) */
        for (;;) {
            float c = cosv;
            float s = (float)dir * sinv;    /* forward +sin, inverse -sin */
            for (int g = 0; g < iVar9; g++) {
                float *a = x + iVar10 + g * stride;
                float *b = x + iVar10 + iVar1 + g * stride;
                float are = a[0], aim = a[1], bre = b[0], bim = b[1];
                float wr = bre * c - bim * s;
                float wi = bim * c + bre * s;
                a[0] = are + wr; a[1] = aim + wi;
                b[0] = are - wr; b[1] = aim - wi;
            }
            iVar10 += 2;
            if (iVar1 == iVar10) break;
            cosv = tw[0]; sinv = tw[1]; tw += iVar11;
        }
        nn >>= 1;
        iVar11 >>= 1;
        iVar2 = iVar1;
    } while (nn > 4u);
}

uint32_t cr_fft_fwd(float *out, const float *in, uint32_t n) {
    if (!cr_fft_pow2_ok(n)) return 0x69;
    const int16_t *rev = cr_fft_bitrev + (int)(n - 1);
    float *o = out;
    int cnt = 0;
    do {
        int r0 = rev[0], r1 = rev[1], r2 = rev[2], r3 = rev[3];
        float Ar = in[2*r0], Ai = in[2*r0+1];
        float Br = in[2*r1], Bi = in[2*r1+1];
        float Cr = in[2*r2], Ci = in[2*r2+1];
        float Dr = in[2*r3], Di = in[2*r3+1];
        float f18 = Ar + Br, f17 = Ai + Bi, f12 = Ai - Bi, f21 = Ar - Br;
        float f19 = Cr + Dr, f20 = Ci + Di, f15 = Ci - Di, f14 = Cr - Dr;
        o[0]=f18+f19; o[1]=f17+f20;
        o[2]=f21-f15; o[3]=f12+f14;
        o[4]=f18-f19; o[5]=f17-f20;
        o[6]=f15+f21; o[7]=f12-f14;
        o += 8; rev += 4; cnt += 4;
    } while (cnt < (int)n);
    cr_fft_stages(out, n, +1);
    return 0;
}

uint32_t cr_fft_inv(float *out, const float *in, uint32_t n) {
    if (!cr_fft_pow2_ok(n)) return 0x69;
    const int16_t *rev = cr_fft_bitrev + (int)(n - 1);
    float *o = out;
    int cnt = 0;
    do {
        int r0 = rev[0], r1 = rev[1], r2 = rev[2], r3 = rev[3];
        float Ar = in[2*r0], Ai = in[2*r0+1];
        float Br = in[2*r1], Bi = in[2*r1+1];
        float Cr = in[2*r2], Ci = in[2*r2+1];
        float Dr = in[2*r3], Di = in[2*r3+1];
        float f18 = Ar + Br, f17 = Ai + Bi, f12 = Ai - Bi, f21 = Ar - Br;
        float f19 = Cr + Dr, f20 = Ci + Di, f15 = Ci - Di, f14 = Cr - Dr;
        o[0]=f18+f19; o[1]=f17+f20;
        o[2]=f21+f15; o[3]=f12-f14;
        o[4]=f18-f19; o[5]=f17-f20;
        o[6]=f21-f15; o[7]=f12+f14;
        o += 8; rev += 4; cnt += 4;
    } while (cnt < (int)n);
    cr_fft_stages(out, n, -1);
    return 0;
}

/* ------------------------------------------------------------------------ *
 * 0x180018330 — n-point real transform from an (n/2)-point complex FFT.
 *   int fn(float *a1, float *a2, int n)
 *
 * n must be a power of two in [16,512] (else 0x69).  First runs
 *   cr_fft_fwd(a2, a1, n/2)          (a1 -> a2, half-size complex FFT)
 * then the real-recombination butterfly for i = 0..n/4-2 with the shared
 * unit-circle twiddles tw1 = cos(2pi(i+1)/n), tw2 = sin(2pi(i+1)/n) read from
 * cr_fft_twiddle at float offset (4096/n)*(i+1):
 *   A=a2[2+2i] C=a2[3+2i] B=a2[n-1-2i] D=a2[n-2-2i]
 *   ad=(A+D)/2  da=(D-A)/2  cb=(C+B)/2  cbm=(C-B)/2
 *   p = tw1*da + cb*tw2
 *   q = tw1*cb - tw2*da
 *   a1[2+2i]     = ad + q
 *   a1[n-2-2i]   = ad - q
 *   a1[3+2i]     = cbm + p
 *   a1[n-1-2i]   = p - cbm
 * and the four leftover bins:
 *   a1[0] = a2[0]+a2[1]   a1[1] = a2[0]-a2[1]
 *   a1[n/2] = a2[n/2]     a1[n/2+1] = a2[n/2+1]
 * Returns 0, or the FFT status on failure.
 * ------------------------------------------------------------------------ */
int cr_fft_real_n(float *a1, float *a2, int n)
{
    if ((unsigned)(n - 0x10) > 0x1f0u)
        return 0x69;
    if (((uint32_t)1u << (cr_hi_bit_index((uint32_t)n) & 0x1f)) != (uint32_t)n)
        return 0x69;

    uint32_t r = cr_fft_fwd(a2, a1, (uint32_t)(n >> 1));
    if (r != 0)
        return (int)r;

    int S = 4096 / n;                        /* float stride into the table */
    for (int i = 0; i < (n >> 2) - 1; i++) {
        const float *tw = cr_fft_twiddle + (size_t)(i + 1) * (size_t)S;
        float tw1 = tw[0], tw2 = tw[1];
        float A = a2[2 + 2 * i], C = a2[3 + 2 * i];
        float B = a2[n - 1 - 2 * i], D = a2[n - 2 - 2 * i];
        float ad  = (A + D) * 0.5f;
        float da  = (D - A) * 0.5f;
        float cb  = (C + B) * 0.5f;
        float cbm = (C - B) * 0.5f;
        float p = tw1 * da + cb * tw2;
        float q = tw1 * cb - tw2 * da;
        a1[2 + 2 * i]     = ad + q;
        a1[n - 2 - 2 * i] = ad - q;
        a1[3 + 2 * i]     = cbm + p;
        a1[n - 1 - 2 * i] = p - cbm;
    }
    int half = n >> 1;
    a1[0]        = a2[0] + a2[1];
    a1[1]        = a2[0] - a2[1];
    a1[half]     = a2[half];
    a1[half + 1] = a2[half + 1];
    return 0;
}

/* ------------------------------------------------------------------------ *
 * 0x180029510 — scaled real FFT front-end.
 *   int fn(float *a1, unsigned n, float *a3)
 *
 * Guard n > 512 -> 0x69.  De-interleaves the n real samples of a1 into a3
 * (even samples to the front, reversed odd samples to the back), runs
 * cr_fft_real_n(a3, a1, n), repacks into a1 through the unit-circle twiddle
 * table, then scales every output by scale_tab[cr_hi_bit_index(n)].
 * ------------------------------------------------------------------------ */
int cr_fft_real_fwd(float *a1, unsigned n, float *a3)
{
    static const float scale_tab[11] = {
        1.4142135f, 1.0f, 0.70710677f, 0.5f, 0.35355338f, 0.25f,
        0.17677669f, 0.125f, 0.088388346f, 0.0625f, 0.044194173f
    };

    if (n > 0x200u)
        return 0x69;

    int half = (int)n >> 1;
    float scale = scale_tab[cr_hi_bit_index(n)];

    if (half != 0) {
        for (int k = 0; k < half; k++) {
            a3[k] = a1[2 * k];
            a3[(int)n - 1 - k] = a1[2 * k + 1];
        }
    }

    uint32_t r = (uint32_t)cr_fft_real_n(a3, a1, (int)n);
    if (r != 0)
        return (int)r;

    a1[0] = a3[0] * 0.70710677f;
    int step = 1024 / (int)(2u * n);             /* 512 / n */

    if (half < 2) {
        a1[half] = cr_fft_twiddle[step * (int)n] * a3[1];
        if (n == 0)
            return (int)r;
    } else {
        int stride = step * 2;                   /* 1024 / n */
        int off    = ((int)n + 2) * step;        /* (n + 2) * (512 / n) */
        for (int k = 1; k < half; k++) {
            const float *tw = cr_fft_twiddle + off + (k - 1) * stride;
            a1[k] = a3[2 * k] * cr_fft_twiddle[k * stride]
                  - a3[2 * k + 1] * cr_fft_twiddle[k * stride + 1];
            a1[half + k] = a3[(int)n - 2 * k] * tw[0]
                         + a3[(int)n - 2 * k + 1] * tw[1];
        }
        a1[half] = cr_fft_twiddle[step * (int)n] * a3[1];
    }

    for (int i = 0; i < (int)n; i++)
        a1[i] *= scale;

    return (int)r;
}

/* ------------------------------------------------------------------------ *
 * 0x180045490 — inverse real FFT front-end (twin of cr_fft_real_fwd).
 *   int fn(float *p1, float *p2, unsigned n)
 *
 * Guard (uint)(n-16) > 496 -> 0x69; n must also be a power of two.
 * Recombines the n spectra of p1 into p2 (mirror butterfly with the
 * unit-circle twiddle table, stride S = 4096/n), folds the four leftover
 * bins, then tail-calls cr_fft_inv(p1, p2, n/2) — so the result lands in p1
 * and p2 is scratch.
 * ------------------------------------------------------------------------ */
int cr_fft_real_inv(float *p1, float *p2, unsigned n)
{
    if ((uint32_t)(n - 0x10u) > 0x1f0u)
        return 0x69;
    if (((uint32_t)1u << (cr_hi_bit_index(n) & 0x1f)) != n)
        return 0x69;

    int quarter = (int)n >> 2;
    if (quarter > 1) {
        const float *tw = cr_fft_twiddle + 4096u / n;   /* stride S */
        unsigned S = 4096u / n;
        for (int j = 0; j < quarter - 1; j++) {
            float a = p1[3 + 2 * j], b = p1[(int)n - 1 - 2 * j];
            float c = p1[2 + 2 * j], d = p1[(int)n - 2 - 2 * j];
            float tw1 = tw[0], tw2 = tw[1];
            tw += S;
            float f12 = (a + b) * -0.5f;
            float f16 = (a - b) * 0.5f;
            float f15 = (c + d) * 0.5f;
            float f13 = (d - c) * -0.5f;
            float f14 = tw1 * f12 + tw2 * f13;
            float f11 = tw1 * f13 - f12 * tw2;
            p2[2 + 2 * j]        = f15 + f14;
            p2[3 + 2 * j]        = f16 + f11;
            p2[(int)n - 1 - 2 * j] = f11 - f16;
            p2[(int)n - 2 - 2 * j] = f15 - f14;
        }
    }

    float a0 = p1[0], a1v = p1[1];
    unsigned half = n >> 1;
    p2[0]        = (a1v + a0) * 0.5f;
    p2[1]        = (a0 - a1v) * 0.5f;
    p2[half]     = p1[half];
    p2[half + 1] = p1[half + 1];

    return (int)cr_fft_inv(p1, p2, half);
}

/* ------------------------------------------------------------------------ *
 * 0x18001d050 — scaled inverse real FFT (twin of cr_fft_real_fwd).
 *   int fn(float *a1, unsigned n, float *a3)
 *
 * Guard n > 512 -> 0x69.  Repacks the n spectra of a1 into a3 with the
 * unit-circle twiddle table (stride step = 512/n), runs
 * cr_fft_real_inv(a3, a1, n), de-interleaves a3 back into a1
 * (a1[2k]=a3[k], a1[2k+1]=a3[n-1-k]) and scales by
 * scale_tab[cr_hi_bit_index(n)].
 * ------------------------------------------------------------------------ */
int cr_fft_real_bwd(float *a1, unsigned n, float *a3)
{
    static const float scale_tab[11] = {
        1.4142135f, 1.0f, 0.70710677f, 0.5f, 0.35355338f, 0.25f,
        0.17677669f, 0.125f, 0.088388346f, 0.0625f, 0.044194173f
    };

    if (n > 0x200u)
        return 0x69;

    float scale = scale_tab[cr_hi_bit_index(n)];
    int half = (int)n >> 1;
    a3[0] = a1[0] * 1.4142135f;
    int step = 1024 / (int)(2u * n);             /* 512 / n */

    if (half > 1) {
        for (int k = 0; k < half - 1; k++) {
            int i1 = 2 * step * (k + 1);
            int i2 = 2 * step * ((int)n - 1 - k);
            a3[2 + 2 * k] = a1[1 + k] * cr_fft_twiddle[i1]
                          + a1[(int)n - 1 - k] * cr_fft_twiddle[i2];
            a3[3 + 2 * k] = a1[(int)n - 1 - k] * cr_fft_twiddle[i2 + 1]
                          - a1[1 + k] * cr_fft_twiddle[i1 + 1];
        }
    }
    a3[1] = a1[half] * cr_fft_twiddle[step * (int)n];

    uint32_t r = (uint32_t)cr_fft_real_inv(a3, a1, n);
    if (r != 0)
        return (int)r;

    if (half == 0) {
        if (n == 0)
            return (int)r;
    } else {
        for (int k = 0; k < half; k++) {
            a1[2 * k]     = a3[k];
            a1[2 * k + 1] = a3[(int)n - 1 - k];
        }
    }

    for (int i = 0; i < (int)n; i++)
        a1[i] *= scale;

    return (int)r;
}
