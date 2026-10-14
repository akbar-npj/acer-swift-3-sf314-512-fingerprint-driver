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
