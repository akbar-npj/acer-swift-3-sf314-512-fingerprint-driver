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
