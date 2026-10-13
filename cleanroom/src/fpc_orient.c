/*
 * fpc_orient.c — clean-room reimplementation of 0x1800309a0.  Derived from
 * disassembly of fpc_enclave.dll; the RVA <-> cr_ map is in MAP.md.
 *
 * Given a byte array `arr`, a flag byte `flag`, a coefficient kernel `coeff`,
 * a length parameter `half` and a size `k`, it correlates `*src` against
 * `coeff` in both directions over k*k taps:
 *
 *     fwd = sum_{i=0..kk-1} src[i]        * coeff[i]
 *     rev = sum_{i=0..kk-1} src[kk-1-i]   * coeff[i]      (kk = k*k)
 *
 * If |fwd| >= |rev| it reports 0 and does nothing else.  Otherwise it flips the
 * top bit of `flag[0]` (adds 0x80), swaps the first d bytes of `arr` with the
 * next d bytes (d derived from `half`), and reports 1.  (kk == 0 also reports 0.)
 *
 * The odd `d` derivation is the vendor's own code, transcribed literally:
 * it adds bit 7 of `half` back into `half`, then arithmetic-shifts the low byte
 * right by one.
 */
#include "fpc_bep.h"

void cr_orient_pick(uint8_t *arr, uint8_t *flag, int *out,
                    const uint8_t *const *src, const int16_t *coeff,
                    int half, int k)
{
    int32_t kk = k * k;
    const uint8_t *base = *src;

    if (kk == 0) {
        *out = 0;
        return;
    }

    int32_t fwd = 0, rev = 0;
    for (int i = 0; i < kk; i++) {
        int32_t c = coeff[i];
        fwd += (int32_t)base[i] * c;
        rev += (int32_t)base[kk - 1 - i] * c;
    }

    int32_t af = fwd < 0 ? -fwd : fwd;
    int32_t ar = rev < 0 ? -rev : rev;
    if (af >= ar) {
        *out = 0;
        return;
    }

    flag[0] = (uint8_t)(flag[0] + 0x80u);

    uint32_t eax = (uint32_t)half;
    eax = (eax & 0xffffff00u) | ((eax >> 7) & 1u);
    int32_t edi = (int32_t)((uint32_t)half + eax);
    int8_t dil = (int8_t)(edi & 0xff);
    dil = (int8_t)(dil >> 1);

    int d = (int)dil;
    if (d > 0) {
        for (int i = 0; i < d; i++) {
            uint8_t t = arr[d + i];
            arr[d + i] = arr[i];
            arr[i] = t;
        }
    }

    *out = 1;
}
