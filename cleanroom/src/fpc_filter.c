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
