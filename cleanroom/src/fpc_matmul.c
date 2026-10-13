/*
 * fpc_matmul.c — clean-room reimplementation of 0x18003e9f0, a float matrix
 * multiply "N x T" (out = in * W^T).  Derived from disassembly of
 * fpc_enclave.dll; the RVA <-> cr_ map is in MAP.md.
 *
 * `in` is (nrows x K) row-major, `W` is (ncols x K) row-major, and `out` is
 * (nrows x ncols) row-major:
 *
 *     out[i*ncols + j] = sum_{k=0..K-1} in[i*K + k] * W[j*K + k]
 *
 * Returns 1 (an error code) when K != Kcheck; otherwise 0.  A non-positive
 * nrows or ncols simply produces no output.  For K <= 0 each dot product is 0.
 */
#include "fpc_bep.h"

int cr_matmul_nt(const float *in, int nrows, int K, const float *W,
                 int ncols, int Kcheck, float *out)
{
    if (K != Kcheck)
        return 1;
    if (nrows <= 0)
        return 0;

    for (int i = 0; i < nrows; i++) {
        const float *x = in + (long long)(int32_t)(i * K);
        const float *w = W;
        float *o = out + (long long)(int32_t)(i * ncols);

        for (int j = 0; j < ncols; j++) {
            float s = 0.0f;
            if (K > 0)
                for (int k = 0; k < K; k++)
                    s += x[k] * w[k];
            o[j] = s;
            w += K;
        }
    }
    return 0;
}
