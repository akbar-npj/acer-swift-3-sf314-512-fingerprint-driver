/*
 * fpc_stats.c — clean-room reimplementation of two small numeric leaves from
 * the reachable BEP tree.  Derived from disassembly of fpc_enclave.dll; the
 * RVA <-> cr_ map is in MAP.md.
 *
 *   cr_masked_variance  0x180037e70  count*sumsq - sum^2 over masked samples
 *   cr_read_quad        0x1800469e0  big-endian 4-byte probe at 1/3 & 2/3
 *
 * Both are transcribed in the exact order of operations the vendor uses so the
 * floating-point rounding matches bit-for-bit (build with -ffp-contract=off).
 */
#include "fpc_bep.h"

/*
 * 0x180037e70 — variance numerator over the samples selected by a byte mask.
 *
 * `data` is a column-major float array: element (i, j) is data[i + j*rows],
 * with i in [0,rows) and j in [0,cols).  `mask` points at a single byte-array
 * pointer; mask byte (i, j) is (*mask)[i + j*rows] (same column-major layout).
 * A zero mask byte means "count this sample".
 *
 * Returns (float)count * sum(v^2) - sum(v)^2, i.e. the un-normalised variance.
 * For rows <= 0 it returns 0.
 */
float cr_masked_variance(const float *data, int rows, int cols,
                         const uint8_t *const *mask)
{
    if (rows <= 0)
        return 0.0f;

    const uint8_t *mp = *mask;
    float sum = 0.0f, sumsq = 0.0f;
    int count = 0;

    for (int i = 0; i < rows; i++) {
        const float *d = data + i;
        const uint8_t *m = mp + i;
        for (int j = 0; j < cols; j++) {
            if (m[0] == 0) {
                float v = d[0];
                count++;
                sum   += v;
                sumsq += v * v;
            }
            d += rows;
            m += rows;
        }
    }

    return (float)count * sumsq - sum * sum;
}

/*
 * 0x1800469e0 — read a 4-byte big-endian value from an image-like descriptor.
 *
 * Descriptor fields used: +0x00 stride (int), +0x08 data (ptr),
 * +0x10 A (int), +0x14 B (int).  The four bytes are sampled at
 *   (row,col) in {A/3, 2A/3} x {B/3, 2B/3}
 * where the byte at (row,col) lives at data[stride*col + row].  Returns the
 * value assembled big-endian, or -1 when the descriptor is NULL or the value
 * is zero.
 */
int cr_read_quad(const int *p)
{
    if (!p)
        return -1;

    int32_t stride = *(const int32_t *)((const char *)p + 0x00);
    const uint8_t *data = *(const uint8_t *const *)((const char *)p + 0x08);
    int32_t A = *(const int32_t *)((const char *)p + 0x10);
    int32_t B = *(const int32_t *)((const char *)p + 0x14);

    int32_t a3 = A / 3, b3 = B / 3;

    uint32_t v = (uint32_t)data[stride * b3 + a3]           << 24
               | (uint32_t)data[stride * b3 + 2 * a3]       << 16
               | (uint32_t)data[stride * 2 * b3 + a3]       << 8
               | (uint32_t)data[stride * 2 * b3 + 2 * a3];

    return v ? (int)v : -1;
}
