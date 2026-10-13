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

/*
 * 0x180020130 — min / max / count of image pixels selected by a bitmap.
 *
 * `img` is a byte image (w = +0x10, h = +0x14, data = +8, row-major w*h).
 * `bitmap` is a 1-bit image (stride = +0x00, data = +8, offx = +0x18,
 * offy = +0x1c); its bit at linear index `p` is word[p>>5] >> (p & 31).
 * For every set bit in the bitmap sub-rectangle [offx,offx+w) x [offy,offy+h),
 * the corresponding image pixel is (row, col) -> img->data[row*w + col].
 *
 * Writes min (init 0xff), max (init 0) and the count to the three int outputs.
 * For h <= 0 nothing is scanned and the outputs are (0xff, 0, 0).
 */
void cr_masked_minmax(int *out_min, int *out_max, int *out_count,
                      const cr_image *img, const cr_image *bitmap)
{
    int h = img->h, w = img->w;
    uint32_t mn = 0xffu, mx = 0u;
    int count = 0;

    if (h > 0) {
        int stride = bitmap->a;
        const uint8_t *bm = (const uint8_t *)bitmap->data;
        const uint8_t *px = (const uint8_t *)img->data;
        int offx = bitmap->offx, offy = bitmap->offy;
        int rowbase = 0;                         /* row * w */

        for (int row = 0; row < h; row++) {
            if (w > 0) {
                int base = (offy + row) * stride;
                int end  = base + offx + w;
                for (int eax = base + offx; eax < end; eax++) {
                    uint32_t word = ((const uint32_t *)bm)[eax >> 5];
                    if ((word >> ((eax - base) & 31)) & 1u) {
                        uint8_t v = px[rowbase - base - offx + eax];
                        if ((uint8_t)mn > v) mn = v;
                        if ((uint8_t)mx < v) mx = v;
                        count++;
                    }
                }
            }
            rowbase += w;
        }
    }

    *out_min = (int)mn;
    *out_max = (int)mx;
    *out_count = count;
}

/*
 * 0x18003f460 — mean and standard deviation of a byte buffer.
 *
 *   sum   = sum_{i<n} data[i]
 *   sumsq = sum_{i<n} data[i]^2
 *   *out_mean = sum / n
 *   var       = sumsq / n - mean*mean
 *   *out_std  = sqrt(var)          (via the vendor's seed + 2 Newton steps)
 *
 * The seed/Newton part is exactly cr_sqrtf, so we reuse it.  For n <= 0 the
 * sums are 0 and the divisions by (float)n = 0.0 yield NaN, as in the vendor.
 */
void cr_mean_stddev(float *out_mean, float *out_std,
                    const uint8_t *data, int n)
{
    int32_t sum = 0, sumsq = 0;

    if (n > 0) {
        for (int i = 0; i < n; i++) {
            int32_t b = data[i];
            sum   += b;
            sumsq += b * b;
        }
    }

    float fn = (float)n;
    float mean = (float)sum / fn;
    float eq   = (float)sumsq / fn;

    *out_mean = mean;

    float var = eq - mean * mean;
    *out_std = cr_sqrtf(var);
}

/*
 * 0x1800277e0 — min / max / count of int16 image samples, optionally masked.
 *
 * `img` is an int16 image (data at +8, w at +0x10, h at +0x14).  When `mask`
 * is non-NULL its byte array (+8) selects samples: sample i is used iff
 * (mask[i] & and_mask) != 0.  When `mask` is NULL every sample is used.
 *
 * min/max are signed int16 comparisons, reported sign-extended; they default
 * to +32767 / -32768 when nothing is selected.  count is the number of selected
 * samples (or h*w in the unmasked case).
 */
void cr_masked_minmax_s16(int *out_min, int *out_max, int *out_count,
                          const cr_image *img, const cr_image *mask,
                          uint8_t and_mask)
{
    int total = img->h * img->w;
    const int16_t *d = (const int16_t *)img->data;
    int32_t mn = 0x7fff, mx = (int32_t)0xffff8000;

    if (!mask) {
        if (total > 0) {
            for (int i = 0; i < total; i++) {
                int32_t v = d[i];
                if ((int16_t)mn > (int16_t)v) mn = v;
                if ((int16_t)mx < (int16_t)v) mx = v;
            }
        }
        *out_min = (int)mn;
        *out_max = (int)mx;
        *out_count = total;
        return;
    }

    if (total <= 0) {
        *out_min = 0x7fff;
        *out_max = (int)0xffff8000;
        *out_count = 0;
        return;
    }

    const uint8_t *m = (const uint8_t *)mask->data;
    int count = 0;
    for (int i = 0; i < total; i++) {
        if (m[i] & and_mask) {
            int32_t v = d[i];
            if ((int16_t)mn > (int16_t)v) mn = v;
            if ((int16_t)mx < (int16_t)v) mx = v;
            count++;
        }
    }
    *out_min = (int)mn;
    *out_max = (int)mx;
    *out_count = count;
}
