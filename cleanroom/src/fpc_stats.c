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

/* 0x180017840 — float twin of cr_masked_minmax_s16.  Scans img->h*img->w
 * contiguous float samples (stride is ignored, like the s16 version); with a
 * mask, a sample counts iff (mask[i] & and_mask) != 0.  Uses SSE minss/maxss
 * semantics, i.e. `(mn < v) ? mn : v` / `(mx > v) ? mx : v` (which also
 * reproduce the "return the second operand on NaN" behaviour exactly). */
void cr_masked_minmax_f32(float *out_min, float *out_max, int *out_count,
                          const cr_image *img, const cr_image *mask,
                          uint8_t and_mask)
{
    int total = img->h * img->w;
    const float *d = (const float *)img->data;
    float mn = 3.4028234663852886e+38f;    /* +FLT_MAX */
    float mx = -3.4028234663852886e+38f;   /* -FLT_MAX */

    if (!mask) {
        if (total > 0) {
            for (int i = 0; i < total; i++) {
                float v = d[i];
                mn = (mn < v) ? mn : v;
                mx = (mx > v) ? mx : v;
            }
        }
        *out_min = mn;
        *out_max = mx;
        *out_count = total;
        return;
    }

    if (total <= 0) {
        *out_min = 3.4028234663852886e+38f;
        *out_max = -3.4028234663852886e+38f;
        *out_count = 0;
        return;
    }

    const uint8_t *m = (const uint8_t *)mask->data;
    int count = 0;
    for (int i = 0; i < total; i++) {
        if (m[i] & and_mask) {
            float v = d[i];
            mn = (mn < v) ? mn : v;
            mx = (mx > v) ? mx : v;
            count++;
        }
    }
    *out_min = mn;
    *out_max = mx;
    *out_count = count;
}

/* 0x180037330 — sum + count of the masked pixels in a centred square box.
 *
 * `idx` is a linear pixel index into an image `W x H` (row-major, stride W):
 * cy = idx / W, cx = idx % W (signed).  The box is [cy-r, cy+r] x [cx-r, cx+r]
 * with r = win/2, clamped to the image; if it is empty nothing happens.  For
 * every pixel in the box with (mask[y*W+x] & and_mask) != 0 the float sample
 * img[y*W+x] is added to *out_sum and *out_count is incremented.  Both outputs
 * are zeroed up front.  (img and mask share the same W-stride pixel layout.) */
void cr_masked_box_sum(int *out_count, float *out_sum,
                       const cr_image *img, const cr_image *mask,
                       uint8_t and_mask, int win, int idx)
{
    int W = img->w;
    int H = img->h;
    const float   *data = (const float *)img->data;
    const uint8_t *mdat = (const uint8_t *)mask->data;

    *out_count = 0;
    *out_sum = 0.0f;

    int r  = win / 2;
    int cy = idx / W;
    int cx = idx % W;

    int y0 = cy - r; if (y0 < 0) y0 = 0;
    int x0 = cx - r; if (x0 < 0) x0 = 0;
    int y1 = cy + r; if (y1 > H - 1) y1 = H - 1;
    int x1 = cx + r; if (x1 > W - 1) x1 = W - 1;

    if (y0 > y1)
        return;

    for (int y = y0; y <= y1; y++) {
        if (x0 > x1)
            continue;
        int yw = y * W;
        const float   *frow = data + yw;
        const uint8_t *mrow = mdat + yw;
        for (int x = x0; x <= x1; x++) {
            if (mrow[x] & and_mask) {
                *out_sum += frow[x];
                (*out_count)++;
            }
        }
    }
}

/* 0x18000d040 — box sum + count of the pixels NOT in a u16 index list.
 *
 * `idx` is a linear index into a packed W x H byte image (row-major, stride
 * W): cy = idx / W, cx = idx % W.  The window is [cy-hw, cy+hw] x [cx-hw,
 * cx+hw] with hw = win >> 1, clamped to the image; if the row range is empty
 * nothing happens.  For every pixel whose linear index (r*W + c) is NOT one of
 * the `*count` u16 entries in `(*indices)[0..count)`, the byte sample is added
 * to *out_sum (as a float) and *out_count is incremented.  When `*count` is 0
 * every pixel in the window is summed.  Both outputs are zeroed up front.
 * (Despite the vendor symbol name this has nothing to do with templates.)
 */
void cr_box_sum_excl(int width, int height, const uint8_t *data,
                     const uint16_t *count, const uint16_t *const *indices,
                     int win, int idx, int *out_count, float *out_sum)
{
    int hw = win >> 1;
    *out_sum = 0.0f;
    *out_count = 0;

    int row = idx / width;
    int col = idx % width;

    int r0 = row - hw; if (r0 < 0) r0 = 0;
    int c0 = col - hw; if (c0 < 0) c0 = 0;
    int r1 = row + hw; if (r1 > height - 1) r1 = height - 1;
    int c1 = col + hw; if (c1 > width - 1) c1 = width - 1;

    if (r0 > r1)
        return;

    for (int r = r0; r <= r1; r++) {
        uint16_t cnt = *count;
        long long rowbase = (long long)r * width;
        for (int c = c0; c <= c1; c++) {
            if (cnt != 0) {
                int found = 0;
                for (int k = 0; k < cnt; k++)
                    if ((uint32_t)(*indices)[k] == (uint32_t)(rowbase + c)) {
                        found = 1;
                        break;
                    }
                if (found)
                    continue;
            }
            (*out_count)++;
            *out_sum = (float)data[rowbase + c] + *out_sum;
        }
    }
}

/* ------------------------------------------------------------------------ *
 * 0x1800363b0 — two-way softmax of scaled int16 samples.
 *   void fn(float *out, const void *ctx, const int16_t *vals):
 *     s = 2^-24 * (float)*(uint32_t*)(ctx+0x20);
 *     a = (float)vals[0] * s * 2^-14;  b = (float)vals[1] * s * 2^-14;
 *     m = (b <= a) ? a : b;            // MAXSS tie -> a
 *     *out = expf(a-m) / (expf(b-m) + expf(a-m));
 * ------------------------------------------------------------------------ */
void cr_softmax2(float *out, const void *ctx, const int16_t *vals)
{
    float s = 0x1p-24f * (float)*(const uint32_t *)((const uint8_t *)ctx + 0x20);
    float a = (float)(int)vals[0] * s * 0x1p-14f;
    float b = (float)(int)vals[1] * s * 0x1p-14f;
    float m = (b <= a) ? a : b;
    float ea = cr_expf(a - m);
    float eb = cr_expf(b - m);
    *out = ea / (eb + ea);
}
