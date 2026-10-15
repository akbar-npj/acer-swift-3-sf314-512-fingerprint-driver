/*
 * fpc_sample.c — clean-room reimplementation of the geometric image sampler.
 *
 *   cr_bilinear_sample_u8  0x18001f790  Q15 bilinear resample of a byte image
 *
 * Derived from disassembly of fpc_enclave.dll (RVA <-> cr_ map in MAP.md).
 */
#include "fpc_bep.h"

/* 0x18001f790 — sample `n` bytes of a byte image along an affine path.
 *
 * For each output i, the source position is
 *     x(i) = xcoef*idx + xbase + i*xstep
 *     y(i) = ycoef*idx + ybase + i*ystep
 * in Q15 fixed point (0x8000 == 1.0).  The value is a bilinear blend of the
 * four neighbours (floor(x),floor(y)), (floor(x),floor(y)+1),
 * (floor(x)+1,floor(y)), (floor(x)+1,floor(y)+1) with weights
 *     w00=((0x8000-fx)*(0x8000-fy))>>15   w01=((0x8000-fx)*fy)>>15
 *     w10=(fx*(0x8000-fy))>>15            w11=(fx*fy)>>15
 * and the result is (w00*p0 + w01*p1 + w10*p2 + w11*p3) >> 15.  `img` is a
 * cr_image; its stride and origin (offy*a + offx) are honoured.  x and y are
 * 32-bit and may go negative (the vendor reads out of bounds; we reproduce it
 * verbatim).  The four neighbours are p0=base[r], p1=base[r+a],
 * p2=base[r+1], p3=base[r+a+1] with r = y>>15*a + (x>>15). */
void cr_bilinear_sample_u8(uint8_t *out, const cr_image *img,
                           const cr_sampler *s, int n, int idx)
{
    if (n <= 0)
        return;

    int stride = img->a;
    const uint8_t *base = (const uint8_t *)img->data
                        + (long long)(int32_t)(img->offy * img->a + img->offx);

    int32_t x = s->xcoef * idx + s->xbase;
    int32_t y = s->ycoef * idx + s->ybase;
    int32_t dx = s->xstep, dy = s->ystep;

    for (int i = 0; i < n; i++, x += dx, y += dy) {
        int ix = x >> 15, fx = x & 0x7fff;
        int iy = y >> 15, fy = y & 0x7fff;
        int bi = iy * stride + ix;

        int p0 = base[bi];
        int p1 = base[bi + stride];
        int p2 = base[bi + 1];
        int p3 = base[bi + stride + 1];

        int w00 = ((0x8000 - fx) * (0x8000 - fy)) >> 15;
        int w01 = ((0x8000 - fx) * fy) >> 15;
        int w10 = (fx * (0x8000 - fy)) >> 15;
        int w11 = (fx * fy) >> 15;

        out[i] = (uint8_t)((w00 * p0 + w01 * p1 + w10 * p2 + w11 * p3) >> 15);
    }
}

/* ------------------------------------------------------------------------ *
 * 0x1800466f0 — grid-bucketed keypoint sampler.
 *   int fn(cr_pt8 *pts, int *out_count, int npts, int maxout,
 *          const int *dims, uint32_t seed, const uint8_t *cfg)
 *
 * Buckets the `npts` keypoint records (coords `f4`/`f6`) into a `cfg[0x26]`
 * (rows) x `cfg[0x25]` (cols) grid, where cell x = f4*cols/dims[4] and cell
 * y = f6*rows/dims[5] (each clamped, negatives to 0, then to the grid edge).
 * `heads[cell]` is the per-cell linked-list head and `nexts[kp]` the chain,
 * both -1 terminated; the list is built by a *descending* keypoint scan so the
 * head is the lowest index.  The `ncells` cell ids are then shuffled by
 * `cr_shuffle_indices(seed)`.  Finally the shuffled cell order is walked
 * (wrapping) and, for every non-empty cell, the current head's payload word
 * (record+4) is copied to `pts[outn].f0` and the cell advances down its chain,
 * until `maxout` outputs (or every cell is drained).  The count is stored in
 * `*out_count`.  Scratch: `nexts` is `(int16)cfg[0x10]` ints, `heads`/`order`
 * are `ncells` ints each, all via `cr_malloc_aligned16`; on any alloc failure
 * the already-allocated buffers are freed and the status returned.  On success
 * all three are freed and 0 returned.
 *
 * Trap: the per-record update writes the 4 bytes at record+4 with the record's
 * own 4-byte word 0 *after* both coords have been read; the union `cr_pt8`
 * captures this (w[1] = w[0]).
 * ------------------------------------------------------------------------ */
int cr_keypoint_grid_sample(cr_pt8 *pts, int *out_count, int npts, int maxout,
                            const int *dims, uint32_t seed, const uint8_t *cfg)
{
    int32_t *nexts = NULL;      /* local_60 */
    int32_t *heads = NULL;      /* local_58 */
    int32_t *order = NULL;      /* local_50  */
    int      st;

    const int cols = cfg[0x25];
    const int rows = cfg[0x26];
    const int W    = dims[4];
    const int H    = dims[5];

    st = cr_malloc_aligned16((void **)&nexts,
                             (size_t)((int64_t)*(const int16_t *)(cfg + 0x10) << 2));
    if (st != 0)
        return st;

    const int ncells = rows * cols;
    st = cr_malloc_aligned16((void **)&heads, (size_t)((int64_t)ncells << 2));
    if (st != 0) {
        cr_sized_free((void **)&nexts);
        return st;
    }
    st = cr_malloc_aligned16((void **)&order, (size_t)((int64_t)ncells << 2));
    if (st != 0) {
        cr_sized_free((void **)&nexts);
        cr_sized_free((void **)&heads);
        return st;
    }

    for (int k = 0; k < ncells; k++)
        heads[k] = -1;

    if (npts - 1 >= 0) {
        for (int kp = npts - 1; kp >= 0; kp--) {
            int32_t f0 = pts[kp].w[0];
            int16_t s4 = pts[kp].s.f4;
            int16_t s6 = pts[kp].s.f6;

            int c = ((int)s4 * cols) / W;
            if (c < 0)
                c = 0;
            int r = ((int)s6 * rows) / H;
            pts[kp].w[1] = f0;
            if (r < 0)
                r = 0;
            if (r > rows - 1)
                r = rows - 1;
            if (c > cols - 1)
                c = cols - 1;

            int32_t *head = &heads[c + r * cols];
            if (*head == -1) {
                *head = kp;
                nexts[kp] = -1;
            } else {
                nexts[kp] = *head;
                *head = kp;
            }
        }
    }

    cr_shuffle_indices(order, ncells, (uint64_t)seed);

    int outn = 0;
    if (maxout >= 1) {
        int idx = 0;
        do {
            int cur = idx;
            idx = (cur >= ncells - 1) ? 0 : cur + 1;
            int32_t *head = &heads[order[cur]];
            if (*head != -1) {
                pts[outn].w[0] = pts[*head].w[1];
                *head = nexts[*head];
                outn++;
            }
        } while (outn < maxout);
    }

    *out_count = outn;

    cr_sized_free((void **)&nexts);
    cr_sized_free((void **)&heads);
    cr_sized_free((void **)&order);
    return 0;
}
