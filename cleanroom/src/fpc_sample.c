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
