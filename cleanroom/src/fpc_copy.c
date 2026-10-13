/*
 * fpc_copy.c — clean-room reimplementation of the image-copy leaves from the
 * reachable BEP tree.  Derived from disassembly of fpc_enclave.dll; see MAP.md.
 *
 * All three copy a w x h region from `src` to `dst` using each image's own
 * stride (`a`) and origin (offx/offy).  The u8 and u32 variants require the two
 * images to have equal w/h (else return 0x69); the u16 variant shifts each
 * element left by `shift & 0x1f` while copying.
 */
#include "fpc_bep.h"

/* 0x1800308d0 — copy w*h bytes; requires dst->w/h == src->w/h. */
uint64_t cr_image_copy_u8(cr_image *dst, const cr_image *src)
{
    int w = src->w, h = src->h;
    if (w != dst->w || h != dst->h)
        return 0x69u;

    int dw = dst->a, sw = src->a;
    int dox = dst->offx, doy = dst->offy, sox = src->offx, soy = src->offy;
    uint8_t *dd = (uint8_t *)dst->data, *sd = (uint8_t *)src->data;

    if (h > 0) {
        int drow = 0, srow = 0;
        for (int r = 0; r < h; r++, drow += dw, srow += sw) {
            if (w > 0)
                for (int j = 0; j < w; j++)
                    dd[(long long)(int32_t)(doy * dw + dox) + drow + j] =
                    sd[(long long)(int32_t)(soy * sw + sox) + srow + j];
        }
    }
    return 0;
}

/* 0x18000f600 — copy w*h 32-bit words; requires dst->w/h == src->w/h. */
uint64_t cr_image_copy_u32(cr_image *dst, const cr_image *src)
{
    int w = src->w, h = src->h;
    if (w != dst->w || h != dst->h)
        return 0x69u;

    int dw = dst->a, sw = src->a;
    int dox = dst->offx, doy = dst->offy, sox = src->offx, soy = src->offy;
    uint8_t *dd = (uint8_t *)dst->data, *sd = (uint8_t *)src->data;

    if (h > 0) {
        int drow = 0, srow = 0;
        for (int r = 0; r < h; r++, drow += dw, srow += sw) {
            if (w > 0)
                for (int j = 0; j < w; j++)
                    *(uint32_t *)(dd + (long long)(int32_t)(doy * dw + dox) * 4
                                     + (long long)drow * 4 + (long long)j * 4) =
                    *(const uint32_t *)(sd + (long long)(int32_t)(soy * sw + sox) * 4
                                           + (long long)srow * 4 + (long long)j * 4);
        }
    }
    return 0;
}

/* 0x18002ade0 — copy w*h int16, shifting each left by (shift & 0x1f).
 *   Uses dst's w/h and both images' own stride/origin.  No dimension check. */
void cr_image_copy_u16_shl(cr_image *dst, const cr_image *src, uint8_t shift)
{
    int sw = src->a, dw = dst->a;
    int soy = src->offy, doy = dst->offy;
    int sox = src->offx, dox = dst->offx;
    int h = dst->h;
    uint8_t *sd = (uint8_t *)src->data, *dd = (uint8_t *)dst->data;

    if (h > 0) {
        int w = dst->w;
        int drow = 0, srow = 0;
        for (int r = 0; r < h; r++, drow += dw, srow += sw) {
            if (w > 0)
                for (int j = 0; j < w; j++)
                    *(int16_t *)(dd + (long long)(int32_t)(doy * dw + dox) * 2
                                     + (long long)drow * 2 + (long long)j * 2) =
                    (int16_t)(*(const int16_t *)(sd + (long long)(int32_t)(soy * sw + sox) * 2
                                                    + (long long)srow * 2 + (long long)j * 2)
                              << (shift & 0x1f));
        }
    }
}

/* 0x1800334c0 — convert an int16 image to a float image with a power-of-two
 * scale.  Uses dst's w/h and both images' own stride/origin.  The scale is:
 *   shift > 0 : 1.0f / (float)(1 << (shift & 31))
 *   shift == 0: 1.0f
 *   shift < 0 : (float)(1 << ((-shift) & 31))
 * (the shift is a 32-bit x86 `shl`, so the count is masked to 5 bits). */
void cr_i16_to_f32_scaled(cr_image *dst, const cr_image *src, int shift)
{
    float scale;
    if (shift > 0)
        scale = 1.0f / (float)(int32_t)((uint32_t)1 << ((unsigned)shift & 31u));
    else if (shift == 0)
        scale = 1.0f;
    else
        scale = (float)(int32_t)((uint32_t)1 << ((unsigned)(-shift) & 31u));

    int h = dst->h;
    if (h <= 0)
        return;

    int w = dst->w;
    int da = dst->a, sa = src->a;
    float *dd = (float *)dst->data;
    const int16_t *sd = (const int16_t *)src->data;
    int doff = dst->offy * dst->a + dst->offx;
    int soff = src->offy * src->a + src->offx;

    int32_t drow = 0, srow = 0;
    for (int r = 0; r < h; r++, drow += da, srow += sa) {
        if (w > 0) {
            long long db = (long long)(int32_t)doff + (long long)drow;
            long long sb = (long long)(int32_t)soff + (long long)srow;
            for (int j = 0; j < w; j++)
                dd[db + j] = (float)sd[sb + j] * scale;
        }
    }
}
