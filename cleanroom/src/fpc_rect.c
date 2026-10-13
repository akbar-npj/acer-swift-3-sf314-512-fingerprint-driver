/*
 * fpc_rect.c — clean-room reimplementation of the rectangle-fill leaves from
 * the reachable BEP tree.  Derived from disassembly of fpc_enclave.dll; see
 * MAP.md.  All three fill a `cols x rows` block at the image origin
 * (offx, offy) with a constant, stepping by the image stride `a` per row.
 *
 * Image descriptor layout (see fpc_bep.h):
 *   +0x00 a (stride)  +0x08 data  +0x10 w  +0x14 h  +0x18 offx  +0x1c offy
 */
#include "fpc_bep.h"

/* 0x1800465a0 — fill the (w x h) block at (offx,offy) with an 8-bit value. */
void cr_rect_fill_u8(cr_image *img, uint8_t val)
{
    int rows = img->h;                 /* param_1[5]  +0x14 */
    int stride = img->a;               /* *param_1    +0x00 */
    int cols = img->w;                 /* param_1[4]  +0x10 */
    uint8_t *data = (uint8_t *)img->data;
    if (rows > 0) {
        long long base = (int32_t)(img->offy * stride + img->offx);
        int row = 0;
        for (int cnt = 0; cnt < rows; cnt++, row += stride) {
            if (cols > 0)
                for (int j = 0; j < cols; j++)
                    data[base + row + j] = val;
        }
    }
}

/* 0x18001d700 — same, but 16-bit elements. */
void cr_rect_fill_u16(cr_image *img, uint16_t val)
{
    int rows = img->h;
    int stride = img->a;
    int cols = img->w;
    uint8_t *data = (uint8_t *)img->data;
    if (rows > 0) {
        long long base = (long long)(int32_t)(img->offy * stride + img->offx) * 2;
        int row = 0;
        for (int cnt = 0; cnt < rows; cnt++, row += stride) {
            if (cols > 0) {
                uint16_t *p = (uint16_t *)(data + base + (long long)row * 2);
                for (int j = 0; j < cols; j++)
                    p[j] = val;
            }
        }
    }
}

/* 0x18001edb0 — same, but 32-bit float elements.
 *   The vendor stores `movss [..],xmm1`, so the fill value arrives in the
 *   *second* float slot (xmm1) — the callers load it from 0x18008c5c0. */
void cr_rect_fill_f32(cr_image *img, float val)
{
    int rows = img->h;
    int stride = img->a;
    int cols = img->w;
    uint8_t *data = (uint8_t *)img->data;
    if (rows > 0) {
        long long base = (long long)(int32_t)(img->offy * stride + img->offx) * 4;
        int row = 0;
        for (int cnt = 0; cnt < rows; cnt++, row += stride) {
            if (cols > 0) {
                float *p = (float *)(data + base + (long long)row * 4);
                for (int j = 0; j < cols; j++)
                    p[j] = val;
            }
        }
    }
}
