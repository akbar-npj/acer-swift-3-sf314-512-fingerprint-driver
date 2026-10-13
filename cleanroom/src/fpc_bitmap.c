/*
 * fpc_bitmap.c — clean-room reimplementation of the bitmap leaves from the
 * reachable BEP tree.  Derived from disassembly of fpc_enclave.dll; see MAP.md.
 *
 * A "bitmap image" is an image descriptor whose `data` points at packed 32-bit
 * words; bit index = (y + offy) * stride + (x + offx), word = idx >> 5, bit =
 * idx & 31.  `stride` is the image's first width word `a`.
 */
#include "fpc_bep.h"

/* 0x180037fb0 — clear the bits for the half-open rectangle [y0,y1) x [x0,x1). */
void cr_bitmap_clear_rect(cr_image *img, int y0, int y1, int x0, int x1)
{
    if (y0 < y1) {
        do {
            if (x0 < x1) {
                uint8_t *data = (uint8_t *)img->data;
                int x = x0;
                do {
                    int col = img->offx + x;
                    x++;
                    uint32_t *word = (uint32_t *)(data +
                        (long long)(((img->offy + y0) * img->a + col) >> 5) * 4);
                    *word &= ~(1u << ((uint8_t)col & 0x1f));
                } while (x1 != x);
            }
            y0++;
        } while (y1 != y0);
    }
}

/* 0x180023bb0 — set bitmap bits where the source image byte has (b & 0xe) != 0.
 *   src is w x h (from src->w/src->h); bm stride/offset come from bm. */
void cr_bitmap_set_from_image(cr_image *bm, const cr_image *src)
{
    int h = src->h;
    int w = src->w;
    if (h > 0) {
        int row = 0;
        for (int rr = 0; rr < h; rr++, row += w) {
            if (w > 0) {
                const uint8_t *sdata = (const uint8_t *)src->data;
                uint8_t *bdata = (uint8_t *)bm->data;
                for (int j = 0; j < w; j++) {
                    int col = bm->offx + j;
                    uint8_t b = sdata[row + j];
                    uint32_t *word = (uint32_t *)(bdata +
                        (long long)(((bm->offy + rr) * bm->a + col) >> 5) * 4);
                    *word |= (uint32_t)((b & 0xeu) != 0) << ((uint8_t)col & 0x1f);
                }
            }
        }
    }
}

/* 0x180041cc0 — expand a bitmap into the destination image's bytes:
 *   dst->data[i] = bit ? 0xff : 0x00, walking dst with stride `a`. */
void cr_bitmap_unpack(cr_image *dst, const cr_image *src)
{
    int h = dst->h;
    int w = dst->w;
    int stride = dst->a;
    if (h > 0) {
        int row = 0;
        for (int rr = 0; rr < h; rr++, row += stride) {
            int j = 0;
            long long off = row;
            if (w > 0) {
                do {
                    int col = src->offx + j;
                    j++;
                    const uint8_t *sdata = (const uint8_t *)src->data;
                    uint32_t word = *(const uint32_t *)(sdata +
                        (long long)(((src->offy + rr) * src->a + col) >> 5) * 4);
                    uint8_t bit = (uint8_t)((word >> ((uint8_t)col & 0x1f)) & 1u);
                    ((uint8_t *)dst->data)[off] = (uint8_t)(-bit);
                    off++;
                } while (w != j);
            }
        }
    }
}
