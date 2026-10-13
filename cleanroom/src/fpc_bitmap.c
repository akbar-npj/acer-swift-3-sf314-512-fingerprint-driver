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

/* 0x180019490 — build a bitmap marking which bytes of an input image are
 * "intermediate" (1..254, i.e. neither 0 nor 255).  `out->data` is a uint32
 * bitmap with row stride `out->a >> 5` words; `out->h` rows; `out->w` is both
 * the input row stride (bytes) and the number of significant columns.
 *
 * For each 32-byte block starting at column `lo`, the block covers
 * [lo, hi] with hi = min(lo+31, w-1).  The bytes are visited hi, hi-1, ... for
 * 2 + ((hi-lo) & ~1) bytes and folded into a word (first byte = MSB) where a
 * bit is 1 iff the byte is 0 or 255; the stored word is the complement (so a
 * set bit means an intermediate byte).  A degenerate empty block stores -1. */
void cr_block_extreme_bitmap(cr_image *out, const cr_image *in)
{
    int h = out->h;
    if (h <= 0)
        return;

    int w = out->w;
    int word_stride = out->a >> 5;
    uint32_t *outdata = (uint32_t *)out->data;
    const uint8_t *indata = (const uint8_t *)in->data;

    int bound = ((w - 1) & ~31) + 32;
    int byte_row = 0, outrow_word = 0;

    for (int row = 0; row < h; row++) {
        if (w > 0) {
            for (int lo = 0; lo != bound; lo += 32) {
                int hi = (lo + 31 < w) ? lo + 31 : w - 1;
                uint32_t word;
                if (hi < lo) {
                    word = 0xffffffffu;
                } else {
                    const uint8_t *p = indata + byte_row + hi;
                    const uint8_t *end = indata + byte_row - 2 + hi
                                       - ((hi - lo) & ~1);
                    uint32_t acc = 0;
                    do {
                        unsigned a = *p;
                        acc = (acc * 2u) | (((254u - a) | (a - 1u)) >> 31);
                        p -= 2;
                        unsigned b = *(p + 1);
                        acc = (acc * 2u) | (((254u - b) | (b - 1u)) >> 31);
                    } while (p != end);
                    word = ~acc;
                }
                outdata[(lo >> 5) + outrow_word] = word;
            }
        }
        outrow_word += word_stride;
        byte_row += w;
    }
}

/* 0x180034190 — total number of set bits in a bitmap with row stride `a` bits
 * and `w` significant bits per row.  Counts the `w/32` full words of each row
 * (offset by row*a/32), then, when `w != a`, the partial word at index
 * `w/32` masked to its low `w%32` bits (`0xffffffff >> ((a-w)&31)`). */
int cr_bitmap_popcount(const cr_image *img)
{
    int a = img->a;
    int w = img->w;
    int h = img->h;
    const uint32_t *data = (const uint32_t *)img->data;

    if (h <= 0)
        return 0;

    uint32_t mask = 0xffffffffu >> ((unsigned)(a - w) & 31u);
    int nwords = w >> 5;
    int nw_clamped = (nwords >= 0) ? nwords : 0;
    int total = 0;
    int rowoff = 0;

    for (int row = 0; row < h; row++, rowoff += a) {
        if (nwords > 0) {
            int widx = rowoff >> 5;
            const uint32_t *p = data + widx;
            const uint32_t *end = data + widx + nwords;
            while (p != end)
                total += __builtin_popcount(*p++);
        }
        if (w != a) {
            int widx = (rowoff >> 5) + nw_clamped;
            total += __builtin_popcount(data[widx] & mask);
        }
    }
    return total;
}
