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

/* 0x180024cb0 — binary dilation of a packed bitmap.  `dst` supplies the word
 * stride (ceil(dst->a/32) words per row) and the row count (dst->h); `src`
 * supplies the input words.  Each of the `count` passes ORs every bit with its
 * left/right neighbours (a 3-wide OR), then with its up/down neighbours; from
 * the second pass on the source is `dst` itself, so the buffer self-feeds.
 *
 * The per-word horizontal update for interior words k (0..words-2) is
 *   dst[k] = (prev >> 31) | cur | cur*2 | cur >> 1 | (next << 31)
 * (the `>>31` / `<<31` carry the wrap-around bits between adjacent words), and
 * the final word is handled with the same window minus the incoming carry. */
void cr_bitmap_dilate(cr_image *dst, const cr_image *src, int count)
{
    int words = dst->a;                          /* row stride, in bits */
    words = (words >= 0 ? words : words + 0x1f) >> 5;
    int h = dst->h;
    uint32_t *base = (uint32_t *)dst->data;

    if (count <= 0)
        return;

    int rows_minus1 = h - 1;
    int it = 0;
    uint32_t *s = (uint32_t *)src->data;

    do {
        /* horizontal pass: one 3-wide OR window per row */
        if (h > 0) {
            int ri = 0;
            uint32_t *d = base;
            do {
                uint32_t cur = *s;
                uint32_t prev;
                if (words < 2) {
                    prev = 0;
                } else {
                    long long off = 0;
                    uint32_t p = 0;
                    do {
                        prev = cur;
                        cur = *(const uint32_t *)((const char *)s + off + 4);
                        *(uint32_t *)((char *)d + off) =
                            (p >> 31) | prev | (prev * 2u) | (prev >> 1) | (cur << 31);
                        off += 4;
                        p = prev;
                    } while ((unsigned long long)off !=
                             (unsigned long long)(words - 2) * 4 + 4);
                    prev = prev >> 31;
                }
                ri++;
                s = s + words;
                d[(long long)words - 1] = (cur >> 1) | prev | cur | (cur * 2u);
                d = d + words;
            } while (ri != h);
        }

        /* vertical pass: 3-wide OR window down each column */
        s = base;
        if (words > 0) {
            do {
                while (rows_minus1 > 0) {
                    int ri = 0;
                    uint32_t *d = s;
                    uint32_t cur = *d;
                    uint32_t prev = 0;
                    uint32_t acc = 0;
                    do {
                        uint32_t p = cur;
                        cur = d[words];
                        ri++;
                        acc = cur | p;
                        *d = prev | acc;
                        d = d + words;
                        prev = p;
                    } while (ri != rows_minus1);
                    s[words * rows_minus1] = acc;
                    s = s + 1;
                    if (base + (unsigned long long)(words - 1) + 1 == s)
                        goto next_iteration;
                }
                s[words * rows_minus1] = *s;
                s = s + 1;
            } while (base + (unsigned long long)(words - 1) + 1 != s);
        }
    next_iteration:
        it++;
        s = base;
    } while (count != it);
}

/* 0x180017ac0 — set a border frame of a packed bitmap to a constant.  `d` must
 * have a==w (stride in bits), b==0, offx==0 and w a multiple of 32, else 0x69
 * is returned.  It writes `v` (all-ones when `value`!=0, else all-zeros) to:
 *   - the whole of the first `top` rows and the last `bottom` rows;
 *   - the left `left` bits and right `right` bits of every row (partial edge
 *     words are masked with `0xffffffff << (left&31)` / `0xffffffff >> (right&31)`).
 * Returns 0 on success. */
int cr_bitmap_border_set(cr_image *d, int left, int top, int right,
                         int bottom, int value)
{
    /* guard: the descriptor carries duplicate dimensions — (a,b) must equal
     * (w,h) as an 8-byte pair, and (offx,offy) must be zero. */
    if (d->a != d->w || d->b != d->h || d->offx != 0 || d->offy != 0)
        return 0x69;
    if ((d->w & 0x1f) != 0)
        return 0x69;

    int w = d->w;
    int h = d->h;
    uint32_t *data = (uint32_t *)d->data;
    uint32_t v = value ? 0xffffffffu : 0u;
    int words = (w >= 0 ? w : w + 0x1f) >> 5;

    /* top / bottom rows: fill every word of those rows */
    if (words > 0) {
        int bot = h - bottom;
        for (int col = 0; col < words; col++) {
            uint32_t *p = data + col;
            for (int r = 0; r < top; r++) { *p = v; p += words; }
            if (h > bot) {
                uint32_t *q = data + col + (long long)bot * words;
                for (int r = bot; r < h; r++) { *q = v; q += words; }
            }
        }
    }

    /* left bits: whole words set to v, the final partial word masked */
    if (left > 0) {
        uint32_t mask = 0xffffffffu << (left & 31);
        int last = ((left - 1) & ~31) + 0x20;
        int off = 0;
        int next;
        do {
            next = off + 0x20;
            uint32_t m = (next >= left) ? mask : 0u;
            if (h > 0) {
                uint32_t *p = data + (off >> 5);
                for (int r = 0; r < h; r++) {
                    *p = ((*p ^ v) & m) ^ v;
                    p += words;
                }
            }
            off = next;
        } while (next != last);
    }

    /* right bits: the first partial word masked, the rest set to v */
    uint32_t mask2 = (right == 0x20) ? 0u : (0xffffffffu >> (right & 31));
    int off = w - right;
    if (w > off) {
        int last = ((right - 1) & ~31) + off + 0x20;
        for (;;) {
            if (h > 0) {
                uint32_t *p = data + (off >> 5);
                for (int r = 0; r < h; r++) {
                    *p = ((*p ^ v) & mask2) ^ v;
                    p += words;
                }
            }
            mask2 = 0;
            if (off + 0x20 == last)
                break;
            off += 0x20;
        }
    }
    return 0;
}

/* 0x1800220e0 — binary erosion: the AND-twin of cr_bitmap_dilate.  `dst`
 * supplies the word count (dst->w >> 5) and height (dst->h); `src` supplies the
 * input words.  The horizontal interior update is
 *   dst[k] = (prev >> 31 | cur*2) & cur & (cur >> 1 | next << 31)
 * with a leading 0xffffffff carry and a trailing 0x80000000 mask; the vertical
 * pass ANDs each column with its up/down neighbours.  Repeated `count` times. */
void cr_bitmap_erode(cr_image *dst, const cr_image *src, int count)
{
    int words = dst->w >> 5;                     /* row stride, in words */
    int h = dst->h;
    uint32_t *base = (uint32_t *)dst->data;

    if (count <= 0)
        return;

    int rows_minus1 = h - 1;
    int it = 0;
    uint32_t *s = (uint32_t *)src->data;

    do {
        if (h > 0) {
            int ri = 0;
            uint32_t *d = base;
            do {
                uint32_t cur = *s;
                uint32_t prev;
                if (words < 2) {
                    prev = 1;
                } else {
                    long long off = 0;
                    uint32_t p = 0xffffffffu;
                    do {
                        prev = cur;
                        cur = *(const uint32_t *)((const char *)s + off + 4);
                        *(uint32_t *)((char *)d + off) =
                            (p >> 31 | prev * 2u) & prev & (prev >> 1 | cur << 31);
                        off += 4;
                        p = prev;
                    } while ((unsigned long long)off !=
                             (unsigned long long)(words - 2) * 4 + 4);
                    prev = prev >> 31;
                }
                ri++;
                s = s + words;
                d[(long long)words - 1] =
                    cur & (prev | cur * 2u) & (cur >> 1 | 0x80000000u);
                d = d + words;
            } while (ri != h);
        }

        s = base;
        if (words > 0) {
            do {
                while (rows_minus1 > 0) {
                    int ri = 0;
                    uint32_t *d = s;
                    uint32_t cur = *d;
                    uint32_t prev = 0xffffffffu;
                    uint32_t acc = 0;
                    do {
                        uint32_t p = cur;
                        cur = d[words];
                        ri++;
                        acc = cur & p;
                        *d = prev & acc;
                        d = d + words;
                        prev = p;
                    } while (ri != rows_minus1);
                    s[words * rows_minus1] = acc;
                    s = s + 1;
                    if (base + (unsigned long long)(words - 1) + 1 == s)
                        goto next_iteration;
                }
                s[words * rows_minus1] = *s;
                s = s + 1;
            } while (base + (unsigned long long)(words - 1) + 1 != s);
        }
    next_iteration:
        it++;
        s = base;
    } while (count != it);
}

/* 0x18003cb30 — replicate-extend the border of a packed bitmap.
 *   void fn(cr_image *bm, int left, int top, int right, int bottom)
 *
 * `bm` is a packed bitmap (a = row stride in bits, offx/offy origin, w x h
 * content rectangle [offx, offx+w) x [offy, offy+h)).  The surrounding border is
 * filled by edge replication:
 *   - `left`   columns [offx, offx+left-1]        <- column offx+left
 *   - `right`  columns [offx+w-right, offx+w-1]   <- column offx+w-right-1
 *   - `top`    rows    [offy, offy+top-1]         <- row offy+top
 *   - `bottom` rows    [offy+h-bottom, offy+h-1]  <- row offy+h-bottom-1
 * The horizontal fills cover the middle rows [top, h-bottom) first; the vertical
 * fills then copy those (already extended) rows into the top/bottom bands.  Each
 * destination bit under mask = cr_bitmask_range(...) is replaced by the source
 * bit for the horizontal passes, and by the same-column source word bit for the
 * vertical passes (dst = (dst ^ srcword) & mask ^ dst). */
void cr_bitmap_extend_border(cr_image *bm, int left, int top, int right,
                             int bottom)
{
    int a = bm->a;                       /* row stride, in bits */
    int w = bm->w, h = bm->h;
    int offx = bm->offx, offy = bm->offy;
    uint32_t *data = (uint32_t *)bm->data;
    int sw = ((a >= 0) ? a : a + 0x1f) >> 5;
    uint32_t *base = data + (long long)offy * sw;

    /* --- left columns, middle rows --- */
    if ((left >> 5) >= 0) {
        for (int wc = 0; wc != (left >> 5) + 1; wc++) {
            uint32_t mask = cr_bitmask_range(wc, offx, offx - 1 + left);
            if (top < h - bottom) {
                uint32_t *d = base + (long long)top * sw + wc;
                for (int r = top; r != h - bottom; r++, d += sw) {
                    uint32_t bit = (data[((offy + r) * a + offx + left) >> 5]
                                    >> ((offx + left) & 31)) & 1u;
                    *d = (-bit ^ *d) & mask ^ *d;
                }
            }
        }
    }

    /* --- right columns, middle rows --- */
    {
        int col = (w - right) + -1;
        int wc = col >> 5;
        if (wc < sw) {
            uint32_t *d = base + (long long)top * sw + wc;
            do {
                uint32_t mask = cr_bitmask_range(wc, offx + w - right,
                                                 offx + w - 1);
                if (top < h - bottom) {
                    uint32_t *p = d;
                    for (int r = top; r != h - bottom; r++, p += sw) {
                        int cc = offx + col;
                        uint32_t bit = (data[((offy + r) * a + cc) >> 5]
                                        >> (cc & 31)) & 1u;
                        *p = (-bit ^ *p) & mask ^ *p;
                    }
                }
                wc++;
                d++;
            } while (sw != wc);
        }
    }

    /* --- top/bottom rows, full content width --- */
    {
        int lo = offx >> 5;
        int hi = (offx + w) >> 5;
        uint32_t *p = base + lo;
        while (lo < hi) {
            int hb = h - bottom;
            uint32_t mask = cr_bitmask_range(lo, offx, offx + w - 1);
            uint32_t src = p[(long long)top * sw];
            if (top > 0) {
                uint32_t *q = p;
                for (int r = 0; r < top; r++, q += sw)
                    *q = (*q ^ src) & mask ^ *q;
            }
            src = p[(long long)(hb - 1) * sw];
            if (hb < h) {
                uint32_t *q = p + (long long)hb * sw;
                for (int r = hb; r < h; r++, q += sw)
                    *q = (*q ^ src) & mask ^ *q;
            }
            lo++;
            p++;
        }
    }
}

/*
 * 0x18002ddd0 — centroid of the set bits in a bitmap, clamped to a window.
 *
 * Scans every bit of the (masked) bitmap, accumulating the count, the sum of
 * row indices and the sum of column indices, then returns the centroid minus
 * half the window, clamped into [margin, dim - win - margin] per axis.  The
 * vendor masks only the last word of each row (the first loop iteration) and
 * uses 32-bit accumulators; the fast paths for all-zero / all-one words and
 * bytes are just closed forms of the same sums, so a plain bit scan reproduces
 * them exactly (32-bit wrapping addition is order-independent).
 *
 * Returns 0, or 0x82 when the window does not fit inside the bitmap.
 */
int cr_bitmap_centroid(const cr_bitmap_desc *bm, int win_h, int win_w,
                       int *out_y, int *out_x, int margin)
{
    int32_t h = bm->h;
    int32_t w = bm->w;
    if (h - 2 * margin < win_h)
        return 0x82;
    if (w - 2 * margin < win_w)
        return 0x82;

    int32_t stride = bm->a >> 5;             /* words per row */
    int wlast = ((w + 31) >> 5) - 1;         /* last word index (-1 when w<=0) */

    int32_t count = 0, rowsum = 0, colsum = 0;
    for (int wc = wlast; wc >= 0; wc--) {
        uint32_t mask = 0xffffffffu;
        if (wc == wlast)
            mask = 0xffffffffu >> ((~(uint32_t)(w + 31)) & 31u);
        for (int row = 0; row < h; row++) {
            uint32_t word = bm->data[(int64_t)row * stride + wc] & mask;
            if (word == 0)
                continue;
            for (int j = 0; j < 4; j++) {
                uint32_t b = (word >> (8 * j)) & 0xffu;
                for (int k = 0; k < 8; k++) {
                    if (b & (1u << k)) {
                        count++;
                        rowsum += row;
                        colsum += wc * 32 + j * 8 + k;
                    }
                }
            }
        }
    }

    int32_t xc = count ? rowsum / count : 0;
    int32_t yc = count ? colsum / count : 0;

    /* half() == the vendor's (v + (uint32)v>>31) >> 1 */
    int32_t oh = (win_h + (int32_t)((uint32_t)win_h >> 31)) >> 1;
    int32_t ow = (win_w + (int32_t)((uint32_t)win_w >> 31)) >> 1;

    int32_t oy = xc - oh;
    if (oy < margin) oy = margin;
    int32_t ox = yc - ow;
    if (ox < margin) ox = margin;

    int32_t ty = h - win_h - margin;
    if (ty > oy) ty = oy;
    *out_y = ty;

    int32_t tx = w - win_w - margin;
    if (tx <= ox) ox = tx;
    *out_x = ox;

    return 0;
}

/* ------------------------------------------------------------------------ *
 * 0x18003f780 — threshold an int16 image, morphological-open the mask, and
 * mark the byte image where the opened mask is clear.
 *
 *   img    (a1): u8 image; +0x10 w, +0x14 h, +0x08 data
 *   src    (a2): int16 image sharing img's width; +0x08 data
 *   thresh (r8d): compared as int16
 *
 * Allocates a bitmap of width round_up(w + 12, 32) and height h + 12, sets
 * bit (j+6, i+6) for every src pixel with `src[i*w+j] < (int16)thresh`, erodes
 * then dilates it (5 passes each), then writes 0x10 into img[i*w+j] wherever
 * the opened bitmap bit is clear.  Returns the bitmap-alloc status.
 * ------------------------------------------------------------------------ */
int cr_thresh_open_mark(cr_image *img, const cr_image *src, int thresh)
{
    const int w = img->w;
    const int h = img->h;
    cr_image bmp;
    int st;

    int w2 = w + 0x2b;
    if (w2 < 0)
        w2 = w + 0x4a;
    w2 &= ~0x1f;

    st = cr_bitmap_alloc((uint32_t *)&bmp, (uint32_t)w2, (uint32_t)(h + 0xc));
    if (st != 0)
        return st;

    if (h <= 0) {
        cr_bitmap_erode(&bmp, &bmp, 5);
        cr_bitmap_dilate(&bmp, &bmp, 5);
        cr_cleanup_ptr8_b(&bmp);
        return st;
    }

    {
        const int32_t  stride = bmp.a;              /* desc[0] */
        uint32_t      *bits   = (uint32_t *)bmp.data;
        const int16_t *s      = (const int16_t *)src->data;
        for (int i = 0; i < h; i++) {
            if (w <= 0)
                break;
            for (int j = 0; j < w; j++) {
                if (s[i * w + j] < (int16_t)thresh) {
                    int idx = (i + 6) * (int)stride + (j + 6);
                    bits[idx >> 5] |= 1u << ((j + 6) & 31);
                }
            }
        }
    }

    cr_bitmap_erode(&bmp, &bmp, 5);
    cr_bitmap_dilate(&bmp, &bmp, 5);

    {
        uint8_t *d = (uint8_t *)img->data;
        for (int i = 0; i < h; i++) {
            if (w <= 0)
                break;
            for (int j = 0; j < w; j++) {
                if (cr_bitmap_get(&bmp, j + 6, i + 6) == 0)
                    d[i * w + j] = 0x10;
            }
        }
    }

    cr_cleanup_ptr8_b(&bmp);
    return st;
}

/* ------------------------------------------------------------------------ *
 * 0x180023900 — build a binary bitmap from a masked source, box-sum it,
 * threshold at a full k*k window, optionally blur with a 7-tap FIR, then
 * clear pixels whose source lacks bit 2.
 *   int fn(cr_image *out, const cr_image *src, uint8_t maskbyte, int k,
 *          int niter, float sigma):
 *     n = src->h * src->w;
 *     if (n > 0) for i: out->data[i] = (src->data[i] & maskbyte) ? 1 : 0;
 *     if ((k & 1) == 0) return 0x69;
 *     r = cr_box_sum_u8(&out->data, out, k);  if (r) return r;
 *     if (n > 0) { kk = k*k; for i: out->data[i] = (out->data[i]==(uint8_t)kk)?0xff:0; }
 *     if (niter > 0) for j: { r = cr_fir7_image_u8(out, out, sigma); if (r) return r; }
 *     if (n > 0) for i: if ((src->data[i] & 4) == 0) out->data[i] = 0;
 *     return 0;
 * ------------------------------------------------------------------------ */
int cr_mask_boxmax_fir_clear(cr_image *out, const cr_image *src,
                             uint8_t maskbyte, int k, int niter, float sigma)
{
    int n = src->h * src->w;

    if (n > 0) {
        const uint8_t *s = (const uint8_t *)src->data;
        uint8_t *o = (uint8_t *)out->data;
        for (int i = 0; i < n; i++)
            o[i] = (uint8_t)((s[i] & maskbyte) ? 1 : 0);
    }

    if ((k & 1) == 0)
        return 0x69;

    int r = cr_box_sum_u8(&out->data, out, k);
    if (r != 0)
        return r;

    if (n > 0) {
        uint8_t *o = (uint8_t *)out->data;
        int kk = k * k;
        for (int i = 0; i < n; i++)
            o[i] = (o[i] == (uint8_t)kk) ? 0xff : 0;
    }

    if (niter > 0) {
        for (int j = 0; j < niter; j++) {
            r = cr_fir7_image_u8(out, out, sigma);
            if (r != 0)
                return r;
        }
    }

    if (n > 0) {
        const uint8_t *s = (const uint8_t *)src->data;
        uint8_t *o = (uint8_t *)out->data;
        for (int i = 0; i < n; i++)
            if ((s[i] & 4) != 0)
                o[i] = 0;
    }

    return 0;
}

/* ------------------------------------------------------------------------ *
 * 0x1800388b0 — build a masked bitmap image sized to `src`.
 *   int fn(cr_image *out, const cr_image *src, const void *cfg):
 *     r = cr_image_alloc_u8((int*)out, src->w, src->h);
 *     if (r == 0) {
 *         r2 = cr_mask_boxmax_fir_clear(out, src, 0xf, 1, 1,
 *                                       *(float*)(cfg + 0x48));
 *         if (r2 != 0) { cr_cleanup_ptr8_a(out); return r2; }
 *     }
 *     return r;
 * ------------------------------------------------------------------------ */
int cr_bitmap_build_masked(cr_image *out, const cr_image *src, const void *cfg)
{
    int r = cr_image_alloc_u8((int *)out, src->w, src->h);
    if (r == 0) {
        int r2 = cr_mask_boxmax_fir_clear(
            out, src, 0xf, 1, 1, *(const float *)((const char *)cfg + 0x48));
        if (r2 != 0) {
            cr_cleanup_ptr8_a(out);
            return r2;
        }
    }
    return r;
}
