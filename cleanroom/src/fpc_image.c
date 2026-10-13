/*
 * fpc_image.c — clean-room reimplementation of the image-descriptor leaf
 * functions from the reachable BEP tree.  Derived from disassembly of
 * fpc_enclave.dll; see MAP.md.  Several vendor addresses are byte-identical
 * duplicates of each other and share one implementation here.
 */
#include "fpc_bep.h"

/* ------------------------------------------------------------------------ *
 * 0x180023a60 — fill the image's pixel buffer with the constant 2.
 *   asm: n = img->h * img->w ; if (n>0) for i in [0,n) img->data[i] = 2
 * ------------------------------------------------------------------------ */
void cr_image_fill_const2(cr_image *img)
{
    int n = img->h * img->w;
    if (n > 0) {
        uint8_t *p = (uint8_t *)img->data;
        for (int i = 0; i < n; i++)
            p[i] = 2;
    }
}

/* ------------------------------------------------------------------------ *
 * 0x18003b250 / 0x18003fbc0 — initialise an image descriptor.
 *   p==NULL        -> 1
 *   w<0 || h<0     -> 0x69
 *   else           -> 0, with a=b=w?  (a=w,b=h), data set, w,h set, offx=offy=0
 * ------------------------------------------------------------------------ */
uint32_t cr_image_set(cr_image *img, void *data, int w, int h)
{
    if (img == NULL)
        return 1;
    if (w < 0 || h < 0)
        return 0x69u;

    img->a = w;
    img->b = h;
    img->data = data;
    img->w = w;
    img->h = h;
    img->offx = 0;
    img->offy = 0;
    return 0;
}

/* ------------------------------------------------------------------------ *
 * 0x180010ef0 / 0x180017a80 — build a sub-view of `src`.
 *   copies a,b,data from src; sets w,h from the arguments; adds the origin
 *   offset (dx,dy) to src's own offset.
 * ------------------------------------------------------------------------ */
void cr_image_subview(cr_image *dst, const cr_image *src,
                      int dx, int dy, int w, int h)
{
    dst->a = src->a;
    dst->b = src->b;
    dst->data = src->data;
    dst->w = w;
    dst->h = h;
    dst->offx = dx + src->offx;
    dst->offy = dy + src->offy;
}

/* ------------------------------------------------------------------------ *
 * 0x1800305b0 — mark pixels listed in an index list with the value 4.
 *   asm: if (list && list->count)
 *          for i in [0, count) img->data[ list->indices[i] ] = 4
 * ------------------------------------------------------------------------ */
void cr_image_mark_indices(cr_image *img, const cr_index_list *l)
{
    if (l == NULL || l->count == 0)
        return;
    uint8_t *dst = (uint8_t *)img->data;
    int n = (int)(unsigned)l->count;
    for (int i = 0; i < n; i++)
        dst[l->indices[i]] = 4;
}

/* ------------------------------------------------------------------------ *
 * 0x180033ae0 — threshold mark: where src's i16 samples are >= thr, set the
 * corresponding image byte to 0x10.
 *   asm: n = img->w * img->h ; if (n>0)
 *          for i in [0,n) if (thr <= src->data16[i]) img->data[i] = 0x10
 * ------------------------------------------------------------------------ */
void cr_image_threshold_mark(cr_image *img, const cr_image *src, int16_t thr)
{
    int n = img->w * img->h;
    if (n > 0) {
        const int16_t *s = (const int16_t *)src->data;
        uint8_t *d = (uint8_t *)img->data;
        for (int i = 0; i < n; i++)
            if (thr <= s[i])
                d[i] = 0x10;
    }
}

/* ------------------------------------------------------------------------ *
 * 0x1800182b0 — mark pixels where the int16 source is <= 0 with the value 1.
 *   asm: n = img->w * img->h ; if (n>0)
 *          for i in [0,n) if (src->data16[i] <= 0) img->data[i] = 1
 * ------------------------------------------------------------------------ */
void cr_image_mark_nonpos(cr_image *img, const cr_image *src)
{
    int n = img->w * img->h;
    if (n > 0) {
        const int16_t *s = (const int16_t *)src->data;
        uint8_t *d = (uint8_t *)img->data;
        for (int i = 0; i < n; i++)
            if (s[i] <= 0)
                d[i] = 1;
    }
}

/* ------------------------------------------------------------------------ *
 * 0x180034490 — initialise an image descriptor with a 32-aligned pitch.
 *   Same as cr_image_set but the first width word (a) is the stride rounded
 *   up to a multiple of 32:  a = (w + 31) & ~31.  b = h.
 *   p==NULL -> 1 ; w<0 || h<0 -> 0x69 ; else 0.
 * ------------------------------------------------------------------------ */
uint32_t cr_image_set_pitch(cr_image *img, void *data, int w, int h)
{
    if (img == NULL)
        return 1;
    if (w < 0 || h < 0)
        return 0x69u;

    img->w = w;
    img->h = h;
    img->b = h;
    img->offx = 0;
    img->offy = 0;
    img->a = (int32_t)(((uint32_t)w + 31u) & ~31u);
    img->data = data;
    return 0;
}

/* ------------------------------------------------------------------------ *
 * 0x180041bb0 — reclassify marked image pixels from a float value array.
 *   For each index k in indices[0..*count):
 *     pc = *base + k;
 *     if (*pc != 8) continue;               // only pixels already tagged 8
 *     v = vals[k];
 *     if (v <= 0.0f)          *pc = 0x01;
 *     else if (!(v < 255.0f)) *pc = 0x10;   // NaN also lands here
 *   (255.0f is the vendor constant at 0x18008c6b0.)
 * ------------------------------------------------------------------------ */
void cr_classify_mark(const float *vals, uint8_t *const *base,
                      const uint16_t *count, const uint16_t *const *indices)
{
    uint32_t cnt = *count;
    if (cnt == 0)
        return;
    for (uint32_t i = 0; i < cnt; i++) {
        uint16_t k = (*indices)[i];
        uint8_t *pc = *base + k;
        if (*pc != 8)
            continue;
        float v = vals[k];
        if (v <= 0.0f)
            *pc = 0x01;
        else if (!(v < 255.0f))
            *pc = 0x10;
    }
}

/* 0x180026fb0 — integer-factor block-average downsample.
 *
 * `out` (int16 image) receives, for each (r,c), the mean of the f x f block of
 * the byte image `in` at rows [r*f, r*f+f) and columns [c*f, c*f+f):
 *   out[r*out->w + c] = (int16)(Σ in[(r*f+k)*in->w + c*f + j] / (f*f))
 * (signed, truncated toward zero).  Neither stride/origin is used; both images
 * are packed.  Returns 0x69 if out->w*f < in->w or out->h*f < in->h, else 0.
 * If f <= 0 every output sample is 0 (the sum loop is skipped, no division). */
int cr_downsample_mean(cr_image *out, const cr_image *in, int16_t f)
{
    if (out->w * f < in->w)
        return 0x69;
    if (out->h * f < in->h)
        return 0x69;
    if (out->h <= 0)
        return 0;

    int16_t *od = (int16_t *)out->data;
    const uint8_t *id = (const uint8_t *)in->data;
    int ow = out->w, oh = out->h, iw = in->w;
    int ff = f * f;

    int orow = 0, irow = 0;
    for (int r = 0; r < oh; r++) {
        if (ow > 0) {
            int base = irow;
            for (int c = 0; c < ow; c++, base += f) {
                int32_t val = 0;
                if (f > 0) {
                    int32_t sum = 0;
                    for (int k = 0; k < f; k++)
                        for (int j = 0; j < f; j++)
                            sum += id[base + k * iw + j];
                    val = sum / ff;
                }
                od[orow + c] = (int16_t)val;
            }
        }
        irow += iw * f;
        orow += ow;
    }
    return 0;
}

/* ------------------------------------------------------------------------ *
 * 0x18001c4e0 — int16 multi-region border fill.
 *   Args (ms_abi): rcx=img, rdx=top, r8=bottom, r9=left,
 *   [rsp+0x20]=right (5th), [rsp+0x28]=fill (uint16, 6th).
 *   Reads a=stride, data, w, h, offx, offy from the descriptor and writes a
 *   constant word into a rectangular FRAME around the image window: the outer
 *   rectangle is the window expanded by (top,bottom,left,right) on each side;
 *   the inner window (offx..offx+w-1, offy..offy+h-1) is left untouched.
 *   Implemented as four strips (top/bottom horizontal bars, left/right
 *   vertical bars) that together cover the frame.  NOTE: the assembly
 *   measures row/column steps in BYTES; these pointers are int16_t* so all
 *   steps below are in int16 ELEMENTS (half the byte count).
 * ------------------------------------------------------------------------ */
void cr_image_fill_border(cr_image *img, int top, int bottom, int left,
                          int right, uint16_t fill)
{
    int16_t *data = (int16_t *)img->data;
    int32_t  a    = img->a;            /* stride (int16 elements per row) */
    int32_t  w    = img->w;
    int32_t  h    = img->h;
    int32_t  offx = img->offx;
    int32_t  offy = img->offy;

    int64_t  base_off = (int64_t)offy * a + offx;
    int16_t *r12 = data + base_off;    /* inner top-left element */

    /* region 1 : top horizontal bar — `top` rows above the window, width w */
    if (top > 0) {
        int64_t r14 = (int64_t)a;             /* row step (elements) */
        int16_t *rsi = r12;
        int32_t r13 = 0;
        do {
            rsi = rsi - r14;                  /* one row up */
            if (w > 0) {
                int16_t *end = rsi + w;
                int16_t *p = rsi;
                do { *p = (int16_t)fill; p++; } while (p != end);
            }
            r13 += 1;
        } while (r13 != top);
    }

    /* region 2 : bottom horizontal bar — `bottom` rows below the window */
    if (bottom > 0) {
        int16_t *rsi = r12 + (int64_t)(h - 1) * a;   /* bottom window row */
        int64_t r14 = (int64_t)a;                    /* row step (down) */
        int32_t r13 = 0;
        do {
            rsi = rsi + r14;                         /* one row down */
            if (w > 0) {
                int16_t *end = rsi + w;
                int16_t *p = rsi;
                do { *p = (int16_t)fill; p++; } while (p != end);
            }
            r13 += 1;
        } while (r13 != bottom);
    }

    /* region 3 : left vertical bar — `left` columns left of the window,
     * spanning the full frame height (h + top + bottom rows). */
    if (left > 0) {
        int16_t *rdi = r12 - (int64_t)a * top;       /* topmost frame row */
        int32_t esi = h + top + bottom;              /* full height */
        int16_t *r13 = rdi - left;                   /* column end */
        do {
            rdi = rdi - 1;                           /* step left first (col offx-1 ..) */
            if (esi > 0) {
                int16_t *rcx = rdi;
                int32_t eax = 0;
                do {
                    eax += 1;
                    *rcx = (int16_t)fill;
                    rcx = rcx + a;                   /* next row */
                } while (eax != esi);
            }
        } while (rdi != r13);
    }

    /* region 4 : right vertical bar — `right` columns starting at the
     * window's right edge (offx+w-1), full frame height. */
    if (right > 0) {
        int64_t rbp = (int64_t)(w - 1) - (int64_t)a * top;  /* topmost row, col offx+w-1 */
        int16_t *r9p = r12 + rbp;
        int32_t r8d = bottom + (top + h);                   /* h+top+bottom */
        int16_t *rdx_end = r9p + (int64_t)right;            /* r9_start + right */
        do {
            r9p = r9p + 1;                                  /* next column right */
            if (r8d > 0) {
                int16_t *rcx = r9p;
                int32_t eax = 0;
                do {
                    eax += 1;
                    *rcx = (int16_t)fill;
                    rcx = rcx + a;                          /* next row */
                } while (eax != r8d);
            }
        } while (rdx_end != r9p);
    }
}

/* ------------------------------------------------------------------------ *
 * 0x18001fb80 — byte-per-pixel border EXTENSION (edge replication).
 *   Same four-region frame as cr_image_fill_border, but instead of writing a
 *   constant it replicates the window's edge pixels outward:
 *     region 1: `top` rows above  <- copy of the window's TOP row (w bytes)
 *     region 2: `bottom` rows below <- copy of the window's BOTTOM row
 *     region 3: `left` columns left  <- copy of the window's LEFT column
 *     region 4: `right` columns right<- copy of the window's RIGHT column
 *   Args (ms_abi): rcx=img, rdx=top, r8=bottom, r9=left, [rsp+0x20]=right.
 *   `a` is the row stride in BYTES (u8 image), so the row step is `a`.
 * ------------------------------------------------------------------------ */
void cr_image_border_extend(cr_image *img, int top, int bottom, int left,
                            int right)
{
    uint8_t *data = (uint8_t *)img->data;
    int32_t  a    = img->a;
    int32_t  w    = img->w;
    int32_t  h    = img->h;
    int32_t  offx = img->offx;
    int32_t  offy = img->offy;

    uint8_t *r11 = data + (int64_t)offy * a + offx;   /* window top-left */

    /* region 1 : top — replicate the window's top row into `top` rows above */
    if (top > 0) {
        uint8_t *rdi = r11;
        int32_t  r12 = 0;
        do {
            rdi = rdi - a;
            if (w > 0)
                for (int32_t i = 0; i < w; i++) rdi[i] = r11[i];
            r12 += 1;
        } while (r12 != top);
    }

    /* region 2 : bottom — replicate the window's bottom row into `bottom` rows */
    if (bottom > 0) {
        uint8_t *rdi = r11 + (int64_t)(h - 1) * a;    /* window bottom row */
        uint8_t *rcx = rdi;
        int32_t  r12 = 0;
        do {
            rcx = rcx + a;
            if (w > 0)
                for (int32_t i = 0; i < w; i++) rcx[i] = rdi[i];
            r12 += 1;
        } while (r12 != bottom);
    }

    /* region 3 : left — replicate the window's left column into `left` cols */
    if (left > 0) {
        uint8_t *rdi = r11 - (int64_t)a * top;        /* frame top-left col */
        int32_t  ebp = h + top + bottom;              /* full frame height */
        uint8_t *r9  = rdi;
        uint8_t *r14 = rdi - left;                    /* end column */
        uint8_t *r13;
        do {
            r13 = r9 - 1;                             /* next column left */
            if (ebp > 0) {
                int32_t ecx = 0;
                int64_t rax = 0;
                do {
                    r13[rax] = rdi[rax];              /* copy down the column */
                    ecx += 1;
                    rax += a;
                } while (ecx != ebp);
            }
            r9 = r13;
        } while (r14 != r13);
    }

    /* region 4 : right — replicate the window's right column into `right` cols */
    if (right > 0) {
        uint8_t *src = r11 + (int64_t)(w - 1) - (int64_t)a * top; /* frame top-right col */
        int32_t  r8d = h + top + bottom;              /* full frame height */
        uint8_t *rbx = src;
        uint8_t *r10 = src + right;                   /* end column */
        uint8_t *r9;
        do {
            r9 = rbx + 1;                             /* next column right */
            if (r8d > 0) {
                int32_t edx = 0;
                int64_t rax = 0;
                do {
                    r9[rax] = src[rax];               /* copy down the column */
                    edx += 1;
                    rax += a;
                } while (edx != r8d);
            }
            rbx = r9;
        } while (r9 != r10);
    }
}

/* ------------------------------------------------------------------------ *
 * 0x180016df0 — int16 border extension (edge replication).
 *   The 16-bit twin of cr_image_border_extend: identical four-region frame
 *   logic, but the pixels are int16 and `a` is the row stride in ELEMENTS.
 *   Args (ms_abi): rcx=img, rdx=top, r8=bottom, r9=left, [rsp+0x20]=right.
 * ------------------------------------------------------------------------ */
void cr_image_border_extend_s16(cr_image *img, int top, int bottom, int left,
                                int right)
{
    int16_t *data = (int16_t *)img->data;
    int32_t  a    = img->a;
    int32_t  w    = img->w;
    int32_t  h    = img->h;
    int32_t  offx = img->offx;
    int32_t  offy = img->offy;

    int16_t *r11 = data + (int64_t)offy * a + offx;   /* window top-left */

    if (top > 0) {
        int16_t *rdi = r11;
        int32_t  r12 = 0;
        do {
            rdi = rdi - a;
            if (w > 0)
                for (int32_t i = 0; i < w; i++) rdi[i] = r11[i];
            r12 += 1;
        } while (r12 != top);
    }

    if (bottom > 0) {
        int16_t *rdi = r11 + (int64_t)(h - 1) * a;
        int16_t *rcx = rdi;
        int32_t  r12 = 0;
        do {
            rcx = rcx + a;
            if (w > 0)
                for (int32_t i = 0; i < w; i++) rcx[i] = rdi[i];
            r12 += 1;
        } while (r12 != bottom);
    }

    if (left > 0) {
        int16_t *rdi = r11 - (int64_t)a * top;
        int32_t  ebp = h + top + bottom;
        int16_t *r9  = rdi;
        int16_t *r14 = rdi - left;
        int16_t *r13;
        do {
            r13 = r9 - 1;
            if (ebp > 0) {
                int32_t ecx = 0;
                int64_t rax = 0;
                do {
                    r13[rax] = rdi[rax];
                    ecx += 1;
                    rax += a;
                } while (ecx != ebp);
            }
            r9 = r13;
        } while (r14 != r13);
    }

    if (right > 0) {
        int16_t *src = r11 + (int64_t)(w - 1) - (int64_t)a * top;
        int32_t  r8d = h + top + bottom;
        int16_t *rbx = src;
        int16_t *r10 = src + right;
        int16_t *r9;
        do {
            r9 = rbx + 1;
            if (r8d > 0) {
                int32_t edx = 0;
                int64_t rax = 0;
                do {
                    r9[rax] = src[rax];
                    edx += 1;
                    rax += a;
                } while (edx != r8d);
            }
            rbx = r9;
        } while (r9 != r10);
    }
}

/* ------------------------------------------------------------------------ *
 * 0x1800356e0 — "saturation / usable-pixel" score for a byte image.
 *   n = h * w ; if n <= 0 -> *out = 1000.
 *   count = number of pixels equal to 0 or 255 (i.e. (uint8)(b-1) > 253).
 *   *out = 1000 + (count * -1000) / n   (C truncated division, idiv).
 * ------------------------------------------------------------------------ */
void cr_saturation_score(int *out, const cr_pixbuf *s)
{
    int n = (int)s->h * (int)s->w;
    if (n > 0) {
        const uint8_t *p   = s->data;
        const uint8_t *end = p + n;
        int count = 0;
        do {
            uint8_t b = *p++;
            count += (int)((uint8_t)(b - 1) > 253);
        } while (p != end);
        int32_t num = (int32_t)((uint32_t)count * 0xFFFFFC18u);  /* count * -1000 */
        *out = 1000 + num / n;
    } else {
        *out = 1000;
    }
}

/* ------------------------------------------------------------------------ *
 * 0x1800337e0 — widen a byte image to int16 with a signed shift.
 *   `dst` and `src` share w/h; both are packed (row stride = src->w).  For
 *   every pixel, with b = (uint8_t)shift:
 *     shift >= 1 : out = (uint16_t)((uint16_t)in << (b & 31))
 *     shift == 0 : out = in
 *     shift <  0 : sh = ((uint8_t)-b) & 31;
 *                  rnd = (int32_t)(int16_t)(1u << sh) >> 1;   (16-bit trunc)
 *                  out = (uint16_t)((int32_t)((uint32_t)in + (uint32_t)rnd) >> sh)
 *   (The vendor splits rows into pairs for speed; the flat form below is
 *    bit-identical, including the odd trailing row.)
 * ------------------------------------------------------------------------ */
void cr_u8_to_u16_shifted(cr_image *dst, const cr_image *src, int shift)
{
    int w = src->w, h = src->h;
    const uint8_t *s = (const uint8_t *)src->data;
    uint16_t *d = (uint16_t *)dst->data;
    uint8_t b = (uint8_t)shift;

    if (shift >= 1) {
        unsigned sh = b & 31u;
        for (int r = 0; r < h; r++)
            for (int c = 0; c < w; c++)
                d[(long long)r * w + c] =
                    (uint16_t)((uint16_t)s[(long long)r * w + c] << sh);
    } else if (shift == 0) {
        for (int r = 0; r < h; r++)
            for (int c = 0; c < w; c++)
                d[(long long)r * w + c] = (uint16_t)s[(long long)r * w + c];
    } else {
        unsigned sh = ((uint8_t)(-b)) & 31u;
        int32_t rnd = (int32_t)(int16_t)(uint16_t)(1u << sh) >> 1;
        for (int r = 0; r < h; r++)
            for (int c = 0; c < w; c++) {
                uint32_t v = (uint32_t)s[(long long)r * w + c] + (uint32_t)rnd;
                d[(long long)r * w + c] = (uint16_t)((int32_t)v >> sh);
            }
    }
}

/* ------------------------------------------------------------------------ *
 * 0x180028930 — symmetric (BORDER_REFLECT) extension of an int16 image.
 *   Extends the window by `top`/`bottom` rows and `left`/`right` columns with
 *   reflection that repeats the edge sample (row -1 <- row 0, row h <- row
 *   h-1).  The reflection index is computed exactly as the vendor does:
 *       idx = v % (2n);  if (idx >= n) idx = 2n - idx - 1;
 *   with v counting down from n<<16 for the top/left and up from (n<<16)+n
 *   for the bottom/right.  Top and bottom bars cover only the middle w
 *   columns; the left and right bars then cover the full frame height, so the
 *   corners are filled from the already-extended frame.  `a` is the row
 *   stride in int16 elements.
 * ------------------------------------------------------------------------ */
static int cr_reflect_idx(int v, int n)
{
    int idx = v % (n * 2);
    if (idx >= n)
        idx = (n * 2 - idx) - 1;
    return idx;
}

void cr_mirror_extend_s16(cr_image *img, int top, int bottom, int left,
                          int right)
{
    int a = img->a;
    int w = img->w;
    int h = img->h;
    int16_t *base = (int16_t *)img->data
        + ((long long)img->offy * a + img->offx);

    /* top : `top` rows above the window, middle w columns */
    if (top > 0) {
        int ctr = h * 0x10000;
        int end = ctr - top;
        int16_t *dp = base;
        do {
            ctr--;
            dp -= a;
            int idx = cr_reflect_idx(ctr, h);
            if (w > 0)
                for (int i = 0; i < w; i++)
                    dp[i] = base[(long long)idx * a + i];
        } while (end != ctr);
    }

    /* bottom : `bottom` rows below the window, middle w columns */
    if (bottom > 0) {
        int ctr = h * 0x10001;
        int end = bottom + ctr;
        int16_t *dp = base + (long long)h * a;
        do {
            int idx = cr_reflect_idx(ctr, h);
            if (w > 0)
                for (int i = 0; i < w; i++)
                    dp[i] = base[(long long)idx * a + i];
            ctr++;
            dp += a;
        } while (end != ctr);
    }

    int16_t *frame_top = base - (long long)a * top;
    int nrows = top + h + bottom;

    /* left : `left` columns left of the window, full frame height */
    if (left > 0) {
        int ctr = w * 0x10000;
        int end = ctr - left;
        int16_t *dp = frame_top;
        do {
            ctr--;
            int idx = cr_reflect_idx(ctr, w);
            if (nrows > 0)
                for (int r = 0; r < nrows; r++)
                    dp[-1 + (long long)r * a] =
                        frame_top[(long long)idx + (long long)r * a];
            dp -= 1;
        } while (ctr != end);
    }

    /* right : `right` columns right of the window, full frame height */
    if (right > 0) {
        int ctr = w * 0x10001;
        int end = right + ctr;
        int16_t *dp = frame_top + w;
        do {
            int idx = cr_reflect_idx(ctr, w);
            if (nrows > 0)
                for (int r = 0; r < nrows; r++)
                    dp[(long long)r * a] =
                        frame_top[(long long)idx + (long long)r * a];
            ctr++;
            dp += 1;
        } while (ctr != end);
    }
}

/* ------------------------------------------------------------------------ *
 * 0x1800342d0 — crop a sub-view then extend its border back (int16 image).
 *   int fn(cr_image *img, int t, int b, int l, int r):
 *     w2 = (img->w - l) - r;  if (w2 < 0) return 0x69;
 *     h2 = (img->h - t) - b;  if (h2 < 0) return 0x69;
 *     cr_image_subview(&local, img, l, t, w2, h2);
 *     cr_image_border_extend_s16(&local, t, b, l, r);
 *     return 0;
 * ------------------------------------------------------------------------ */
int cr_subview_extend_s16(cr_image *img, int t, int b, int l, int r)
{
    int w2 = (img->w - l) - r;
    if (w2 < 0)
        return 0x69;
    int h2 = (img->h - t) - b;
    if (h2 < 0)
        return 0x69;
    cr_image local;
    cr_image_subview(&local, img, l, t, w2, h2);
    cr_image_border_extend_s16(&local, t, b, l, r);
    return 0;
}

/* ------------------------------------------------------------------------ *
 * 0x180037f10 — the byte-image twin: same crop + border-extend, using the
 * 8-bit border extend.
 *   int fn(cr_image *img, int t, int b, int l, int r)
 * ------------------------------------------------------------------------ */
int cr_subview_extend_u8(cr_image *img, int t, int b, int l, int r)
{
    int w2 = (img->w - l) - r;
    if (w2 < 0)
        return 0x69;
    int h2 = (img->h - t) - b;
    if (h2 < 0)
        return 0x69;
    cr_image local;
    cr_image_subview(&local, img, l, t, w2, h2);
    cr_image_border_extend(&local, t, b, l, r);
    return 0;
}

/* ------------------------------------------------------------------------ *
 * Batch 59 — "blit a source image into a sub-window of a container image,
 * then fix up the window border".  All three share the same prologue:
 *   cr_image sub;
 *   cr_image_subview(&sub, dst, left, top, src->w, src->h);
 *   r = cr_copy_u16_shl_guarded(&sub, src, 0);      // guarded dim match
 *   if (r == 0) <border op>(&sub, top, bottom, left, right[, fill]);
 *   return r;
 * The sub-window shares dst's data pointer (only the origin moves), so the
 * border operation writes into dst's buffer.
 * ------------------------------------------------------------------------ */

/* 0x180024fa0 — mirror-extend (BORDER_REFLECT) the placed window. */
uint32_t cr_blit_mirror_s16(cr_image *dst, const cr_image *src,
                            int top, int bottom, int left, int right)
{
    cr_image sub;
    cr_image_subview(&sub, dst, left, top, src->w, src->h);
    uint32_t r = cr_copy_u16_shl_guarded(&sub, src, 0);
    if ((int)r == 0)
        cr_mirror_extend_s16(&sub, top, bottom, left, right);
    return r;
}

/* 0x180046a80 — edge-replicate the placed window's border. */
uint32_t cr_blit_extend_s16(cr_image *dst, const cr_image *src,
                            int top, int bottom, int left, int right)
{
    cr_image sub;
    cr_image_subview(&sub, dst, left, top, src->w, src->h);
    uint32_t r = cr_copy_u16_shl_guarded(&sub, src, 0);
    if ((int)r == 0)
        cr_image_border_extend_s16(&sub, top, bottom, left, right);
    return r;
}

/* 0x18003cf00 — fill the placed window's border with a constant. */
uint32_t cr_blit_fillborder_s16(cr_image *dst, const cr_image *src,
                                int top, int bottom, int left, int right,
                                uint16_t fill)
{
    cr_image sub;
    cr_image_subview(&sub, dst, left, top, src->w, src->h);
    uint32_t r = cr_copy_u16_shl_guarded(&sub, src, 0);
    if ((int)r == 0)
        cr_image_fill_border(&sub, top, bottom, left, right, fill);
    return r;
}
