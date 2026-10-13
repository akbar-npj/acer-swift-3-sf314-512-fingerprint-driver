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
