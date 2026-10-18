/*
 * fpc_desc.c — small descriptor / table-pointer getter leaves.
 *
 * These functions dispatch on a byte selector to populate a descriptor struct
 * with a static table pointer + size from the vendor's read-only data section.
 * The cleanroom library does not contain the vendor's data tables, so the
 * pointer stores are zeroed (the scalar fields, byte markers and u64 tags are
 * reproduced exactly).  The difftest compares status codes and scalar fields;
 * pointer slots are compared for nullness only.
 *
 * One exception: the sel-6 table at 0x1801174e0 is a plain 128-entry int16
 * coefficient block (a 64-tap 8x8 kernel), not trained-model state, so it is
 * embedded verbatim below and the getter hands out its address.
 */

#include "fpc_bep.h"

/* 0x1801174e0 — 0x100-byte coefficient block returned by selector 6. */
static const int16_t cr_tab_1174e0[128] = {
      4740,  -3087,   2594,   1077,    182,   1086,   1124,    707,
       397,   1775,    900,  -1691,   4801,   2013, -13967,  29921,
    -28547,  15340,   -660,  -3402,   3072,    378,   -282,   1038,
       229,    770,    652,   -845,   2526,   1134,  -7308,  15792,
    -14982,   8125,   -303,  -1747,   1664,    249,   -111,    593,
       190,    412,    386,   -287,   1206,    593,  -3159,   7102,
     -6569,   3698,    -47,   -692,    831,    201,     21,    369,
       189,    192,    338,     50,    257,    685,   -802,   1228,
      2743,  -1791,   1531,    575,    112,    755,    428,    421,
       825,     46,    450,   1854,  -1546,   -100,   8249, -14665,
     15866,  -7053,   1277,   2778,   -654,    645,   1307,    404,
       296,   1447,    682,  -1178,   3570,   1517, -10079,  21788,
    -20661,  11198,   -413,  -2409,   2294,    345,   -153,    817,
       262,    569,    533,   -396,   1663,    818,  -4357,   9796,
     -9060,   5100,    -65,   -955,   1146,    277,     29,    510,
       260,    264,    466,     69,    355,    946,  -1106,   1694,
};

/* 0x18002aeb0 — single pointer getter, selector 4. */
uint64_t cr_desc_get_ptr1(void *p, char sel)
{
    void **q = (void **)p;
    *q = NULL;
    if (sel == 4)
        return 0;
    return 1;
}

/* 0x180012f30 — pointer + size getter, selector 6; sel 0 returns 0 too. */
uint64_t cr_desc_get_ptr_size(void *p1, uint32_t *p2, char sel)
{
    void **q1 = (void **)p1;
    *q1 = NULL;
    *p2 = 0;
    if (sel == 0)
        return 0;
    if (sel == 6) {
        *q1 = (void *)cr_tab_1174e0;      /* 0x1801174e0 */
        *p2 = 0x100;
        return 0;
    }
    return 1;
}

/* 0x180020860 — two-selector pointer getter. */
uint64_t cr_desc_get_ptr2(void *p, char sel)
{
    void **q = (void **)p;
    *q = NULL;
    if (sel == 12 || sel == 13)
        return 0;
    return 1;
}

/* 0x18002dab0 — tag + pointer getter, selector 0, NULL-guarded. */
uint64_t cr_desc_get_tag_ptr(void *p, char sel)
{
    if (p == NULL)
        return 1;
    uint64_t *q = (uint64_t *)p;
    q[0] = 0;
    q[1] = 0;
    if (sel == 0) {
        q[0] = 0x1f500000009ULL;
        return 0;
    }
    return 1;
}

/* 0x1800448f0 — two-selector pointer getter (returns 0x69 on unknown). */
uint64_t cr_desc_get_ptr2_69(void *p, char sel)
{
    void **q = (void **)p;
    *q = NULL;
    if (sel == 0 || sel == 1)
        return 0;
    return 0x69;
}

/* 0x180018e50 — pointer + two int getters, selectors 0 and 1. */
uint64_t cr_desc_get_ptr_ints(void *p1, uint32_t *p2, uint32_t *p3, char sel)
{
    void **q1 = (void **)p1;
    if (sel == 0 || sel == 1) {
        *q1 = NULL;
        *p3 = 9;
        *p2 = 9;
        return 0;
    }
    *q1 = NULL;
    return 1;
}

/* 0x180017960 — pointer + size, selectors 15 and 16; sel 0 returns 0, rest 0x69. */
uint8_t cr_desc_get_ptr_size_69(void *p1, uint32_t *p2, char sel)
{
    void **q1 = (void **)p1;
    *q1 = NULL;
    *p2 = 0;
    if (sel == 15) {
        *p2 = 0x620;
        return 0;
    }
    if (sel == 16) {
        *p2 = 0x100;
        return 0;
    }
    /* ~( -(sel==0) ) & 0x69  =>  sel==0 ? 0 : 0x69 */
    return (sel == 0) ? 0 : 0x69;
}

/* 0x180028de0 — tag + byte + pointer, selectors 2 and 4, NULL-guarded. */
uint64_t cr_desc_get_tag_byte_ptr(void *p, char sel)
{
    if (p == NULL)
        return 1;
    uint64_t *q = (uint64_t *)p;
    ((uint8_t *)p)[8] = 0;
    q[0] = 0;
    q[2] = 0;
    q[3] = 0;
    if (sel == 2) {
        ((uint8_t *)p)[8] = 0x10;
        q[0] = 0x1000000019ULL;
        return 0;
    }
    if (sel == 4) {
        ((uint8_t *)p)[8] = 4;
        q[0] = 0x1000000019ULL;
        return 0;
    }
    return 1;
}

/* 0x18002d4e0 — three-qword descriptor, selectors 0 and 5, range [0,5]. */
uint64_t cr_desc_get_triple(void *p, uint8_t sel)
{
    if (sel >= 6)
        return 0x69;
    if (p == NULL)
        return 1;
    uint64_t *q = (uint64_t *)p;
    q[0] = 0;
    q[1] = 0;
    q[2] = 0;
    if (sel == 0)
        return 0;
    if (sel == 5) {
        q[0] = 0x2000000010ULL;
        return 0;
    }
    return 1;
}

/* ------------------------------------------------------------------------ *
 * 0x180027730 — clamp a requested (w,h) to the descriptor's minimum and round
 * each up to the next power of two.
 *   uint32_t fn(uint32_t *out_w, uint32_t *out_h, uint32_t w, uint32_t h,
 *               const void *cfg):
 *     uint64_t tmp[2] = {0,0}; uint32_t lo, hi;
 *     r = cr_desc_get_ptr_ints(tmp, &lo, &hi, *(char*)(cfg+4));
 *     if ((int)r == 0) {
 *         if ((int)w <= (int)lo) w = lo;
 *         k = cr_hi_bit_index(w);
 *         if ((1u << (k&31)) != w) w = 1u << ((k+1)&31);
 *         if ((int)h <= (int)hi) h = hi;
 *         *out_w = w;
 *         k = cr_hi_bit_index(h);
 *         if ((1u << (k&31)) != h) h = 1u << ((k+1)&31);
 *         *out_h = h;
 *     }
 *     return (uint32_t)r;
 * ------------------------------------------------------------------------ */
uint32_t cr_round_dims_pow2(uint32_t *out_w, uint32_t *out_h,
                            uint32_t w, uint32_t h, const void *cfg)
{
    uint64_t tmp[2] = { 0, 0 };
    uint32_t lo, hi;
    uint64_t r = cr_desc_get_ptr_ints(tmp, &lo, &hi, *((const char *)cfg + 4));
    if ((int32_t)r == 0) {
        if ((int32_t)w <= (int32_t)lo)
            w = lo;
        int k = cr_hi_bit_index(w);
        if ((1u << (k & 0x1f)) != w)
            w = 1u << ((k + 1) & 0x1f);
        if ((int32_t)h <= (int32_t)hi)
            h = hi;
        *out_w = w;
        k = cr_hi_bit_index(h);
        if ((1u << (k & 0x1f)) != h)
            h = 1u << ((k + 1) & 0x1f);
        *out_h = h;
    }
    return (uint32_t)r;
}

/* ------------------------------------------------------------------------ *
 * 0x180020770 — fill a u16 image from a pointer-array slot descriptor.
 *   int fn(void **arr, int idx, uint8_t shift, cr_image *dst):
 *     d = arr[idx];
 *     if (d == NULL) return 0x69;
 *     if (d->w != dst->w || d->h != dst->h) return 0x69;
 *     if (d->type == 0x10) {                      // u16 source
 *       cr_copy(dst->data, d->src, d->w * d->h * 2);
 *       out = 0; r = cr_meta_get_u32(arr[idx + 7], 0x148, &out);
 *       e = (r == 0) ? (int)out - 8 : 4;          // miss forces out := 0xc
 *       return cr_copy_u16_shl_guarded(dst, dst, (uint8_t)(shift - e));
 *     }
 *     if (d->type == 8) {                         // u8 source -> u16
 *       if (d->w * d->h > 0)
 *         for (i = 0; i < d->w * d->h; i++)
 *           ((uint16_t *)dst->data)[i] =
 *               (uint16_t)(((const uint8_t *)d->src)[i] << (shift & 0x1f));
 *       return 0;
 *     }
 *     return 0x69;
 * ------------------------------------------------------------------------ */
int cr_image_fill_desc(void **arr, int idx, uint8_t shift, cr_image *dst)
{
    cr_slot_desc *d = (cr_slot_desc *)arr[idx];

    if (d == NULL)
        return 0x69;

    int w = (int)d->w;
    int h = (int)d->h;

    if (w != dst->w || h != dst->h)
        return 0x69;

    if (d->type == 0x10) {
        cr_copy(dst->data, d->src, w * h * 2);

        uint32_t out = 0;
        int r = cr_meta_get_u32(arr[idx + 7], 0x148u, &out);
        int e;
        if (r == 0) {
            e = (int)out - 8;
        } else {
            out = 0xc;
            e = 4;
        }
        return cr_copy_u16_shl_guarded(dst, dst, (uint8_t)(shift - e));
    }

    if (d->type == 8) {
        if (w * h > 0) {
            const uint8_t *s = (const uint8_t *)d->src;
            uint16_t *o = (uint16_t *)dst->data;
            for (int i = 0; i < w * h; i++)
                o[i] = (uint16_t)(s[i] << (shift & 0x1f));
        }
        return 0;
    }

    return 0x69;
}
