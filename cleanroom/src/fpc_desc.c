/*
 * fpc_desc.c — small descriptor / table-pointer getter leaves.
 *
 * These functions dispatch on a byte selector to populate a descriptor struct
 * with a static table pointer + size from the vendor's read-only data section.
 * The cleanroom library does not contain the vendor's data tables, so the
 * pointer stores are zeroed (the scalar fields, byte markers and u64 tags are
 * reproduced exactly).  The difftest compares status codes and scalar fields;
 * pointer slots are not compared.
 */

#include "fpc_bep.h"

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
