/*
 * fpc_alloc.c — clean-room reimplementation of the small allocator wrappers
 * in the reachable BEP tree of fpc_enclave.dll.  See MAP.md.
 *
 * These are thin wrappers around the platform allocator; the vendor versions
 * call the DLL's internal CRT malloc/free (0x18006afa0 / 0x180069b60).  The
 * clean-room versions use the C library allocator.  Only the *observable
 * contract* (status codes, null-ing) is compared by the differential test —
 * the raw pointer values necessarily differ between the two allocators.
 */
#include "fpc_bep.h"
#include <stdlib.h>
#include <string.h>

/* Mirror of the shim's SHIM_HEAD (native/win32_shims.c): every block is
 * preceded by CR_HEAD zeroed bytes so that vendor routines which read a few
 * dozen bytes *before* an allocation (e.g. the streaming vertical-FIR mirror
 * branch's negative ring index) observe the same zeros as the vendor side. */
#define CR_HEAD 4096

/* ------------------------------------------------------------------------ *
 * 0x180002fe0 — malloc wrapper.
 *   int fn(void **out, size_t size):
 *     size == 0 -> *out = NULL, return 1
 *     else      -> *out = malloc(size), return (ptr == NULL)
 * ------------------------------------------------------------------------ */
int cr_malloc(void **out, size_t size)
{
    if (size == 0) {
        *out = NULL;
        return 1;
    }
    void *raw = malloc(CR_HEAD + size);
    if (!raw) {
        *out = NULL;
        return 1;
    }
    memset(raw, 0, CR_HEAD + size);
    *out = (char *)raw + CR_HEAD;
    return 0;
}

/* ------------------------------------------------------------------------ *
 * 0x180002fb0 — free wrapper.
 *   void fn(void **p): if (*p) { free(*p); *p = NULL; }
 * ------------------------------------------------------------------------ */
void cr_free(void **p)
{
    void *q = *p;
    if (q) {
        free((char *)q - CR_HEAD);
        *p = NULL;
    }
}

/* ------------------------------------------------------------------------ *
 * 0x18003bf40 — "sized free": the object carries a 1-byte offset immediately
 * before the pointer; the real allocation base is `*p - *((uint8_t*)*p - 1)`.
 *   void fn(void **p): if (*p) { base = *p - *(byte*)(*p-1);
 *                                free_wrapper(&base); *p = NULL; }
 * ------------------------------------------------------------------------ */
void cr_sized_free(void **p)
{
    void *q = *p;
    if (q) {
        uint8_t  sz   = *((uint8_t *)q - 1);
        void    *base = (uint8_t *)q - sz;
        cr_free(&base);
        *p = NULL;
    }
}

/* ------------------------------------------------------------------------ *
 * 0x18001f080 — allocate a zeroed bit vector of `n` bits: ceil(n/8) bytes via
 * the 16-byte-aligned allocator, then zeroed.
 *   int fn(void **out, int n):
 *     if (n < 1) { *out = NULL; return 0; }
 *     r = cr_malloc_aligned16(out, ((uint32_t)(n + 7) & ~7u) >> 3);
 *     if (r == 0) { zero ((uint32_t)(n + 7)) >> 3 bytes at *out; }
 *     return r;
 * ------------------------------------------------------------------------ */
int cr_bit_alloc(void **out, int n)
{
    if (n < 1) {
        *out = NULL;
        return 0;
    }
    int r = cr_malloc_aligned16(out, (size_t)(((uint32_t)(n + 7) & 0xfffffff8u) >> 3));
    if (r == 0) {
        int cnt = (int)((uint32_t)(n + 7) >> 3);
        uint8_t *p = (uint8_t *)*out;
        for (int i = 0; i < cnt; i++)
            p[i] = 0;
    }
    return r;
}

/* ------------------------------------------------------------------------ *
 * batch 55 — pool wrappers (0x180044230/0x180047e30/0x180010f40/0x18001b9e0/
 * 0x18001d480).  Each builds a contiguous pool of N 16-aligned sub-blocks via
 * cr_pool_builder and, only on success (return 0), copies the N block pointers
 * out to the caller's out-parameters.  The sizes are passed as separate u32
 * arguments, collected into an array in argument order.
 * ------------------------------------------------------------------------ */
int cr_pool_alloc1(void **hdr, void **out0, uint32_t s0)
{
    uint32_t sizes[1] = { s0 };
    void *ptrs[1];
    int rc = cr_pool_builder(hdr, ptrs, 1, sizes);
    if (rc == 0)
        *out0 = ptrs[0];
    return rc;
}

int cr_pool_alloc2(void **hdr, void **out0, uint32_t s0,
                   void **out1, uint32_t s1)
{
    uint32_t sizes[2] = { s0, s1 };
    void *ptrs[2];
    int rc = cr_pool_builder(hdr, ptrs, 2, sizes);
    if (rc == 0) {
        *out0 = ptrs[0];
        *out1 = ptrs[1];
    }
    return rc;
}

int cr_pool_alloc3(void **hdr, void **out0, uint32_t s0,
                   void **out1, uint32_t s1,
                   void **out2, uint32_t s2)
{
    uint32_t sizes[3] = { s0, s1, s2 };
    void *ptrs[3];
    int rc = cr_pool_builder(hdr, ptrs, 3, sizes);
    if (rc == 0) {
        *out0 = ptrs[0];
        *out1 = ptrs[1];
        *out2 = ptrs[2];
    }
    return rc;
}

int cr_pool_alloc4(void **hdr, void **out0, uint32_t s0,
                   void **out1, uint32_t s1,
                   void **out2, uint32_t s2,
                   void **out3, uint32_t s3)
{
    uint32_t sizes[4] = { s0, s1, s2, s3 };
    void *ptrs[4];
    int rc = cr_pool_builder(hdr, ptrs, 4, sizes);
    if (rc == 0) {
        *out0 = ptrs[0];
        *out1 = ptrs[1];
        *out2 = ptrs[2];
        *out3 = ptrs[3];
    }
    return rc;
}

int cr_pool_alloc5(void **hdr, void **out0, uint32_t s0,
                   void **out1, uint32_t s1,
                   void **out2, uint32_t s2,
                   void **out3, uint32_t s3,
                   void **out4, uint32_t s4)
{
    uint32_t sizes[5] = { s0, s1, s2, s3, s4 };
    void *ptrs[5];
    int rc = cr_pool_builder(hdr, ptrs, 5, sizes);
    if (rc == 0) {
        *out0 = ptrs[0];
        *out1 = ptrs[1];
        *out2 = ptrs[2];
        *out3 = ptrs[3];
        *out4 = ptrs[4];
    }
    return rc;
}
