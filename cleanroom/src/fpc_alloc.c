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
    void *p = malloc(size);
    *out = p;
    return p == NULL ? 1 : 0;
}

/* ------------------------------------------------------------------------ *
 * 0x180002fb0 — free wrapper.
 *   void fn(void **p): if (*p) { free(*p); *p = NULL; }
 * ------------------------------------------------------------------------ */
void cr_free(void **p)
{
    void *q = *p;
    if (q) {
        free(q);
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
