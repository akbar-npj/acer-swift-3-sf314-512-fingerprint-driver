/*
 * fpc_tree.c — clean-room reimplementation of the BEP object-tree lifecycle
 * helpers and image-data accessors in the reachable tree of fpc_enclave.dll.
 *
 * These operate on the vendor's heap objects (which carry a 1-byte size prefix
 * consumed by cr_sized_free) and on the image-definition table.  The raw
 * pointer values necessarily differ from the vendor's, so the differential
 * test compares the observable contract: guard behaviour, NULL-ing, and the
 * scalar fields written into caller-owned structs.  See MAP.md.
 */
#include "fpc_bep.h"

/* ------------------------------------------------------------------------ *
 * 0x18004b640 — int16 metadata put.
 *   Assembly is just `MOVZX R9D, R9B ; JMP 0x18004b670`: the overwrite flag is
 *   zero-extended and the call tail-jumps into the uint16 store.  Semantically
 *   identical to cr_meta_put_u32.
 *     int fn(void *store, u32 key, u32 value, bool overwrite)
 * ------------------------------------------------------------------------ */
int cr_meta_put_i16(void *store, uint32_t key, uint32_t value, bool overwrite)
{
    return cr_meta_put_u32(store, key, value, overwrite);
}

/* ------------------------------------------------------------------------ *
 * 0x18000fc20 — free the sized object held at obj+8, if present.
 *   void fn(void *obj):
 *     if (obj && *(void**)(obj+8)) cr_sized_free((void**)(obj+8));
 * 0x180011a50 is a byte-identical duplicate of this function.
 * ------------------------------------------------------------------------ */
void cr_cleanup_ptr8_a(void *obj)
{
    if (obj && *(void **)((uint8_t *)obj + 8))
        cr_sized_free((void **)((uint8_t *)obj + 8));
}

void cr_cleanup_ptr8_b(void *obj)
{
    if (obj && *(void **)((uint8_t *)obj + 8))
        cr_sized_free((void **)((uint8_t *)obj + 8));
}

/* ------------------------------------------------------------------------ *
 * 0x180024760 — free and clear the sized object held at obj+8.
 *   void fn(void *obj):
 *     if (obj) { if (*(void**)(obj+8)) cr_sized_free((void**)(obj+8));
 *                *(void**)(obj+8) = NULL; }
 * ------------------------------------------------------------------------ */
void cr_cleanup_ptr8_clear(void *obj)
{
    if (obj) {
        if (*(void **)((uint8_t *)obj + 8))
            cr_sized_free((void **)((uint8_t *)obj + 8));
        *(void **)((uint8_t *)obj + 8) = NULL;
    }
}

/* ------------------------------------------------------------------------ *
 * 0x18001f9f0 — zero the first 12 bytes of the payload *obj, then sized-free
 * it and NULL the slot.
 *   void fn(void **obj):
 *     p = *obj;
 *     if (p) { *(u64*)p = 0; *(u32*)((u8*)p + 8) = 0; cr_sized_free(obj); }
 * ------------------------------------------------------------------------ */
void cr_obj_zero_free(void **obj)
{
    uint8_t *p = (uint8_t *)*obj;
    if (p) {
        *(uint64_t *)p = 0;
        *(uint32_t *)(p + 8) = 0;
        cr_sized_free(obj);
    }
}

/* ------------------------------------------------------------------------ *
 * 0x180017170 — destroy an object that owns eight sized pointers: six
 * consecutive at +0x00..+0x28, then one at +0x30 and one at +0x70.
 *   void fn(void *obj)
 * ------------------------------------------------------------------------ */
void cr_free_ptr_struct(void *obj)
{
    if (!obj)
        return;
    for (int i = 0; i < 6; i++)
        cr_sized_free((void **)((uint8_t *)obj + 8 * i));
    cr_sized_free((void **)((uint8_t *)obj + 0x30));
    cr_sized_free((void **)((uint8_t *)obj + 0x70));
}

/* ------------------------------------------------------------------------ *
 * 0x1800100c0 — 16-byte-aligned sized malloc.
 *   int fn(void **out, size_t size):
 *     if (cr_malloc(&base, size + 0x10)) return 2;      // failure / size 0
 *     n = 0x10 - ((uintptr_t)base & 0xf);
 *     ((u8*)base)[n - 1] = (u8)n;                       // size prefix
 *     *out = (u8*)base + n;                             // 16-byte aligned
 *     return 0;
 *   The returned block is released with cr_sized_free.  Note n is in 1..16,
 *   so the stored prefix byte is never 0 (it would alias "unallocated").
 * ------------------------------------------------------------------------ */
int cr_malloc_aligned16(void **out, size_t size)
{
    void *base = NULL;
    if (cr_malloc(&base, size + 0x10))
        return 2;
    int n = 0x10 - (int)((uintptr_t)base & 0xf);
    ((uint8_t *)base)[n - 1] = (uint8_t)n;
    *out = (uint8_t *)base + n;
    return 0;
}

/* ------------------------------------------------------------------------ *
 * 0x18004a890 — fpc_image_data_get_dp_buffer: fetch slot `idx` (0..0x15) from
 * the definition table at defs+0x10 and return it only if it is a debug-class
 * buffer.
 *   void *fn(const void *defs, u32 idx)
 * ------------------------------------------------------------------------ */
void *cr_image_get_dp(const void *defs, uint32_t idx)
{
    if (defs && idx < 0x16) {
        void *p = *(void **)((const uint8_t *)defs + 0x10 + (uint64_t)idx * 8);
        if ((char)cr_buf_is_debug_class(p))
            return p;
    }
    return NULL;
}

/* ------------------------------------------------------------------------ *
 * 0x18004ab90 — fpc_image_data_init_buffers: fill an output descriptor from
 * the pixels buffer found at ctx+0x18.
 *   void fn(const void *ctx, void *out):
 *     p = ctx ? *(u8**)(ctx + 0x18) : NULL;
 *     if (p && cr_buf_is_pixels(p)) {
 *         out[0x00] (i16) = (i16)*(u32*)(p + 0x0c);
 *         out[0x08] (ptr) = p + 0x10;
 *         out[0x10] (i16) = (i16)(*(u32*)(p + 0x04) >> 1);
 *         out[0x14] (i32) = 1;
 *     } else {
 *         out[0x00] (i16) = 0; out[0x08] (ptr) = NULL;
 *         out[0x10] (i16) = 0; out[0x14] (i32) = 1;
 *     }
 * ------------------------------------------------------------------------ */
void cr_image_buf_desc(const void *ctx, void *out)
{
    uint8_t *o = (uint8_t *)out;

    if (ctx) {
        uint8_t *p = *(uint8_t **)((const uint8_t *)ctx + 0x18);
        if (p && cr_buf_is_pixels(p)) {
            *(uint16_t *)(o + 0x00) = (uint16_t)*(uint32_t *)(p + 0x0c);
            *(void **)(o + 0x08)    = p + 0x10;
            *(uint16_t *)(o + 0x10) = (uint16_t)(*(uint32_t *)(p + 0x04) >> 1);
            *(uint32_t *)(o + 0x14) = 1;
            return;
        }
    }
    *(uint16_t *)(o + 0x00) = 0;
    *(void **)(o + 0x08)    = NULL;
    *(uint16_t *)(o + 0x10) = 0;
    *(uint32_t *)(o + 0x14) = 1;
}
