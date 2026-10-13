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
#include <string.h>

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

/* ======================================================================== *
 *  Batch 48 — object constructors / flag-driven destructors
 * ======================================================================== */

/* ------------------------------------------------------------------------ *
 * 0x18000ee40 — destructor: always sized-free the object at obj+0x28; if the
 * flag byte at obj+0x50 has bit 0 set, also sized-free the one at obj+8.
 *   void fn(void *obj)
 * ------------------------------------------------------------------------ */
void cr_free_obj_28_8(void *obj)
{
    cr_sized_free((void **)((uint8_t *)obj + 0x28));
    if ((*(uint8_t *)((uint8_t *)obj + 0x50) & 1) == 0)
        return;
    cr_sized_free((void **)((uint8_t *)obj + 8));
}

/* ------------------------------------------------------------------------ *
 * 0x1800303d0 — set an int16 metadata key on the debug-class buffer held in
 * slot `idx` of the definition table.
 *   uint8_t fn(const void *defs, uint32_t idx, int key, int value):
 *     p = cr_image_get_dp(defs, idx);
 *     if (!p) return 0x6a;
 *     return cr_meta_put_i16(p, key, value, true) != 0;
 * ------------------------------------------------------------------------ */
uint8_t cr_meta_set_slot(const void *defs, uint32_t idx, int key, int value)
{
    void *p = cr_image_get_dp(defs, idx);
    if (!p)
        return 0x6a;
    return cr_meta_put_i16(p, (uint32_t)key, (uint32_t)value, true) != 0;
}

/* ------------------------------------------------------------------------ *
 * 0x180046b80 — initialise a 0x58-byte object: zero it, clear three 8-byte
 * pointer slots, and set the status word at +0x50 to -1.
 *   uint64_t fn(void *obj)   (always returns 0)
 * ------------------------------------------------------------------------ */
uint64_t cr_obj_init_58(void *obj)
{
    uint8_t *o = (uint8_t *)obj;
    cr_fill(o, 0, 0x58);
    *(uint64_t *)(o + 0x08) = 0;
    *(uint64_t *)(o + 0x28) = 0;
    *(uint64_t *)(o + 0x48) = 0;
    *(uint32_t *)(o + 0x50) = 0xffffffffu;
    return 0;
}

/* ------------------------------------------------------------------------ *
 * 0x18002ad90 — allocate (16-byte aligned, 0x28 bytes) and initialise a small
 * handle object.
 *   void fn(void **out):
 *     if (cr_malloc_aligned16(out, 0x28) != 0) return;
 *     p = *out;
 *     *(u64*)p = 0; *(u32*)(p+8) = 0; *(u8*)(p+0xc) = 0;
 *     *(u64*)(p+0x10) = ~0; *(u64*)(p+0x18) = ~0; *(u32*)(p+0x20) = ~0;
 * ------------------------------------------------------------------------ */
void cr_alloc_handle(void **out)
{
    if (cr_malloc_aligned16(out, 0x28) != 0)
        return;
    uint8_t *p = (uint8_t *)*out;
    *(uint64_t *)p = 0;
    *(uint32_t *)(p + 0x08) = 0;
    *(uint8_t *)(p + 0x0c) = 0;
    *(uint64_t *)(p + 0x10) = ~(uint64_t)0;
    *(uint64_t *)(p + 0x18) = ~(uint64_t)0;
    *(uint32_t *)(p + 0x20) = 0xffffffffu;
}

/* ------------------------------------------------------------------------ *
 * 0x18003fb70 — allocate (16-byte aligned, 0x38 bytes) and initialise an
 * object with a magic field of 400 at +4.
 *   int fn(void **out):
 *     r = cr_malloc_aligned16(out, 0x38);
 *     if (r == 0) { p = *out; cr_fill(p, 0, 0x38);
 *                   *(u32*)(p+4) = 400; *(u64*)(p+8) = 0; }
 *     return r;
 * ------------------------------------------------------------------------ */
int cr_alloc_400(void **out)
{
    int r = cr_malloc_aligned16(out, 0x38);
    if (r == 0) {
        uint8_t *p = (uint8_t *)*out;
        cr_fill(p, 0, 0x38);
        *(uint32_t *)(p + 4) = 400;
        *(uint64_t *)(p + 8) = 0;
    }
    return r;
}

/* ------------------------------------------------------------------------ *
 * 0x18001d820 — initialise a byte-image descriptor and allocate its pixels.
 *   int fn(int *desc, int w, int h):
 *     if (!desc) return 1;
 *     if (w < 0 || h < 0) return 0x69;
 *     desc[4]=w; desc[0]=w; desc[5]=h; desc[1]=h;
 *     desc[6]=0; desc[7]=0; desc[2]=0; desc[3]=0;
 *     if (w*h == 0) return 0;
 *     return cr_malloc_aligned16((void**)(desc+2), (uint32_t)(w*h));
 * ------------------------------------------------------------------------ */
int cr_image_alloc_u8(int *desc, int w, int h)
{
    if (!desc)
        return 1;
    if (w < 0 || h < 0)
        return 0x69;
    desc[4] = w;
    desc[0] = w;
    desc[5] = h;
    desc[1] = h;
    desc[6] = 0;
    desc[7] = 0;
    desc[2] = 0;
    desc[3] = 0;
    if (w * h == 0)
        return 0;
    return cr_malloc_aligned16((void **)(desc + 2), (uint32_t)(w * h));
}

/* ------------------------------------------------------------------------ *
 * 0x18003d790 — int16 twin of the above: pixel size = (long long)w*h*2.
 *   int fn(int *desc, int w, int h)
 * ------------------------------------------------------------------------ */
int cr_image_alloc_s16(int *desc, int w, int h)
{
    if (!desc)
        return 1;
    if (w < 0 || h < 0)
        return 0x69;
    desc[4] = w;
    desc[5] = h;
    desc[0] = w;
    desc[1] = h;
    desc[6] = 0;
    desc[7] = 0;
    desc[2] = 0;
    desc[3] = 0;
    if (w * h == 0)
        return 0;
    return cr_malloc_aligned16((void **)(desc + 2),
                               (size_t)((long long)w * (long long)h * 2));
}

/* ------------------------------------------------------------------------ *
 * 0x18000f570 — flag-driven destructor.  The flag word at +0x74 selects which
 * sub-objects to free; the vendor reloads it after each free (so a helper that
 * touched it would be seen), which the rewrite reproduces verbatim.
 *   void fn(void *obj):
 *     if (!obj) return;
 *     f = *(u32*)(obj+0x74);
 *     if (f & 1)     { cr_cleanup_ptr8_a(obj+0x10); f = *(u32*)(obj+0x74); }
 *     if (f & 2)     { cr_cleanup_ptr8_b(obj+0x50); f = *(u32*)(obj+0x74); }
 *     if (f & 0x100) { cr_sized_free((void**)(obj+0x88)); f = *(u32*)(obj+0x74); }
 *     if (f & 0x200) cr_cleanup_ptr8_clear(obj+0x30);
 * ------------------------------------------------------------------------ */
void cr_free_obj_flags(void *obj)
{
    if (!obj)
        return;
    uint32_t f = *(uint32_t *)((uint8_t *)obj + 0x74);
    if (f & 1) {
        cr_cleanup_ptr8_a((uint8_t *)obj + 0x10);
        f = *(uint32_t *)((uint8_t *)obj + 0x74);
    }
    if (f & 2) {
        cr_cleanup_ptr8_b((uint8_t *)obj + 0x50);
        f = *(uint32_t *)((uint8_t *)obj + 0x74);
    }
    if (f & 0x100) {
        cr_sized_free((void **)((uint8_t *)obj + 0x88));
        f = *(uint32_t *)((uint8_t *)obj + 0x74);
    }
    if (f & 0x200)
        cr_cleanup_ptr8_clear((uint8_t *)obj + 0x30);
}

/* ------------------------------------------------------------------------ *
 * 0x180029750 — initialise a packed-bitmap descriptor and allocate + zero its
 * word buffer.  Row stride is w rounded up to 32; the buffer is r*h dwords
 * (r = ceil(w/32)), all zeroed.
 *   int fn(uint32_t *desc, uint32_t w, uint32_t h)
 * ------------------------------------------------------------------------ */
int cr_bitmap_alloc(uint32_t *desc, uint32_t w, uint32_t h)
{
    if (!desc)
        return 1;
    if ((int32_t)w < 0 || (int32_t)h < 0)
        return 0x69;
    desc[4] = w;
    desc[5] = h;
    desc[1] = h;
    desc[0] = (w + 0x1fu) & 0xffffffe0u;
    int r = (int)(w + 0x1fu) >> 5;
    desc[6] = 0;
    desc[7] = 0;
    desc[2] = 0;
    desc[3] = 0;
    if (h * (uint32_t)r != 0) {
        int s = cr_malloc_aligned16((void **)(desc + 2),
                                    (size_t)((long long)r * (long long)(int32_t)h * 4));
        if (s == 0) {
            if ((desc[0] & 0x1f) == 0) {
                int n = (int)desc[0] * (int)desc[1];
                if (n < 0)
                    n += 0x1f;
                if ((n >> 5) > 0)
                    memset(*(void **)(desc + 2), 0, (size_t)(n >> 5) * 4);
                return 0;
            }
            cr_sized_free((void **)(desc + 2));
            return 0x69;
        }
        return s;
    }
    return 0;
}

/* ======================================================================== *
 *  Batch 49 — higher-level destructors / accessors
 * ======================================================================== */

/* ------------------------------------------------------------------------ *
 * 0x18003d430 — free the eight sized pointers owned by an object, in the
 * vendor's order: +0x00, +0x28, +0x38, +0x08, +0x18, +0x10, +0x48, +0x50.
 *   void fn(void *obj)   (no NULL guard; a NULL slot is a free no-op)
 * ------------------------------------------------------------------------ */
void cr_free_8slot(void *obj)
{
    cr_sized_free((void **)((uint8_t *)obj + 0x00));
    cr_sized_free((void **)((uint8_t *)obj + 0x28));
    cr_sized_free((void **)((uint8_t *)obj + 0x38));
    cr_sized_free((void **)((uint8_t *)obj + 0x08));
    cr_sized_free((void **)((uint8_t *)obj + 0x18));
    cr_sized_free((void **)((uint8_t *)obj + 0x10));
    cr_sized_free((void **)((uint8_t *)obj + 0x48));
    cr_sized_free((void **)((uint8_t *)obj + 0x50));
}

/* ------------------------------------------------------------------------ *
 * 0x180035740 — allocate (16-byte aligned, 0x58 bytes) and initialise an
 * object; on any post-allocation failure free it again.
 *   int fn(void **out):
 *     if (!out) return 1;
 *     i = cr_malloc_aligned16(out, 0x58);
 *     if (i == 0) {
 *         if (*out == NULL) i = 1;
 *         else { i = cr_obj_init_58(*out); if (i == 0) return 0; }
 *         cr_sized_free(out);
 *     }
 *     return i;
 *   (cr_obj_init_58 always returns 0, so the failure branch is defensive.)
 * ------------------------------------------------------------------------ */
int cr_alloc_obj_58(void **out)
{
    if (!out)
        return 1;
    int i = cr_malloc_aligned16(out, 0x58);
    if (i == 0) {
        if (*out == NULL) {
            i = 1;
        } else {
            i = (int)cr_obj_init_58(*out);
            if (i == 0)
                return 0;
        }
        cr_sized_free(out);
    }
    return i;
}

/* ------------------------------------------------------------------------ *
 * 0x18003a8d0 — read an int16 metadata key from the debug-class buffer held in
 * slot `idx` of the definition table.
 *   uint8_t fn(const void *defs, uint32_t idx, int key, uint32_t *out):
 *     p = cr_image_get_dp(defs, idx);
 *     if (!p) return 0x6a;
 *     return cr_meta_get_u32(p, key, out) != 0;
 * ------------------------------------------------------------------------ */
uint8_t cr_meta_get_slot(const void *defs, uint32_t idx, int key, uint32_t *out)
{
    void *p = cr_image_get_dp(defs, idx);
    if (!p)
        return 0x6a;
    return cr_meta_get_u32(p, (uint32_t)key, out) != 0;
}
