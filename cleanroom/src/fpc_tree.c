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

/* ------------------------------------------------------------------------ *
 * 0x180017ca0 — build an image/scan object graph from a source descriptor.
 *   int fn(void *p1, void *p2, int mode):   rcx=p1, rdx=p2, r8d=mode
 *
 * p2 layout (source):  +0x00 i32 tag, +0x10 cr_image src (a,b,data@+0x18,
 * w@+0x20, h@+0x24, offx@+0x28, offy@+0x2c), +0x50 cr_image bmp-src,
 * +0x78 i32, +0x80 i16 n, +0x88 ptr i16 array.
 * p1 layout (dest): +0x00 cr_image #1, +0x20 cr_image #2 (packed bitmap),
 * +0x40 i32, +0x44 i16, +0x48 ptr (0x60 helper), +0x50 i32.
 *
 * Allocates the 0x60 helper at p1+0x48; clears p1's #1 data ptr (+8) and #2
 * data ptr (+0x28) and sets +0x44 = -1.  mode==1 binds p1's #1 image to the
 * p2+0x18 buffer via cr_image_set and blanks the p2+0x10 descriptor; otherwise
 * allocates p1's #1 image (u8, w=p2[0x20], h=p2[0x24]) and copies p2+0x10 into
 * it.  Always allocates the packed bitmap at p1+0x20 and extracts p2+0x50 into
 * it.  If n = (i16)p2[0x80] > 0, allocates 2n bytes under the helper (+0x48)
 * and copies n int16 from p2[0x88].  Stores (u16)p2[0] at p1+0x44 and p2[0x78]
 * at p1+0x40.  Returns 0, or the first callee error.
 * ------------------------------------------------------------------------ */
int cr_obj_init_17ca0(void *a1, void *a2, int mode)
{
    uint8_t *p1 = (uint8_t *)a1, *p2 = (uint8_t *)a2;
    int w = *(int *)(p2 + 0x20);
    int h = *(int *)(p2 + 0x24);
    int r = cr_alloc_60_init((void **)(p1 + 0x48));
    if (r != 0)
        return r;

    *(void **)(p1 + 8) = NULL;
    *(int16_t *)(p1 + 0x44) = (int16_t)-1;
    *(void **)(p1 + 0x28) = NULL;

    if (mode == 1) {
        r = (int)cr_image_set((cr_image *)p1, *(void **)(p2 + 0x18), w, h);
        if (r != 0)
            return r;
        r = (int)cr_image_set((cr_image *)(p2 + 0x10), NULL, 0, 0);
        if (r != 0)
            return r;
        *(int *)(p1 + 0x50) = -2;
    } else {
        r = cr_image_alloc_u8((int *)p1, w, h);
        if (r != 0)
            return r;
        r = (int)cr_image_copy_u8((cr_image *)p1,
                                  (const cr_image *)(p2 + 0x10));
        if (r != 0)
            return r;
    }

    r = cr_bitmap_alloc((uint32_t *)(p1 + 0x20), (uint32_t)w, (uint32_t)h);
    if (r != 0)
        return r;
    r = cr_bitmap_extract_shift((cr_image *)(p1 + 0x20),
                                (const cr_image *)(p2 + 0x50));
    if (r != 0)
        return r;

    int16_t n = *(int16_t *)(p2 + 0x80);
    if (n > 0) {
        uint8_t *obj = *(uint8_t **)(p1 + 0x48);
        r = cr_malloc_aligned16((void **)(obj + 0x48), (size_t)(2 * n));
        if (r != 0)
            return r;
        *(int16_t *)(obj + 0x40) = n;
        const int16_t *src = *(const int16_t **)(p2 + 0x88);
        int16_t       *dst = *(int16_t **)(obj + 0x48);
        for (int i = 0; i < n; i++)
            dst[i] = src[i];
    }
    *(int16_t *)(p1 + 0x44) = *(int16_t *)(p2 + 0x00);
    *(int *)(p1 + 0x40) = *(int *)(p2 + 0x78);
    return 0;
}

/* ------------------------------------------------------------------------ *
 * 0x180012fe0 — object constructor (bind-or-allocate image + bitmap + count).
 *   int fn(void *a1, void *a2, void *a3)
 *
 * a2 (source image descriptor): +0x00 i16 w, +0x02 i16 h, +0x10 void *pixels.
 * a3 (config): +0x08 -> {i16 w@+0xc, i16 h@+0xe}, +0x10 -> {u8 flag@+0x3d},
 * +0x28 -> {i16 count@+0x20}.
 * a1 (dest, >= 0x90 bytes): +0x10 u8 cr_image, +0x30 s16 cr_image,
 * +0x50 packed bitmap, +0x74 u32 free-flag, +0x80 i16 count, +0x88 ptr.
 *
 * Zeroes a1 (0x90 bytes) plus the four pointer slots, then:
 *   a2 == NULL          -> allocate the u8 image (w,h from a3+8) and blank it,
 *                          free-flag = -1
 *   a2->pixels == NULL  -> return 1
 *   a2->w/h != a3+8 w/h -> return 0x69
 *   else                -> bind a1+0x10 to a2->pixels, free-flag = -2
 * then always allocates the packed bitmap (w,h from a3+8).  If the count at
 * a3+0x28 is > 0, allocates 2*count zeroed bytes at a1+0x88 and stores the
 * count at a1+0x80.  If a3+0x10's byte at +0x3d is non-zero, allocates and
 * blanks the s16 image at a1+0x30.  Any post-allocation failure runs
 * cr_free_obj_flags(a1) and returns the error; success returns 0.
 * ------------------------------------------------------------------------ */
int cr_obj_init_12fe0(void *a1, void *a2, void *a3)
{
    uint8_t       *o = (uint8_t *)a1;
    const uint8_t *c = (const uint8_t *)a3;
    const uint8_t *q = *(const uint8_t *const *)(c + 8);

    cr_fill(o, 0, 0x90);
    *(void **)(o + 0x58) = NULL;
    *(void **)(o + 0x18) = NULL;
    *(void **)(o + 0x88) = NULL;
    *(void **)(o + 0x38) = NULL;

    int edi;
    if (a2 == NULL) {
        edi = (int)cr_image_alloc_u8((int *)(o + 0x10),
                                     *(const int16_t *)(q + 0xc),
                                     *(const int16_t *)(q + 0xe));
        if (edi != 0)
            return edi;
        cr_rect_fill_u8((cr_image *)(o + 0x10), 0);
        *(uint32_t *)(o + 0x74) = 0xffffffffu;
    } else {
        const uint8_t *s   = (const uint8_t *)a2;
        const uint8_t *pix = *(const uint8_t *const *)(s + 0x10);
        if (pix == NULL)
            return 1;
        if (*(const int16_t *)(s + 0) != *(const int16_t *)(q + 0xc))
            return 0x69;
        if (*(const int16_t *)(s + 2) != *(const int16_t *)(q + 0xe))
            return 0x69;
        edi = (int)cr_image_set((cr_image *)(o + 0x10), (void *)pix,
                                *(const int16_t *)(s + 0),
                                *(const int16_t *)(s + 2));
        if (edi != 0)
            return edi;
        *(uint32_t *)(o + 0x74) = 0xfffffffeu;
    }

    edi = cr_bitmap_alloc((uint32_t *)(o + 0x50),
                          (uint32_t)*(const int16_t *)(q + 0xc),
                          (uint32_t)*(const int16_t *)(q + 0xe));
    if (edi != 0)
        goto fail;

    {
        const uint8_t *r = *(const uint8_t *const *)(c + 0x28);
        int ax = *(const int16_t *)(r + 0x20);
        if (ax > 0) {
            edi = cr_malloc_aligned16((void **)(o + 0x88), (size_t)(2 * ax));
            if (edi != 0)
                goto fail;
            *(int16_t *)(o + 0x80) = (int16_t)ax;
            cr_fill(*(void **)(o + 0x88), 0, 2 * ax);
        }
    }

    {
        const uint8_t *s2 = *(const uint8_t *const *)(c + 0x10);
        if (*(const uint8_t *)(s2 + 0x3d) == 0)
            return 0;
        edi = cr_image_alloc_s16((int *)(o + 0x30),
                                 *(const int16_t *)(q + 0xc),
                                 *(const int16_t *)(q + 0xe));
        if (edi != 0)
            goto fail;
        cr_rect_fill_u16((cr_image *)(o + 0x30), 0);
    }
    return 0;

fail:
    cr_free_obj_flags(o);
    return edi;
}

/* ------------------------------------------------------------------------ *
 * 0x180013340 — image-set descriptor constructor. Fills the 128-byte
 * (16-qword) descriptor at `out` from the definition table `defs`.
 *   uint32_t fn(const void *defs, void *out, int flag)
 *
 * Returns 0x69 if `out` is NULL. Zeroes all 16 qwords, then walks the five
 * "even debug" slots 0xc,0xe,0x10,0x12,0x14 (step 2 while != 0x16): for each
 * non-empty slot it allocates a 0x38-byte block into out[i], dumps the slot
 * into it (a dump failure returns 0x6a) and stores dp(slot+1) into out[i+7],
 * then advances i.
 *
 * If `flag` and out[0] are non-zero, the pixel buffers for slots 8 and 10 are
 * set up (each when defined-but-empty) using the i16 rows/cols in out[0]'s
 * descriptor; a non-zero setup status is returned.
 *
 * Finally: if slot 8 is non-empty, alloc out[5] (0x38), dump slot 8 and set
 * out[0xc] = dp(9); if slot 10 is non-empty, alloc out[6] (0x38), dump slot 10
 * and set out[0xd] = dp(0xb). Always out[0xf] = dp(0); if slot 1 is non-empty,
 * alloc out[0xe] (0x18) and fill its buffer descriptor. Returns 0x69 when
 * out[0] ended up NULL, else 0.
 * ------------------------------------------------------------------------ */
uint32_t cr_obj_init_13340(const void *defs, void *out, int flag)
{
    if (out == NULL)
        return 0x69;

    uint8_t *o = (uint8_t *)out;
    for (int k = 0; k < 16; k++)
        ((uint64_t *)o)[k] = 0;

    int i = 0;
    for (uint32_t s = 0xc; s != 0x16; s += 2) {
        if (cr_image_slot_empty(defs, s))
            continue;
        void **blk = (void **)(o + (size_t)i * 8);
        int st = cr_malloc_aligned16(blk, 0x38);
        if (st != 0)
            return (uint32_t)st;
        if ((int)cr_image_data_dump(defs, s, *blk) != 0)
            return 0x6a;
        *(void **)(o + (size_t)(i + 7) * 8) = cr_image_get_dp(defs, s + 1);
        i++;
    }

    if (flag != 0 && *(void **)o != NULL) {
        const void *d0 = *(void *const *)o;
        const int16_t rows = *(const int16_t *)d0;
        const int16_t cols = ((const int16_t *)d0)[1];
        if (cr_image_slot_defined(defs, 8) && cr_image_slot_empty(defs, 8)) {
            uint32_t r = cr_pixel_buf_setup(defs, 8, rows, cols);
            if (r != 0)
                return r;
        }
        if (cr_image_slot_defined(defs, 10) && cr_image_slot_empty(defs, 10)) {
            uint32_t r = cr_pixel_buf_setup(defs, 10, rows, cols);
            if (r != 0)
                return r;
        }
    }

    if (!cr_image_slot_empty(defs, 8)) {
        int st = cr_malloc_aligned16((void **)(o + 5 * 8), 0x38);
        if (st != 0)
            return (uint32_t)st;
        if ((int)cr_image_data_dump(defs, 8, *(void **)(o + 5 * 8)) != 0)
            return 0x6a;
        *(void **)(o + 0xc * 8) = cr_image_get_dp(defs, 9);
    }
    if (!cr_image_slot_empty(defs, 10)) {
        int st = cr_malloc_aligned16((void **)(o + 6 * 8), 0x38);
        if (st != 0)
            return (uint32_t)st;
        if ((int)cr_image_data_dump(defs, 10, *(void **)(o + 6 * 8)) != 0)
            return 0x6a;
        *(void **)(o + 0xd * 8) = cr_image_get_dp(defs, 0xb);
    }

    *(void **)(o + 0xf * 8) = cr_image_get_dp(defs, 0);

    if (!cr_image_slot_empty(defs, 1)) {
        int st = cr_malloc_aligned16((void **)(o + 0xe * 8), 0x18);
        if (st != 0)
            return (uint32_t)st;
        cr_image_buf_desc(defs, *(void **)(o + 0xe * 8));
    }

    return *(void **)o == NULL ? 0x69u : 0u;
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

/* ------------------------------------------------------------------------ *
 * 0x18003fcd0 — free a sized object held in a slot: tear down its 8 sub-slots
 * (cr_free_8slot) then release the block itself via the sized allocator.
 *   void fn(void **slot):
 *     if (slot) {
 *         if (*slot) cr_free_8slot(*slot);
 *         cr_sized_free(slot);
 *     }
 * ------------------------------------------------------------------------ */
void cr_free_8slot_wrap(void **slot)
{
    if (slot) {
        if (*slot)
            cr_free_8slot(*slot);
        cr_sized_free(slot);
    }
}

/* ------------------------------------------------------------------------ *
 * 0x18001c680 — destroy an object: release the sized slot at obj+0x48 (via
 * cr_free_8slot_wrap) then free the 28/8-byte object itself.
 *   void fn(void *obj):
 *     cr_free_8slot_wrap((void **)((uint8_t *)obj + 0x48));
 *     cr_free_obj_28_8(obj);
 * ------------------------------------------------------------------------ */
void cr_obj_destroy(void *obj)
{
    cr_free_8slot_wrap((void **)((uint8_t *)obj + 0x48));
    cr_free_obj_28_8(obj);
}

/* ------------------------------------------------------------------------ *
 * 0x180044ce0 — destroy a wrapper: if the held object is present, destroy it
 * (cr_obj_destroy) and release the wrapper slot itself.
 *   void fn(void **slot):
 *     if (*slot) { cr_obj_destroy(*slot); cr_sized_free(slot); }
 * ------------------------------------------------------------------------ */
void cr_wrap_destroy(void **slot)
{
    if (*slot) {
        cr_obj_destroy(*slot);
        cr_sized_free(slot);
    }
}

/* ------------------------------------------------------------------------ *
 * 0x180043a10 — destroy an outer wrapper: if the held object is present,
 * destroy the inner wrapper at *slot+8 (cr_wrap_destroy) and release the outer
 * slot itself.
 *   void fn(void **slot):
 *     if (*slot) { cr_wrap_destroy((void **)((uint8_t *)*slot + 8));
 *                  cr_sized_free(slot); }
 * ------------------------------------------------------------------------ */
void cr_wrap_destroy2(void **slot)
{
    if (*slot) {
        cr_wrap_destroy((void **)((uint8_t *)*slot + 8));
        cr_sized_free(slot);
    }
}

/* ======================================================================== *
 *  Batch 51 — small ready wrappers
 * ======================================================================== */

/* ------------------------------------------------------------------------ *
 * 0x180038720 — free the sized object held in a slot, but only if present.
 *   Assembly: CMP qword [RCX],0 ; JZ ret ; JMP cr_sized_free.  No guard on the
 *   slot pointer itself (the caller always passes a valid address).
 *   void fn(void **slot): if (*slot) cr_sized_free(slot);
 * ------------------------------------------------------------------------ */
void cr_sized_free_if(void **slot)
{
    if (*slot)
        cr_sized_free(slot);
}

/* ------------------------------------------------------------------------ *
 * 0x18001f640 — free two consecutive sized pointers at obj+0 and obj+8.
 *   void fn(void *obj): cr_sized_free(obj); cr_sized_free(obj + 8);
 * ------------------------------------------------------------------------ */
void cr_free_pair8(void *obj)
{
    cr_sized_free((void **)obj);
    cr_sized_free((void **)((uint8_t *)obj + 8));
}

/* ------------------------------------------------------------------------ *
 * 0x180033f40 — free the sized object at obj+8, if obj is non-NULL.
 *   void fn(void *obj): if (obj) cr_sized_free((void **)((uint8_t *)obj + 8));
 * ------------------------------------------------------------------------ */
void cr_free_slot8(void *obj)
{
    if (obj)
        cr_sized_free((void **)((uint8_t *)obj + 8));
}

/* ------------------------------------------------------------------------ *
 * 0x1800276a0 — NULL-guarded cr_cleanup_ptr8_a.
 *   void fn(void *obj): if (obj) cr_cleanup_ptr8_a(obj);
 * ------------------------------------------------------------------------ */
void cr_cleanup_ptr8_guard(void *obj)
{
    if (obj)
        cr_cleanup_ptr8_a(obj);
}

/* ------------------------------------------------------------------------ *
 * 0x1800464b0 — free four sized pointers, in the vendor's order:
 *   obj+0x18, obj+0x00, obj+0x20, obj+0x28.
 *   void fn(void *obj)
 * ------------------------------------------------------------------------ */
void cr_free_4slot(void *obj)
{
    cr_sized_free((void **)((uint8_t *)obj + 0x18));
    cr_sized_free((void **)((uint8_t *)obj + 0x00));
    cr_sized_free((void **)((uint8_t *)obj + 0x20));
    cr_sized_free((void **)((uint8_t *)obj + 0x28));
}

/* ------------------------------------------------------------------------ *
 * 0x18004a910 — read a metadata-class buffer from slot `idx` of the definition
 * table (the metadata twin of cr_image_get_dp, which uses the debug class).
 *   void *fn(const void *defs, uint32_t idx):
 *     if (defs && idx < 0x16) {
 *         p = *(void **)((uint8_t *)defs + 0x10 + idx * 8);
 *         if (cr_buf_is_metadata_class(p)) return p;
 *     }
 *     return NULL;
 * ------------------------------------------------------------------------ */
void *cr_image_get_meta_dp(const void *defs, uint32_t idx)
{
    if (defs && idx < 0x16) {
        void *p = *(void **)((const uint8_t *)defs + 0x10 + (size_t)idx * 8);
        if (cr_buf_is_metadata_class(p))
            return p;
    }
    return NULL;
}

/* ------------------------------------------------------------------------ *
 * 0x18003b920 — byte-identical twin of cr_cleanup_ptr8_clear: free the sized
 * object at obj+8 and unconditionally clear the slot.
 *   void fn(void *obj):
 *     if (obj) { if (*(void**)(obj+8)) cr_sized_free(obj+8);
 *                *(void**)(obj+8) = NULL; }
 * ------------------------------------------------------------------------ */
void cr_cleanup_ptr8_clear_b(void *obj)
{
    if (obj) {
        if (*(void **)((uint8_t *)obj + 8))
            cr_sized_free((void **)((uint8_t *)obj + 8));
        *(void **)((uint8_t *)obj + 8) = NULL;
    }
}

/* ------------------------------------------------------------------------ *
 * 0x18000fd40 — free four sized pointers passed by value: the vendor copies
 * each argument into a stack local and sized-frees that local.
 *   void fn(void *p0, void *p1, void *p2, void *p3):
 *     cr_sized_free(&p0); cr_sized_free(&p1);
 *     cr_sized_free(&p2); cr_sized_free(&p3);
 * ------------------------------------------------------------------------ */
void cr_free_4args(void *p0, void *p1, void *p2, void *p3)
{
    cr_sized_free(&p0);
    cr_sized_free(&p1);
    cr_sized_free(&p2);
    cr_sized_free(&p3);
}

/* ======================================================================== *
 *  Batch 52 — ready wrappers / allocators
 * ======================================================================== */

/* ------------------------------------------------------------------------ *
 * 0x180046490 — NULL-guarded cr_free_4slot.
 *   void fn(void *obj): if (obj) cr_free_4slot(obj);
 * ------------------------------------------------------------------------ */
void cr_free_4slot_guard(void *obj)
{
    if (obj)
        cr_free_4slot(obj);
}

/* ------------------------------------------------------------------------ *
 * 0x180011890 — clear the sized slots at obj + {0xa0, 0x00, 0x20, 0x40, 0x60,
 * 0x80} (each via cr_cleanup_ptr8_clear).
 *   void fn(void *obj)
 * ------------------------------------------------------------------------ */
void cr_clear_6ptr(void *obj)
{
    static const int off[6] = { 0xa0, 0x00, 0x20, 0x40, 0x60, 0x80 };
    for (int i = 0; i < 6; i++)
        cr_cleanup_ptr8_clear((uint8_t *)obj + off[i]);
}

/* ------------------------------------------------------------------------ *
 * 0x18001e8b0 — float-image allocator: canonical descriptor init with a
 * 4-byte-per-pixel buffer.  Same shape as cr_image_alloc_u8 but the pixel
 * buffer is `(uint32_t)(w*h) << 2` bytes.
 *   int fn(cr_image *img, int w, int h):
 *     if (!img) return 1;
 *     if (w < 0 || h < 0) return 0x69;
 *     img->a=w; img->w=w; img->b=h; img->h=h;
 *     img->offx=0; img->offy=0; img->data=NULL;
 *     if (w*h == 0) return 0;
 *     return cr_malloc_aligned16(&img->data, (uint32_t)(w*h) << 2);
 * ------------------------------------------------------------------------ */
int cr_image_alloc_f32(cr_image *img, int w, int h)
{
    if (!img)
        return 1;
    if (w < 0 || h < 0)
        return 0x69;
    img->a = w;
    img->w = w;
    img->b = h;
    img->h = h;
    img->offx = 0;
    img->offy = 0;
    img->data = NULL;
    if (w * h == 0)
        return 0;
    return cr_malloc_aligned16(&img->data, (size_t)(uint32_t)(w * h) << 2);
}

/* ------------------------------------------------------------------------ *
 * 0x180026d00 — set four descriptor fields to (64, 64, 2, 2) then allocate a
 * byte image of size ((w',h') >> 2), where w' = (w >= 4) ? w-4 : w-1 (and
 * likewise for h).  The four fixed fields live at +0x20..+0x2c, which
 * cr_image_alloc_u8 does not touch.
 *   int fn(cr_image *img, int w, int h)   (tail-call, so it returns the
 *   cr_image_alloc_u8 status)
 * ------------------------------------------------------------------------ */
int cr_image_alloc_quarter(cr_image *img, int w, int h)
{
    int32_t *d = (int32_t *)img;
    d[8]  = 0x40;
    d[9]  = 0x40;
    d[10] = 2;
    d[11] = 2;
    int wi = (w - 4 > -1) ? w - 4 : w - 1;
    int hi = (h - 4 > -1) ? h - 4 : h - 1;
    return cr_image_alloc_u8(d, wi >> 2, hi >> 2);
}

/* ------------------------------------------------------------------------ *
 * 0x1800357a0 — copy the pixel buffers of two small int16 descriptors into the
 * caller's buffers.  `a` holds descriptors at +0x28 and +0x30 (each
 * {int16 w@0, int16 h@2, ..., void *data@0x10}); `b` holds destinations at
 * +0x58 and +0x18.  The second copy runs only if the first source is present.
 *   int fn(void *a, void *b):
 *     if (!b) return 0;
 *     p = *(short**)(a+0x28);
 *     if (p && *(void**)(b+0x58)) {
 *         cr_copy(*(void**)((uint8_t*)p+0x10), *(void**)(b+0x58), (int)*p * p[1] * 2);
 *         p = *(short**)(a+0x30);
 *         if (p && *(void**)(b+0x18))
 *             cr_copy(*(void**)((uint8_t*)p+0x10), *(void**)(b+0x18),
 *                     (int)*p * p[1] * 2);
 *     }
 *     return 0;
 * ------------------------------------------------------------------------ */
int cr_copy_image_fields(void *a, void *b)
{
    if (b) {
        short *p = *(short **)((uint8_t *)a + 0x28);
        if (p && *(void **)((uint8_t *)b + 0x58)) {
            cr_copy(*(void **)((uint8_t *)p + 0x10), *(void **)((uint8_t *)b + 0x58),
                    (int)*p * (int)p[1] * 2);
            p = *(short **)((uint8_t *)a + 0x30);
            if (p && *(void **)((uint8_t *)b + 0x18))
                cr_copy(*(void **)((uint8_t *)p + 0x10), *(void **)((uint8_t *)b + 0x18),
                        (int)*p * (int)p[1] * 2);
        }
    }
    return 0;
}

/* ------------------------------------------------------------------------ *
 * 0x180032530 — guarded u8→u16 widen: both descriptors must be full-view
 *   (a==w, b==h, offx==0, offy==0) before delegating to cr_u8_to_u16_shifted.
 *   int fn(cr_image *dst, const cr_image *src, int16_t shift):
 *     if (dst->a==dst->w && dst->offx==0 && dst->offy==0 &&
 *         src->a==src->w && src->offx==0 && src->offy==0)
 *       { cr_u8_to_u16_shifted(dst, src, shift); return 0; }
 *     return 0x69;
 * ------------------------------------------------------------------------ */
int cr_u8_to_u16_guarded(cr_image *dst, const cr_image *src, int16_t shift)
{
    if (dst->a == dst->w && dst->offx == 0 && dst->offy == 0 &&
        src->a == src->w && src->offx == 0 && src->offy == 0) {
        cr_u8_to_u16_shifted(dst, src, shift);
        return 0;
    }
    return 0x69;
}

/* ------------------------------------------------------------------------ *
 * 0x180024e60 — guarded u16 copy+shift: widths and heights must match before
 *   delegating to cr_image_copy_u16_shl.
 *   int fn(cr_image *dst, const cr_image *src, uint8_t shift):
 *     if (dst->w==src->w && dst->h==src->h)
 *       { cr_image_copy_u16_shl(dst, src, shift); return 0; }
 *     return 0x69;
 * ------------------------------------------------------------------------ */
int cr_copy_u16_shl_guarded(cr_image *dst, const cr_image *src, uint8_t shift)
{
    if (dst->w == src->w && dst->h == src->h) {
        cr_image_copy_u16_shl(dst, src, shift);
        return 0;
    }
    return 0x69;
}

/* ------------------------------------------------------------------------ *
 * 0x1800280d0 — column-FIR validate-and-call wrapper.
 *   int fn(int16_t *out, const int16_t *in, const int16_t *coef,
 *          int K, int W, int L):
 *     Fast paths: K==7 or K==0xf with (W & 7)==0 and L<=256.
 *     General path: K>=0, K<L, L<=256.
 *     On success tail-calls cr_fir_reflect(out, in, coef, K, W, L).
 *     Returns 0x69 on validation failure.
 * ------------------------------------------------------------------------ */
int cr_fir_reflect_guarded(int16_t *out, const int16_t *in,
                           const int16_t *coef, int K, int W, int L)
{
    if (K == 7) {
        if ((W & 7) == 0) {
            if ((uint32_t)(L - 8) <= 0xf8)
                goto ok;
            return 0x69;
        }
    } else if (K == 0xf) {
        if ((W & 7) == 0) {
            if ((uint32_t)(L - 0x10) <= 0xf0)
                goto ok;
            return 0x69;
        }
    }
    /* general path */
    if (K < 0 || L <= K || L > 0x100)
        return 0x69;
ok:
    return cr_fir_reflect(out, in, coef, K, W, L);
}

/* ------------------------------------------------------------------------ *
 * 0x18002d960 — row-FIR validate-and-call wrapper (twin of the above).
 *   int fn(int16_t *out, const int16_t *in, const int16_t *coef,
 *          int K, int W, int R):
 *     Same validation but returns 1 (not 0x69) on failure.
 *     On success tail-calls cr_fir_reflect_rows.
 * ------------------------------------------------------------------------ */
int cr_fir_reflect_rows_guarded(int16_t *out, const int16_t *in,
                                const int16_t *coef, int K, int W, int R)
{
    if (K == 7) {
        if ((W & 7) == 0) {
            if ((uint32_t)(W - 8) <= 0xf8)
                goto ok;
            return 1;
        }
    } else if (K == 0xf) {
        if ((W & 7) == 0) {
            if ((uint32_t)(W - 0x10) <= 0xf0)
                goto ok;
            return 1;
        }
    }
    if (K < 0 || W <= K || W > 0x100)
        return 1;
ok:
    return cr_fir_reflect_rows(out, in, coef, K, W, R);
}

/* ------------------------------------------------------------------------ *
 * 0x180010e60 — palette LUT remap with allocation.
 *   int fn(void *ctx, cr_image *lut_desc, void *flag_obj):
 *     flag = *(char*)((uint8_t*)flag_obj + 0x3d);
 *     if (flag == 0) return 0;
 *     obj = *(void**)((uint8_t*)ctx + 0x48);   // palette object
 *     count = *(int32_t*)((uint8_t*)obj + 0x20);
 *     r = cr_malloc_aligned16((void**)((uint8_t*)obj + 0x18),
 *                             (size_t)(uint32_t)count * 2);
 *     if (r != 0) return r;
 *     if (count > 0) {
 *         src  = *(uint8_t**)obj;               // obj+0x00: byte-pair source
 *         dst  = *(int16_t**)((uint8_t*)obj + 0x18); // just-allocated output
 *         lut  = *(int16_t**)((uint8_t*)lut_desc + 0x08); // lut_desc->data
 *         mult = *(int32_t*)((uint8_t*)lut_desc + 0x10); // lut_desc->w
 *         for (int i = 0; i < count; i++) {
 *             uint32_t idx = (uint32_t)src[i*2+1] * (uint32_t)mult +
 *                            (uint32_t)src[i*2];
 *             dst[i] = lut[idx];
 *         }
 *     }
 *     return 0;
 * ------------------------------------------------------------------------ */
int cr_palette_remap(void *ctx, const cr_image *lut_desc, const void *flag_obj)
{
    if (*(const char *)((const uint8_t *)flag_obj + 0x3d) == 0)
        return 0;
    uint8_t *obj = *(uint8_t **)((uint8_t *)ctx + 0x48);
    int count = *(int32_t *)((uint8_t *)obj + 0x20);
    int r = cr_malloc_aligned16((void **)((uint8_t *)obj + 0x18),
                                (size_t)(uint32_t)count * 2);
    if (r != 0)
        return r;
    if (count > 0) {
        const uint8_t *src = *(const uint8_t **)obj;
        int16_t       *dst = *(int16_t **)((uint8_t *)obj + 0x18);
        const int16_t *lut = *(const int16_t **)(&lut_desc->data);
        int            mult = lut_desc->w;
        for (int i = 0; i < count; i++) {
            uint32_t idx = (uint32_t)src[i * 2 + 1] * (uint32_t)mult +
                           (uint32_t)src[i * 2];
            dst[i] = lut[idx];
        }
    }
    return 0;
}

/* ------------------------------------------------------------------------ *
 * 0x180038930 — centroid-based Q15 affine seed (scale must be in [1,2)).
 *   int fn(int *out, const void *bm, float scale, int win_w, int win_h, int margin):
 *     if (scale < 1.0 || scale >= 2.0) return 0x69;
 *     r = cr_bitmap_centroid(bm, win_h, win_w, &out_y, &out_x, margin);
 *     if (r == 0) {
 *       out[1]=0; out[3]=0;
 *       q = (int)(0x40000000LL / (long long)(int)(scale*32768.0f));
 *       out[0]=q; out[4]=q;
 *       a = win_w*0x8000 - win_w*q;  b = win_h*0x8000 - q*win_h;
 *       out[2] = (((a - (a>>31)) >> 16) + out_x) * 0x8000;
 *       out[5] = (((b - (b>>31)) >> 16) + out_y) * 0x8000;
 *     }
 *     return r;
 * ------------------------------------------------------------------------ */
int cr_centroid_affine(int *out, const void *bm, float scale,
                       int win_w, int win_h, int margin)
{
    if (scale >= 1.0f && scale < 2.0f) {
        int out_y = 0, out_x = 0;
        int r = cr_bitmap_centroid((const cr_bitmap_desc *)bm, win_h, win_w,
                                   &out_y, &out_x, margin);
        if (r == 0) {
            out[1] = 0;
            out[3] = 0;
            int q = (int)(0x40000000LL / (long long)(int)(scale * 32768.0f));
            out[0] = q;
            out[4] = q;
            int a = win_w * 0x8000 - win_w * q;
            int b = win_h * 0x8000 - q * win_h;
            out[2] = (((a - (a >> 31)) >> 16) + out_x) * 0x8000;
            out[5] = (((b - (b >> 31)) >> 16) + out_y) * 0x8000;
        }
        return r;
    }
    return 0x69;
}

/* ------------------------------------------------------------------------ *
 * 0x18003b690 — descriptor pool builder.
 *   void fn(void **hdr, void **ptrs, uint8_t n, const uint32_t *sizes):
 *   `hdr` is a caller struct {void *base @0; u8 count @8; u8 4 @9}.  Allocates
 *   one 16-aligned block of `4*n + 0xf + Σ((sizes[i]+0x13)&~0xf)` bytes, stores
 *   the n u32 sizes verbatim at the front, then lays out n 16-aligned sub-blocks
 *   of `(sizes[i]+0x13)&~0xf` bytes each; each block ends with a 4-byte trailer
 *   {u8 i, u8 0, u8 0x30, u8 0x27}.  `ptrs[i]` receives block i's start.  On
 *   allocation failure nothing else is written (base stays NULL).
 * ------------------------------------------------------------------------ */
int cr_pool_builder(void **hdr, void **ptrs, uint8_t n, const uint32_t *sizes)
{
    uint32_t N = n;
    int total = (int)(N * 4u + 0xfu);
    hdr[0] = NULL;
    ((uint8_t *)hdr)[8] = n;
    ((uint8_t *)hdr)[9] = 4;
    for (uint32_t i = 0; i < N; i++)
        total += (int)((sizes[i] + 0x13u) & 0xfffffff0u);
    void *base = NULL;
    int rc = cr_malloc_aligned16(&base, (size_t)total);
    if (rc != 0)
        return rc;               /* returns the allocator's failure code (2) */
    hdr[0] = base;
    uint8_t *p = (uint8_t *)base;
    for (uint32_t i = 0; i < N; i++) {
        p[0] = (uint8_t)(sizes[i] & 0xffu);
        p[1] = (uint8_t)((sizes[i] >> 8) & 0xffu);
        p[2] = (uint8_t)((sizes[i] >> 16) & 0xffu);
        p[3] = (uint8_t)((sizes[i] >> 24) & 0xffu);
        p += 4;
    }
    uint8_t *cur = (uint8_t *)((((uintptr_t)base) + 4u * N + 0xfu) &
                               ~(uintptr_t)0xfu);
    if (((uint8_t *)hdr)[8] != 0) {
        for (uint32_t i = 0; i < N; i++) {
            uint32_t bs = (sizes[i] + 0x13u) & 0xfffffff0u;
            ptrs[i] = cur;
            uint8_t *t = cur + bs - 4;
            t[0] = (uint8_t)i;
            t[1] = 0;
            t[2] = 0x30;
            t[3] = 0x27;
            cur += bs;
        }
    }
    return 0;
}

/* ======================================================================== *
 *  batch 57 — small destructor / constructor wrappers
 * ======================================================================== */

/* ------------------------------------------------------------------------ *
 * 0x18003f940 — tear down a 4-slot object: clear the sized slot at obj+8,
 * then free the sized slots at obj+0x28, obj+0x48, obj+0x68 (stride 0x20).
 *   void fn(void *obj)
 * ------------------------------------------------------------------------ */
void cr_free_4slot_clear1(void *obj)
{
    cr_cleanup_ptr8_clear_b(obj);
    cr_cleanup_ptr8_a((uint8_t *)obj + 0x20);
    cr_cleanup_ptr8_a((uint8_t *)obj + 0x40);
    cr_cleanup_ptr8_a((uint8_t *)obj + 0x60);
}

/* ------------------------------------------------------------------------ *
 * 0x1800140d0 — free the three sized pointers at a+0x00, a+0x08, a+0x28 (only
 * when `a` is non-NULL), then free the sized pointer at b+0x08.
 *   void fn(void **a, void *b)
 * ------------------------------------------------------------------------ */
void cr_free_3ptr_and8(void **a, void *b)
{
    if (a != NULL) {
        cr_sized_free(a);
        cr_sized_free((void **)((uint8_t *)a + 0x08));
        cr_sized_free((void **)((uint8_t *)a + 0x28));
    }
    cr_cleanup_ptr8_a(b);
}

/* ------------------------------------------------------------------------ *
 * 0x180012f70 — tear down a 9-slot object: clear the sized slots reached from
 * obj, obj+0x20 .. obj+0xa0 (i.e. the six slots at obj+0x08 .. obj+0xa8,
 * stride 0x20), then free the sized slots reached from obj+0xc0, +0xe0, +0x100
 * (slots at obj+0xc8, +0xe8, +0x108).
 *   void fn(void *obj)
 * ------------------------------------------------------------------------ */
void cr_free_9slot_clear6(void *obj)
{
    for (int i = 0; i < 6; i++)
        cr_cleanup_ptr8_clear_b((uint8_t *)obj + 0x20 * i);
    cr_cleanup_ptr8_a((uint8_t *)obj + 0xc0);
    cr_cleanup_ptr8_a((uint8_t *)obj + 0xe0);
    cr_cleanup_ptr8_a((uint8_t *)obj + 0x100);
}

/* ------------------------------------------------------------------------ *
 * 0x180038820 — allocate a 16-byte-aligned 0x60-byte object and initialise it:
 * zero the whole block, then set the single byte at +0x30 to 1 (the vendor's
 * extra zero stores target bytes the fill already cleared).
 *   int fn(void **slot):
 *     r = cr_malloc_aligned16(slot, 0x60);
 *     if (r == 0) { p = *slot; cr_fill(p, 0, 0x60); p[0x30] = 1; }
 *     return r;
 * ------------------------------------------------------------------------ */
int cr_alloc_60_init(void **slot)
{
    int r = cr_malloc_aligned16(slot, 0x60);
    if (r == 0) {
        uint8_t *p = (uint8_t *)*slot;
        cr_fill(p, 0, 0x60);
        p[0x30] = 1;
    }
    return r;
}

/* ------------------------------------------------------------------------ *
 * 0x180020aa0 — object constructor driven by a template descriptor.
 *   int fn(void *obj, void *buf, void *arg3, void *arg4, int arg5,
 *           const void *desc)
 *
 * Zeroes the 0x50-byte `buf`, clears the four sized-pointer slots of `obj`
 * (+0x00, +0x18, +0x20, +0x28) and stores arg5 at +0x4c.  Then, based on the
 * byte at desc+0x24:
 *   sel == 2: allocate +0x20 (2*w10) and +0x28 (4*w10) from the int16 at
 *             desc+0x10 (w10); store arg3/arg4 at +0x08/+0x10 and w10 at +0x48.
 *             First allocation failing is tolerated (returns 0); a second
 *             failure frees the object and returns the allocator error.
 *   sel == 5: allocate +0x18 (2*d14, d14 = (int)desc+0x14) and +0x00
 *             (8*b25*b26, b25 = desc+0x25, b26 = desc+0x26); fill the +0x00
 *             buffer with 8-byte records {u16=0, u16=0xFFFF, float=1.0f}.
 *             Store b25/+0x30, b26/+0x34, d14/+0x48.  A second-allocation
 *             failure frees the object and returns the allocator error.
 *   else: return 0x69.
 * ------------------------------------------------------------------------ */
int cr_obj_ctor_20aa0(void *obj, void *buf, void *arg3, void *arg4, int arg5,
                       const void *desc)
{
    uint8_t *o = (uint8_t *)obj;
    const uint8_t *d = (const uint8_t *)desc;

    cr_fill(buf, 0, 0x50);
    *(void **)(o + 0x00) = NULL;
    *(void **)(o + 0x18) = NULL;
    *(void **)(o + 0x20) = NULL;
    *(void **)(o + 0x28) = NULL;
    *(int *)(o + 0x4c) = arg5;

    uint8_t sel = d[0x24];
    if (sel == 2) {
        int w10 = (int16_t)*(const uint16_t *)(d + 0x10);
        *(uint32_t *)(o + 0x30) = 0;
        *(uint32_t *)(o + 0x34) = 0;
        *(uint32_t *)(o + 0x38) = 0;
        *(uint32_t *)(o + 0x3c) = 0;
        *(uint32_t *)(o + 0x40) = 0;
        *(void **)(o + 0x08) = arg3;
        *(void **)(o + 0x10) = arg4;
        *(int *)(o + 0x48) = w10;
        if (cr_malloc_aligned16((void **)(o + 0x20),
                                (size_t)(uint32_t)(2u * (uint32_t)w10)) != 0)
            return 0;                       /* tolerated */
        if (cr_malloc_aligned16((void **)(o + 0x28),
                                (size_t)(uint32_t)(4u * (uint32_t)w10)) != 0) {
            cr_free_4slot(obj);
            return 2;                        /* allocator error code */
        }
        return 0;
    } else if (sel == 5) {
        uint8_t b25 = d[0x25];
        uint8_t b26 = d[0x26];
        int d14 = *(const int32_t *)(d + 0x14);
        *(void **)(o + 0x08) = arg3;
        *(void **)(o + 0x10) = arg4;
        *(uint32_t *)(o + 0x48) = (uint32_t)d14;
        *(uint32_t *)(o + 0x30) = b25;
        *(uint32_t *)(o + 0x34) = b26;
        *(uint32_t *)(o + 0x40) = 0;
        if (cr_malloc_aligned16((void **)(o + 0x18),
                                (size_t)(uint32_t)(2u * (uint32_t)d14)) != 0)
            return 0;                        /* tolerated */
        int total = (int)b25 * (int)b26;
        if (cr_malloc_aligned16((void **)(o + 0x00),
                                (size_t)(uint32_t)(8u * (uint32_t)(uint32_t)total)) != 0) {
            cr_free_4slot(obj);
            return 2;                        /* allocator error code */
        }
        uint8_t *base = (uint8_t *)*(void **)(o + 0x00);
        for (int r = 0; r < (int)b26; r++) {
            for (int c = 0; c < (int)b25; c++) {
                uint8_t *rec = base + (r * (int)b25 + c) * 8;
                *(uint16_t *)(rec + 0) = 0;
                *(uint16_t *)(rec + 2) = 0xFFFFu;
                *(float   *)(rec + 4) = 1.0f;
            }
        }
        return 0;
    }
    return 0x69u;
}
