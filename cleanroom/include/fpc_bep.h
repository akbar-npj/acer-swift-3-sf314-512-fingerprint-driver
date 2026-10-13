/*
 * fpc_bep.h — clean-room reimplementation of the FPC e340 BEP algorithm.
 *
 * This is a from-scratch C rewrite of the functions in the reachable BEP tree of
 * fpc_enclave.dll (see ../REACHABLE.md).  Nothing here is copied from the vendor
 * binary: each function was derived by reading its disassembly/decompilation and
 * transcribing the arithmetic, then validated bit-for-bit against the vendor
 * function via tools/difftest.c.
 *
 * Conventions:
 *   - The vendor symbol names are adversarial and MUST NOT be trusted
 *     (e.g. the function named "FpcSin" is actually sqrtf).  Clean-room names
 *     are semantic: cr_<what_it_does>.  See MAP.md for RVA <-> cr_ mappings.
 *   - All float math is transcribed in the exact order of operations the vendor
 *     code uses.  Build with -ffp-contract=off so the compiler cannot fuse
 *     mul+add into an FMA and change the rounding.
 *   - Integer casts of out-of-range floats rely on x86-64 cvttss2si semantics
 *     (INT_MIN on overflow/NaN); this project is x86-64 only.
 */
#ifndef FPC_BEP_H
#define FPC_BEP_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* ---- bit reinterpretation helpers -------------------------------------- */
static inline uint32_t cr_f2u(float f)  { uint32_t u; __builtin_memcpy(&u, &f, 4); return u; }
static inline float    cr_u2f(uint32_t u) { float f; __builtin_memcpy(&f, &u, 4); return f; }

/* ---- math kernel ------------------------------------------------------- */
float cr_sqrtf(float x);          /* vendor 0x180003080 ("FpcSin")           */
float cr_expf(float x);           /* vendor 0x180002dd0 ("FpcCos")           */
int   cr_roundf_to_int(float x);  /* vendor 0x180003020 ("FpcMalloc")        */
int   cr_floorf_to_int(float x);  /* vendor 0x180002f70 ("FpcExp")           */
float cr_ldexpf(float x, int k);  /* vendor 0x1800413a0                      */
int   cr_lroundf(float x);        /* vendor 0x180002d60 ("FpcBioTemplateSave")*/

/* ---- buffer / image helpers ------------------------------------------- */
/*
 * Vendor "fpc_buffer_*" operate on a buffer descriptor whose first 32-bit word
 * is a type tag.  A `cr_buf` mirrors the layout the functions actually touch:
 *   +0x00 u32 type       (0 = pixels, 1 = ? , >=8 = metadata/debug class)
 *   +0x04 u32 size       (payload capacity)
 *   +0x08 u32 used
 *   +0x0c ...            metadata key/value records
 */
typedef struct {
    uint32_t type;
    uint32_t size;
    uint32_t used;
} cr_buf_hdr;

bool cr_buf_is_pixels(const void *buf);        /* vendor 0x1800490d0 */
bool cr_buf_is_metadata_class(const void *buf);/* vendor 0x180049120 */
bool cr_buf_is_debug_class(const void *buf);   /* vendor 0x1800490f0 */

/*
 * Metadata store: a record list of {u32 key; u32 size; u32 value} triples
 * following the header.  put appends or overwrites; get looks up.
 */
int  cr_meta_put_u32(void *store, uint32_t key, uint32_t value, bool overwrite);
int  cr_meta_get_u32(void *store, uint32_t key, uint32_t *out);

/* image definition table (16 slots of 8-byte pointers at +0x10) */
bool cr_image_slot_defined(const void *defs, uint32_t idx);  /* 0x18004aa70 */
bool cr_image_slot_empty(const void *defs, uint32_t idx);    /* 0x18004a250 */

/* ---- util kernel (leaf functions) -------------------------------------- */
uint32_t cr_status_from_flag(char flag);                 /* 0x180016720 */
uint32_t cr_status_from_ctx(const void *ctx);            /* 0x1800216d0 */
void     cr_fill(void *dst, uint8_t val, int n);         /* 0x180011000 */
void     cr_copy(void *dst, const void *src, int n);     /* 0x180040de0 */
float    cr_modff(float x, float *intpart);              /* 0x180040e20 */
uint32_t cr_bitmap_get(const void *bm, int x, int y);    /* 0x180027380 */
uint32_t cr_bitmask_range(int word, int start, int end); /* 0x18003c540 */

void     cr_s16_clamp_nonneg(int16_t *dst, const int16_t *src, int n); /* 0x180012060 */
int      cr_prng_range(uint64_t *state, int lo, int hi);               /* 0x18002fd00 */
uint32_t cr_clz(uint32_t x);                                           /* 0x1800393b0 */
void     cr_sincos(int32_t *a, int32_t *b, uint32_t phase);            /* 0x18001b990 */
float    cr_dot_f32(const float *a, const float *b, int n);            /* 0x18003b800 */

/* ---- image descriptor -------------------------------------------------- *
 * Matches the vendor layout the leaf functions touch:
 *   +0x00 w   +0x04 h   +0x08 data   +0x10 w   +0x14 h   +0x18 offx +0x1c offy
 */
typedef struct {
    int32_t  a;       /* +0x00  width  (duplicate)   */
    int32_t  b;       /* +0x04  height (duplicate)   */
    void    *data;    /* +0x08  pixel buffer         */
    int32_t  w;       /* +0x10  width                */
    int32_t  h;       /* +0x14  height               */
    int32_t  offx;    /* +0x18                       */
    int32_t  offy;    /* +0x1c                       */
} cr_image;

/* index list used by cr_image_mark_indices: count at +0, u16 array ptr at +8 */
typedef struct {
    uint16_t        count;    /* +0x00 */
    uint16_t        _pad;
    uint32_t        _pad2;
    const uint16_t *indices;  /* +0x08 */
} cr_index_list;

void     cr_image_fill_const2(cr_image *img);                        /* 0x180023a60 */
uint32_t cr_image_set(cr_image *img, void *data, int w, int h);      /* 0x18003b250 / 0x18003fbc0 / 0x180036460 */
uint32_t cr_image_set_pitch(cr_image *img, void *data, int w, int h);/* 0x180034490 */void     cr_image_subview(cr_image *dst, const cr_image *src,
                          int dx, int dy, int w, int h);             /* 0x180010ef0 / 0x180017a80 */
void     cr_image_mark_indices(cr_image *img, const cr_index_list *l); /* 0x1800305b0 */
void     cr_image_threshold_mark(cr_image *img, const cr_image *src,
                                 int16_t thr);                       /* 0x180033ae0 */
void     cr_image_mark_nonpos(cr_image *img, const cr_image *src);   /* 0x1800182b0 */

/* ---- rect fills / bitmap ops / misc leaves (batch 4) ------------------- */
void     cr_rect_fill_u8(cr_image *img, uint8_t val);                 /* 0x1800465a0 */
void     cr_rect_fill_u16(cr_image *img, uint16_t val);               /* 0x18001d700 */
void     cr_rect_fill_f32(cr_image *img, float val);                  /* 0x18001edb0 */
void     cr_bitmap_clear_rect(cr_image *img, int y0, int y1, int x0, int x1); /* 0x180037fb0 */
void     cr_bitmap_set_from_image(cr_image *bm, const cr_image *src); /* 0x180023bb0 */
void     cr_bitmap_unpack(cr_image *dst, const cr_image *src);        /* 0x180041cc0 */
void     cr_classify_mark(const float *vals, uint8_t *const *base,
                          const uint16_t *count,
                          const uint16_t *const *indices);            /* 0x180041bb0 */
uint64_t cr_copy_or_relu(void *dst, const void *src, int n, int mode);/* 0x180030270 */
void     cr_array_rotate(uint64_t *a, int n);                         /* 0x18001d7b0 */
uint64_t cr_type_desc_getter(void *p, char type);                     /* 0x18003d8f0 */

#endif /* FPC_BEP_H */
