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

/* ---- batch 5: image copies / stats / affine ---------------------------- */
uint64_t cr_image_copy_u8(cr_image *dst, const cr_image *src);        /* 0x1800308d0 */
uint64_t cr_image_copy_u32(cr_image *dst, const cr_image *src);       /* 0x18000f600 */
void     cr_image_copy_u16_shl(cr_image *dst, const cr_image *src,
                               uint8_t shift);                        /* 0x18002ade0 */
float    cr_masked_variance(const float *data, int rows, int cols,
                            const uint8_t *const *mask);              /* 0x180037e70 */
int      cr_read_quad(const int *p);                                  /* 0x1800469e0 */
uint64_t cr_buffer_pixels_setup(void *p, const void *src, uint32_t len,
                                int a, int b, int c);                 /* 0x1800491e0 */
void     cr_affine_transform(float *out, const float *pts,
                             const float *scores);                    /* 0x180014b30 */

/* ---- batch 6: 256-byte leaves ------------------------------------------ */
void     cr_vfir4_u8(uint8_t *out, const uint8_t *in, const int16_t *coeff,
                     int n, int m);                                   /* 0x18000fb20 */
void     cr_masked_minmax(int *out_min, int *out_max, int *out_count,
                          const cr_image *img, const cr_image *bitmap);/* 0x180020130 */
void     cr_orient_pick(uint8_t *arr, uint8_t *flag, int *out,
                        const uint8_t *const *src, const int16_t *coeff,
                        int half, int k);                             /* 0x1800309a0 */
float    cr_atan2_deg(float a, float b);                              /* 0x1800391b0 */
void     cr_sincos_f32(float *out_cos, float *out_sin, float x);      /* 0x18000eca0 */

/* ---- batch 7: 272-byte leaves ------------------------------------------ */
int      cr_matmul_nt(const float *in, int nrows, int K, const float *W,
                      int ncols, int Kcheck, float *out);             /* 0x18003e9f0 */
void     cr_mean_stddev(float *out_mean, float *out_std,
                        const uint8_t *data, int n);                  /* 0x18003f460 */
void     cr_masked_minmax_s16(int *out_min, int *out_max, int *out_count,
                              const cr_image *img, const cr_image *mask,
                              uint8_t and_mask);                      /* 0x1800277e0 */

/* ---- batch 8: 288-byte leaves ------------------------------------------ */
void     cr_masked_minmax_f32(float *out_min, float *out_max, int *out_count,
                              const cr_image *img, const cr_image *mask,
                              uint8_t and_mask);                      /* 0x180017840 */
void     cr_i16_to_f32_scaled(cr_image *dst, const cr_image *src,
                              int shift);                             /* 0x1800334c0 */

/* ---- batch 9: 304-byte leaves ------------------------------------------ */
/* affine Q15 sampler parameters (six consecutive int32 fields, 24 bytes) */
typedef struct {
    int32_t xstep, xcoef, xbase;   /* +0x00 x(i) = xcoef*idx + xbase + i*xstep */
    int32_t ystep, ycoef, ybase;   /* +0x0c y(i) = ycoef*idx + ybase + i*ystep */
} cr_sampler;

void     cr_bilinear_sample_u8(uint8_t *out, const cr_image *img,
                               const cr_sampler *s, int n, int idx); /* 0x18001f790 */
void     cr_box_blur_h_f32(void *dst_ref, const float *src, int nrows,
                           int ncols, int win);                      /* 0x18002cc00 */
void     cr_masked_box_sum(int *out_count, float *out_sum,
                           const cr_image *img, const cr_image *mask,
                           uint8_t and_mask, int win, int idx);      /* 0x180037330 */

/* ---- batch 10: 320-byte leaves ----------------------------------------- */
void     cr_f32_to_i16_scaled(cr_image *dst, const cr_image *src,
                              int shift);                            /* 0x18000f9d0 */
void     cr_block_extreme_bitmap(cr_image *out, const cr_image *in); /* 0x180019490 */
int      cr_bitmap_popcount(const cr_image *img);                    /* 0x180034190 */

/* ---- batch 11: 336-byte leaf ------------------------------------------- */
int      cr_downsample_mean(cr_image *out, const cr_image *in,
                            int16_t f);                              /* 0x180026fb0 */

/* ---- batch 13: 384-byte border-fill leaf ------------------------------- */
void     cr_image_fill_border(cr_image *img, int top, int bottom,
                              int left, int right, uint16_t fill);   /* 0x18001c4e0 */

/* ---- batch 14: 400/96-byte border-extend + saturation leaves ----------- */
void     cr_image_border_extend(cr_image *img, int top, int bottom,
                                int left, int right);                /* 0x18001fb80 */
void     cr_image_border_extend_s16(cr_image *img, int top, int bottom,
                                    int left, int right);            /* 0x180016df0 */

/* byte image descriptor used by the saturation scorer: w/h at +0/+2, data at +0x10 */
typedef struct {
    int16_t  w;       /* +0x00 */
    int16_t  h;       /* +0x02 */
    int32_t  _r[3];   /* +0x04 .. +0x0f */
    uint8_t *data;    /* +0x10 */
} cr_pixbuf;

void     cr_saturation_score(int *out, const cr_pixbuf *s);          /* 0x1800356e0 */

/* ---- batch 16: allocator wrappers -------------------------------------- */
int      cr_malloc(void **out, size_t size);                         /* 0x180002fe0 */
void     cr_free(void **p);                                          /* 0x180002fb0 */
void     cr_sized_free(void **p);                                    /* 0x18003bf40 */

/* ---- batch 17: bitmap morphology (dilate / erode pair) ------------------ */
void     cr_bitmap_dilate(cr_image *dst, const cr_image *src, int count); /* 0x180024cb0 */
void     cr_bitmap_erode(cr_image *dst, const cr_image *src, int count);  /* 0x1800220e0 */

/* ---- batch 18: affine resample + 4-phase FIR --------------------------- */
/* affine Q15 grid: x = x_org + row*x_row + col*x_col, y likewise */
typedef struct {
    int32_t x_col;   /* +0x00  x step per column */
    int32_t x_row;   /* +0x04  x step per row    */
    int32_t x_org;   /* +0x08  x origin (Q15)    */
    int32_t y_col;   /* +0x0c  y step per column */
    int32_t y_row;   /* +0x10  y step per row    */
    int32_t y_org;   /* +0x14  y origin (Q15)    */
} cr_affine_map;

void     cr_affine_sample_u8(cr_image *dst, const cr_image *src,
                             const cr_affine_map *s);                     /* 0x18002ca30 */
void     cr_polyphase_fir4(uint8_t *out, const uint8_t *in,
                           const int16_t *coef, int nbytes, int ncoef);   /* 0x18000ee70 */

/* ---- batch 19: 464-byte bilinear splat --------------------------------- */
void     cr_splat_bilinear(const float *w, float *bufA, float *bufB,
                           const float *alpha, float x0, float y0,
                           float scale);                                 /* 0x180044b10 */

/* ---- batch 20: bitmap border set --------------------------------------- */
int      cr_bitmap_border_set(cr_image *d, int left, int top, int right,
                              int bottom, int value);                    /* 0x180017ac0 */

/* ---- batch 21: 8-neighbour 3x3 Laplacian --------------------------------- */
void     cr_laplacian_3x3(int16_t *out, const int16_t *A, const int16_t *C,
                          const int16_t *B, int w);                      /* 0x1800169b0 */

/* ---- batch 22: 7-tap edge-clamped int16 FIR ------------------------------ */
int      cr_fir7_s16(cr_image *dst, const cr_image *src,
                     const int16_t *coef);                               /* 0x180020d80 */

/* ---- batch 23: in-place row permutation ---------------------------------- */
int      cr_permute_rows(uint8_t *data, int32_t *perm, int n, int stride); /* 0x180024200 */

/* ---- batch 24: bit-shifted bitmap blit ----------------------------------- */
int      cr_bitmap_copy_shift(cr_image *dst, const cr_image *src,
                              uint32_t bitoff, int rowoff);             /* 0x18000fd90 */

/* ---- batch 25: right-shifted bitmap extract ------------------------------ */
int      cr_bitmap_extract_shift(cr_image *dst, const cr_image *src);    /* 0x18003e590 */

/* ---- batch 26: column-wise 7-tap clamped int16 FIR ----------------------- */
int      cr_fir7_s16_col(cr_image *dst, const cr_image *src,
                         const int16_t *coef);                           /* 0x18001c280 */

/* ---- batch 27: masked per-column mean correction ------------------------- */
int      cr_bitmap_mean_correct(cr_image *img, const cr_image *bm,
                                const uint8_t *cfg);                     /* 0x18000d8e0 */

#endif /* FPC_BEP_H */
