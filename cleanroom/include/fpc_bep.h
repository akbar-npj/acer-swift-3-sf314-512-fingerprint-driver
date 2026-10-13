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

/* ---- batch 28: bit-packed sign signature of a filter bank ---------------- */
int      cr_signpack_dot(uint8_t *out, const void *const *inpp,
                         const uint8_t *cfg);                            /* 0x180043db0 */

/* ---- batch 29: u8->i16 shift widen + symmetric border extend ------------- */
void     cr_u8_to_u16_shifted(cr_image *dst, const cr_image *src,
                              int shift);                                /* 0x1800337e0 */
void     cr_mirror_extend_s16(cr_image *img, int top, int bottom,
                              int left, int right);                      /* 0x180028930 */
void     cr_box_sum_excl(int width, int height, const uint8_t *data,
                         const uint16_t *count, const uint16_t *const *indices,
                         int win, int idx, int *out_count, float *out_sum); /* 0x18000d040 */

/* ---- batch 31: separable 15x15 box filter --------------------------------- */
void     cr_boxsum15_s16(int16_t *base, int W, int H);                   /* 0x180032830 */
void     cr_boxsum15_u8(uint8_t *base, int W, int H);                    /* 0x18001aaa0 */

/* ---- batch 33: u8 row widen + m-tap symmetric FIR ------------------------- */
void     cr_u8_expand_convolve(int16_t *out, uint16_t *scratch,
                               const uint8_t *in, const int16_t *coef,
                               int n, int m);                            /* 0x18003ecc0 */

/* ---- batch 34: spatial top-K accumulator (batch 34) ----------------------- */
/* one cell of the W*H node table: count @0, list head @2, weight @4 */
typedef struct {
    int16_t key;      /* +0x00  slots currently held by this cell       */
    int16_t head;     /* +0x02  head slot index (-1 = empty list)       */
    float   val;      /* +0x04  accumulated weight (read only here)     */
} cr_grid_node;

typedef struct {
    cr_grid_node *nodes;   /* +0x00  W*H cells                        */
    uint8_t      *coords;  /* +0x08  2 bytes per slot                 */
    float        *values;  /* +0x10  value per slot                   */
    int16_t      *next;    /* +0x18  next slot per slot (-1 = end)    */
    uint8_t      *coords2; /* +0x20  mode-2 coords                    */
    float        *values2; /* +0x28  mode-2 values                    */
    int32_t       W;       /* +0x30                                   */
    int32_t       H;       /* +0x34                                   */
    int32_t       divx;    /* +0x38                                   */
    int32_t       divy;    /* +0x3c                                   */
    int32_t       count;   /* +0x40  slots held                       */
    int32_t       count2;  /* +0x44  mode-2 entries                   */
    int32_t       cap;     /* +0x48  slot capacity                    */
} cr_grid;

/* param_5: only the fields this leaf reads */
typedef struct {
    uint8_t  _pad[0x10];
    int16_t  cap2;         /* +0x10  mode-2 capacity                  */
    uint8_t  _pad2[0x12];
    uint8_t  mode;         /* +0x24  2 = append, 5 = accumulate       */
} cr_grid_cfg;

int      cr_grid_insert(cr_grid *g, uint8_t x, uint8_t y, float v,
                        cr_grid_cfg *cfg);                               /* 0x18002f070 */

/* ---- batch 35: bitmap set-bit centroid ------------------------------------ */
typedef struct {
    int32_t         a;      /* +0x00  row stride in bits       */
    int32_t         b;      /* +0x04                           */
    const uint32_t *data;   /* +0x08  packed 32-bit words      */
    int32_t         w;      /* +0x10  width in bits            */
    int32_t         h;      /* +0x14  height in rows           */
} cr_bitmap_desc;

int      cr_bitmap_centroid(const cr_bitmap_desc *bm, int win_h, int win_w,
                            int *out_y, int *out_x, int margin);         /* 0x18002ddd0 */

/* ---- batch 36: small descriptor / table-pointer getters ------------------- */
/* These dispatch on a byte selector; pointer stores from the vendor's
 * read-only data section are zeroed (cleanroom has no vendor tables).
 * The difftest compares status + scalar fields + pointer NULL-ness. */
uint64_t cr_desc_get_ptr1(void *p, char sel);                            /* 0x18002aeb0 */
uint64_t cr_desc_get_ptr_size(void *p1, uint32_t *p2, char sel);          /* 0x180012f30 */
uint64_t cr_desc_get_ptr2(void *p, char sel);                             /* 0x180020860 */
uint64_t cr_desc_get_tag_ptr(void *p, char sel);                         /* 0x18002dab0 */
uint64_t cr_desc_get_ptr2_69(void *p, char sel);                         /* 0x1800448f0 */
uint64_t cr_desc_get_ptr_ints(void *p1, uint32_t *p2,
                               uint32_t *p3, char sel);                  /* 0x180018e50 */
uint8_t  cr_desc_get_ptr_size_69(void *p1, uint32_t *p2, char sel);      /* 0x180017960 */
uint64_t cr_desc_get_tag_byte_ptr(void *p, char sel);                    /* 0x180028de0 */
uint64_t cr_desc_get_triple(void *p, uint8_t sel);                       /* 0x18002d4e0 */

/* ---- batch 37: 9-tap triangular filter over the 9 lines of an n x 9 buffer -- */
void     cr_tri9_filter(float *in, float *out, int n);                   /* 0x180043a50 */

/* ---- batch 38: reflect-101-padded int16 FIR down each column -------------- */
int      cr_fir_reflect(int16_t *out, const int16_t *in, const int16_t *coef,
                        int p4, int W, int L);                           /* 0x180030fc0 */

/* ---- batch 39: row-wise twin of the reflect-101 column FIR ---------------- */
int      cr_fir_reflect_rows(int16_t *out, const int16_t *in,
                             const int16_t *coef, int p4, int W, int R); /* 0x180040560 */

/* ---- batch 40: fixed 7-tap reflect-101 FIR down each row ------------------ */
void     cr_fir7_reflect(int16_t *out, const int16_t *in, const int16_t *coef,
                         int W, int R);                                  /* 0x180033b40 */

/* ---- batch 41: in-place separable box mean (3x3 / 5x5) on a float image --- */
int      cr_box_mean_f32(void *img1, void *img2, int mode);              /* 0x18002c600 */

/* ---- batch 42: stack-based Hoare quicksort over 8-byte records ------------ */
int      cr_sort_records(void *recs, int n, int key_type, int dir);      /* 0x18003bf90 */

/* ---- batch 43: short-line orientation fit --------------------------------- */
void     cr_line_orient_fit(float *samples, int px, int py,
                            float stepx, float stepy, const void *desc,
                            float *out_m, float *out_res);               /* 0x180020230 */

/* ---- batch 44: fixed 7-tap reflect-101 FIR down each column --------------- */
void     cr_vfir7_cols(int16_t *out, const int16_t *in, const int16_t *coef,
                       int n, int sel);                                  /* 0x1800433b0 */

/* ---- batch 45: separable 11x11 int16 FIR, one output row ------------------ */
void     cr_sep11_row(int16_t *out, const uint8_t *in, const int16_t *coef,
                      int w, int s);                                     /* 0x18002e6a0 */

/* ---- batch 46: per-pixel kernel-bank 2D correlation ----------------------- */
int      cr_corr_kbank(int32_t *out, const int16_t *in, const int16_t *kbank,
                       const int16_t *selarr, long long unused,
                       int ow, int oh, int iw, int ih, int K);           /* 0x180038ac0 */

/* ---- batch 47: object-tree lifecycle helpers + image-data accessors ------- *
 * These call into the sized allocator (cr_malloc / cr_sized_free), so their
 * observable contract is guard behaviour + NULL-ing, not pointer identity. */
int      cr_meta_put_i16(void *store, uint32_t key, uint32_t value,
                         bool overwrite);                    /* 0x18004b640 */
void     cr_cleanup_ptr8_a(void *obj);                       /* 0x18000fc20 */
void     cr_cleanup_ptr8_b(void *obj);                       /* 0x180011a50 */
void     cr_cleanup_ptr8_clear(void *obj);                   /* 0x180024760 */
void     cr_obj_zero_free(void **obj);                       /* 0x18001f9f0 */
void     cr_free_ptr_struct(void *obj);                      /* 0x180017170 */
int      cr_malloc_aligned16(void **out, size_t size);       /* 0x1800100c0 */
void    *cr_image_get_dp(const void *defs, uint32_t idx);    /* 0x18004a890 */
void     cr_image_buf_desc(const void *ctx, void *out);      /* 0x18004ab90 */

/* ---- batch 48: object constructors / flag-driven destructors ------------- */
void     cr_free_obj_28_8(void *obj);                        /* 0x18000ee40 */
uint8_t  cr_meta_set_slot(const void *defs, uint32_t idx,
                          int key, int value);               /* 0x1800303d0 */
uint64_t cr_obj_init_58(void *obj);                          /* 0x180046b80 */
void     cr_alloc_handle(void **out);                        /* 0x18002ad90 */
int      cr_alloc_400(void **out);                           /* 0x18003fb70 */
int      cr_image_alloc_u8(int *desc, int w, int h);         /* 0x18001d820 */
int      cr_image_alloc_s16(int *desc, int w, int h);        /* 0x18003d790 */
void     cr_free_obj_flags(void *obj);                       /* 0x18000f570 */
int      cr_bitmap_alloc(uint32_t *desc, uint32_t w, uint32_t h);  /* 0x180029750 */

/* ---- batch 49: higher-level destructors / accessors ---------------------- */
int      cr_clz_or32(uint32_t x);                            /* 0x180039390 */
void     cr_free_8slot(void *obj);                           /* 0x18003d430 */
int      cr_alloc_obj_58(void **out);                        /* 0x180035740 */
uint8_t  cr_meta_get_slot(const void *defs, uint32_t idx,
                          int key, uint32_t *out);           /* 0x18003a8d0 */
int      cr_subview_extend_s16(cr_image *img, int t, int b,
                               int l, int r);                /* 0x1800342d0 */
int      cr_subview_extend_u8(cr_image *img, int t, int b,
                              int l, int r);                 /* 0x180037f10 */

/* ---- batch 50: nested destructor chain ---------------------------------- */
void     cr_free_8slot_wrap(void **slot);                    /* 0x18003fcd0 */
void     cr_obj_destroy(void *obj);                          /* 0x18001c680 */
void     cr_wrap_destroy(void **slot);                       /* 0x180044ce0 */
void     cr_wrap_destroy2(void **slot);                      /* 0x180043a10 */

/* ---- batch 51: small ready wrappers ------------------------------------- */
void     cr_sized_free_if(void **slot);                      /* 0x180038720 */
void     cr_free_pair8(void *obj);                           /* 0x18001f640 */
void     cr_free_slot8(void *obj);                           /* 0x180033f40 */
void     cr_cleanup_ptr8_guard(void *obj);                   /* 0x1800276a0 */
void     cr_free_4slot(void *obj);                           /* 0x1800464b0 */
int      cr_hi_bit_index(uint32_t x);                        /* 0x1800384c0 */
void    *cr_image_get_meta_dp(const void *defs, uint32_t idx); /* 0x18004a910 */
void     cr_cleanup_ptr8_clear_b(void *obj);                 /* 0x18003b920 */
void     cr_free_4args(void *p0, void *p1, void *p2, void *p3); /* 0x18000fd40 */

/* ---- batch 52: ready wrappers / allocators ------------------------------ */
void     cr_free_4slot_guard(void *obj);                     /* 0x180046490 */
void     cr_clear_6ptr(void *obj);                           /* 0x180011890 */
int      cr_bit_alloc(void **out, int n);                    /* 0x18001f080 */
int      cr_image_alloc_f32(cr_image *img, int w, int h);    /* 0x18001e8b0 */
void     cr_image_alloc_quarter(cr_image *img, int w, int h); /* 0x180026d00 */
int      cr_copy_image_fields(void *a, void *b);             /* 0x1800357a0 */
int      cr_sqrt_q16(uint32_t x);                            /* 0x180038a50 */
int      cr_u8_to_u16_guarded(cr_image *dst, const cr_image *src,
                              int16_t shift);                /* 0x180032530 */
int      cr_copy_u16_shl_guarded(cr_image *dst, const cr_image *src,
                                 uint8_t shift);             /* 0x180024e60 */
int      cr_fir_reflect_guarded(int16_t *out, const int16_t *in,
                                const int16_t *coef, int K, int W, int L); /* 0x1800280d0 */
int      cr_fir_reflect_rows_guarded(int16_t *out, const int16_t *in,
                                     const int16_t *coef, int K,
                                     int W, int R);          /* 0x18002d960 */
int      cr_palette_remap(void *ctx, const cr_image *lut_desc,
                         const void *flag_obj);              /* 0x180010e60 */

/* ---- batch 53: ready wrappers (size 160-500) ---------------------------- */
void     cr_shuffle_indices(int *arr, int n, uint64_t seed); /* 0x18000d310 */
void     cr_softmax2(float *out, const void *ctx,
                     const int16_t *vals);                   /* 0x1800363b0 */
int      cr_centroid_affine(int *out, const void *bm, float scale,
                            int win_w, int win_h, int margin); /* 0x180038930 */
void     cr_running_avg(int16_t *cnt, int16_t *dst, const int16_t *src,
                        int n, float k, const int16_t *limit); /* 0x180030ea0 */
int      cr_atan2_fixed(int p1, int p2);                     /* 0x180012260 */
void     cr_box_mean_edge(float *out, const float *in, int n,
                          uint32_t w);                       /* 0x1800335e0 */

#endif /* FPC_BEP_H */
