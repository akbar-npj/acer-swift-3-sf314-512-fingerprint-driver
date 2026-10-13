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

#endif /* FPC_BEP_H */
