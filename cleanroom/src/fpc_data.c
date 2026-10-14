/*
 * fpc_data.c — clean-room reimplementation of the vendor data-blob accessors
 * and image-data dump/setup helpers.
 *
 * These tiny functions map a selector to a (pointer, length) pair into the
 * vendor's read-only data, returning a status code (0 ok, 0x69 invalid).  The
 * pointers are mirrored via g_cr_image_base so the differential test (which maps
 * the real DLL at that base) sees identical addresses.
 */
#include "fpc_bep.h"
#include <string.h>
#include <stdint.h>

uintptr_t g_cr_image_base = 0;

/* 0x180048d40 — global bio-context getter.
 *   void *fn(void)  =  (*(void **)[0x18016f4c8]) + 8
 * The global lives in the mapped image, so it is read through g_cr_image_base
 * exactly as the vendor does. */
void *cr_bio_init(void)
{
    return (char *)(*(void **)(g_cr_image_base + 0x16f4c8u)) + 8;
}

/* 0x180030340 — calibration/data blob lookup by selector.
 * Transcribed from disassembly: store 0 into both outputs, then switch(sel):
 *   0 -> ptr=0,    len=0,     ret 0
 *   1 -> ptr=0,    len=0x4000, ret 0
 *   2 -> ptr=0,    len=0x3840, ret 0
 *   5 -> ptr=&DAT_180117800 (len 0x1900), ret 0
 *   6 -> ptr=&DAT_18012d3a0 (len 0x1000),  ret 0
 *   default -> (already zeroed), ret 0x69
 */
uint32_t cr_get_calib_blob(uint64_t *p1, uint32_t *p2, uint8_t sel)
{
    *p1 = 0;
    *p2 = 0;
    switch (sel) {
    case 0:  return 0;
    case 1:  *p2 = 0x4000u; return 0;
    case 2:  *p2 = 0x3840u; return 0;
    case 5:  *p1 = (uint64_t)(g_cr_image_base + 0x117800u); *p2 = 0x1900u; return 0;
    case 6:  *p1 = (uint64_t)(g_cr_image_base + 0x12d3a0u); *p2 = 0x1000u; return 0;
    default: return 0x69u;
    }
}

/* 0x18004a680 — fpc_image_data_dump.
 *   uint32_t fn(const void *defs, uint32_t idx, void *out)
 *
 * Looks up defs[idx] (via the +0x10 slot array), validates it with
 * cr_buf_is_metadata_class, then fills `out` with a packed header:
 *   out[0..1]  word  = meta[0x0c] (truncated)
 *   out[2..3]  word  = meta[0x10] (truncated)
 *   out[4..5]  word  = 0xFFFF
 *   out[6]     byte  = meta[0x14] (truncated)
 *   out[7..8]  word  = 0xFF01  (-255 as u16)
 *   out[9]     byte  = meta[0x18] (truncated)
 *   out[0xa..b] word = 1
 *   out[0x10..17] qword = meta+0x24
 *   out[0x18..1b] dword = meta[4] - 0x18
 * Then calls cr_image_buf_desc(defs, out+0x20).
 * Returns 0 on success, 0xFFFFFFFE (-2) on invalid/missing slot. */
uint32_t cr_image_data_dump(const void *defs, uint32_t idx, void *out)
{
    if (!defs || idx > 0x15u)
        return 0xFFFFFFFEu;

    unsigned char *defs_p = (unsigned char *)defs;
    void *meta;
    __builtin_memcpy(&meta, defs_p + (size_t)idx * 8 + 0x10, sizeof meta);
    if (!meta || !cr_buf_is_metadata_class(meta))
        return 0xFFFFFFFEu;

    unsigned char *m = (unsigned char *)meta;
    unsigned char *o = (unsigned char *)out;

    /* out[0..1] = meta[0x0c] as word */
    {  uint32_t v; __builtin_memcpy(&v, m + 0x0c, 4); *(uint16_t *)(o + 0) = (uint16_t)v; }
    /* out[2..3] = meta[0x10] as word */
    {  uint32_t v; __builtin_memcpy(&v, m + 0x10, 4); *(uint16_t *)(o + 2) = (uint16_t)v; }
    /* out[4..5] = 0xFFFF */
    *(uint16_t *)(o + 4) = 0xFFFFu;
    /* out[6] = meta[0x14] as byte */
    {  uint32_t v; __builtin_memcpy(&v, m + 0x14, 4); o[6] = (unsigned char)v; }
    /* out[7..8] = 0xFF01 */
    *(uint16_t *)(o + 7) = 0xFF01u;
    /* out[9] = meta[0x18] as byte */
    {  uint32_t v; __builtin_memcpy(&v, m + 0x18, 4); o[9] = (unsigned char)v; }
    /* out[0xa..b] = 1 */
    *(uint16_t *)(o + 0x0a) = 1;
    /* out[0x10..17] = meta+0x24 */
    {  uint64_t v = (uint64_t)(m + 0x24); __builtin_memcpy(o + 0x10, &v, 8); }
    /* out[0x18..1b] = meta[4] - 0x18 */
    {  uint32_t v; __builtin_memcpy(&v, m + 4, 4); v -= 0x18u; __builtin_memcpy(o + 0x18, &v, 4); }

    cr_image_buf_desc(defs, o + 0x20);
    return 0;
}

/* 0x18003d840 — pixel-buffer setup wrapper.
 *   uint32_t fn(const void *defs, uint32_t idx, int rows, int cols)
 *
 * Validates defs with cr_image_slot_defined, allocates rows*2*cols bytes
 * (16-byte aligned), zero-fills, calls cr_image_get_meta_dp to get the data
 * pointer, then cr_buffer_pixels_setup to populate the buffer, and frees it.
 * Returns 1 if cr_buffer_pixels_setup returned non-zero, else 0.
 * Returns 0 early if slot check fails or allocation fails. */
uint32_t cr_pixel_buf_setup(const void *defs, uint32_t idx, int rows, int cols)
{
    if (!cr_image_slot_defined(defs, idx))
        return 0;

    int total = (rows * 2) * cols;
    void *buf = NULL;
    if (cr_malloc_aligned16(&buf, (size_t)total) != 0)
        return 0;

    cr_fill(buf, 0, total);
    void *meta_dp = cr_image_get_meta_dp(defs, idx);
    /* Vendor call: cr_buffer_pixels_setup(meta_dp, buf, total, rows, cols, 0x10) */
    uint64_t result = cr_buffer_pixels_setup(meta_dp, buf, (uint32_t)total,
                                              rows, cols, 0x10);
    cr_sized_free(&buf);
    return (result != 0) ? 1u : 0u;
}
