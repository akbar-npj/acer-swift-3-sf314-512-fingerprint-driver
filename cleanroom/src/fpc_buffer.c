/*
 * fpc_buffer.c — clean-room buffer / metadata / image-slot helpers.
 *
 * Derived from disassembly of fpc_enclave.dll (see MAP.md for the RVA map).
 * The vendor "fpc_buffer_*" / "fpc_metadata_*" / "fpc_image_*" names are only
 * partly accurate; the behaviour below is what the code actually does.
 */
#include "fpc_bep.h"
#include <string.h>

/* --- buffer type predicates -------------------------------------------- *
 * A buffer descriptor starts with a u32 type tag:
 *   0        -> raw / null buffer
 *   1        -> pixel buffer
 *   2        -> (other)
 *   >=8      -> metadata / debug class (parity of the tag selects sub-class)
 */

/* 0x1800490d0 */
bool cr_buf_is_pixels(const void *buf)
{
    return buf != NULL && *(const uint32_t *)buf == 1u;
}

/* 0x1800490f0 — "debug class": tag==0 -> true; tag in (0,8] -> false;
 * tag>8 -> true when the tag is odd. */
bool cr_buf_is_debug_class(const void *buf)
{
    if (!buf)
        return false;
    uint32_t t = *(const uint32_t *)buf;
    if (t == 0)
        return true;
    if ((int32_t)(t - 8u) <= 0)
        return false;
    return ((t - 7u) ^ 1u) & 1u;
}

/* 0x180049120 — "metadata class": tag >= 8 and even. */
bool cr_buf_is_metadata_class(const void *buf)
{
    if (!buf)
        return false;
    uint32_t t = *(const uint32_t *)buf;
    if ((int32_t)(t - 8u) >= 0)
        return (t ^ 1u) & 1u;
    return false;
}

/* --- metadata store ---------------------------------------------------- *
 * Layout:  u32 type; u32 capacity; u32 used; then {u32 key; u32 size; u8 val[size]}.
 * This store only ever holds size==4 records.
 */

/* 0x18004b4e0 */
int cr_meta_get_u32(void *store, uint32_t key, uint32_t *out)
{
    uint8_t *b = (uint8_t *)store;
    uint32_t used = *(uint32_t *)(b + 8);
    if (used == 0)
        return -3;
    if (*(uint32_t *)(b + 4) < used)
        return -4;

    uint32_t *p = (uint32_t *)(b + 0xc);
    uint32_t off = 0;
    while (*p != key) {
        uint32_t step = p[1] + 8u;
        off += step;
        p += step >> 2;
        if (used <= off)
            return -5;
    }
    if (p[1] == 4u) {
        *out = p[2];
        return 0;
    }
    return -7;
}

/* 0x18004b670 */
int cr_meta_put_u32(void *store, uint32_t key, uint32_t value, bool overwrite)
{
    uint8_t *b = (uint8_t *)store;
    uint32_t used = *(uint32_t *)(b + 8);

    if (used != 0 && overwrite) {
        uint32_t *p = (uint32_t *)(b + 0xc);
        uint32_t off = 0;
        do {
            if (*p == key) {
                if (p[1] == 4u) {
                    p[2] = value;
                    return 0;
                }
                return -7;
            }
            uint32_t step = p[1] + 8u;
            off += step;
            p += step >> 2;
        } while (off < used);
    }

    if ((uint64_t)used + 0xc <= (uint64_t)*(uint32_t *)(b + 4)) {
        uint32_t *p = (uint32_t *)(b + used + 0xc);
        p[0] = key;
        p[1] = 4u;
        p[2] = value;
        *(uint32_t *)(b + 8) = used + 0xc;
        return 0;
    }
    return -1;
}

/* --- image slot table -------------------------------------------------- *
 * 22 (0x16) slots of 8-byte pointers starting at +0x10.
 */

/* 0x18004aa70 */
bool cr_image_slot_defined(const void *defs, uint32_t idx)
{
    if (!defs || idx > 0x15u)
        return false;
    return *(const uint64_t *)((const uint8_t *)defs + 0x10 + (uint64_t)idx * 8) != 0;
}

/* 0x18004a250 */
bool cr_image_slot_empty(const void *defs, uint32_t idx)
{
    if (!defs || idx > 0x15u)
        return true;
    const uint8_t *p = *(const uint8_t *const *)
                       ((const uint8_t *)defs + 0x10 + (uint64_t)idx * 8);
    if (!p)
        return true;
    return *(const int32_t *)(p + 8) == 0;
}
