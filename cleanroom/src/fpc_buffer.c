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

/* --- pixel buffer setup ------------------------------------------------ */

/*
 * 0x1800491e0 — initialise a pixel-buffer descriptor from a source block.
 *
 * `p` is the descriptor: +0x04 is its payload capacity.  The payload begins at
 * +0x24.  The call copies `len` bytes of `src` into p+0x24 and records the
 * geometry (a, b, c) supplied by the caller:
 *     +0x08 = a*b          +0x0c = a          +0x10 = b
 *     +0x14 = c            +0x18 = 0x100000000 (two u32: 0, 1)
 *     +0x20 = (a*c < 0 ? a*c + 7 : a*c) >> 3
 * Returns 0 on success, 0xffffffff if p is NULL or `len` does not fit the
 * remaining capacity (including a signed-overflow guard on the capacity add).
 */
uint64_t cr_buffer_pixels_setup(void *p, const void *src, uint32_t len,
                                int a, int b, int c)
{
    if (!p)
        return 0xffffffffu;

    int32_t cap = (int32_t)*(uint32_t *)((uint8_t *)p + 4) - 0x18;
    int32_t l   = (int32_t)len;

    if (l < 0)
        return 0xffffffffu;
    if (l > cap)
        return 0xffffffffu;
    if (l > (int32_t)((uint32_t)cap + (uint32_t)l))
        return 0xffffffffu;

    uint8_t *pb = (uint8_t *)p;
    memmove(pb + 0x24, src, (size_t)len);

    *(int32_t *)(pb + 0x0c) = a;
    *(int32_t *)(pb + 0x10) = b;
    *(int32_t *)(pb + 0x14) = c;
    *(int32_t *)(pb + 0x08) = a * b;

    int32_t ac = a * c;
    if (ac < 0)
        ac += 7;
    *(int32_t *)(pb + 0x20) = ac >> 3;
    *(uint64_t *)(pb + 0x18) = 0x100000000ull;

    return 0;
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
