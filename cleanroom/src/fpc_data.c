/*
 * fpc_data.c — clean-room reimplementation of the vendor data-blob accessors.
 *
 * These tiny functions map a selector to a (pointer, length) pair into the
 * vendor's read-only data, returning a status code (0 ok, 0x69 invalid).  The
 * pointers are mirrored via g_cr_image_base so the differential test (which maps
 * the real DLL at that base) sees identical addresses.
 */
#include "fpc_bep.h"

uintptr_t g_cr_image_base = 0;

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
