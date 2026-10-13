/*
 * fpc_util.c — clean-room reimplementation of small leaf helpers from the
 * reachable BEP tree.  All derived from disassembly of fpc_enclave.dll; see
 * MAP.md for the RVA <-> name map.  Vendor names are not trusted.
 */
#include "fpc_bep.h"
#include <string.h>

/* ------------------------------------------------------------------------ *
 * 0x180016720 — "status from a byte flag".
 *   asm: cmp dl,1 ; sbb eax,eax ; not eax ; and eax,0x69
 *   => flag == 0 ? 0 : 0x69
 * ------------------------------------------------------------------------ */
uint32_t cr_status_from_flag(char flag)
{
    return flag == 0 ? 0u : 0x69u;
}

/* ------------------------------------------------------------------------ *
 * 0x1800216d0 — status derived from a nested context byte.
 *   asm: rax = [rcx+0x78]; al = byte [rax+0x3c]; cmp al,1; sbb/not/and 0x69
 *   => byte == 0 ? 0 : 0x69
 * ------------------------------------------------------------------------ */
uint32_t cr_status_from_ctx(const void *ctx)
{
    const uint8_t *inner = *(const uint8_t *const *)((const uint8_t *)ctx + 0x78);
    return inner[0x3c] == 0 ? 0u : 0x69u;
}

/* ------------------------------------------------------------------------ *
 * 0x180011000 — memset (only for n > 0; n <= 0 is a no-op, unlike libc).
 * ------------------------------------------------------------------------ */
void cr_fill(void *dst, uint8_t val, int n)
{
    if (n > 0)
        memset(dst, val, (size_t)n);
}

/* ------------------------------------------------------------------------ *
 * 0x180040de0 — memcpy (only for n > 0).
 * ------------------------------------------------------------------------ */
void cr_copy(void *dst, const void *src, int n)
{
    if (n > 0)
        memcpy(dst, src, (size_t)n);
}

/* ------------------------------------------------------------------------ *
 * 0x180040e20 — modff: split x into integer and fractional parts.
 *   asm: cvttss2si eax,xmm0 ; cvtsi2ss xmm1,eax ; [rdx]=xmm1 ; xmm0-=xmm1
 * ------------------------------------------------------------------------ */
float cr_modff(float x, float *intpart)
{
    int32_t i = (int32_t)x;      /* cvttss2si: truncate toward zero */
    float fi = (float)i;
    *intpart = fi;
    return x - fi;
}

/* ------------------------------------------------------------------------ *
 * 0x180027380 — bitmap bit test.  Bit index = y*width + x.
 *   asm: r8d = y*[rcx] + x ; sar r8d,5 ; word = [rcx+8][r8d] ;
 *        eax = word >> (x & 31) & 1
 * ------------------------------------------------------------------------ */
uint32_t cr_bitmap_get(const void *bm, int x, int y)
{
    const int32_t  width = *(const int32_t *)bm;
    const uint32_t *words = *(const uint32_t *const *)((const uint8_t *)bm + 8);
    int32_t idx = (y * width + x) >> 5;          /* arithmetic shift, as sar */
    return (words[idx] >> (x & 31)) & 1u;
}

/* ------------------------------------------------------------------------ *
 * 0x18003c540 — build a 32-bit mask for bits [start,end] that fall inside
 * word `word` (each word covers 32 bits).  Bits outside the word are left set
 * unless the whole range is outside, in which case the mask is all-ones.
 *   asm: eax = 0xffffffff << (start & 31)
 *        if (start>>5 != word)      eax = 0xffffffff
 *        if ((end+1)>>5 != word)    return eax
 *        return eax & ~(0xffffffff << ((end+1) & 31))
 * ------------------------------------------------------------------------ */
uint32_t cr_bitmask_range(int word, int start, int end)
{
    uint32_t mask = 0xffffffffu << (start & 31);
    if ((start >> 5) != word)
        mask = 0xffffffffu;
    if (((end + 1) >> 5) != word)
        return mask;
    return mask & ~(0xffffffffu << ((end + 1) & 31));
}
