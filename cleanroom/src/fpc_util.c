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

/* ------------------------------------------------------------------------ *
 * 0x180012060 — clamp an array of int16 to non-negative (negatives -> 0).
 *   asm: if (n > 0) for i in [0,n): dst16[i] = src16[i] < 0 ? 0 : src16[i]
 * ------------------------------------------------------------------------ */
void cr_s16_clamp_nonneg(int16_t *dst, const int16_t *src, int n)
{
    if (n > 0)
        for (int i = 0; i < n; i++)
            dst[i] = src[i] < 0 ? 0 : src[i];
}

/* ------------------------------------------------------------------------ *
 * 0x18002fd00 — LCG step + range reduction.
 *   asm: s = (s>>32) + (uint32)s * 0xf83f630a   (64-bit, wrapping)
 *        if (hi != lo) hi = (uint32)s % (uint32)(hi-lo) + lo
 *        return hi
 * ------------------------------------------------------------------------ */
int cr_prng_range(uint64_t *state, int lo, int hi)
{
    uint64_t s = *state;
    s = (s >> 32) + (uint64_t)(uint32_t)s * 0xf83f630au;
    *state = s;
    if (hi != lo)
        hi = (int)((uint32_t)s % (uint32_t)(hi - lo)) + lo;
    return hi;
}

/* ------------------------------------------------------------------------ *
 * 0x1800393b0 — count leading zeros.
 *   The vendor spreads the set bits (x |= x>>1 ... x>>16), adds 1, multiplies
 *   by the de Bruijn constant 0x76be629 and shifts right by 27 to index a
 *   32-byte lookup table; the net result is __builtin_clz(x) for x != 0 and
 *   0 for x == 0 (table[0] == 0).  Verified exhaustively via difftest.
 * ------------------------------------------------------------------------ */
uint32_t cr_clz(uint32_t x)
{
    return x ? (uint32_t)__builtin_clz(x) : 0u;
}

/* ------------------------------------------------------------------------ *
 * 0x18001b990 — quadrant sine/cosine lookup.
 *   table[k] = round(16384 * sin(k*pi/128)), k in [0,64] (int16).
 *   k = phase & 0x3f; A = table[k]; B = table[0x40-k];
 *   if (phase & 0x80) { A = -A; B = -B; }
 *   if (phase & 0x40) { *a = -A; *b = B; } else { *a = B; *b = A; }
 * ------------------------------------------------------------------------ */
static const int16_t cr_sin_q[65] = {
        0,   402,   804,  1205,  1606,  2006,  2404,  2801,  3196,  3590,
     3981,  4370,  4756,  5139,  5520,  5897,  6270,  6639,  7005,  7366,
     7723,  8076,  8423,  8765,  9102,  9434,  9760, 10080, 10394, 10702,
    11003, 11297, 11585, 11866, 12140, 12406, 12665, 12916, 13160, 13395,
    13623, 13842, 14053, 14256, 14449, 14635, 14811, 14978, 15137, 15286,
    15426, 15557, 15679, 15791, 15893, 15986, 16069, 16143, 16207, 16261,
    16305, 16340, 16364, 16379, 16384,
};

void cr_sincos(int32_t *a, int32_t *b, uint32_t phase)
{
    int     k = (int)(phase & 0x3fu);
    int32_t A = cr_sin_q[k];            /* table[k]        */
    int32_t B = cr_sin_q[0x40 - k];     /* table[0x40 - k] */
    if (phase & 0x80u) { A = -A; B = -B; }
    if (phase & 0x40u) { *a = -A; *b = B; }
    else               { *a = B;  *b = A; }
}

/* ------------------------------------------------------------------------ *
 * 0x18003b800 — single-precision dot product (n <= 0 -> 0.0f).
 *   asm: acc = 0; for i in [0,n) acc += a[i]*b[i];  (mulss then addss)
 * ------------------------------------------------------------------------ */
float cr_dot_f32(const float *a, const float *b, int n)
{
    float acc = 0.0f;
    if (n > 0)
        for (int i = 0; i < n; i++)
            acc += a[i] * b[i];
    return acc;
}
