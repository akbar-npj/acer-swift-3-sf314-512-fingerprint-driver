/*
 * fpc_math.c — clean-room float math kernel used by the BEP algorithm.
 *
 * All four functions were derived from disassembly of fpc_enclave.dll.  The
 * vendor symbol names are misleading; the semantic names below are what the
 * code actually does (see MAP.md).
 *
 * Build requirement: -ffp-contract=off (no FMA contraction) so the arithmetic
 * rounds exactly like the vendor's SSE scalar ops.
 */
#include "fpc_bep.h"

/* ------------------------------------------------------------------------ *
 * 0x180003080  (vendor name "FpcSin")  ->  sqrtf
 *
 * Table-driven seed + two Newton iterations of  y <- y*(3 - x*y*y)/2,
 * which converges to 1/sqrt(x); the result is x * y_final = sqrt(x).
 * ------------------------------------------------------------------------ */
static const uint8_t cr_invsqrt_seed[256] = {
    0xff, 0xfd, 0xfb, 0xf9, 0xf7, 0xf5, 0xf3, 0xf2, 0xf0, 0xee, 0xec, 0xea, 0xe9, 0xe7, 0xe5, 0xe4,
    0xe2, 0xe0, 0xdf, 0xdd, 0xdb, 0xda, 0xd8, 0xd7, 0xd5, 0xd4, 0xd2, 0xd1, 0xcf, 0xce, 0xcc, 0xcb,
    0xc9, 0xc8, 0xc6, 0xc5, 0xc4, 0xc2, 0xc1, 0xc0, 0xbe, 0xbd, 0xbc, 0xba, 0xb9, 0xb8, 0xb7, 0xb5,
    0xb4, 0xb3, 0xb2, 0xb0, 0xaf, 0xae, 0xad, 0xac, 0xaa, 0xa9, 0xa8, 0xa7, 0xa6, 0xa5, 0xa4, 0xa3,
    0xa2, 0xa0, 0x9f, 0x9e, 0x9d, 0x9c, 0x9b, 0x9a, 0x99, 0x98, 0x97, 0x96, 0x95, 0x94, 0x93, 0x92,
    0x91, 0x90, 0x8f, 0x8e, 0x8d, 0x8c, 0x8c, 0x8b, 0x8a, 0x89, 0x88, 0x87, 0x86, 0x85, 0x84, 0x83,
    0x83, 0x82, 0x81, 0x80, 0x7f, 0x7e, 0x7e, 0x7d, 0x7c, 0x7b, 0x7a, 0x79, 0x79, 0x78, 0x77, 0x76,
    0x76, 0x75, 0x74, 0x73, 0x72, 0x72, 0x71, 0x70, 0x6f, 0x6f, 0x6e, 0x6d, 0x6d, 0x6c, 0x6b, 0x6a,
    0x69, 0x68, 0x67, 0x65, 0x64, 0x63, 0x61, 0x60, 0x5f, 0x5d, 0x5c, 0x5b, 0x5a, 0x58, 0x57, 0x56,
    0x55, 0x54, 0x52, 0x51, 0x50, 0x4f, 0x4e, 0x4d, 0x4c, 0x4b, 0x4a, 0x48, 0x47, 0x46, 0x45, 0x44,
    0x43, 0x42, 0x41, 0x40, 0x3f, 0x3e, 0x3d, 0x3c, 0x3c, 0x3b, 0x3a, 0x39, 0x38, 0x37, 0x36, 0x35,
    0x34, 0x33, 0x33, 0x32, 0x31, 0x30, 0x2f, 0x2e, 0x2e, 0x2d, 0x2c, 0x2b, 0x2a, 0x2a, 0x29, 0x28,
    0x27, 0x26, 0x26, 0x25, 0x24, 0x23, 0x23, 0x22, 0x21, 0x21, 0x20, 0x1f, 0x1e, 0x1e, 0x1d, 0x1c,
    0x1c, 0x1b, 0x1a, 0x1a, 0x19, 0x18, 0x18, 0x17, 0x16, 0x16, 0x15, 0x14, 0x14, 0x13, 0x13, 0x12,
    0x11, 0x11, 0x10, 0x10, 0x0f, 0x0e, 0x0e, 0x0d, 0x0d, 0x0c, 0x0b, 0x0b, 0x0a, 0x0a, 0x09, 0x09,
    0x08, 0x08, 0x07, 0x06, 0x06, 0x05, 0x05, 0x04, 0x04, 0x03, 0x03, 0x02, 0x02, 0x01, 0x01, 0x00,
};

float cr_sqrtf(float x)
{
    uint32_t bits = cr_f2u(x) + 0x800000u;

    /* rebuild the seed float: exponent 0xbe - (bits>>24), mantissa top byte
       taken from the table indexed by bits>>16 & 0xff. */
    uint32_t seed = (uint32_t)((0xbe - (bits >> 24)) << 23)
                  | ((uint32_t)cr_invsqrt_seed[(bits >> 16) & 0xff] << 15);
    float t = cr_u2f(seed);

    /* first Newton step:  y1 = t*(3 - x*t*t)/2 */
    float s = x * t;
    s = s * t;                 /* x*t*t */
    float a = 3.0f - s;
    a = a * 0.5f;
    float y1 = a * t;

    /* second Newton step: y2 = y1*(3 - x*y1*y1)/2 */
    float b = x * y1;
    b = b * y1;                /* x*y1*y1 */
    float c = 3.0f - b;
    c = c * 0.5f;
    float y2 = c * y1;

    return x * y2;             /* x / sqrt(x) = sqrt(x) */
}

/* ------------------------------------------------------------------------ *
 * 0x180002dd0  (vendor name "FpcCos")  ->  expf
 *
 * Range-reduce by ln2, evaluate the degree-6 rational kernel
 *     f = 1 + 2t / (2 - t*P(t*t))
 * then scale by 2^k via an exponent add on the raw float bits.
 * ------------------------------------------------------------------------ */
float cr_expf(float x)
{
    const float LN2 = 0.6931471825f;
    int   k;
    float f;

    if (x > 88.72280121f) {                 /* overflow clamp */
        k = 0x80;
        f = 0.999961853f;
        goto scale;
    }
    if (x >= -87.33650208f) {               /* normal path */
        float q = x / LN2;
        /* round-half-away-from-zero, then truncate (cvttss2si) */
        if (q > 0.0f) k = (int)(q + 0.5f);
        else          k = (int)(q - 0.5f);

        float t  = x - (float)k * LN2;
        float t2 = t * t;

        float p = 4.138136944e-08f;
        p = p * t2; p = p - 1.6533902e-06f;
        p = p * t2; p = p + 6.613755977e-05f;
        p = p * t2; p = p - 0.002777777845f;
        p = p * t2; p = p + 0.1666666716f;
        p = p * t2; p = p + 2.0f;
        p = p - t;

        float two_t = t + t;
        f = 1.0f + two_t / p;
        if (f == 0.0f)
            return 0.0f;
    } else {                                /* underflow clamp */
        k = -0x7e;
        f = 1.000045776f;
    }

scale:
    return cr_u2f(cr_f2u(f) + (uint32_t)(k * 0x800000));
}

/* ------------------------------------------------------------------------ *
 * 0x180003020  (vendor name "FpcMalloc")  ->  roundf (to int)
 *   x > 0 ? (int)(x + 0.5) : (int)(x - 0.5)      [truncating cast]
 * ------------------------------------------------------------------------ */
int cr_roundf_to_int(float x)
{
    if (!(x > 0.0f))            /* also catches NaN -> subtract branch */
        return (int)(x - 0.5f);
    return (int)(x + 0.5f);
}

/* ------------------------------------------------------------------------ *
 * 0x180002f70  (vendor name "FpcExp")  ->  floorf (to int)
 *   e = trunc(x +/- 0.5);  if (x - e < 0) e -= 1;
 * ------------------------------------------------------------------------ */
int cr_floorf_to_int(float x)
{
    int e;
    if (x > 0.0f) e = (int)(x + 0.5f);
    else          e = (int)(x - 0.5f);

    float d = (float)e;
    if (0.0f > (x - d))         /* seta: strict, false when unordered */
        e -= 1;
    return e;
}
