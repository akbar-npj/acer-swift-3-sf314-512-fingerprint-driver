/*
 * fpc_linefit.c — clean-room reimplementation of 0x180020230, a short-line
 * orientation fit.
 *
 * The function samples 10 points along a line through a 16-bit image (bilinear,
 * clamp-to-edge), then evaluates 9 orientation hypotheses against those samples.
 * Each hypothesis has a 3-parameter model (m0, m1, m2) fitted by projecting the
 * samples onto a fixed (sin, cos) orientation pair and accumulating the residual
 * sum of squares.  The caller is expected to pick the hypothesis with the
 * smallest residual.
 *
 * Layouts
 *   samples : 10 floats, written by this function and read back by every model.
 *   desc    : int stride; (pad); const int16_t *data; int w; int h; int offA;
 *             int offB  — the pixel index is  x + offA + stride*(y + offB).
 *   out_m   : 9 * 3 floats  (m0, m1, m2 per hypothesis).
 *   out_res : 9 floats      (residual sum of squares per hypothesis).
 *
 * The 9 hypotheses are: model 0 uses inline constants, models 1..8 use the rows
 * of a coefficient table; hypothesis k uses orientation group k of the sin/cos
 * tables (group 0 duplicates model 0's inline sin/cos).  All float constants are
 * transcribed as exact hex-float literals from the vendor data sections
 * (0x18008c7b0.., 0x18008ec40.., 0x1801450e8..).
 *
 * Float evaluation order matters and is transcribed verbatim; build with
 * -ffp-contract=off.
 */
#include "fpc_bep.h"

/* hypothesis 0 (inline constants) followed by coefficient-table rows 0..7 */
static const float kCoef[9][10] = {
    { 0x1.c7789a0000000p-3f, 0x1.f383f00000000p-9f, -0x1.f383f00000000p-9f, -0x1.0156e20000000p-3f, 0x1.532d6e0000000p-4f, -0x1.532d6e0000000p-4f, 0x1.5e37580000000p-1f, 0x1.532d6e0000000p-4f, 0x1.4391500000000p-2f, 0x0.0p+0f },
    { 0x1.d388a80000000p-3f, 0x1.0492360000000p-11f, -0x1.0492360000000p-11f, -0x1.d1e1080000000p-5f, 0x1.41248e0000000p-4f, -0x1.41248e0000000p-4f, 0x1.57dbd20000000p-1f, 0x1.41248e0000000p-4f, 0x1.50485a0000000p-2f, -0x1.9d8bd60000000p+1f },
    { 0x1.c71c540000000p-3f, -0x0.0p+0f, 0x0.0p+0f, -0x0.0p+0f, 0x1.2f68380000000p-4f, -0x1.2f68380000000p-4f, 0x1.5555600000000p-1f, 0x1.2f68380000000p-4f, 0x1.55553e0000000p-2f, -0x1.8000000000000p+1f },
    { 0x1.af28420000000p-3f, 0x1.2599ee0000000p-15f, -0x1.2599ee0000000p-15f, 0x1.254a3c0000000p-6f, 0x1.1f6fd20000000p-4f, -0x1.1f6fd20000000p-4f, 0x1.5555c60000000p-1f, 0x1.1f6fd20000000p-4f, 0x1.5554760000000p-2f, -0x1.5523780000000p+1f },
    { 0x1.99999a0000000p-3f, -0x0.0p+0f, 0x0.0p+0f, -0x0.0p+0f, 0x1.11116a0000000p-4f, -0x1.11116a0000000p-4f, 0x1.5555600000000p-1f, 0x1.11116a0000000p-4f, 0x1.55553e0000000p-2f, -0x1.2aaaa80000000p+1f },
    { 0x1.8ca9260000000p-3f, 0x1.7fc7600000000p-13f, -0x1.7fc7600000000p-13f, -0x1.4c74b80000000p-5f, 0x1.0418940000000p-4f, -0x1.0418940000000p-4f, 0x1.53e9860000000p-1f, 0x1.0418940000000p-4f, 0x1.582cf60000000p-2f, -0x1.065dc80000000p+1f },
    { 0x1.894c440000000p-3f, 0x1.0624de0000000p-10f, -0x1.0624de0000000p-10f, -0x1.7cd78c0000000p-4f, 0x1.f149840000000p-5f, -0x1.f149840000000p-5f, 0x1.50ac7e0000000p-1f, 0x1.f149840000000p-5f, 0x1.5ea7040000000p-2f, -0x1.d225c80000000p+0f },
    { 0x1.8e789e0000000p-3f, 0x1.69e3ca0000000p-9f, -0x1.69e3ca0000000p-9f, -0x1.3451760000000p-3f, 0x1.de0d660000000p-5f, -0x1.de0d660000000p-5f, 0x1.4baffc0000000p-1f, 0x1.de0d660000000p-5f, 0x1.68a00a0000000p-2f, -0x1.a3adc00000000p+0f },
    { 0x1.9ac2580000000p-3f, 0x1.729b280000000p-8f, -0x1.729b280000000p-8f, -0x1.ad76260000000p-3f, 0x1.cf4c6e0000000p-5f, -0x1.cf4c6e0000000p-5f, 0x1.45288c0000000p-1f, 0x1.cf4c6e0000000p-5f, 0x1.75aee60000000p-2f, -0x1.7eca360000000p+0f },
};

static const float kSin[9][10] = {
    { -0x1.6a09ee0000000p-1f, -0x1.0000000000000p+0f, -0x1.6a09ee0000000p-1f, -0x0.0p+0f, 0x1.6a09ee0000000p-1f, 0x1.0000000000000p+0f, 0x1.6a09ee0000000p-1f, 0x0.0p+0f, -0x1.6a09ee0000000p-1f, -0x1.0000000000000p+0f },
    { -0x1.58eeae0000000p-1f, -0x1.fdd0d80000000p-1f, -0x1.9895b00000000p-1f, -0x1.7851ec0000000p-3f, 0x1.0d887e0000000p-1f, 0x1.ec74760000000p-1f, 0x1.ca52ce0000000p-1f, 0x1.71e96c0000000p-2f, -0x1.71e96c0000000p-2f, -0x1.ca52ce0000000p-1f },
    { -0x1.491b820000000p-1f, -0x1.f838c20000000p-1f, -0x1.bb67a00000000p-1f, -0x1.5e3a7e0000000p-2f, 0x1.5e3a7e0000000p-2f, 0x1.bb67a00000000p-1f, 0x1.f838c20000000p-1f, 0x1.491b820000000p-1f, 0x0.0p+0f, -0x1.491b820000000p-1f },
    { -0x1.3a7a200000000p-1f, -0x1.f055320000000p-1f, -0x1.d4e0320000000p-1f, -0x1.e75ea60000000p-2f, 0x1.51172e0000000p-3f, 0x1.78b0d00000000p-1f, 0x1.fe40420000000p-1f, 0x1.aca1060000000p-1f, 0x1.4c7de60000000p-2f, -0x1.4c7de60000000p-2f },
    { -0x1.2cf2280000000p-1f, -0x1.e6f0f20000000p-1f, -0x1.e6f0f20000000p-1f, -0x1.2cf2280000000p-1f, -0x0.0p+0f, 0x1.2cf2280000000p-1f, 0x1.e6f0f20000000p-1f, 0x1.e6f0f20000000p-1f, 0x1.2cf2280000000p-1f, 0x0.0p+0f },
    { -0x1.206b7a0000000p-1f, -0x1.dc9b840000000p-1f, -0x1.f329c40000000p-1f, -0x1.5c3fa20000000p-1f, -0x1.313cee0000000p-3f, 0x1.bc4c160000000p-2f, 0x1.bb67a00000000p-1f, 0x1.fe91860000000p-1f, 0x1.904c280000000p-1f, 0x1.2dd4420000000p-2f },
    { -0x1.14cee60000000p-1f, -0x1.d1bb4a0000000p-1f, -0x1.fac9d20000000p-1f, -0x1.82f1aa0000000p-1f, -0x1.207e9e0000000p-2f, 0x1.207e9e0000000p-2f, 0x1.82f1aa0000000p-1f, 0x1.fac9d20000000p-1f, 0x1.d1bb4a0000000p-1f, 0x1.14cee60000000p-1f },
    { -0x1.0a06ea0000000p-1f, -0x1.c698dc0000000p-1f, -0x1.fece780000000p-1f, -0x1.a249e40000000p-1f, -0x1.97f66e0000000p-2f, 0x1.16deba0000000p-3f, 0x1.431df80000000p-1f, 0x1.e270080000000p-1f, 0x1.f54a800000000p-1f, 0x1.7630220000000p-1f },
    { -0x1.0000000000000p-1f, -0x1.bb67a00000000p-1f, -0x1.0000000000000p+0f, -0x1.bb67a00000000p-1f, -0x1.0000000000000p-1f, -0x0.0p+0f, 0x1.0000000000000p-1f, 0x1.bb67a00000000p-1f, 0x1.0000000000000p+0f, 0x1.bb67a00000000p-1f },
};

static const float kCos[9][10] = {
    { 0x1.6a09ee0000000p-1f, 0x0.0p+0f, -0x1.6a09ee0000000p-1f, -0x1.0000000000000p+0f, -0x1.6a09ee0000000p-1f, -0x0.0p+0f, 0x1.6a09ee0000000p-1f, 0x1.0000000000000p+0f, 0x1.6a09ee0000000p-1f, 0x0.0p+0f },
    { 0x1.7a5f640000000p-1f, 0x1.79ee020000000p-4f, -0x1.348c940000000p-1f, -0x1.f7483c0000000p-1f, -0x1.b34fa40000000p-1f, -0x1.183b1e0000000p-2f, 0x1.c86f8a0000000p-2f, 0x1.dd6cf80000000p-1f, 0x1.dd6cf80000000p-1f, 0x1.c86f8a0000000p-2f },
    { 0x1.8836ec0000000p-1f, 0x1.63a1900000000p-3f, -0x1.0000000000000p-1f, -0x1.e11f700000000p-1f, -0x1.e11f700000000p-1f, -0x1.0000000000000p-1f, 0x1.63a1900000000p-3f, 0x1.8836ec0000000p-1f, 0x1.0000000000000p+0f, 0x1.8836ec0000000p-1f },
    { 0x1.940a4a0000000p-1f, 0x1.f6c0d60000000p-3f, -0x1.9b55f00000000p-2f, -0x1.c24a6a0000000p-1f, -0x1.f904500000000p-1f, -0x1.5ac4b40000000p-1f, -0x1.523e5c0000000p-4f, 0x1.1809920000000p-1f, 0x1.e442200000000p-1f, 0x1.e442200000000p-1f },
    { 0x1.9e377a0000000p-1f, 0x1.3c6ef40000000p-2f, -0x1.3c6ef40000000p-2f, -0x1.9e377a0000000p-1f, -0x1.0000000000000p+0f, -0x1.9e377a0000000p-1f, -0x1.3c6ef40000000p-2f, 0x1.3c6ef40000000p-2f, 0x1.9e377a0000000p-1f, 0x1.0000000000000p+0f },
    { 0x1.a708cc0000000p-1f, 0x1.761bf40000000p-2f, -0x1.c7b9180000000p-3f, -0x1.7752980000000p-1f, -0x1.fa480e0000000p-1f, -0x1.cd4bd00000000p-1f, -0x1.0000000000000p-1f, 0x1.3218160000000p-4f, 0x1.3f3a140000000p-1f, 0x1.e940de0000000p-1f },
    { 0x1.aeb8d80000000p-1f, 0x1.a9628c0000000p-2f, -0x1.23760c0000000p-3f, -0x1.4f49f00000000p-1f, -0x1.eb42aa0000000p-1f, -0x1.eb42aa0000000p-1f, -0x1.4f49f00000000p-1f, -0x1.23760c0000000p-3f, 0x1.a9628c0000000p-2f, 0x1.aeb8d80000000p-1f },
    { 0x1.b576680000000p-1f, 0x1.d71b480000000p-2f, -0x1.1784ec0000000p-4f, -0x1.27429a0000000p-1f, -0x1.d59cae0000000p-1f, -0x1.fb3b320000000p-1f, -0x1.8d29fe0000000p-1f, -0x1.56eac80000000p-2f, 0x1.a0ad8a0000000p-3f, 0x1.5d77960000000p-1f },
    { 0x1.bb67a00000000p-1f, 0x1.0000000000000p-1f, 0x0.0p+0f, -0x1.0000000000000p-1f, -0x1.bb67a00000000p-1f, -0x1.0000000000000p+0f, -0x1.bb67a00000000p-1f, -0x1.0000000000000p-1f, -0x0.0p+0f, 0x1.0000000000000p-1f },
};

static int clamp_lo_hi(int v, int lo, int hi)
{
    if (v < lo)
        v = lo;
    if (v > hi)
        v = hi;
    return v;
}

void cr_line_orient_fit(float *samples, int px, int py, float stepx, float stepy,
                        const void *desc, float *out_m, float *out_res)
{
    const int32_t *d = (const int32_t *)desc;
    const int16_t *data = *(const int16_t *const *)((const char *)desc + 8);
    int stride = d[0];
    int Wm1 = d[4] - 1;
    int Hm1 = d[5] - 1;
    int offA = d[6];
    int offB = d[7];

    /* ---- part 1: 10 bilinear samples along the line ------------------- */
    float x = (float)px + stepx;
    float y = (float)py + stepx;
    for (int t = 0; t < 10; t++) {
        int xi = (int)x;
        int yi = (int)y;
        float fx = x - (float)xi;
        float fy = y - (float)yi;
        int cx0 = clamp_lo_hi(xi, 0, Wm1);
        int cx1 = clamp_lo_hi(xi + 1, 0, Wm1);
        int cy0 = clamp_lo_hi(yi, 0, Hm1);
        int cy1 = clamp_lo_hi(yi + 1, 0, Hm1);
        int rb0 = (cy0 + offB) * stride + offA;
        int rb1 = (cy1 + offB) * stride + offA;
        float p00 = (float)data[cx0 + rb0];
        float p01 = (float)data[cx1 + rb0];
        float p10 = (float)data[cx0 + rb1];
        float p11 = (float)data[cx1 + rb1];
        samples[t] = p00 * ((1.0f - fx) * (1.0f - fy))
                   + p01 * ((1.0f - fy) * fx)
                   + p10 * ((1.0f - fx) * fy)
                   + p11 * (fx * fy);
        x += stepx;
        y += stepy;
    }

    float center = (float)data[px + offA + stride * (py + offB)];

    /* ---- part 2: fit 9 orientation hypotheses ------------------------- */
    for (int k = 0; k < 9; k++) {
        const float *C = kCoef[k];
        const float *S = kSin[k];
        const float *Cs = kCos[k];

        float sum = 0.0f, A = 0.0f, B = 0.0f;
        for (int j = 0; j < 10; j++) {
            float v = samples[j];
            float tsin = S[j] * v;
            sum += v;
            float tcos = Cs[j] * v;
            B -= tsin;
            A += tcos;
        }

        float m0 = (sum * C[2] + (C[0] * B + A * C[1])) + C[3] * center;
        float m1 = (C[6] * center) + ((C[1] * B + C[4] * A) + sum * C[5]);
        float m2 = (C[8] * center) + (sum * C[7] + (A * C[5] + B * C[2]));
        out_m[k * 3 + 0] = m0;
        out_m[k * 3 + 1] = m1;
        out_m[k * 3 + 2] = m2;

        float acc = 0.0f;
        for (int j = 0; j < 10; j++) {
            float v = samples[j];
            float res = v - ((Cs[j] * m1 - S[j] * m0) + m2);
            acc += res * res;
            out_res[k] = acc;
        }
    }
}
