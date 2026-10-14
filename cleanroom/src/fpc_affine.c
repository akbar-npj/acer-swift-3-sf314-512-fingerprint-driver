/*
 * fpc_affine.c — clean-room reimplementation of 0x180014b30, a table-driven
 * affine transform.  Derived from disassembly of fpc_enclave.dll; see MAP.md.
 *
 * It picks the index k in [0,9) with the smallest score, then maps a 3-float
 * source point (pts[3k..3k+2]) to 16 output floats:
 *     out[i] = pts[3k]*T[k][i] + pts[3k+1]*T[k][16+i] + pts[3k+2]
 * where T is a 9x32 float table (a DCT/rotation basis) that the vendor stores
 * at 0x18008ec40.  The table is reproduced here byte-exact; its 288 floats are
 * cos/sin-style basis values and cannot be regenerated to the bit (note the
 * signed zeros at e.g. T[0][3] = -0.0 and T[8][5] = -0.0, which are load-bearing
 * for bit parity).
 */
#include "fpc_bep.h"

static const float cr_affine_tab[288] = {
    -0.707107008f, -1.0f, -0.707107008f, -0.0f, 0.707107008f, 1.0f, 0.707107008f, 0.0f, -0.707107008f, -1.0f, -0.707107008f, -0.0f, 0.707107008f, 1.0f, 0.707107008f, 0.0f, 0.707107008f, 0.0f, -0.707107008f, -1.0f, -0.707107008f, -0.0f, 0.707107008f, 1.0f, 0.707107008f, 0.0f, -0.707107008f, -1.0f, -0.707107008f, -0.0f, 0.707107008f, 1.0f,
    -0.673695982f, -0.995733976f, -0.798017025f, -0.183750004f, 0.526431978f, 0.961826026f, 0.895163f, 0.361241996f, -0.361241996f, -0.895163f, -0.961826026f, -0.526431978f, 0.183750004f, 0.798017025f, 0.995733976f, 0.673695982f, 0.739009023f, 0.0922679976f, -0.602635026f, -0.98297298f, -0.850216985f, -0.273663014f, 0.445737988f, 0.932471991f, 0.932471991f, 0.445737988f, -0.273663014f, -0.850216985f, -0.98297298f, -0.602635026f, 0.0922679976f, 0.739009023f,
    -0.642787993f, -0.984808028f, -0.866024971f, -0.342020005f, 0.342020005f, 0.866024971f, 0.984808028f, 0.642787993f, 0.0f, -0.642787993f, -0.984808028f, -0.866024971f, -0.342020005f, 0.342020005f, 0.866024971f, 0.984808028f, 0.766044021f, 0.173648f, -0.5f, -0.939692974f, -0.939692974f, -0.5f, 0.173648f, 0.766044021f, 1.0f, 0.766044021f, 0.173648f, -0.5f, -0.939692974f, -0.939692974f, -0.5f, 0.173648f,
    -0.61421299f, -0.969399989f, -0.915772974f, -0.475946993f, 0.164594993f, 0.735723972f, 0.996583998f, 0.837166011f, 0.324699014f, -0.324699014f, -0.837166011f, -0.996583998f, -0.735723972f, -0.164594993f, 0.475946993f, 0.915772974f, 0.789140999f, 0.245484993f, -0.401695013f, -0.879473984f, -0.986361027f, -0.677281976f, -0.0825790018f, 0.546948016f, 0.945816994f, 0.945816994f, 0.546948016f, -0.0825790018f, -0.677281976f, -0.986361027f, -0.879473984f, -0.401695013f,
    -0.587785006f, -0.951057017f, -0.951057017f, -0.587785006f, -0.0f, 0.587785006f, 0.951057017f, 0.951057017f, 0.587785006f, 0.0f, -0.587785006f, -0.951057017f, -0.951057017f, -0.587785006f, -0.0f, 0.587785006f, 0.809017003f, 0.309017003f, -0.309017003f, -0.809017003f, -1.0f, -0.809017003f, -0.309017003f, 0.309017003f, 0.809017003f, 1.0f, 0.809017003f, 0.309017003f, -0.309017003f, -0.809017003f, -1.0f, -0.809017003f,
    -0.563319981f, -0.93087399f, -0.974928021f, -0.68017298f, -0.149041995f, 0.433883995f, 0.866024971f, 0.997204006f, 0.781831026f, 0.294755012f, -0.294755012f, -0.781831026f, -0.997204006f, -0.866024971f, -0.433883995f, 0.149041995f, 0.82623899f, 0.365341008f, -0.222521007f, -0.733052015f, -0.988830984f, -0.900969028f, -0.5f, 0.0747300014f, 0.623489976f, 0.955573022f, 0.955573022f, 0.623489976f, 0.0747300014f, -0.5f, -0.900969028f, -0.988830984f,
    -0.54064101f, -0.909632027f, -0.989821017f, -0.75575f, -0.281733006f, 0.281733006f, 0.75575f, 0.989821017f, 0.909632027f, 0.54064101f, 0.0f, -0.54064101f, -0.909632027f, -0.989821017f, -0.75575f, -0.281733006f, 0.841253996f, 0.415414989f, -0.142315f, -0.654860973f, -0.959492981f, -0.959492981f, -0.654860973f, -0.142315f, 0.415414989f, 0.841253996f, 1.0f, 0.841253996f, 0.415414989f, -0.142315f, -0.654860973f, -0.959492981f,
    -0.519584f, -0.887884974f, -0.997668982f, -0.816969991f, -0.398400992f, 0.136167005f, 0.631088018f, 0.942260981f, 0.979084015f, 0.730835974f, 0.269796997f, -0.269796997f, -0.730835974f, -0.979084015f, -0.942260981f, -0.631088018f, 0.854418993f, 0.460065007f, -0.0682419986f, -0.576680005f, -0.917210996f, -0.990685999f, -0.775711f, -0.334879994f, 0.203455999f, 0.682552993f, 0.96291697f, 0.96291697f, 0.682552993f, 0.203455999f, -0.334879994f, -0.775711f,
    -0.5f, -0.866024971f, -1.0f, -0.866024971f, -0.5f, -0.0f, 0.5f, 0.866024971f, 1.0f, 0.866024971f, 0.5f, 0.0f, -0.5f, -0.866024971f, -1.0f, -0.866024971f, 0.866024971f, 0.5f, 0.0f, -0.5f, -0.866024971f, -1.0f, -0.866024971f, -0.5f, -0.0f, 0.5f, 0.866024971f, 1.0f, 0.866024971f, 0.5f, 0.0f, -0.5f,
};

void cr_affine_transform(float *out, const float *pts, const float *scores)
{
    /* index of the smallest of scores[0..9); ties keep the earlier index */
    unsigned best = 0;
    float bv = scores[0];
    for (unsigned i = 1; i != 9; i++) {
        if (scores[i] < bv) {
            best = i;
            bv = scores[i];
        }
    }
    int k = (int)best;
    const float *T = cr_affine_tab + (long long)k * 32;

    for (int i = 0; i < 16; i++)
        out[i] = pts[(long long)k * 3] * T[i]
               + pts[(long long)k * 3 + 1] * T[16 + i]
               + pts[(long long)k * 3 + 2];
}

/* ------------------------------------------------------------------------ *
 * 0x180044040 — nearest-neighbour int16 affine resample with OOB fill.
 *   void fn(cr_image *dst, const cr_image *src, const float *m, int16_t fill):
 *   `m` is a Q20 affine map {x_col, x_row, x_org, y_col, y_row, y_org} (the
 *   same layout as cr_affine_map).  Both accumulators start at
 *   `(int)(m[2]*2^20) + 0x80000` (origin only), step by the per-column deltas
 *   for each output column and by the per-row deltas for each output row.
 *   A dst pixel whose src coords (acc >> 20) are out of [0,w)x[0,h) is set to
 *   `fill`; otherwise it copies src[y*src->a + x + src->offx + src->a*src->offy].
 * ------------------------------------------------------------------------ */
void cr_affine_sample_s16_nn(cr_image *dst, const cr_image *src,
                             const float *m, int16_t fill)
{
    const int16_t *sdata = (const int16_t *)src->data;
    int16_t *ddata = (int16_t *)dst->data;
    int sw = src->w, sh = src->h, ss = src->a;
    int dw = dst->w, dh = dst->h, ds = dst->a;
    long soff = src->offx + ss * src->offy;
    int16_t *drowbase = ddata + dst->offy * ds + dst->offx;
    const float sc = 0x1p-20f;
    uint32_t xstep = (uint32_t)(int)(m[0] / sc);   /* per column */
    uint32_t ystep = (uint32_t)(int)(m[3] / sc);   /* per column */
    uint32_t xrow = (uint32_t)(int)(m[1] / sc);    /* per row    */
    uint32_t yrow = (uint32_t)(int)(m[4] / sc);    /* per row    */
    uint32_t xacc_row = (uint32_t)((int)(m[2] / sc) + 0x80000);
    uint32_t yacc_row = (uint32_t)((int)(m[5] / sc) + 0x80000);
    int rowoff = 0;
    for (int r = 0; r < dh; r++) {
        int16_t *drow = drowbase + rowoff;
        uint32_t xacc = xacc_row, yacc = yacc_row;
        for (int c = 0; c < dw; c++) {
            int x = ((int)xacc) >> 20;
            int y = ((int)yacc) >> 20;
            if (x >= 0 && x < sw && y >= 0 && y < sh)
                drow[c] = sdata[(long)y * ss + x + soff];
            else
                drow[c] = fill;
            xacc += xstep;
            yacc += ystep;
        }
        xacc_row += xrow;
        yacc_row += yrow;
        rowoff += ds;
    }
}

/* ------------------------------------------------------------------------ *
 * 0x180014110 — nearest-neighbour uint8 affine resample with OOB fill.
 *   void fn(cr_image *dst, const cr_image *src, const float *m, uint8_t fill):
 *   the byte twin of cr_affine_sample_s16_nn.  Same Q20 map, same accumulators
 *   and same in-bounds test (the vendor folds it into a single sign test:
 *   0 <= x < src->w && 0 <= y < src->h).  Out-of-range dst pixels take `fill`;
 *   in-range pixels copy src[y*src->a + x + src->offx + src->a*src->offy].
 * ------------------------------------------------------------------------ */
void cr_affine_sample_u8_nn(cr_image *dst, const cr_image *src,
                            const float *m, uint8_t fill)
{
    const uint8_t *sdata = (const uint8_t *)src->data;
    uint8_t *ddata = (uint8_t *)dst->data;
    int sw = src->w, sh = src->h, ss = src->a;
    int dw = dst->w, dh = dst->h, ds = dst->a;
    long soff = src->offx + ss * src->offy;
    uint8_t *drowbase = ddata + dst->offy * ds + dst->offx;
    const float sc = 0x1p-20f;
    uint32_t xstep = (uint32_t)(int)(m[0] / sc);   /* per column */
    uint32_t ystep = (uint32_t)(int)(m[3] / sc);   /* per column */
    uint32_t xrow = (uint32_t)(int)(m[1] / sc);    /* per row    */
    uint32_t yrow = (uint32_t)(int)(m[4] / sc);    /* per row    */
    uint32_t xacc_row = (uint32_t)((int)(m[2] / sc) + 0x80000);
    uint32_t yacc_row = (uint32_t)((int)(m[5] / sc) + 0x80000);
    int rowoff = 0;
    for (int r = 0; r < dh; r++) {
        uint8_t *drow = drowbase + rowoff;
        uint32_t xacc = xacc_row, yacc = yacc_row;
        for (int c = 0; c < dw; c++) {
            int x = ((int)xacc) >> 20;
            int y = ((int)yacc) >> 20;
            if (x >= 0 && x < sw && y >= 0 && y < sh)
                drow[c] = sdata[(long)y * ss + x + soff];
            else
                drow[c] = fill;
            xacc += xstep;
            yacc += ystep;
        }
        xacc_row += xrow;
        yacc_row += yrow;
        rowoff += ds;
    }
}

/* ------------------------------------------------------------------------ *
 * 0x18001c700 — rotate/translate-warp `src` into an N x N u8 buffer.
 *   int fn(void *dst_buf, const cr_image *src, int ox, int oy, int phase,
 *          const int *cfg):
 *     M = cfg[0]; N = cfg[1];
 *     if (N > 31) return 0x69;                        // signed
 *     img = { a=b=N, data=dst_buf, w=h=N, offx=offy=0 };
 *     r = cr_image_set(&img, dst_buf, N, N); if (r) return r;
 *     cr_sincos(&A, &B, (uint8_t)phase);
 *     half  = (M - 1) / 2;                            // trunc toward zero
 *     scale = (int32_t)((M - 1) << 15) / (N - 1);     // 32-bit shift, signed
 *     map.x_col = (A * scale) >> 14;  map.y_row = map.x_col;
 *     map.y_col = (scale * B) >> 14;  map.x_row = -map.y_col;
 *     map.x_org = ((uint8_t)ox << 15) - half * (A - B) * 2;
 *     map.y_org = ((uint8_t)oy << 15) - (A + B) * 2 * half;
 *     cr_affine_sample_u8_clamped(&img, src, &map);
 *     return 0;
 *   The (N-1) divisor is a divide-by-zero when N == 1, exactly as in the
 *   vendor (IDIV #DE); callers must not pass N == 1.
 * ------------------------------------------------------------------------ */
int cr_warp_rotate_u8(void *dst_buf, const cr_image *src,
                      int ox, int oy, int phase, const int *cfg)
{
    int M = cfg[0];
    int N = cfg[1];

    if (N > 31)
        return 0x69;

    cr_image img;
    uint32_t r = cr_image_set(&img, dst_buf, N, N);
    if (r != 0)
        return (int)r;

    int32_t A, B;
    cr_sincos(&A, &B, (uint32_t)(uint8_t)phase);

    int     half  = (M - 1) / 2;
    int32_t num   = (int32_t)((uint32_t)(M - 1) << 15);
    int     scale = (int32_t)((int64_t)num / (int64_t)(int32_t)(N - 1));

    cr_affine_map map;
    map.x_col = (int32_t)((uint32_t)A * (uint32_t)scale) >> 14;
    map.y_row = map.x_col;
    map.y_col = (int32_t)((uint32_t)scale * (uint32_t)B) >> 14;
    map.x_row = -map.y_col;
    map.x_org = ((int)((uint8_t)ox << 15)) - half * ((A - B) * 2);
    map.y_org = ((int)((uint8_t)oy << 15)) - ((A + B) * 2) * half;

    cr_affine_sample_u8_clamped(&img, src, &map);
    return 0;
}
