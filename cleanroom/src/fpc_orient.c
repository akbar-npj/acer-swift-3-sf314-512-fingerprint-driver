/*
 * fpc_orient.c — clean-room reimplementation of 0x1800309a0.  Derived from
 * disassembly of fpc_enclave.dll; the RVA <-> cr_ map is in MAP.md.
 *
 * Given a byte array `arr`, a flag byte `flag`, a coefficient kernel `coeff`,
 * a length parameter `half` and a size `k`, it correlates `*src` against
 * `coeff` in both directions over k*k taps:
 *
 *     fwd = sum_{i=0..kk-1} src[i]        * coeff[i]
 *     rev = sum_{i=0..kk-1} src[kk-1-i]   * coeff[i]      (kk = k*k)
 *
 * If |fwd| >= |rev| it reports 0 and does nothing else.  Otherwise it flips the
 * top bit of `flag[0]` (adds 0x80), swaps the first d bytes of `arr` with the
 * next d bytes (d derived from `half`), and reports 1.  (kk == 0 also reports 0.)
 *
 * The odd `d` derivation is the vendor's own code, transcribed literally:
 * it adds bit 7 of `half` back into `half`, then arithmetic-shifts the low byte
 * right by one.
 */
#include "fpc_bep.h"
#include <string.h>

void cr_orient_pick(uint8_t *arr, uint8_t *flag, int *out,
                    const uint8_t *const *src, const int16_t *coeff,
                    int half, int k)
{
    int32_t kk = k * k;
    const uint8_t *base = *src;

    if (kk == 0) {
        *out = 0;
        return;
    }

    int32_t fwd = 0, rev = 0;
    for (int i = 0; i < kk; i++) {
        int32_t c = coeff[i];
        fwd += (int32_t)base[i] * c;
        rev += (int32_t)base[kk - 1 - i] * c;
    }

    int32_t af = fwd < 0 ? -fwd : fwd;
    int32_t ar = rev < 0 ? -rev : rev;
    if (af >= ar) {
        *out = 0;
        return;
    }

    flag[0] = (uint8_t)(flag[0] + 0x80u);

    uint32_t eax = (uint32_t)half;
    eax = (eax & 0xffffff00u) | ((eax >> 7) & 1u);
    int32_t edi = (int32_t)((uint32_t)half + eax);
    int8_t dil = (int8_t)(edi & 0xff);
    dil = (int8_t)(dil >> 1);

    int d = (int)dil;
    if (d > 0) {
        for (int i = 0; i < d; i++) {
            uint8_t t = arr[d + i];
            arr[d + i] = arr[i];
            arr[i] = t;
        }
    }

    *out = 1;
}

/* ------------------------------------------------------------------------ *
 * 0x180014e70 — 16-block Haar orientation accumulator.
 *
 * Descriptors (only the fields this function reads are listed):
 *   re   (a1): +0x08 ptr data ; +0x10 i32 w ; +0x14 i32 h     (int16 out)
 *   im   (a2): +0x08 ptr data                                  (int16 out)
 *   src  (a3): +0x00 i32 byte stride ; +0x08 ptr data ;
 *              +0x18 i32 offx ; +0x1c i32 offy
 *   pt   (a4): +0x28 i32 dx ; +0x2c i32 dy
 *
 * The source origin is  src->data + (dy+offy)*stride + (dx+offx).  For every
 * output pixel (x,y) a 5x5 byte window is read with row step `stride` and
 * column step 4 bytes, based at  srcp + 4*stride*y + 4*x.  Over the sixteen
 * 2x2 sub-blocks of that window the horizontal/vertical Haar gradients are
 *
 *     Dx = (p[r][c]-p[r][c+1]) + (p[r+1][c]-p[r+1][c+1])
 *     Dy = (p[r][c]-p[r+1][c]) + (p[r][c+1]-p[r+1][c+1])
 *
 * and the sums  Re = sum(Dx*Dx - Dy*Dy),  Im = sum(2*Dx*Dy)  are formed.
 * Both are then arithmetically shifted right by
 *
 *     shift = 18 - cr_clz_or32( ((Re>>1)^Re | (Im>>1)^Im) | 0x2000 )
 *
 * and stored as int16 into re->data[x] (Re) and im->data[x] (Im).  Integer
 * addition is commutative, so the accumulation order is irrelevant; the
 * result is the exact 32-bit sum.  h<=0 or w<=0 touch no memory.
 * ------------------------------------------------------------------------ */
int cr_haar16_orient(cr_image *re, cr_image *im, const cr_image *src,
                     const void *pt)
{
    const int w = re->w;
    const int h = re->h;
    const int32_t S = src->a;                 /* byte stride between rows */
    const uint8_t *base = (const uint8_t *)src->data;
    const int32_t dx = *(const int32_t *)((const uint8_t *)pt + 0x28);
    const int32_t dy = *(const int32_t *)((const uint8_t *)pt + 0x2c);
    int16_t *o1 = (int16_t *)re->data;
    int16_t *o2 = (int16_t *)im->data;

    /* source origin, 32-bit wrapping like the vendor */
    const int32_t off = (int32_t)((dy + src->offy) * S + (dx + src->offx));
    const uint8_t *srcp = base + (int64_t)off;

    if (h <= 0 || w <= 0)
        return 0;

    int32_t A = S;             /* row-1 byte offset */
    int32_t B = 3 * S;         /* row-3 byte offset */
    const int32_t fourS = 4 * S;

    for (int y = 0; y < h; y++) {
        const uint8_t *row0 = srcp + (int64_t)(int32_t)(A - S);
        const uint8_t *row1 = srcp + (int64_t)A;
        const uint8_t *row2 = srcp + (int64_t)(int32_t)(A + S);
        const uint8_t *row3 = srcp + (int64_t)B;
        const uint8_t *row4 = srcp + (int64_t)(int32_t)(B + S);

        for (int x = 0; x < w; x++) {
            const uint8_t *rows[5];
            rows[0] = row0 + 4 * x;
            rows[1] = row1 + 4 * x;
            rows[2] = row2 + 4 * x;
            rows[3] = row3 + 4 * x;
            rows[4] = row4 + 4 * x;

            int32_t acc_re = 0, acc_im = 0;
            for (int r = 0; r < 4; r++) {
                const uint8_t *ra = rows[r];
                const uint8_t *rb = rows[r + 1];
                for (int c = 0; c < 4; c++) {
                    int a = ra[c], b = ra[c + 1];
                    int cc = rb[c], d = rb[c + 1];
                    int Dx = (a - b) + (cc - d);
                    int Dy = (a - cc) + (b - d);
                    acc_re += Dx * Dx - Dy * Dy;
                    acc_im += 2 * Dx * Dy;
                }
            }

            uint32_t mask = (uint32_t)(((acc_re >> 1) ^ acc_re) |
                                       ((acc_im >> 1) ^ acc_im)) | 0x2000u;
            int shift = 18 - cr_clz_or32(mask);
            o1[x] = (int16_t)(acc_re >> shift);
            o2[x] = (int16_t)(acc_im >> shift);
        }

        o1 += w;
        o2 += w;
        A += fourS;
        B += fourS;
    }
    return 0;
}

/* ------------------------------------------------------------------------ *
 * 0x18003f970 — per-pixel orientation field from the Haar accumulator.
 *
 *   ctx   (a1): a cr_orient_ctx (u8 image + dx@+0x28 / dy@+0x2c)
 *   src   (a2): source descriptor fed to cr_haar16_orient
 *   sigma (xmm2): Gaussian blur scale
 *
 * Allocates two int16 images of ctx->img's size, fills them with the
 * (Re, Im) Haar accumulator, blurs both with a 7-tap Gaussian, and (if the
 * blur reports success) writes the per-pixel orientation angle into
 * ctx->img via cr_atan2_image_u8.  Returns the first failure status, else the
 * blur's status (0).  The scratch images are always freed.
 * ------------------------------------------------------------------------ */
int cr_orient_map_haar(cr_orient_ctx *ctx, const cr_image *src, float sigma)
{
    const int w = ctx->img.w;
    const int h = ctx->img.h;
    cr_image a1, a2;
    int st;

    st = cr_image_alloc_s16((int *)&a1, w, h);
    if (st != 0)
        return st;

    st = cr_image_alloc_s16((int *)&a2, w, h);
    if (st != 0) {
        cr_cleanup_ptr8_clear(&a1);
        return st;
    }

    cr_haar16_orient(&a1, &a2, src, ctx);
    st = cr_gauss_blur7_pair(&a1, &a2, sigma);
    if (st == 0)
        cr_atan2_image_u8(&ctx->img, &a1, &a2);

    cr_cleanup_ptr8_clear(&a1);
    cr_cleanup_ptr8_clear(&a2);
    return st;
}

/* ------------------------------------------------------------------------ *
 * 0x18003fe20 — build a quarter-resolution orientation field of the source
 * image (a2), then for each of the `count` (x,y) byte pairs in in_coords
 * bilinear-sample that field and write (angle>>1) into out_buf.
 *
 *   int fn(cr_af_ds_desc *a1, const cr_image *a2, const void *cfg):
 *     cr_orient_ctx q;
 *     int st = cr_image_alloc_quarter(&q.img, a2->w, a2->h);
 *     if (st) { cr_sized_free(&a1->out_buf); return st; }
 *     int r = cr_orient_map_haar(&q, a2, *(float*)((char*)cfg + 0x30));
 *     if (r) { cr_sized_free(&a1->out_buf); cr_cleanup_ptr8_guard(&q); return r; }
 *     for (i = 0; i < a1->count; i++) {
 *         uint8_t x = in_coords[2*i], y = in_coords[2*i+1];
 *         int ang = cr_bilinear_angle_sample(&q, (x<<4)+8, (y<<4)+8);
 *         out_buf[i] = (int8_t)(ang >> 1);
 *     }
 *     cr_cleanup_ptr8_guard(&q);
 *     return r;
 * ------------------------------------------------------------------------ */
int cr_angle_field_downsample(cr_af_ds_desc *a1, const cr_image *a2,
                              const void *cfg)
{
    cr_orient_ctx q;
    memset(&q, 0, sizeof q);
    int st = cr_image_alloc_quarter(&q.img, a2->w, a2->h);
    if (st != 0) {
        cr_sized_free(&a1->out_buf);
        return st;
    }
    int r = cr_orient_map_haar(&q, a2,
                               *(const float *)((const char *)cfg + 0x30));
    if (r != 0) {
        cr_sized_free(&a1->out_buf);
        cr_cleanup_ptr8_guard(&q);
        return r;
    }
    int n = a1->count;
    const uint8_t *in = (const uint8_t *)a1->in_coords;
    uint8_t *out = (uint8_t *)a1->out_buf;
    for (int i = 0; i < n; i++) {
        int px = ((int)in[2 * i] << 4) + 8;
        int py = ((int)in[2 * i + 1] << 4) + 8;
        int ang = cr_bilinear_angle_sample((cr_angle_field *)&q, px, py);
        /* vendor: sar al, 1 -- arithmetic shift of the *signed low byte* */
        out[i] = (uint8_t)(int8_t)((int8_t)ang >> 1);
    }
    cr_cleanup_ptr8_guard(&q);
    return r;
}

/* ------------------------------------------------------------------------ *
 * 0x1800302f0 — allocate the downsample output buffer, then dispatch.
 *
 *   int fn(cr_af_ds_desc *a1, const cr_image *a2, const void *cfg):
 *     int r = cr_malloc_aligned16(&a1->out_buf,
 *                                 (size_t)((int64)a1->count << 2));
 *     if (r) return r;
 *     if (((const uint8_t*)cfg)[9] != 2) return 0x69;
 *     return cr_angle_field_downsample(a1, a2, cfg);
 *
 * The 0x69 path leaves out_buf allocated (the vendor leaks it); the
 * downsample itself frees out_buf on its own failure paths.
 * ------------------------------------------------------------------------ */
int cr_angle_field_ds_run(cr_af_ds_desc *a1, const cr_image *a2,
                          const void *cfg)
{
    int r = cr_malloc_aligned16(&a1->out_buf,
                                (size_t)((int64_t)a1->count << 2));
    if (r != 0)
        return r;
    if (((const uint8_t *)cfg)[9] != 2)
        return 0x69;
    return cr_angle_field_downsample(a1, a2, cfg);
}
