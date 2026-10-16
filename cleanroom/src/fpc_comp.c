/*
 * fpc_comp.c — clean-room reimplementation of two Gaussian-windowed FIR
 * orchestration functions (0x180046610, 0x180044a20).
 *
 * Both validate a pair of image descriptors (field[0] == field[0x10] and
 * field[0x18] == 0), then build a Q15 Gaussian window and run it through the
 * reflect-101 FIR helpers.  Transcribed from disassembly, including the exact
 * validation/guard ordering and return codes (0x69 invalid, else guard status).
 *
 * The descriptor is read through raw offsets (matching the vendor's memory
 * accesses): +0x08 data pointer, +0x10 (qword, equals +0x00; low 32 = W),
 * +0x14 int (L), +0x18 (qword == 0).
 */
#include "fpc_bep.h"
#include <float.h>

static inline void *desc_data(const void *d) {
    const unsigned char *p = (const unsigned char *)d;
    void *v;
    __builtin_memcpy(&v, p + 0x08, sizeof v);
    return v;
}
static inline int desc_w(const void *d) {
    const unsigned char *p = (const unsigned char *)d;
    int v; __builtin_memcpy(&v, p + 0x10, sizeof v);
    return v;
}
static inline int desc_l(const void *d) {
    const unsigned char *p = (const unsigned char *)d;
    int v; __builtin_memcpy(&v, p + 0x14, sizeof v);
    return v;
}
static inline int desc_valid(const void *d) {
    const unsigned char *p = (const unsigned char *)d;
    uint64_t a, b, c;
    __builtin_memcpy(&a, p + 0x00, sizeof a);
    __builtin_memcpy(&b, p + 0x10, sizeof b);
    __builtin_memcpy(&c, p + 0x18, sizeof c);
    return (a == b) && (c == 0);
}

/* 0x180046610 — general (count-tap) Gaussian-FIR apply. */
int cr_gauss_fir_apply(void *a, void *b, int r8, uint16_t count,
                       float unk0, float unk1, float sigma)
{
    (void)r8; (void)unk0; (void)unk1;
    if (!desc_valid(a) || !desc_valid(b)) return 0x69;
    void *buf = NULL;
    if (cr_malloc_aligned16(&buf, 2u * count) != 0) return 0x69;
    int16_t *coef = (int16_t *)buf;
    void *a_data = desc_data(a);
    void *b_data = desc_data(b);
    int W = desc_w(b);
    int L = desc_l(b);
    cr_gaussian_window_q15(coef, sigma, count);
    int status = cr_fir_reflect_rows_guarded(a_data, b_data, coef, count, W, L);
    if (status == 0)
        status = cr_fir_reflect_guarded(a_data, a_data, coef, count, W, L);
    cr_sized_free(&buf);
    return status;
}

/* ------------------------------------------------------------------------ *
 * 0x18001c6a0 — blur/kernel-apply dispatcher.
 *   int fn(void *a, void *b, float sigma, int count, int sel)
 *
 * Leaf tail-jump.  Under the Microsoft x64 ABI a float at argument position 3
 * lands in xmm2 and the position-4 int in r9, so the vendor reads:
 *   a=rcx, b=rdx, sigma=xmm2, count=r9 (zero-extended to 16 bits via
 *   `movzx r9d,r9w`) and the selector from [rsp+0x28] (argument 5, on the
 *   stack).  It overwrites r8 with the jump-table base and dispatches on the
 *   selector's low byte (`cmp r8b,4 ; ja default`).
 *
 * Jump table @ 0x18008c4b0 (dumped from the DLL; note the *non-obvious* order):
 *   sel 0 -> 0x180046610 cr_gauss_fir_apply            (sigma in xmm2)
 *   sel 1 -> 0x180013a30 cr_sep_gauss_blur_s16_reflect (sigma in xmm2)
 *   sel 2 -> 0x180034930 cr_correlate_34930            (sigma in xmm2)
 *   sel 3 -> 0x180034390 cr_ncc_apply_34390            (sigma in xmm2)
 *   sel 4 -> 0x1800278f0 cr_sep_gauss_blur_s16         (sigma in xmm2)
 *   sel > 4 (unsigned low byte) -> return 0x69
 * Every target reads sigma from xmm2 and count from r9, so the dispatcher just
 * forwards them.  r8 is clobbered and ignored by all targets.
 * ------------------------------------------------------------------------ */
int cr_blur_dispatch_1c6a0(void *a, void *b, float sigma, int count, int sel)
{
    unsigned n = (unsigned)(uint16_t)count;   /* vendor: movzx r9d,r9w */
    switch ((uint8_t)sel) {                   /* vendor: cmp r8b,4 ; ja */
    case 0: return cr_gauss_fir_apply(a, b, 0, (uint16_t)n, 0.0f, 0.0f, sigma);
    case 1: return cr_sep_gauss_blur_s16_reflect(a, b, sigma, (int)n);
    case 2: return cr_correlate_34930(a, b, sigma, (int)n);
    case 3: return cr_ncc_apply_34390(a, b, sigma, (uint16_t)n);
    case 4: return cr_sep_gauss_blur_s16(a, b, sigma, n);
    default: return 0x69;
    }
}

/* ------------------------------------------------------------------------ *
 * 0x18001ee30 — blurred-pair difference normaliser.
 *   int fn(cr_image *src, const void *obj)
 *
 * W = src->w, H = src->h, N = W*H.  Allocates two N*2-byte int16 blocks with
 * cr_pool_alloc2 and wraps them as cr_image ia/ib via cr_image_set.  Runs the
 * blur dispatcher twice on the same source, with sigma0 = obj[0], sigma1 =
 * obj[1], count fixed at 0xf and the selector byte at obj+12:
 *     cr_blur_dispatch_1c6a0(&ia, src, obj[0], 0xf, ob[12])
 *     cr_blur_dispatch_1c6a0(&ib, src, obj[1], 0xf, ob[12])
 * Then, writing in place into src->data (dst):
 *     dst[i] = (int16_t)(A[i] - B[i])            ; m = max |dst[i]|
 * frees the pool, sets scale = m ? (int)(0x7f0000/m) : 0x400, and maps every
 * pixel through
 *     t = (dst[i]*scale >> 10) + 0x2000          ; clamp to [0, 0x3fc0]
 * (t < 1 -> 0, t >= 0x3fc0 -> 0x3fc0).
 *
 * Returns 0 on success, else the first failing status.  The pool is freed on
 * every path once it has been allocated.
 * ------------------------------------------------------------------------ */
int cr_blur_diff_norm(cr_image *src, const void *obj)
{
    const float *of = (const float *)obj;
    const uint8_t *ob = (const uint8_t *)obj;
    int W = src->w;
    int H = src->h;
    int N = W * H;

    void *hdr = NULL, *blkA = NULL, *blkB = NULL;
    int r = cr_pool_alloc2(&hdr, &blkA, (uint32_t)(N * 2),
                           &blkB, (uint32_t)(N * 2));
    if (r == 0) {
        cr_image ia, ib;
        r = (int)cr_image_set(&ia, blkA, W, H);
        if (r == 0) {
            r = (int)cr_image_set(&ib, blkB, W, H);
            if (r == 0) {
                r = cr_blur_dispatch_1c6a0(&ia, src, of[0], 0xf, ob[12]);
                if (r == 0)
                    r = cr_blur_dispatch_1c6a0(&ib, src, of[1], 0xf, ob[12]);
                if (r == 0 && N > 0) {
                    int16_t *A = (int16_t *)blkA;
                    int16_t *B = (int16_t *)blkB;
                    int16_t *D = (int16_t *)src->data;
                    int m = 0;
                    for (int i = 0; i < N; i++) {
                        int16_t d = (int16_t)(A[i] - B[i]);
                        D[i] = d;
                        int a  = (int)d;
                        int s  = -(int)((unsigned)a >> 31);   /* 0 or -1 */
                        int av = (a ^ s) - s;
                        if (m < av) m = av;
                    }
                    cr_sized_free_if(&hdr);
                    int scale = 0x400;
                    if (m != 0) scale = (int)(0x7f0000 / (long long)m);
                    for (int i = 0; i < N; i++) {
                        int16_t v = (int16_t)0x3fc0;
                        int t = ((int)D[i] * scale >> 10) + 0x2000;
                        if (t < 0x3fc0) {
                            v = (int16_t)t;
                            if (t < 1) v = 0;
                        }
                        D[i] = v;
                    }
                    return 0;
                }
            }
        }
        cr_sized_free_if(&hdr);
    }
    return r;
}

/* ------------------------------------------------------------------------ *
 * 0x1800148c0 — u8 blurred-pair difference normaliser (float source).
 *   int fn(cr_image *dst, const cr_image *src, const void *obj)
 *
 * W = src->w, H = src->h, N = W*H.  Allocates three N*2-byte int16 blocks via
 * cr_pool_alloc3 (ia/ib/ic) and wraps them as cr_image.  ia becomes the float
 * source scaled by 64 and rounded to int16 (cr_f32_to_i16_scaled shift 6), then
 * ia is blurred twice:
 *     ib = cr_blur_dispatch_1c6a0(&ib, &ia, obj[0], 0xf, ob[12])
 *     ic = cr_blur_dispatch_1c6a0(&ic, &ia, obj[1], 0xf, ob[12])
 * On success with N > 0:
 *     ia[i] = (int16_t)(ib[i] - ic[i])           ; m = max |ia[i]|
 *     scale = m ? (int)(0x7f0000/m) : 0x400      (32-bit signed division)
 *     t     = ((ia[i]*scale + 0x8000) >> 16) + 0x80
 *     dst->data[i] = t > 0xfe ? 0xff : (t <= 0 ? 0 : (uint8_t)t)
 *
 * Returns 0 on success, else the first failing status.  The pool is freed on
 * every post-allocation path.
 * ------------------------------------------------------------------------ */
int cr_blur_diff_norm_u8(cr_image *dst, const cr_image *src, const void *obj)
{
    const float *of = (const float *)obj;
    const uint8_t *ob = (const uint8_t *)obj;
    int W = src->w;
    int H = src->h;
    int N = W * H;

    void *hdr = NULL, *b0 = NULL, *b1 = NULL, *b2 = NULL;
    int r = cr_pool_alloc3(&hdr, &b0, (uint32_t)(N * 2),
                           &b1, (uint32_t)(N * 2),
                           &b2, (uint32_t)(N * 2));
    if (r == 0) {
        cr_image ia, ib, ic;
        r = (int)cr_image_set(&ia, b0, W, H);
        if (r == 0) r = (int)cr_image_set(&ib, b1, W, H);
        if (r == 0) r = (int)cr_image_set(&ic, b2, W, H);
        if (r == 0) {
            cr_f32_to_i16_scaled(&ia, src, 6);
            r = cr_blur_dispatch_1c6a0(&ib, &ia, of[0], 0xf, ob[12]);
            if (r == 0)
                r = cr_blur_dispatch_1c6a0(&ic, &ia, of[1], 0xf, ob[12]);
            if (r == 0 && N > 0) {
                int16_t *A = (int16_t *)b0;
                int16_t *B = (int16_t *)b1;
                int16_t *C = (int16_t *)b2;
                uint8_t *D = (uint8_t *)dst->data;
                int m = 0;
                for (int i = 0; i < N; i++) {
                    int16_t d = (int16_t)(B[i] - C[i]);
                    A[i] = d;
                    int a  = (int)d;
                    int s  = -(int)((unsigned)a >> 31);   /* 0 or -1 */
                    int av = (a ^ s) - s;
                    if (m < av) m = av;
                }
                int scale = 0x400;
                if (m != 0) scale = 0x7f0000 / m;
                for (int i = 0; i < N; i++) {
                    int t = (((int)A[i] * scale + 0x8000) >> 16) + 0x80;
                    uint8_t v;
                    if (t > 0xfe)    v = 0xff;
                    else if (t <= 0) v = 0;
                    else             v = (uint8_t)t;
                    D[i] = v;
                }
            }
        }
        cr_sized_free_if(&hdr);
    }
    return r;
}

/* ------------------------------------------------------------------------ *
 * 0x180013720 — local-contrast normaliser: mean-subtract + abs, blur, a
 * divisive normalisation, then a contrast stretch written back into the input.
 *   int fn(cr_image *img, const void *cfg)
 *
 * cfg: float +4 (blur sigma), float +8 (denominator floor factor), byte +0xc
 * (selector, must be 3 or 4 else 0x69).
 *
 * W = img->w, H = img->h, N = W*H.  Allocates A,B (int16) and C (float), each
 * W×H.  For N > 0:
 *   mean = (sum of sign-extended img pixels) / N        (IDIV, trunc to zero)
 *   for each i: p = (uint16_t)img[i] - mean             (unsigned load!)
 *               img[i] = (int16_t)p
 *               A[i]   = (int16_t)((int16_t)p < 0 ? -p : p)
 *   B = cr_blur_dispatch_1c6a0(&B, &A, sigma, (uint16_t)(int)(sigma*8+1), sel)
 *   maxB = max(0.0f, max_i (float)B[i])
 *   for each i: C[i] = (float)img[i] / max(cfg[2]*maxB, (float)B[i])
 *               mx = max(mx, C[i]); mn = min(mn, C[i])  (init -FLT_MAX / FLT_MAX)
 *   scale = (1.0f > mx-mn) ? 16320.0f : 16320.0f/(mx-mn)
 *   for each i: img[i] = (int16_t)(int32_t)((C[i]-mn)*scale)
 * For N <= 0 it only runs the blur once.  Returns 0 on success, else the first
 * failing status; A/B/C are freed on every post-allocation path.
 * ------------------------------------------------------------------------ */
int cr_blur_divnorm_stretch(cr_image *img, const void *cfg)
{
    const float   *cf = (const float *)cfg;
    const uint8_t *cb = (const uint8_t *)cfg;

    int sel = (int)cb[0xc];                       /* vendor MOVSX/MOVZX byte */
    if ((uint8_t)(sel - 3) > 1u)
        return 0x69;

    int W = img->w;
    int H = img->h;
    int N = W * H;

    cr_image A, B, C;
    int r = cr_image_alloc_s16((int *)&A, W, H);
    if (r != 0) return r;
    r = cr_image_alloc_s16((int *)&B, W, H);
    if (r != 0) { cr_cleanup_ptr8_clear(&A); return r; }
    r = cr_image_alloc_f32(&C, W, H);
    if (r != 0) {
        cr_cleanup_ptr8_clear(&A);
        cr_cleanup_ptr8_clear(&B);
        return r;
    }

    float sigma = cf[1];
    unsigned kcount = (unsigned)(uint16_t)(int)(sigma * 8.0f + 1.0f);

    int16_t *in = (int16_t *)img->data;
    int16_t *Ad = (int16_t *)A.data;
    int16_t *Bd = (int16_t *)B.data;
    float   *Cd = (float *)C.data;

    if (N < 1) {
        r = cr_blur_dispatch_1c6a0(&B, &A, sigma, (int)kcount, sel);
        cr_cleanup_ptr8_clear(&A);
        cr_cleanup_ptr8_clear(&B);
        cr_cleanup_ptr8_clear_b(&C);
        return r;
    }

    int32_t sum = 0;
    for (int i = 0; i < N; i++) sum += (int)in[i];
    int mean = sum / N;

    for (int i = 0; i < N; i++) {
        int p = (int)(uint16_t)in[i] - mean;
        in[i] = (int16_t)p;
        int32_t q = ((int16_t)p < 0) ? -p : p;
        Ad[i] = (int16_t)q;
    }

    r = cr_blur_dispatch_1c6a0(&B, &A, sigma, (int)kcount, sel);
    if (r != 0) {
        cr_cleanup_ptr8_clear(&A);
        cr_cleanup_ptr8_clear(&B);
        cr_cleanup_ptr8_clear_b(&C);
        return r;
    }

    float maxB = 0.0f;
    for (int i = 0; i < N; i++) {
        float v = (float)Bd[i];
        if (v > maxB) maxB = v;
    }

    float f8 = cf[2];
    float mx = -FLT_MAX, mn = FLT_MAX;
    for (int i = 0; i < N; i++) {
        float denom = f8 * maxB;
        float bv = (float)Bd[i];
        if (bv > denom) denom = bv;
        float c = (float)in[i] / denom;
        Cd[i] = c;
        if (c > mx) mx = c;
        if (c < mn) mn = c;
    }

    float range = mx - mn;
    float scale = 16320.0f;
    if (!(1.0f > range)) scale = 16320.0f / range;

    for (int i = 0; i < N; i++)
        in[i] = (int16_t)(int32_t)((Cd[i] - mn) * scale);

    cr_cleanup_ptr8_clear(&A);
    cr_cleanup_ptr8_clear(&B);
    cr_cleanup_ptr8_clear_b(&C);
    return 0;
}

/* 0x180044a20 — fixed 7-tap twin.  When W is 8-aligned it uses the guarded
 * row/reflect FIRs (returning the guard status); otherwise the fixed fir7_reflect
 * + vfir7_cols pair (always returning 0). */
int cr_gauss_fir7_apply(void *a, void *b, float unk0, float unk1, float sigma)
{
    (void)unk0; (void)unk1;
    if (!desc_valid(a) || !desc_valid(b)) return 0x69;
    int16_t coef[7];
    void *a_data = desc_data(a);
    void *b_data = desc_data(b);
    int W = desc_w(b);
    int L = desc_l(b);
    cr_gaussian_window_q15(coef, sigma, 7);
    if ((W & 7) == 0) {
        int status = cr_fir_reflect_rows_guarded(a_data, b_data, coef, 7, W, L);
        if (status == 0)
            status = cr_fir_reflect_guarded(a_data, a_data, coef, 7, W, L);
        return status;
    }
    cr_fir7_reflect(a_data, b_data, coef, W, L);
    cr_vfir7_cols(a_data, a_data, coef, W, L);
    return 0;
}
