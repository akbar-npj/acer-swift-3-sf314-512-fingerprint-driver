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
#include <stdio.h>

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

/* ------------------------------------------------------------------------ *
 * 0x180045eb0 — oriented 5x5 matched filter, max-pooled, into an int16 image.
 *   int fn(int16_t *out, const uint8_t *const *rows, const void *cfg)
 *
 * cfg: int +0x0c (kernel-bank stride multiplier), int +0x10 (W), int +0x14 (H),
 * int +0x18 (flag), ptr +0x20 (kernel bank: int16, 25/kernel), ptr +0x28
 * (per-row bias: int16).  For each output row r (0..H-1) with bias =
 * (int16)mbase[r] << 14 and kernel block kptr = kbase + r*kmul*25:
 *   - chunk pass over byte offsets off = 0,4,..,4*u  (u = (W-2)>>1): a 5x5
 *     convolution of rows[0..4] and rows[1..5] at 4 horizontal offsets, taking
 *     out[2k] = scale(max(a0,a1,b0,b1)), out[2k+1] = scale(max(a2,a3,b2,b3));
 *   - tail pass over columns j = 2u+2 .. W-1 (only 2 offsets each):
 *     out[j] = scale(max(a0,a1,b0,b1));
 * where scale(v) = (int16)(((uint32_t)v << 6) + bias) >> 15 (wrapping, SAR).
 * If flag == 1 the whole output is clamped non-negative at the end.  Always
 * returns 0.
 * ------------------------------------------------------------------------ */
static void mf_conv4(const uint8_t *const *rows, const int16_t *k, int off, int *o)
{
    int s0 = 0, s1 = 0, s2 = 0, s3 = 0;
    for (int r = 0; r < 5; r++) {
        const uint8_t *row = rows[r] + off;
        int c0 = row[0], c1 = row[1], c2 = row[2], c3 = row[3];
        int c4 = row[4], c5 = row[5], c6 = row[6], c7 = row[7];
        const int16_t *kk = k + r * 5;
        int k0 = kk[0], k1 = kk[1], k2 = kk[2], k3 = kk[3], k4 = kk[4];
        s0 += c0 * k0 + c1 * k1 + c2 * k2 + c3 * k3 + c4 * k4;
        s1 += c1 * k0 + c2 * k1 + c3 * k2 + c4 * k3 + c5 * k4;
        s2 += c2 * k0 + c3 * k1 + c4 * k2 + c5 * k3 + c6 * k4;
        s3 += c3 * k0 + c4 * k1 + c5 * k2 + c6 * k3 + c7 * k4;
    }
    o[0] = s0; o[1] = s1; o[2] = s2; o[3] = s3;
}

static void mf_conv2(const uint8_t *const *rows, const int16_t *k, int off, int *o)
{
    int s0 = 0, s1 = 0;
    for (int r = 0; r < 5; r++) {
        const uint8_t *row = rows[r] + off;
        int c0 = row[0], c1 = row[1], c2 = row[2], c3 = row[3], c4 = row[4], c5 = row[5];
        const int16_t *kk = k + r * 5;
        int k0 = kk[0], k1 = kk[1], k2 = kk[2], k3 = kk[3], k4 = kk[4];
        s0 += c0 * k0 + c1 * k1 + c2 * k2 + c3 * k3 + c4 * k4;
        s1 += c1 * k0 + c2 * k1 + c3 * k2 + c4 * k3 + c5 * k4;
    }
    o[0] = s0; o[1] = s1;
}

static int16_t mf_scale(int v, uint32_t bias)
{
    uint32_t t = ((uint32_t)v << 6) + bias;
    return (int16_t)((int32_t)t >> 15);
}

int cr_matched_filter_45eb0(int16_t *out, const uint8_t *const *rows,
                            const void *cfg)
{
    const uint8_t *cb = (const uint8_t *)cfg;
    int W = *(const int32_t *)(cb + 0x10);
    int H = *(const int32_t *)(cb + 0x14);
    int kmul = *(const int32_t *)(cb + 0x0c);
    const int16_t *kbase = *(const int16_t *const *)(cb + 0x20);
    const int16_t *mbase = *(const int16_t *const *)(cb + 0x28);
    int flag = *(const int32_t *)(cb + 0x18);

    if (H > 0) {
        int rowbase = 0;
        const int16_t *kptr = kbase;
        long kstep = (long)kmul * 25;                 /* shorts per row */
        int r14end = 0, tailstart = 0;

        if (W > 1) {                                  /* only meaningful for W >= 2 */
            int u = (int)(((unsigned)W - 2u) >> 1);
            r14end = 4 + u * 4;
            tailstart = 2 * u + 2;
        }

        for (int r = 0; r < H; r++) {
            uint32_t bias = (uint32_t)(int32_t)mbase[r] << 14;
            int16_t *orow = out + rowbase;

            if (W > 1) {
                for (int off = 0; off != r14end; off += 4) {
                    int A[4], B[4];
                    mf_conv4(rows, kptr, off, A);
                    mf_conv4(rows + 1, kptr, off, B);
                    int o0 = A[0]; if (A[1] > o0) o0 = A[1];
                    if (B[0] > o0) o0 = B[0];
                    if (B[1] > o0) o0 = B[1];
                    int o1 = A[2]; if (A[3] > o1) o1 = A[3];
                    if (B[2] > o1) o1 = B[2];
                    if (B[3] > o1) o1 = B[3];
                    orow[off >> 1]       = mf_scale(o0, bias);
                    orow[(off >> 1) + 1] = mf_scale(o1, bias);
                }
            }

            int start = (W > 1) ? tailstart : 0;
            for (int j = start; j < W; j++) {
                int A[2], B[2];
                mf_conv2(rows, kptr, 2 * j, A);
                mf_conv2(rows + 1, kptr, 2 * j, B);
                int m = A[0]; if (A[1] > m) m = A[1];
                if (B[0] > m) m = B[0];
                if (B[1] > m) m = B[1];
                orow[j] = mf_scale(m, bias);
            }

            rowbase += W;
            kptr += kstep;
        }
    }

    if (flag == 1)
        cr_s16_clamp_nonneg(out, out, W * H);
    return 0;
}

/* 0x180035cf0 — frame quality gate / match decision.
 *
 * int fn(cr_image *img, float *out_q, uint8_t *out_flag, void *state,
 *        void *src, void *handle, const void *cfg)
 *
 * MS x64 ABI: rcx/rdx/r8/r9 = img/out_q/out_flag/state; src/handle/cfg are the
 * 5th/6th/7th args on the stack.  `handle` is a TLV metadata store read through
 * cr_meta_get_u32.  `state`: +0x00 ptr to a >=0x14-byte history, +0x10 previous
 * image data (int16), +0x40 frame count, +0x44 frame counter, +0x48 running
 * quality average, +0x4c running score average.  `cfg`: +0x08 max level,
 * +0x0c min quality, +0x10 margin x, +0x14 margin y, +0x18 diff flag (signed),
 * +0x1c ratio, +0x20 flag threshold, +0x2c mode (0/2/3), +0x30 scale.
 * Returns 0 / 0x3eb / 0x3ec or the first failing status; sets *out_flag to 1
 * when the frame passes the running-score gate.
 */
int cr_quality_gate_35cf0(cr_image *img, float *out_q, uint8_t *out_flag,
                          void *state, void *src, void *handle, const void *cfg)
{
    const uint8_t *c = (const uint8_t *)cfg;
    uint8_t *st = (uint8_t *)state;
    int32_t local_90;                 /* rsp+0x60 */
    int32_t local_84;                 /* rsp+0x6c: correlation valid flag */
    float   local_8c;                 /* rsp+0x64: correlation coefficient */
    float   fv13;
    float   q;

    if (handle == NULL)
        return 0x3ec;

    *out_flag = 0;
    local_8c = 1.0f;

    {
        int32_t ctr = *(int32_t *)(st + 0x44);
        if (ctr != 0x7fffffff)
            *(int32_t *)(st + 0x44) = ctr + 1;
    }

    if (*(const int8_t *)(c + 0x2c) == 0) {
        local_90 = 200;
        fv13 = 10.0f;
    } else {
        if (cr_meta_get_u32(handle, 0xda, (uint32_t *)&local_90) != 0)
            return 0x3eb;
        if (*(const int8_t *)(c + 0x2c) == 2) {
            int32_t t;
            if (cr_meta_get_u32(handle, 0xdd, (uint32_t *)&t) != 0)
                return 0x3eb;
            fv13 = (float)t * 0.0009765625f;
            if (fv13 < 1.0f)
                return 0x3ec;
            local_90 = 0xff - local_90;
        } else if (*(const int8_t *)(c + 0x2c) == 3) {
            int32_t t;
            if (cr_meta_get_u32(handle, 0xdd, (uint32_t *)&t) != 0)
                return 0x3eb;
            fv13 = (float)t * 0.0009765625f;
            if (fv13 < 1.0f)
                return 0x3ec;
        } else {
            fv13 = 10.0f;
        }
    }

    {
        int32_t a, b;
        float fa, fb;
        if (cr_meta_get_u32(handle, 0xd2, (uint32_t *)&a) != 0)
            return 0x3eb;
        if (cr_meta_get_u32(handle, 0xd6, (uint32_t *)&b) != 0)
            return 0x3eb;

        fa = (float)a * 0.0009765625f;
        if (1.0f > fa)
            return 0x3ec;
        fb = 0.0009765625f * (float)b;
        if (1.0f > fb)
            return 0x3ec;

        if (*(const int32_t *)(c + 0x08) >= local_90)
            return 0;

        q = *(const float *)(c + 0x30) *
            (1.0f / ((float)local_90 * fa * fb * fv13));
        *out_q = q;
        if (q > 2.0078433f)
            return 0;
    }

    {
        int32_t count = *(const int32_t *)(st + 0x40);
        float avg_q = *(const float *)(st + 0x48);
        float ratio = *(const float *)(c + 0x1c);
        int do_gate = 1;

        if (count > 0xff) {
            avg_q = (q + avg_q * 255.0f) * 0.00390625f;
            *(float *)(st + 0x48) = avg_q;
            q = avg_q * ratio;
        } else {
            float fc = (float)count;
            float na = (q + avg_q * fc) / (fc + 1.0f);
            *(float *)(st + 0x48) = na;
            if (count <= 1)
                do_gate = 0;
            else
                q = na * ratio;
        }
        if (do_gate && *out_q > q)
            return 0;
    }

    {
        int32_t hh, ww;
        int r = cr_downsample_mean(img, (const cr_image *)src, 4);
        if (r != 0)
            return r;

        hh = *(const int32_t *)((const uint8_t *)img + 0x14);
        ww = *(const int32_t *)((const uint8_t *)img + 0x10);

        if (*(const int8_t *)(c + 0x18) > 0) {
            uint64_t desc[4] __attribute__((aligned(16)));
            int s;
            if ((s = cr_image_alloc_s16((int *)desc, ww, hh)) != 0)
                return s;
            if ((s = cr_ncc_apply_f8b0(desc, (const uint64_t *)img, 5)) != 0) {
                cr_cleanup_ptr8_clear(desc);
                return s;
            }
            {
                int n = hh * ww;
                if (n > 0) {
                    int16_t *idp = *(int16_t **)((uint8_t *)img + 8);
                    int16_t *rdp = *(int16_t **)((uint8_t *)desc + 8);
                    for (int i = 0; i < n; i++) {
                        uint16_t v = (uint16_t)idp[i];
                        if ((int16_t)v <= 0xf9)
                            idp[i] = (int16_t)(uint16_t)(v - (uint16_t)rdp[i]);
                    }
                }
            }
            cr_cleanup_ptr8_clear(desc);
            hh = *(const int32_t *)((const uint8_t *)img + 0x14);
            ww = *(const int32_t *)((const uint8_t *)img + 0x10);
        }

        local_84 = 0;
        cr_corr_coeff(&local_8c, &local_84,
                      *(const int16_t **)((uint8_t *)img + 8),
                      *(const int16_t **)(st + 0x10),
                      ww, hh, 0xfa,
                      *(const int32_t *)(c + 0x10),
                      *(const int32_t *)(c + 0x14));

        {
            int pass = 1;
            uint8_t *hist;
            int sum = 0;

            if (*(const int32_t *)(st + 0x40) != 0) {
                pass = 0;
                if (*(const float *)(c + 0x0c) > local_8c)
                    pass = (local_84 == 1);
            }

            hist = *(uint8_t **)st;
            for (int i = 0x12; i >= 0; i--) {
                hist[i + 1] = hist[i];
                sum += hist[i + 1];
            }
            if (pass) {
                hist[0] = 1;
                int n = *(const int32_t *)((const uint8_t *)img + 0x10) *
                        *(const int32_t *)((const uint8_t *)img + 0x14);
                if (n > 0) {
                    int16_t *sd = *(int16_t **)((uint8_t *)img + 8);
                    int16_t *dd = *(int16_t **)(st + 0x10);
                    for (int i = 0; i < n; i++)
                        dd[i] = sd[i];
                }
            } else {
                hist[0] = 0;
            }
            sum += hist[0];

            {
                int32_t counter = *(const int32_t *)(st + 0x44);
                float div1, div2, avg_s;
                if (counter > 0x14) {
                    div2 = 21.0f;
                    div1 = 20.0f;
                } else {
                    div1 = (float)counter;
                    div2 = div1 + 1.0f;
                }
                avg_s = ((float)sum / div1 +
                         div1 * *(const float *)(st + 0x4c)) / div2;
                *(float *)(st + 0x4c) = avg_s;
                if (pass) {
                    if (avg_s > *(const float *)(c + 0x20))
                        *out_flag = 1;
                }
            }
        }
    }

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

/* 0x18001bbf0 — scale-space Laplacian blob/keypoint detector.
 *
 * Validates the scaled-image bounds held in `desc` (a = image width,
 * b = image height, data = pixels, w/h = scaled width/height, offx/offy =
 * margins), then runs an 11-tap separable Gaussian over successive source rows
 * into a 6-row int16 scratch ring, takes the 3x3 Laplacian of three
 * consecutive smoothed rows, and for every strictly-greater 3x3 local maximum
 * whose mask bit is set inserts a grid point
 *   (x = mode + col, y = row, v = (float)centre).
 * cfg: byte +8 = mode (margin), float +0x1c = sigma.
 * maskcfg: [0] = bit-row stride, [2..3] = word pointer, [6]/[7] = x/y origin.
 * Returns 0x69 on bounds/alloc failure, else 0. */
int cr_blob_detect_1bbf0(cr_grid *grid, const cr_image *desc,
                         const int32_t *maskcfg, const void *cfg)
{
    const uint8_t *c = (const uint8_t *)cfg;
    int mode = (int)(int8_t)c[8];
    int D6 = desc->offx;
    int D7 = desc->offy;

    if (D6 + mode <= 6) return 0x69;
    int w = desc->a;
    if (desc->w + 7 + (D6 - mode) > w) return 0x69;
    if (D7 + mode <= 6) return 0x69;
    int D5 = desc->h;
    if (D5 + 7 + (D7 - mode) > desc->b) return 0x69;

    int Wn = desc->w - 2 * mode;
    int W2 = Wn + 2;
    int W4 = Wn + 4;
    int S  = Wn + 0xe;

    int16_t *buf = NULL;
    int status = cr_malloc_aligned16((void **)&buf,
                     (size_t)(((uint32_t)Wn + 0xcu + (uint32_t)W4) * 3u) * 2u);
    if (status != 0) return status;

    const uint8_t *pix = (const uint8_t *)desc->data;
    int32_t off = (int32_t)((D7 + mode - 2) * w) + D6 + mode;
    const uint8_t *src = pix + (intptr_t)(int64_t)off - 2;

    int16_t coef[24];
    cr_gaussian_window_q15(coef, *(const float *)(const void *)(c + 0x1c), 11);

    int16_t *row0 = buf;
    int16_t *row1 = buf + S;
    int16_t *row2 = buf + 2 * S;
    int16_t *p3S  = buf + 3 * S;

    cr_sep11_row(row2, src, coef, W4, w); src += w;
    cr_sep11_row(row1, src, coef, W4, w); src += w;
    cr_sep11_row(row0, src, coef, W4, w); src += w;
    cr_laplacian_3x3(p3S + W2, row2, row1, row0, W2);
    cr_sep11_row(row2, src, coef, W4, w);
    cr_laplacian_3x3(p3S, row1, row0, row2, W2);

    int bound = D5 - mode;
    if (mode < bound) {
        int16_t *psVar7  = row1;
        int16_t *psVar16 = row2;
        int16_t *psVar23 = row0;
        int16_t *psVar8  = buf + 5 * S - 0x18;
        int16_t *psVar21 = p3S;
        int16_t *psVar19 = p3S + W2;
        const uint32_t *mask =
            (const uint32_t *)(uintptr_t)(((uint64_t)(uint32_t)maskcfg[3] << 32) |
                                          (uint32_t)maskcfg[2]);
        int y = mode;
        do {
            int16_t *psVar22 = psVar16;
            int16_t *psVar18 = psVar8;
            psVar16 = psVar7;
            src += w;
            cr_sep11_row(psVar16, src, coef, W4, w);
            cr_laplacian_3x3(psVar18, psVar23, psVar22, psVar16, W2);
            if (Wn > 0) {
                for (int col = 0; col < Wn; col++) {
                    int16_t sVar5 = psVar21[col + 1];
                    if (psVar19[col] < sVar5 && psVar19[col + 1] < sVar5 &&
                        psVar19[col + 2] < sVar5 &&
                        psVar21[col] < sVar5 && psVar21[col + 2] < sVar5 &&
                        psVar18[col] < sVar5 && psVar18[col + 1] < sVar5 &&
                        psVar18[col + 2] < sVar5) {
                        int32_t bit = mode + col + maskcfg[6];
                        int32_t idx = (maskcfg[7] + y) * maskcfg[0] + bit;
                        if ((mask[idx >> 5] >> (uint32_t)(bit & 0x1f)) & 1u) {
                            cr_grid_insert(grid, (uint8_t)(mode + col), (uint8_t)y,
                                           (float)(int)sVar5, (cr_grid_cfg *)cfg);
                        }
                    }
                }
            }
            y++;
            psVar7  = psVar23;
            psVar8  = psVar19;
            psVar19 = psVar21;
            psVar21 = psVar18;
            psVar23 = psVar22;
        } while (y != bound);
    }

    cr_sized_free((void **)&buf);
    return 0;
}

/* 0x18000d3b0 — Gaussian-derivative structure-tensor orientation encoder.
 *
 * Builds two W×H int16 images A (Gaussian d/dx) and B (Gaussian d/dy) from the
 * source via cr_gauss_deriv_3img, then for every pixel computes the 2×2
 * structure-tensor eigen-decomposition of (aa, ab, bb) = (A², A·B, B²):
 *   half = (aa+bb)*0.5;  s = cr_sqrtf(half² - (aa·bb - ab²));  l1 = half+s; l2 = half-s
 * and encodes the dominant eigenvector as a double-angle pair
 *   (cross, diff) = (ab, |l1|>=|l2| ? l2-aa : l1-aa)
 * scaled by the coherence ((|l1|-|l2|)² / (|l1|²+|l2|²+1e-7)) * 16383 into
 *   A[i] = (int16)((cross²-diff²)/norm · coh),  B[i] = (int16)(2·cross·diff/norm · coh).
 * When cfg->flag == 1 the coherence is zeroed for pixels where
 * (mask[i] & and_mask) == 0.  Both images are then blurred (a single
 * cr_blur_dispatch_1c6a0 pass when count == 1, else `count` passes of
 * cr_gaussian_fir_2pass) and finally fed to cr_cordic_atan_q15(dst, B, A, N, 2).
 * Returns 0, or the first failing status (the pool is always freed). */
int cr_structure_orient_d3b0(void *dst, const cr_image *src, const void *mask,
                             uint8_t and_mask, const void *cfg)
{
    const uint8_t *c = (const uint8_t *)cfg;
    int W = *(const int *)((const uint8_t *)src + 0x10);
    int H = *(const int *)((const uint8_t *)src + 0x14);
    int16_t count = *(const int16_t *)(c + 0x0c);
    uint8_t flag  = c[0x0f];
    float   sigma1 = *(const float *)(c + 0x04);
    float   sigma2 = *(const float *)(c + 0x08);

    cr_image A, B;
    uint32_t r = cr_image_set(&A, NULL, W, H);
    if (r != 0) return (int)r;
    r = cr_image_set(&B, NULL, W, H);
    if (r != 0) return (int)r;

    int N = H * W;
    uint64_t pool[2];
    uint32_t pr = cr_pool_alloc2((void **)pool, &A.data, (uint32_t)(N * 2),
                                 &B.data, (uint32_t)(N * 2));
    if (pr != 0) return (int)pr;

    int st = cr_gauss_deriv_3img(&A, &B, (void *)src, sigma1);
    if (st != 0) { cr_sized_free_if((void **)pool); return st; }

    int16_t *Ad = (int16_t *)A.data;
    int16_t *Bd = (int16_t *)B.data;
    const uint8_t *maskd = *(const uint8_t *const *)((const uint8_t *)mask + 8);

    for (int i = 0; i < N; i++) {
        float fb = (float)(int)Bd[i];
        float fa = (float)(int)Ad[i];
        float bb  = fb * fb;
        float ab  = fb * fa;
        float aa  = fa * fa;
        float ab2 = ab * ab;

        float cross, diff, s6, s2;
        if (1e-12f > ab2) {
            s6 = aa;
            s2 = bb;
            int mb = !(s6 < s2);
            cross = mb ? 0.0f : 1.0f;
            diff  = mb ? 1.0f : 0.0f;
        } else {
            float det  = bb * aa;
            float half = (bb + aa) * 0.5f;
            det = det - ab2;
            float t = half * half;
            t = t - det;
            float s  = cr_sqrtf(t);
            float l1 = half + s;
            float l2 = half - s;
            float d1 = l1 - aa;
            float d2 = l2 - aa;
            s6 = (0.0f > l1) ? -l1 : l1;
            s2 = (0.0f > l2) ? -l2 : l2;
            int mb = !(s6 < s2);
            cross = ab;
            diff  = mb ? d2 : d1;
        }

        float n1  = s6 * s6;
        float n2  = s2 * s2;
        float dd  = s6 - s2;
        float den = (n1 + n2) + 1e-07f;
        dd = dd * dd;
        float coh = dd / den;
        coh = coh * 16383.0f;

        float c2   = cross * cross;
        float df2  = diff * diff;
        float cd   = cross * diff;
        float norm = c2 + df2;
        float vA   = c2 - df2;
        float vB   = cd / norm;
        vA = vA / norm;
        vB = vB + vB;

        if (flag == 1 && (maskd[i] & and_mask) == 0)
            coh = 0.0f;

        Ad[i] = (int16_t)(int32_t)(vA * coh);
        Bd[i] = (int16_t)(int32_t)(vB * coh);
    }

    int16_t *out = *(int16_t *const *)((const uint8_t *)dst + 8);

    if (count == 1) {
        int m = (A.w <= B.h) ? A.w : B.h;
        int cc = (m - 1) | 1;
        if (cc > 0x51) cc = 0x51;
        uint16_t cnt = (uint16_t)cc;
        int e = cr_blur_dispatch_1c6a0(&A, &A, sigma2, cnt, 0);
        if (e != 0) { cr_sized_free_if((void **)pool); return e; }
        e = cr_blur_dispatch_1c6a0(&B, &B, sigma2, cnt, 0);
        if (e != 0) { cr_sized_free_if((void **)pool); return e; }
    } else if (count > 0) {
        for (int k = 0; k < count; k++) {
            int e = cr_gaussian_fir_2pass(&A, &A, sigma2);
            if (e != 0) { cr_sized_free_if((void **)pool); return e; }
            e = cr_gaussian_fir_2pass(&B, &B, sigma2);
            if (e != 0) { cr_sized_free_if((void **)pool); return e; }
        }
    }

    cr_cordic_atan_q15(out, Bd, Ad, N, 2);
    cr_sized_free_if((void **)pool);
    return 0;
}

/* 0x18003b960 — Gaussian-derivative structure-tensor orientation (3-image twin).
 *
 * Near-identical to cr_structure_orient_d3b0 (0x18000d3b0) but the per-pixel
 * tensor components arrive precomputed from cr_gauss_deriv_triple_guarded into
 * three int16 images o1/o2/o3 (I1/I2/I3).  The 2x2 tensor is [[o1, o2],[o2, o3]],
 * i.e. the loop's roles are fVar15=o3 (other diagonal), fVar19=o2 (off-diagonal)
 * and fVar18=o1 (baseline diagonal).  output1 is written back into I1 and
 * output2 into I3; I1 and I3 are then blurred and cr_cordic_atan_q15(dst->data,
 * I3, I1, N, 2) is run.  rcx=dst, rdx=src image, r8=mask, r9=and_mask, [rsp]=cfg.
 * cfg: int16 +0xc=count, uint8 +0xf=flag, float +0x04=sigma1, +0x08=sigma2.
 * Returns 0 / first failing status. */
int cr_structure_orient_3b960(void *dst, const void *src, const void *mask,
                              uint8_t and_mask, const void *cfg)
{
    const uint8_t *c = (const uint8_t *)cfg;
    const uint8_t *s = (const uint8_t *)src;
    int W = *(const int *)(s + 0x10);
    int H = *(const int *)(s + 0x14);
    int16_t count = *(const int16_t *)(c + 0x0c);
    uint8_t flag  = c[0x0f];
    float   sigma1 = *(const float *)(c + 0x04);
    float   sigma2 = *(const float *)(c + 0x08);

    cr_image I1, I2, I3;
    uint32_t r = cr_image_set(&I1, NULL, W, H);
    if (r != 0) return (int)r;
    r = cr_image_set(&I2, NULL, W, H);
    if (r != 0) return (int)r;
    r = cr_image_set(&I3, NULL, W, H);
    if (r != 0) return (int)r;

    int N = H * W;
    uint64_t pool[2];
    uint32_t pr = cr_pool_alloc3((void **)pool, &I1.data, (uint32_t)(N * 2),
                                 &I2.data, (uint32_t)(N * 2),
                                 &I3.data, (uint32_t)(N * 2));
    if (pr != 0) return (int)pr;

    int st = cr_gauss_deriv_triple_guarded(&I1, &I2, &I3, src, sigma1);
    if (st != 0) { cr_sized_free_if((void **)pool); return st; }

    int16_t *p1 = (int16_t *)I1.data;  /* o1: baseline diagonal, gets output1 */
    int16_t *p2 = (int16_t *)I2.data;  /* o2: off-diagonal (read only) */
    int16_t *p3 = (int16_t *)I3.data;  /* o3: other diagonal, gets output2 */
    const uint8_t *maskd = *(const uint8_t *const *)((const uint8_t *)mask + 8);

    for (int l = 0; l < N; l++) {
        /* Assembly mapping: gauss outputs o1->I1, o2->I2, o3->I3, and the
         * per-pixel roles are fVar15=o3 (other diagonal), fVar19=o2
         * (off-diagonal), fVar18=o1 (baseline diagonal). */
        float o1 = (float)(int)p1[l];
        float o2 = (float)(int)p2[l];
        float o3 = (float)(int)p3[l];
        float f15 = o3, f19 = o2, f18 = o1;
        float f14, f17, f16;
        int small = (f19 * f19 < 1e-12f);

        if (small) {
            f14 = 0.0f; f17 = 0.0f; f16 = 1.0f; f19 = 1.0f;
        } else {
            float f20 = (f15 + f18) * 0.5f;
            f14 = cr_sqrtf(f20 * f20 - (f15 * f18 - f19 * f19));
            f15 = f20 - f14;   /* l2 */
            f17 = (f20 + f14) - f18;  /* l1 - c */
            f16 = f15 - f18;   /* l2 - c */
            f18 = f20 + f14;   /* l1 */
            f14 = f19;   /* ab */
        }
        if (f18 < 0.0f) f18 = -f18;   /* |l1| (or |c| in small) */
        if (f15 < 0.0f) f15 = -f15;   /* |l2| (or |a| in small) */
        /* REA: uVar7 = (fVar15 <= fVar18) == (|l2| <= |l1|) == mb.
         * cross = uVar7 ? fVar14 : fVar19 ;  diff = uVar7 ? fVar16 : fVar17. */
        int mb = !(f18 < f15);   /* uVar7 = (|l2| <= |l1|) */
        float cross = mb ? f14 : f19;   /* uVar7 ? fVar14 : fVar19 */
        float diff  = mb ? f16 : f17;   /* uVar7 ? fVar16 : fVar17 */
        float coh = ((f18 - f15) * (f18 - f15)) /
                    (f18 * f18 + f15 * f15 + 1e-07f);
        coh = coh * 16383.0f;
        float norm = cross * cross + diff * diff;
        float cd   = cross * diff / norm;
        if (flag == 1 && (maskd[l] & and_mask) == 0)
            coh = 0.0f;
        /* output1 -> I1 (image0), output2 -> I3 (image2); the blur then
         * rewrites I1 and I3 and the cordic reads (I3, I1). */
        p1[l] = (int16_t)(int32_t)((cross * cross - diff * diff) / norm * coh);
        p3[l] = (int16_t)(int32_t)((cd + cd) * coh);
    }

    int16_t *out = *(int16_t *const *)((const uint8_t *)dst + 8);

    if (count == 1) {
        int m = (I1.w <= I3.h) ? I1.w : I3.h;
        int cc = (m - 1) | 1;
        if (cc > 0x51) cc = 0x51;
        uint16_t cnt = (uint16_t)cc;
        int e = cr_blur_dispatch_1c6a0(&I1, &I1, sigma2, cnt, 0);
        if (e != 0) { cr_sized_free_if((void **)pool); return e; }
        e = cr_blur_dispatch_1c6a0(&I3, &I3, sigma2, cnt, 0);
        if (e != 0) { cr_sized_free_if((void **)pool); return e; }
    } else if (count > 0) {
        for (int k = 0; k < count; k++) {
            int e = cr_gaussian_fir_2pass(&I1, &I1, sigma2);
            if (e != 0) { cr_sized_free_if((void **)pool); return e; }
            e = cr_gaussian_fir_2pass(&I3, &I3, sigma2);
            if (e != 0) { cr_sized_free_if((void **)pool); return e; }
        }
    }

    cr_cordic_atan_q15(out, p3, p1, N, 2);
    cr_sized_free_if((void **)pool);
    return 0;
}

/* 0x180014320 — mask-weighted spatial bin selection.
 *
 * int fn(void *pts, int *out_count, int npts, int maxout, const void *mask,
 *        uint32_t seed, const void *cfg)  [rcx,rdx,r8d,r9d,[rsp+0x20],+0x28,+0x30]
 *
 * pts: npts records of 8 bytes { int32 key(+0); int16 x(+4); int16 y(+6) }.
 * mask: bitmap descriptor { int stride(+0); int pad(+4); uint32 *words(+8);
 *       int w(+0x10); int h(+0x14); int x0(+0x18); int y0(+0x1c) }.
 * cfg:  { int8 margin(+8); int16 maxpts(+0x10); int weight(+0x14);
 *         uint8 NX(+0x25); uint8 NY(+0x26) }.
 * seed: RNG seed handed to cr_shuffle_indices.
 *
 * Bins every point into an NX*NY grid (cell = ceil((dim-2m)/n)), building a
 * per-bin singly-linked list of point indices (bin_head / next_ptr) and a bin
 * population (bin_count); the key is first copied from +0 to +4 of each record.
 * Then, for every bin, sums the mask bits over its pixel window, computes a
 * density threshold cr_lroundf(bits*weight / (bw*bh*nb)) and caps the bin
 * population to it.  Finally counts empty bins, shuffles the bin order, and
 * round-robins over the shuffled bins popping one point at a time into the
 * front of pts (out[i] = in[head].key) until maxout points or all bins empty.
 * Sets *out_count and returns 0 / first failing status. */
int cr_bin_select_14320(void *pts, int *out_count, int npts, int maxout,
                        const void *mask, uint32_t seed, const void *cfg)
{
    const uint8_t *cf = (const uint8_t *)cfg;
    const uint8_t *mk = (const uint8_t *)mask;
    int margin = (int)*(const int8_t *)(cf + 8);
    int NX = cf[0x25];
    int NY = cf[0x26];
    int H  = *(const int *)(mk + 0x14);
    int W  = *(const int *)(mk + 0x10);
    int weight = *(const int *)(cf + 0x14);
    int maxpts = (int)*(const int16_t *)(cf + 0x10);
    int stride = *(const int *)(mk + 0x00);
    int x0 = *(const int *)(mk + 0x18);
    int y0 = *(const int *)(mk + 0x1c);
    const uint32_t *words = *(const uint32_t *const *)(mk + 0x08);

    int nb = NX * NY;
    int32_t *bin_count = NULL, *next_ptr = NULL, *bin_head = NULL, *order = NULL;
    int st;

    st = cr_malloc_aligned16((void **)&bin_count, (size_t)nb * 4);
    if (st != 0) return st;
    st = cr_malloc_aligned16((void **)&next_ptr, (size_t)maxpts * 4);
    if (st != 0) { cr_sized_free((void **)&bin_count); return st; }
    st = cr_malloc_aligned16((void **)&bin_head, (size_t)nb * 4);
    if (st != 0) { cr_sized_free((void **)&bin_count); cr_sized_free((void **)&next_ptr); return st; }
    st = cr_malloc_aligned16((void **)&order, (size_t)nb * 4);
    if (st != 0) { cr_sized_free((void **)&bin_count); cr_sized_free((void **)&next_ptr);
                   cr_sized_free((void **)&bin_head); return st; }

    for (int i = 0; i < nb; i++) { bin_head[i] = -1; bin_count[i] = 0; }

    int Wm = W + margin * -2;
    int Hm = H + margin * -2;
    int bw = (Wm - 1 + NX) / NX;
    int bh = (NY - 1 + Hm) / NY;

    for (int idx = npts - 1; idx >= 0; idx--) {
        uint8_t *rec = (uint8_t *)pts + (int64_t)idx * 8;
        int bx = (*(const int16_t *)(rec + 4) - margin) / bw;
        if (bx < 0) bx = 0;
        int by = (*(const int16_t *)(rec + 6) - margin) / bh;
        *(int32_t *)(rec + 4) = *(const int32_t *)rec;
        if (by < 0) by = 0;
        if (NY - 1 < by) by = NY - 1;
        if (NX - 1 < bx) bx = NX - 1;
        int bi = by * NX + bx;
        bin_count[bi]++;
        if (bin_head[bi] == -1) {
            bin_head[bi] = idx;
            next_ptr[idx] = -1;
        } else {
            next_ptr[idx] = bin_head[bi];
            bin_head[bi] = idx;
        }
    }

    if (NY != 0) {
        int row = margin;
        int bin_i = 0;
        for (int byi = 0; byi < NY; byi++) {
            int yb = bh + row;
            if (NX != 0) {
                int ye = Hm + margin;
                if (yb < ye) ye = yb;
                int col = margin;
                int bc = bin_i;
                for (int bxi = 0; bxi < NX; bxi++) {
                    int xb = bw + col;
                    int xe = Wm + margin;
                    if (xb <= xe) xe = xb;
                    int cnt = 0;
                    if (row < ye) {
                        for (int r = row; r < ye; r++) {
                            if (col < xe) {
                                int rowbase = (y0 + r) * stride;
                                int lin = x0 + col + rowbase;
                                int end = x0 + xe + rowbase;
                                for (; lin != end; lin++)
                                    cnt += (int)((words[lin >> 5] >>
                                          (((uint8_t)lin - (uint8_t)rowbase) & 0x1f)) & 1u);
                            }
                        }
                    }
                    int thr = cr_lroundf((float)(cnt * weight) / (float)(bw * bh * nb));
                    if (bin_count[bc] <= thr) thr = bin_count[bc];
                    bin_count[bc] = thr;
                    col = xb;
                    bc++;
                }
            }
            row = yb;
            bin_i += NX;
        }
    }

    int empty = 0;
    for (int i = 0; i < nb; i++) empty += (bin_count[i] == 0);

    cr_shuffle_indices(order, nb, (uint64_t)seed);

    int out = 0;
    if (maxout >= 1) {
        int idx = 0;
        do {
            int bi = order[idx];
            int wrap = (nb - 1 <= idx);
            idx++;
            if (wrap) idx = 0;
            if (bin_head[bi] != -1 && bin_count[bi] > 0) {
                int oi = out;
                out++;
                *(int32_t *)((uint8_t *)pts + (int64_t)oi * 8) =
                    *(const int32_t *)((const uint8_t *)pts + 4 + (int64_t)bin_head[bi] * 8);
                bin_head[bi] = next_ptr[bin_head[bi]];
                int c = bin_count[bi];
                bin_count[bi] = c - 1;
                empty += (c - 1 == 0);
            }
        } while (empty != nb && out < maxout);
    }
    *out_count = out;

    cr_sized_free((void **)&next_ptr);
    cr_sized_free((void **)&bin_head);
    cr_sized_free((void **)&order);
    cr_sized_free((void **)&bin_count);
    return 0;
}

/* ------------------------------------------------------------------------ *
 * 0x18002cfd0 — structure-tensor orientation dispatcher.
 *   int fn(dst, src, mask, and_mask, cfg):
 *     if (cfg[0x10] == 0) return cr_structure_orient_d3b0(...);
 *     if (cfg[0x10] == 1) return cr_structure_orient_3b960(...);
 *     return 0x69;
 * Tail-jumps, so every argument is forwarded unchanged.
 * ------------------------------------------------------------------------ */
int cr_structure_orient_dispatch_2cfd0(void *dst, const void *src,
                                       const void *mask, uint8_t and_mask,
                                       const void *cfg)
{
    uint8_t sel = *(const uint8_t *)((const uint8_t *)cfg + 0x10);
    if (sel == 0)
        return cr_structure_orient_d3b0(dst, (const cr_image *)src,
                                        mask, and_mask, cfg);
    if (sel == 1)
        return cr_structure_orient_3b960(dst, src, mask, and_mask, cfg);
    return 0x69;
}

/* ------------------------------------------------------------------------ *
 * 0x180038020 — grid-population dispatcher.
 *   int fn(grid, src, mask, cfg):
 *     grid->count = 0;
 *     switch (cfg[1]) { 4: blob_detect; 5: harris minmax; 1: harris max;
 *                       default: 0x69 }
 * ------------------------------------------------------------------------ */
int cr_grid_populate_dispatch_38020(cr_grid *grid, const cr_image *src,
                                    const void *mask, const void *cfg)
{
    grid->count = 0;
    uint8_t sel = *(const uint8_t *)((const uint8_t *)cfg + 1);
    if (sel == 4)
        return cr_blob_detect_1bbf0(grid, src, (const int32_t *)mask, cfg);
    if (sel == 5)
        return cr_harris_local_minmax_grid(grid, src, (const cr_image *)mask,
                                           (const cr_harris_max_cfg *)cfg);
    if (sel == 1)
        return cr_harris_local_max_grid(grid, src, (const cr_image *)mask,
                                        (const cr_harris_max_cfg *)cfg);
    return 0x69;
}

/* ------------------------------------------------------------------------ *
 * 0x180026dc0 — feature-extraction step.
 *   int fn(state, img, handle, packed, cfg):
 *     mode = *(int16*)(cfg+0x24);
 *     if ((uint16)(mode-1) >= 0x7ff) return 0x69;
 *     q16: alloc_s16(W/4, H/4); quality_gate(q16,&q,&flag,state,img,handle,cfg);
 *     cleanup_clear(q16);
 *     if (gate) return gate;
 *     if (flag != 1) return 0;
 *     u8: alloc_u8(W, H);
 *     if (state[0x40] == 0) fill(u8.data, 0xff, W*H);
 *     else boxmax_fir(u8, packed, 1, 1, 1.5) -> on error cleanup_a(u8) & return;
 *     weighted_running_avg(state[0x18], state+0x58, img, &u8.data, q, cfg+0x24);
 *     cleanup_a(u8);
 *     if (state[0x40] < mode) state[0x40] += 1;
 *     if ((int8)state[8] < 1) return feature_qualify(state, cfg, q);
 *     return 0;
 * ------------------------------------------------------------------------ */
int cr_feature_extract_step_26dc0(void *state, const cr_image *img,
                                  void *handle, const cr_image *packed,
                                  const void *cfg)
{
    uint8_t *st = (uint8_t *)state;
    const uint8_t *c = (const uint8_t *)cfg;
    int16_t mode = *(const int16_t *)(c + 0x24);
    if ((uint16_t)(mode - 1) >= 0x7ffu)
        return 0x69;

    int W = img->w;
    int H = img->h;

    cr_image q16;
    int r = cr_image_alloc_s16((int *)&q16, W / 4, H / 4);
    if (r != 0)
        return r;

    float q = 0.0f;
    uint8_t flag = 0;
    int g = cr_quality_gate_35cf0(&q16, &q, &flag, state, (void *)img,
                                  handle, cfg);
    if (g != 0) {
        cr_cleanup_ptr8_clear(&q16);
        return g;
    }
    cr_cleanup_ptr8_clear(&q16);
    if (flag != 1)
        return 0;

    cr_image u8img;
    r = cr_image_alloc_u8((int *)&u8img, W, H);
    if (r != 0)
        return r;

    if (*(int *)(st + 0x40) == 0) {
        cr_fill(u8img.data, 0xff, W * H);
    } else {
        r = cr_bitmap_unpack_boxmax_fir(&u8img, packed, 1, 1, 1.5f);
        if (r != 0) {
            cr_cleanup_ptr8_a(&u8img);
            return r;
        }
    }

    cr_weighted_running_avg((int16_t *)*(void **)(st + 0x18),
                            (int16_t **)(st + 0x58), img,
                            (const uint8_t **)&u8img.data, q,
                            (const int16_t *)(c + 0x24));
    cr_cleanup_ptr8_a(&u8img);

    if (*(int *)(st + 0x40) < (int)mode)
        *(int *)(st + 0x40) = *(int *)(st + 0x40) + 1;

    if (*(int8_t *)(st + 0x08) < 1)
        return cr_feature_qualify(state, (void *)cfg, q);
    return 0;
}

/* ------------------------------------------------------------------------ *
 * 0x18002db20 — float-source feature-extraction step (26dc0 twin).
 *   int fn(state, fimg, handle, packed, cfg):
 *     mode = *(int16*)(cfg+0x24);
 *     if ((uint16)(mode-1) >= 0x7ff) return 0x69;
 *     u8: alloc_u8(W, H); u8[i] = clamp((int)(fimg[i] + 0.5f), 0, 255);
 *     q16: alloc_s16(W/4, H/4);
 *     quality_gate(q16, &q, &flag, state, u8, handle, cfg);
 *     cleanup_clear(q16);
 *     if (gate) { cleanup_a(u8); return gate; }
 *     if (flag != 1) { cleanup_a(u8); return 0; }
 *     u8b: alloc_u8(W, H);
 *     if (state[0x40] == 0) fill(u8b.data, 0xff, W*H);
 *     else mask_boxmax_fir_clear(u8b, packed, 0xf, 1, 1, 1.5)
 *            -> on error cleanup_a(u8), cleanup_a(u8b), return;
 *     weighted_running_avg(state[0x18], state+0x58, u8, &u8b.data, q, cfg+0x24);
 *     cleanup_a(u8b);
 *     if (state[0x40] < mode) state[0x40] += 1;
 *     rv = ((int8)state[8] < 1) ? feature_qualify(state, cfg, q) : 0;
 *     cleanup_a(u8);
 *     return rv;
 * ------------------------------------------------------------------------ */
int cr_feature_extract_step_2db20(void *state, const cr_image *fimg,
                                  void *handle, const cr_image *packed,
                                  const void *cfg)
{
    uint8_t *st = (uint8_t *)state;
    const uint8_t *c = (const uint8_t *)cfg;
    int16_t mode = *(const int16_t *)(c + 0x24);
    if ((uint16_t)(mode - 1) >= 0x7ffu)
        return 0x69;

    int W = fimg->w;
    int H = fimg->h;
    int n = W * H;

    cr_image u8img;
    int r = cr_image_alloc_u8((int *)&u8img, W, H);
    if (r != 0)
        return r;

    const float *fs = (const float *)fimg->data;
    uint8_t *ud = (uint8_t *)u8img.data;
    for (int i = 0; i < n; i++) {
        int v = (int)(fs[i] + 0.5f);
        uint8_t out;
        if (v < 0xff) {
            out = (uint8_t)v;
            if (v < 1)
                out = 0;
        } else {
            out = 0xff;
        }
        ud[i] = out;
    }

    cr_image q16;
    r = cr_image_alloc_s16((int *)&q16, W / 4, H / 4);
    if (r != 0) {
        cr_cleanup_ptr8_a(&u8img);
        return r;
    }

    float q = 0.0f;
    uint8_t flag = 0;
    int g = cr_quality_gate_35cf0(&q16, &q, &flag, state, (void *)&u8img,
                                  handle, cfg);
    cr_cleanup_ptr8_clear(&q16);
    if (g != 0) {
        cr_cleanup_ptr8_a(&u8img);
        return g;
    }
    if (flag != 1) {
        cr_cleanup_ptr8_a(&u8img);
        return 0;
    }

    cr_image u8b;
    r = cr_image_alloc_u8((int *)&u8b, W, H);
    if (r != 0) {
        cr_cleanup_ptr8_a(&u8img);
        return r;
    }

    if (*(int *)(st + 0x40) == 0) {
        cr_fill(u8b.data, 0xff, n);
    } else {
        r = cr_mask_boxmax_fir_clear(&u8b, packed, 0xf, 1, 1, 1.5f);
        if (r != 0) {
            cr_cleanup_ptr8_a(&u8img);
            cr_cleanup_ptr8_a(&u8b);
            return r;
        }
    }

    cr_weighted_running_avg((int16_t *)*(void **)(st + 0x18),
                            (int16_t **)(st + 0x58), &u8img,
                            (const uint8_t **)&u8b.data, q,
                            (const int16_t *)(c + 0x24));
    cr_cleanup_ptr8_a(&u8b);

    if (*(int *)(st + 0x40) < (int)mode)
        *(int *)(st + 0x40) = *(int *)(st + 0x40) + 1;

    int rv = 0;
    if (*(int8_t *)(st + 0x08) < 1)
        rv = cr_feature_qualify(state, (void *)cfg, q);
    cr_cleanup_ptr8_a(&u8img);
    return rv;
}

/* ------------------------------------------------------------------------ *
 * 0x18003de60 — directional 5x5 matched-filter bank (int16 fixed point).
 *   int fn(int16_t *out, const int16_t *const *rows, const void *cfg):
 *     cfg +0x08 stride, +0x0c ncoef, +0x10 w, +0x14 h, +0x18 normalise,
 *         +0x20 coefA (h*ncoef*25 shorts), +0x28 coefB (h shorts).
 *     For each of `h` output rows a 5x5 correlation is slid over `ncoef`
 *     orientation blocks (each block is a 25-short kernel at a distinct row
 *     offset); two shifted responses are max-pooled per position and written
 *     as two int16 channels (>>15).  A trailing partial column uses a reduced
 *     5-tap edge kernel.  If the normalise flag is 1 the whole plane is then
 *     clamped non-negative.  Returns 0.
 * ------------------------------------------------------------------------ */
int cr_dirbank_3de60(int16_t *out, const int16_t *const *rows, const void *cfg)
{
    const uint8_t *c = (const uint8_t *)cfg;
    int h  = *(const int *)(c + 0x14);
    int nc = *(const int *)(c + 0x0c);
    int w  = *(const int *)(c + 0x10);

    if (h > 0) {
        const int16_t *cbase = *(const int16_t *const *)(c + 0x20);
        const int16_t *coefB = *(const int16_t *const *)(c + 0x28);
        int      stride = *(const int *)(c + 0x08);
        uint8_t *outb   = (uint8_t *)out;

        int64_t        local_6c = 0;
        const int16_t *local_b0 = cbase + nc * 25;
        unsigned       uVar10   = (unsigned)((w - 2) >> 1);
        int64_t        lVar5    = (int64_t)stride * 2;
        const int16_t *const *plVar16 = rows + 1;

        for (int r = 0; r < h; r++) {
            int iVar6 = (int)coefB[r] * 0x4000;
            int tail_start;

            if (w < 2) {
                tail_start = 0;
            } else {
                int64_t local_a0 = 0;
                int64_t outrow   = local_6c * 2;      /* byte offset into outb */
                do {
                    int iVar18 = iVar6, iVar30 = iVar6;
                    if (nc > 0) {
                        int iVar27, iVar13, iVar7, iVar11;
                        const int16_t *d8, *w1, *w2, *c0;
                        const int16_t *const *p15;
                        int64_t lVar31 = local_a0 * 2, lVar17;

                        /* pass 1: coefficient rows[0..4] */
                        iVar27 = 0; iVar13 = 0; iVar30 = 0; iVar18 = 0;
                        d8 = cbase; w1 = cbase; lVar17 = lVar31; p15 = rows;
                        do {
                            do {
                                int iVar19 = w1[0];
                                const int16_t *p =
                                    (const int16_t *)((const uint8_t *)p15[0] + lVar17);
                                int iVar29 = p[2], iVar25 = p[3], iVar7b = p[4];
                                int iVar11b = w1[1], iVar20 = w1[2];
                                int iVar14 = p[5], iVar21 = w1[3], iVar12 = w1[4];
                                p15++;
                                iVar18 = iVar7b*iVar12 + iVar25*iVar21 + iVar29*iVar20
                                       + p[1]*iVar11b + iVar18 + p[0]*iVar19;
                                iVar30 = iVar30 + p[1]*iVar19 + iVar29*iVar11b
                                       + iVar25*iVar20 + iVar7b*iVar21 + iVar14*iVar12;
                                iVar27 = iVar27 + iVar29*iVar19 + iVar25*iVar11b
                                       + iVar7b*iVar20 + iVar14*iVar21 + p[6]*iVar12;
                                iVar13 = iVar12*p[7] + iVar21*p[6] + iVar11b*iVar7b
                                       + iVar19*iVar25 + iVar13 + iVar20*iVar14;
                                w1 += 5;
                            } while (rows + 5 != p15);
                            w1 = d8 + 25;
                            lVar17 += lVar5;
                            p15 = rows;
                            d8 = w1;
                        } while (local_b0 != w1);
                        if (iVar30 <= iVar18) iVar30 = iVar18;
                        if (iVar13 <= iVar27) iVar13 = iVar27;

                        /* pass 2: coefficient rows[1..5] */
                        iVar27 = 0; iVar7 = 0; iVar11 = 0; iVar18 = 0;
                        c0 = cbase; w2 = cbase; p15 = plVar16;
                        do {
                            do {
                                int iVar21 = w2[0];
                                const int16_t *q =
                                    (const int16_t *)((const uint8_t *)p15[0] + lVar31);
                                int iVar28 = q[2], iVar26 = q[3], iVar12 = q[4];
                                int iVar14 = w2[1], iVar25 = w2[2], iVar20 = q[5];
                                int iVar29 = w2[3], iVar19 = w2[4];
                                p15++;
                                iVar18 = iVar12*iVar19 + iVar26*iVar29 + iVar28*iVar25
                                       + q[1]*iVar14 + iVar18 + q[0]*iVar21;
                                iVar11 = iVar11 + q[1]*iVar21 + iVar28*iVar14
                                       + iVar26*iVar25 + iVar12*iVar29 + iVar20*iVar19;
                                iVar7 = iVar7 + iVar28*iVar21 + iVar26*iVar14
                                       + iVar12*iVar25 + iVar20*iVar29 + q[6]*iVar19;
                                iVar27 = iVar19*q[7] + iVar29*q[6] + iVar14*iVar12
                                       + iVar21*iVar26 + iVar27 + iVar25*iVar20;
                                w2 += 5;
                            } while (rows + 6 != p15);
                            w2 = c0 + 25;
                            lVar31 += lVar5;
                            p15 = plVar16;
                            c0 = w2;
                        } while (local_b0 != w2);

                        if (iVar18 <= iVar30) iVar18 = iVar30;
                        if (iVar18 < iVar11)  iVar18 = iVar11;
                        if (iVar27 < iVar13)  iVar27 = iVar13;
                        if (iVar27 < iVar7)   iVar27 = iVar7;
                        iVar18 = iVar18 + iVar6;
                        iVar30 = iVar27 + iVar6;
                    }
                    *(int16_t *)(outb + outrow + local_a0) =
                        (int16_t)(iVar18 >> 0xf);
                    *(int16_t *)(outb + outrow + local_a0 + 2) =
                        (int16_t)(iVar30 >> 0xf);
                    local_a0 += 4;
                } while ((int64_t)uVar10 * 4 + 4 != local_a0);
                tail_start = (int)(uVar10 * 2 + 2);
            }

            /* trailing column(s): reduced 5-tap edge kernel */
            for (int j = tail_start; j < w; j++) {
                int iVar18 = iVar6;
                if (nc > 0) {
                    int iVar30 = 0, iVar13;
                    const int16_t *w1, *w2, *c0;
                    const int16_t *const *p15;
                    int64_t lVar31 = (int64_t)(j * 2) * 2, lVar17;

                    iVar18 = 0;
                    w1 = cbase; p15 = rows; lVar17 = lVar31; c0 = cbase;
                    do {
                        do {
                            const int16_t *const *p15n = p15 + 1;
                            const int16_t *q =
                                (const int16_t *)((const uint8_t *)p15[0] + lVar17);
                            iVar30 = q[3]*w1[3] + q[1]*w1[1] + iVar30
                                   + q[0]*w1[0] + q[2]*w1[2] + q[4]*w1[4];
                            iVar18 = w1[3]*q[4] + w1[2]*q[3] + w1[1]*q[2]
                                   + iVar18 + w1[0]*q[1] + w1[4]*q[5];
                            w1 += 5; p15 = p15n;
                        } while (rows + 5 != p15);
                        w1 = c0 + 25; lVar17 += lVar5; p15 = rows; c0 = w1;
                    } while (local_b0 != w1);
                    if (iVar18 <= iVar30) iVar18 = iVar30;

                    iVar13 = 0; iVar30 = 0;
                    c0 = cbase; p15 = plVar16; w2 = cbase;
                    do {
                        do {
                            const int16_t *const *p15n = p15 + 1;
                            const int16_t *q =
                                (const int16_t *)((const uint8_t *)p15[0] + lVar31);
                            iVar13 = q[3]*w2[3] + q[1]*w2[1] + iVar13
                                   + q[0]*w2[0] + q[2]*w2[2] + q[4]*w2[4];
                            iVar30 = w2[3]*q[4] + w2[2]*q[3] + w2[1]*q[2]
                                   + iVar30 + w2[0]*q[1] + w2[4]*q[5];
                            w2 += 5; p15 = p15n;
                        } while (rows + 6 != p15);
                        w2 = c0 + 25; lVar31 += lVar5; p15 = plVar16; c0 = w2;
                    } while (local_b0 != w2);
                    if (iVar30 < iVar18) iVar30 = iVar18;
                    if (iVar30 < iVar13) iVar30 = iVar13;
                    iVar18 = iVar30 + iVar6;
                }
                *(int16_t *)(outb + local_6c * 2 + (int64_t)j * 2) =
                    (int16_t)(iVar18 >> 0xf);
            }

            local_6c += w;
            local_b0 += nc * 25;
            cbase    += nc * 25;
        }
    }
    if (*(const int *)(c + 0x18) == 1)
        cr_s16_clamp_nonneg(out, out, w * h);
    return 0;
}

/* ------------------------------------------------------------------------ *
 * 0x1800364c0 — three-level matched-filter pyramid.
 *
 *   int fn(int16_t *out, const void *obj, const cr_image *img,
 *          const cr_sampler *s):
 *
 * `obj + 0x08` points to a descriptor of three 0x30-byte levels; each level L
 * has  L[0]=plane-count (5/3/5), L[2]=f08, L[3]=f0c, L[4]=W, L[5]=H,
 * L[6]=flag, L[8]=kernel base, L[0xa]=per-row bias base.  The guard requires
 * L0[0]==5 && L1[0]==3 && L2[0]==5.
 *
 * Phase 1 walks `out` building three row-pointer arrays: level k holds
 * (plane-count+1) pointers spaced `stride_k` shorts apart where
 * stride_0 = (L0[3]*L0[2]+1)/2 and stride_{1,2} = L{1,2}[3]*L{1,2}[2].  The
 * running short offset is carried across levels; the tail region is the final
 * dirbank output base.
 *
 * Phase 2 streams `(L2[1]-4)>>1` output blocks: it bilinearly resamples new
 * level-0 rows (cr_bilinear_sample_u8, `n = L0[2]` samples at increasing idx),
 * runs cr_matched_filter_45eb0 into a level-1 plane, cr_block_conv_231a0 into a
 * level-2 plane and cr_dirbank_3de60 into the next block of the tail region.
 * After each level is consumed its pointer ring is rotated by 2
 * (cr_array_rotate) and the fill index backed off by 2.
 *
 * Phase 3 interleaves the per-block dirbank planes into the front of `out`:
 * out[b*nblocks + r] = block[r] row[b].
 *
 * Returns 0 on success, 0x69 on a guard mismatch, else the first nonzero
 * callee status.
 * ------------------------------------------------------------------------ */
int cr_pyramid_364c0(int16_t *out, const void *obj, const cr_image *img,
                     const cr_sampler *s)
{
    const uint8_t *Db = *(const uint8_t *const *)((const uint8_t *)obj + 8);
    const int32_t *D  = (const int32_t *)Db;

    if (!(D[0] == 5 && D[0xc] == 3 && D[0x18] == 5))
        return 0x69;

    intptr_t ptrs[16];
    intptr_t *base[3];
    int       n[3];
    int       offset = 0;      /* running short offset into `out` */

    /* --- phase 1: build the per-level row-pointer arrays --- */
    {
        int mult  = 1;
        int pidx  = 0;
        int count = 5;         /* level0 plane count */
        for (int lvl = 0;; lvl++) {
            const uint8_t *Lk = Db + 0x30 * lvl;
            int f08 = *(const int32_t *)(Lk + 0x08);
            int f0c = *(const int32_t *)(Lk + 0x0c);
            base[lvl] = ptrs + pidx;
            n[lvl]    = count + 1;
            if (count >= 0) {
                mult = (f0c * f08 * mult + 1) / 2;
                intptr_t p = (intptr_t)out + (intptr_t)offset * 2;
                for (int j = 0; j <= count; j++) {
                    base[lvl][j] = p;
                    p += (intptr_t)mult * 2;
                }
                offset += mult * (count + 1);
            }
            if (Db + 8 + 0x30 * (lvl + 1) == Db + 0x98)
                break;
            pidx += count + 1;
            count = *(const int32_t *)(Lk + 0x30);
            mult  = 2;
        }
    }

    intptr_t *A = base[0], *B = base[1], *C = base[2];
    int       na = n[0], nb = n[1], nc = n[2];
    int       ia = 0, ib = 0, ic = 0;

    int16_t *fbase    = (int16_t *)((uint8_t *)out + (intptr_t)offset * 2);
    int      nblocks  = (D[0x19] - 4) >> 1;
    int      row      = 0;
    int      sampIdx  = 0;

    /* --- phase 2: streaming pyramid --- */
    while (row < nblocks) {
        int carry = ia;                       /* iVar11: na when the fill runs */
        if (ia < na) {
            int end = (na - ia) + sampIdx;
            int i   = sampIdx;
            int pi  = ia;
            while (i != end) {
                cr_bilinear_sample_u8((uint8_t *)A[pi], img, s, D[2], i);
                i++;
                pi++;
            }
            sampIdx = end;
            carry   = na;
        }
        if (D[0] != 5)
            return 0x69;
        int st = cr_matched_filter_45eb0((int16_t *)B[ib],
                                         (const uint8_t *const *)A, D);
        if (st)
            return st;
        ib++;
        cr_array_rotate((uint64_t *)A, 6);
        ia = carry - 2;
        if (ib == nb) {
            if (D[0xc] != 3)
                return 0x69;
            st = cr_block_conv_231a0((int16_t *)C[ic],
                                     (const intptr_t *)B, Db + 0x30);
            if (st)
                return st;
            ic++;
            cr_array_rotate((uint64_t *)B, 4);
            ib = ib - 2;
            if (ic == nc) {
                if (D[0x18] != 5)
                    return 0x69;
                st = cr_dirbank_3de60(
                        (int16_t *)((uint8_t *)fbase +
                                    (intptr_t)(D[0x1d] * D[0x1c] * row) * 2),
                        (const int16_t *const *)C, Db + 0x60);
                if (st)
                    return st;
                row++;
                cr_array_rotate((uint64_t *)C, 6);
                ic = ic - 2;
            }
        }
    }

    /* --- phase 3: interleave the block planes into the front of `out` --- */
    {
        int H2 = D[0x1d];
        if (H2 > 0) {
            int W2 = D[0x1c];
            int dstRowBase = 0;
            for (int b = 0; b < H2; b++) {
                if (nblocks > 0) {
                    int srcOff = b * W2;
                    int dstOff = dstRowBase * W2;
                    for (int r = 0; r < nblocks; r++) {
                        if (W2 > 0) {
                            for (int l = 0; l < W2; l++)
                                out[dstOff + l] = fbase[srcOff + l];
                        }
                        srcOff += H2 * W2;
                        dstOff += W2;
                    }
                }
                dstRowBase += nblocks;
            }
        }
    }
    return 0;
}

/* ------------------------------------------------------------------------ *
 * 0x180025960 — fixed-pattern (ridge template) removal on a float image.
 *   int fn(cr_image *img, const cr_image *mask, int sel)
 *
 *   Guard: img NULL -> 0x69; odd h *and* odd w -> 0x69; sel must be 1 or 2
 *   (sel == 0 returns 0, anything else 0x3ee) and then h must equal the
 *   table's 80 / 176 rows with w == 64, else 0x3ee.
 *
 *   A scratch h*64 float plane is allocated and seeded with the separable
 *   ridge template: for o in [0, h/2) row o carries tab[o] plus the 32-entry
 *   ramp tab[0..32) mirrored about the row centre (columns 0..31 get
 *   tab[0..31], columns 63..32 get the same sequence reversed), while the
 *   mirrored row h-1-o carries tab[h/2-1] plus that same ramp.  The template
 *   is then blended toward the
 *   centre sample C = buf[n/2 + 32] by the image itself,
 *       buf[i] = (1 - src[i]/255)*buf[i] + (src[i]/255)*C,
 *   a least-squares gain is fitted over the mask==0xff samples,
 *       gain = 0.9 * sum((buf*cnt - sum)*src) / (cnt*sumsq - sum^2)
 *   (clamped at 0; left at 1.0 when the variance is exactly 0), the template
 *   deviation is subtracted from the image,
 *       src[i] -= (buf[i] - mean(buf)) * gain,
 *   and finally each pixel is blended back toward the image maximum,
 *       src[i] = clamp(((255-m)*maxsrc + src[i]*m) / 255, 0, 255)
 *   with m = mask[i].  The scratch plane is released and 0 returned.
 * ------------------------------------------------------------------------ */
static const float cr_tmpl_tab80[40] = {
    0.0f, 22.4829998f, 37.6220016f, 47.3530006f, 53.6040001f, 57.6580009f,
    60.3300018f, 62.1339989f, 63.3919983f, 64.3010025f, 64.9869995f,
    65.5270004f, 65.9690018f, 66.3450012f, 66.6750031f, 66.9700012f,
    67.2389984f, 67.487999f, 67.7210007f, 67.9400024f, 68.1470032f,
    68.3440018f, 68.5319977f, 68.711998f, 68.8850021f, 69.0510025f,
    69.2099991f, 69.3639984f, 69.5130005f, 69.6559982f, 69.7949982f,
    69.9300003f, 70.060997f, 70.060997f, 70.060997f, 70.060997f, 70.060997f,
    70.060997f, 70.060997f, 70.060997f,
};

static const float cr_tmpl_tab176[88] = {
    0.0f, 22.1560001f, 37.0750008f, 46.6650009f, 52.8250008f, 56.8190002f,
    59.4519997f, 61.230999f, 62.4700012f, 63.3660011f, 64.0419998f,
    64.5739975f, 65.0100021f, 65.3799973f, 65.7050018f, 65.9960022f,
    66.2610016f, 66.5070038f, 66.7360001f, 66.9520035f, 67.1559982f,
    67.3499985f, 67.5360031f, 67.7129974f, 67.8830032f, 68.0459976f,
    68.2040024f, 68.3550034f, 68.5019989f, 68.6429977f, 68.7799988f,
    68.913002f, 69.0419998f, 69.0419998f, 69.0419998f, 69.0419998f,
    69.0419998f, 69.0419998f, 69.0419998f, 69.0419998f, 69.0419998f,
    69.0419998f, 69.0419998f, 69.0419998f, 69.0419998f, 69.0419998f,
    69.0419998f, 69.0419998f, 69.0419998f, 69.0419998f, 69.0419998f,
    69.0419998f, 69.0419998f, 69.0419998f, 69.0419998f, 69.0419998f,
    69.0419998f, 69.0419998f, 69.0419998f, 69.0419998f, 69.0419998f,
    69.0419998f, 69.0419998f, 69.0419998f, 69.0419998f, 69.0419998f,
    69.0419998f, 69.0419998f, 69.0419998f, 69.0419998f, 69.0419998f,
    69.0419998f, 69.0419998f, 69.0419998f, 69.0419998f, 69.0419998f,
    69.0419998f, 69.0419998f, 69.0419998f, 69.0419998f, 69.0419998f,
    69.0419998f, 69.0419998f, 69.0419998f, 69.0419998f, 69.0419998f,
    69.0419998f, 69.0419998f,
};

int cr_template_remove_25960(cr_image *img, const cr_image *mask, int sel)
{
    if (img == NULL)
        return 0x69;
    int h = img->h;
    int w = img->w;
    if ((h & 1) && (w & 1))
        return 0x69;

    const float *tab;
    int need;
    if (sel == 1) { tab = cr_tmpl_tab80;  need = 0x50; }
    else if (sel == 2) { tab = cr_tmpl_tab176; need = 0xb0; }
    else return sel == 0 ? 0 : 0x3ee;

    if (h != need || w != 0x40)
        return 0x3ee;

    float *src = (float *)img->data;
    const uint8_t *msk = (const uint8_t *)mask->data;
    int n = h * 0x40;

    cr_image tmp;
    uint32_t r = cr_image_set(&tmp, NULL, 0x40, h);
    if ((int)r != 0)
        return (int)r;
    r = (uint32_t)cr_malloc_aligned16(&tmp.data, (size_t)n * 4);
    if ((int)r != 0)
        return (int)r;

    float *buf = (float *)tmp.data;
    int half = h >> 1;
    float kc = tab[half - 1];
    for (int o = 0; o < half; o++) {
        for (int i = 0; i < 32; i++) {
            float rp = tab[i];
            float top = tab[o] + rp;
            float bot = kc + rp;
            buf[0x40 * o + i]          = top;   /* row o,      cols 0..31  */
            buf[0x3f + 0x40 * o - i]   = top;   /* row o,      cols 63..32 */
            buf[n - 0x40 - 0x40 * o + i] = bot; /* row h-1-o,  cols 0..31  */
            buf[n - 1 - 0x40 * o - i]  = bot;   /* row h-1-o,  cols 63..32 */
        }
    }

    /* The vendor re-reads the centre sample from the scratch plane on every
     * pixel, so once the scan reaches that index the *blended* value is fed
     * back for the remaining pixels.  Model it with a volatile load. */
    volatile float *centre = &buf[(n >> 1) + 0x20];
    float sum = 0.0f, sumsq = 0.0f;
    int cnt = 0;
    for (int rr = 0; rr < h; rr++) {
        for (int i = 0; i < 0x40; i++) {
            int j = 0x40 * rr + i;
            float a = src[j] / 255.0f;
            float v = (1.0f - a) * buf[j] + a * *centre;
            buf[j] = v;
            if (msk[j] == 0xff) {
                sum += v;
                cnt++;
                sumsq += v * v;
            }
        }
    }

    float cov = 0.0f;
    float cntf = (float)cnt;
    for (int rr = 0; rr < h; rr++) {
        for (int i = 0; i < 0x40; i++) {
            int j = 0x40 * rr + i;
            if (msk[j] == 0xff)
                cov += (buf[j] * cntf - sum) * src[j];
        }
    }

    float var = cntf * sumsq - sum * sum;
    float gain = 1.0f;
    if (var != 0.0f) {
        gain = (cov * 0.9f) / var;
        if (!(0.0f < gain))
            gain = 0.0f;
    }

    float total = 0.0f, maxsrc = 0.0f;
    for (int j = 0; j < n; j++) {
        total += buf[j];
        float s = src[j];
        if (!(s <= maxsrc))
            maxsrc = s;
    }
    float mean = total / (float)n;

    for (int j = 0; j < n; j++)
        src[j] = src[j] - (buf[j] - mean) * gain;

    for (int j = 0; j < n; j++) {
        float v = src[j];
        float out = 255.0f;
        if (!(v >= 255.0f)) {
            float m = (float)(int)msk[j];
            float t = ((float)(int)(0xff - (uint32_t)msk[j]) * maxsrc + v * m) / 255.0f;
            if (!(t > 255.0f))
                out = (t < 0.0f) ? 0.0f : t;
        }
        src[j] = out;
    }

    cr_sized_free(&tmp.data);
    return 0;
}

/* ------------------------------------------------------------------------ *
 * 0x180037460 — grid-bucketed point picker.
 *   int fn(void *pts, int *out_n, int npts, int want, const cr_image *bits,
 *          uint32_t seed, const void *cfg)
 *
 *   `pts` is an array of 8-byte records {int32 v; int16 x; int16 y;}.  cfg:
 *   +0x08 border, +0x10 int16 slot count, +0x25 grid width, +0x26 grid height.
 *   `bits` is a 1-bit-per-pixel image (stride in bits at +0x00).
 *
 *   Phase 1 (reverse order) maps each point's (x,y) into the grid cell
 *   (clamped) and prepends the point to that cell's singly linked list
 *   (heads, nexts); the record's 4-byte tail is then overwritten with `v`.
 *   Phase 2 walks the grid with a sliding window of cell width imgw/gw and
 *   cell height imgh/gh, counts the set bits of the bitmap inside each window
 *   and stores min(round(count*want / (window area * N)), counts[cell]) in
 *   the cell counter.  Phase 3 shuffles the cell order with the caller's seed
 *   and emits one point per visited non-empty cell until `want` are emitted
 *   (cells whose counter is < 1 are only used once every cell is < 1).
 *   Returns 0, or the first allocator status.
 * ------------------------------------------------------------------------ */
int cr_grid_pick_37460(void *pts, int *out_n, int npts, int want,
                       const cr_image *bits, uint32_t seed, const void *cfg)
{
    const uint8_t *c = (const uint8_t *)cfg;
    uint8_t gw = c[0x25];
    uint8_t gh = c[0x26];
    int N = (int)gw * (int)gh;
    int imgw = bits->w;
    int imgh = bits->h;
    int border = (int)(int8_t)c[0x08];
    int nslot = (int)*(const int16_t *)(c + 0x10);

    void *counts_p = NULL, *next_p = NULL, *head_p = NULL, *order_p = NULL;
    int r = cr_malloc_aligned16(&counts_p, (size_t)N * 4);
    if (r != 0)
        return r;
    r = cr_malloc_aligned16(&next_p, (size_t)nslot * 4);
    if (r != 0) { cr_sized_free(&counts_p); return r; }
    r = cr_malloc_aligned16(&head_p, (size_t)N * 4);
    if (r != 0) { cr_sized_free(&counts_p); cr_sized_free(&next_p); return r; }
    r = cr_malloc_aligned16(&order_p, (size_t)N * 4);
    if (r != 0) {
        cr_sized_free(&counts_p);
        cr_sized_free(&next_p);
        cr_sized_free(&head_p);
        return r;
    }

    int *counts = (int *)counts_p;
    int *next   = (int *)next_p;
    int *head   = (int *)head_p;
    int *order  = (int *)order_p;
    uint8_t *rec = (uint8_t *)pts;

    for (int i = 0; i < N; i++) {
        head[i] = -1;
        counts[i] = 0;
    }

    for (int i = npts - 1; i >= 0; i--) {
        int gx = ((int)*(int16_t *)(rec + i * 8 + 4) * (int)gw) / imgw;
        if (gx < 0)
            gx = 0;
        int gy = ((int)*(int16_t *)(rec + i * 8 + 6) * (int)gh) / imgh;
        *(int32_t *)(rec + i * 8 + 4) = *(int32_t *)(rec + i * 8);
        if (gy < 0)
            gy = 0;
        if (gy > (int)gh - 1)
            gy = (int)gh - 1;
        if (gx > (int)gw - 1)
            gx = (int)gw - 1;
        int cell = gy * (int)gw + gx;
        counts[cell] = counts[cell] + 1;
        if (head[cell] == -1) {
            head[cell] = i;
            next[i] = -1;
        } else {
            next[i] = head[cell];
            head[cell] = i;
        }
    }

    if (gh != 0) {
        int col = 0;
        int base = 0;
        for (int k = 0; k < (int)gh; k++) {
            int yhi = imgh / (int)gh + col;
            if (gw != 0) {
                int y2 = imgh - border;
                if (yhi < y2)
                    y2 = yhi;
                if (col <= border)
                    col = border;
                int xs = 0;
                for (int j = 0; j < (int)gw; j++) {
                    int xlo = (border < xs) ? xs : border;
                    xs += imgw / (int)gw;
                    int xhi = imgw - border;
                    if (xs <= xhi)
                        xhi = xs;
                    int cnt = 0;
                    if (col < y2) {
                        for (int y = col; y != y2; y++) {
                            if (xlo < xhi) {
                                int bb = (bits->offy + y) * bits->a;
                                int q = bits->offx + xlo + bb;
                                int qend = bits->offx + xhi + bb;
                                do {
                                    int qn = q + 1;
                                    cnt += (int)(((const uint32_t *)bits->data)[q >> 5]
                                                 >> ((q - bb) & 31) & 1u);
                                    q = qn;
                                } while (qend != q);
                            }
                        }
                    }
                    float f = 0.0f;
                    if (col < y2)
                        f = (float)(cnt * want);
                    int v = cr_lroundf(f / (float)((xhi - xlo) * N * (y2 - col)));
                    if (counts[base + j] <= v)
                        v = counts[base + j];
                    counts[base + j] = v;
                }
            }
            base += (int)gw;
            col = yhi;
        }
    }

    int empty = 0;
    for (int i = 0; i < N; i++)
        empty += (counts[i] < 1);

    cr_shuffle_indices(order, N, (uint64_t)seed);

    int nout = 0;
    if (want >= 1) {
        int cur = 0;
        do {
            int cell = order[cur];
            cur++;
            if (cur >= N)
                cur = 0;
            int h = head[cell];
            if (h != -1) {
                if (counts[cell] < 1) {
                    if (N == empty) {
                        *(int32_t *)(rec + (size_t)nout * 8) =
                            *(int32_t *)(rec + (size_t)h * 8 + 4);
                        nout++;
                        head[cell] = next[h];
                    }
                } else {
                    *(int32_t *)(rec + (size_t)nout * 8) =
                        *(int32_t *)(rec + (size_t)h * 8 + 4);
                    nout++;
                    head[cell] = next[h];
                    int v = counts[cell];
                    counts[cell] = v - 1;
                    empty += (v - 1 == 0);
                }
            }
        } while (nout < want);
    }

    *out_n = nout;
    cr_sized_free(&next_p);
    cr_sized_free(&head_p);
    cr_sized_free(&order_p);
    cr_sized_free(&counts_p);
    return 0;
}

/* 0x180025050 — mask-driven inpaint / classify pipeline.
 *
 * `list` is a 16-byte record: a u16 count at +0 and the u16 index array at +8.
 * cfg[0] selects the mode; see the prototype comment in fpc_bep.h.
 *
 * Mode 7 is a two-pass gap interpolator over the float image: the row pass
 * finds rows whose horizontal neighbour differences are all below cfg+4 and
 * interpolates *vertically* between the two rows that bracket such a run; the
 * column pass does the transposed thing.  Only strictly positive samples are
 * bridged, and only runs no longer than cfg[0xc] / cfg[0xd].
 */

/* Fill the `count` rows strictly between `prev` and `cur` (both w floats). */
static void cr_gap_rows_25050(float *prev, const float *cur, int count, int w)
{
    float inv = (float)(1.0 / (double)(count + 1));
    for (int i = 0; i < w; i++) {
        float a = prev[i];
        if (!(a > 0.0f)) continue;
        float b = cur[i];
        if (!(b > 0.0f)) continue;
        float delta = inv * (b - a);
        for (int k = 1; k <= count; k++)
            prev[(size_t)w * (size_t)k + (size_t)i] = a + (float)k * delta;
    }
}

/* Fill the `count` columns strictly between `prev` and `cur` (both h rows). */
static void cr_gap_cols_25050(float *prev, const float *cur, int count,
                              int w, int h)
{
    float inv = (float)(1.0 / (double)(count + 1));
    for (int j = 0; j < h; j++) {
        float a = prev[0];
        if (a > 0.0f) {
            float b = cur[0];
            if (b > 0.0f) {
                float delta = (b - a) * inv;
                for (int k = 1; k <= count; k++)
                    prev[k] = a + (float)k * delta;
            }
        }
        prev += w;
        cur  += w;
    }
}

int cr_mask_pipeline_25050(cr_image *img, const void *list,
                           const uint8_t *cfg, cr_image *mask)
{
    int mode = cfg[0];

    if (mode == 7) {
        int h = img->h, w = img->w;
        float *data = (float *)img->data;
        float thr = (float)*(const int32_t *)(cfg + 4);
        int maxrow = (int8_t)cfg[0xc];
        int maxcol = (int8_t)cfg[0xd];

        if (h > 0) {
            int count = 0;
            float *prev = NULL;
            float *row = data;
            for (int r = 0; r < h; r++) {
                float d = 0.0f;
                int brk = 1;
                if (w >= 2) {
                    d = (row[1] - row[0]) * (row[1] - row[0]);
                    if (d < thr) {
                        float *p = row + 1;
                        float *end = row + (w - 1);
                        brk = 0;
                        while (p != end) {
                            d = (p[1] - p[0]) * (p[1] - p[0]);
                            p++;
                            if (!(d < thr)) { brk = 1; break; }
                        }
                    }
                } else {
                    brk = !(d < thr);
                }
                if (!brk && !(d < thr)) brk = 1;
                if (brk) {
                    if (prev != NULL && count != 0 && maxrow >= count)
                        cr_gap_rows_25050(prev, row, count, w);
                    prev = row;
                    count = 0;
                } else {
                    count++;
                }
                row += w;
            }
        }

        if (w >= 1) {
            int count = 0;
            float *prev = NULL;
            float *col = data;
            for (int c = 0; c < w; c++) {
                float d = 0.0f;
                int brk = 1;
                if (h >= 2) {
                    d = (col[w] - col[0]) * (col[w] - col[0]);
                    if (d < thr) {
                        float *p = col + w;
                        int k = 1;
                        brk = 0;
                        for (;;) {
                            k++;
                            if (h == k) break;
                            d = (p[w] - p[0]) * (p[w] - p[0]);
                            p += w;
                            if (!(d < thr)) { brk = 1; break; }
                        }
                    }
                } else {
                    brk = !(d < thr);
                }
                if (!brk && !(d < thr)) brk = 1;
                if (brk) {
                    if (count != 0 && prev != NULL && maxcol >= count)
                        cr_gap_cols_25050(prev, col, count, w, h);
                    prev = col;
                    count = 0;
                } else {
                    count++;
                }
                col++;
            }
        }
        return 0;
    }

    if (list == NULL) return 0;
    const cr_index_list *l = (const cr_index_list *)list;
    uint16_t limit = *(const uint16_t *)(cfg + 2);
    if (cfg[1] != 0 && l->count > limit) return 0x3e9;
    if (mode == 0) return 0;

    const uint16_t *idx = l->indices;
    uint8_t *mb = (uint8_t *)mask->data;
    float   *fd = (float *)img->data;

    if (mode == 5) {
        cr_inpaint_index_list(img, mask, &l->count, &idx);
    } else if (mode == 4) {
        int iters = 0;
        cr_inpaint_index_list(img, mask, &l->count, &idx);
        for (;;) {
            if (l->count == 0) break;
            int found = 0;
            for (int i = 0; i < (int)l->count; i++)
                if (mb[idx[i]] & 4) { found = 1; break; }
            if (!found) break;
            if (iters >= (int)limit) break;
            iters++;
            for (int i = 0; i < (int)l->count; i++) {
                uint16_t p = idx[i];
                if (mb[p] & 4) {
                    int cnt;
                    float sum;
                    cr_masked_box_sum(&cnt, &sum, img, mask, 0x1b, 5, (int)p);
                    if (cnt > 5) {
                        float mean = sum / (float)cnt;
                        fd[p] = mean;
                        mb[p] = 0x20;
                    }
                }
            }
            for (int i = 0; i < (int)l->count; i++)
                if (mb[idx[i]] & 0x20) mb[idx[i]] = 8;
        }
    } else {
        int apply = 0;
        if (mode != 3) {
            if (mode != 2) {
                if (mode != 1) return 0x69;
                cr_inpaint_masked_box(mask, img, 2, 1);
                cr_inpaint_index_list(img, mask, &l->count, &idx);
                cr_classify_mark((const float *)img->data,
                                 (uint8_t *const *)&mask->data, &l->count, &idx);
                cr_inpaint_masked_box(mask, img, 0x13, 0);
                goto post;
            }
            apply = 1;
        }
        cr_inpaint_masked_box(mask, img, 2, apply);
        cr_inpaint_index_list(img, mask, &l->count, &idx);
        cr_classify_mark((const float *)img->data,
                         (uint8_t *const *)&mask->data, &l->count, &idx);
    }

post:
    if (cfg[1] != 0 && l->count != 0) {
        for (int i = 0; i < (int)l->count; i++)
            if (mb[idx[i]] & 4) return 0x3e9;
        return 0;
    }
    return 0;
}

/* 0x18002bd60 — i16 image row/column normalisation.
 *
 * img->data is int16, mask->data one byte per pixel (bit 0xe selects samples,
 * mask->w is used as the row stride).  cfg:
 *   +0x09  mode: 0 none, 1 gain normalise, 2 offset normalise, 3 table map
 *   +0x0a  row-normalisation pass (0/1)
 *   +0x0b  table selector for mode 3 (0..5)
 *   +0x0c  x0, +0x10 window width, +0x14 row0, +0x18 row count
 */

static const float cr_norm_tab_a[35] = {
    0.367000014f, 0.419f, 0.481000006f, 0.551999986f, 0.629000008f, 0.700999975f,
    0.764999986f, 0.818000019f, 0.865999997f, 0.904999971f, 0.933000028f, 0.961000025f,
    0.984000027f, 1.01499999f, 1.03299999f, 1.051f, 1.05599999f, 1.05999994f,
    1.05900002f, 1.04999995f, 1.02999997f, 1.00399995f, 0.971000016f, 0.939999998f,
    0.901000023f, 0.856000006f, 0.810000002f, 0.760999978f, 0.709999979f, 0.646000028f,
    0.574999988f, 0.503000021f, 0.439999998f, 0.393000007f, 0.358999997f,
};
static const float cr_norm_tab_b[36] = {
    0.324999988f, 0.367000014f, 0.419f, 0.481000006f, 0.551999986f, 0.629000008f,
    0.700999975f, 0.764999986f, 0.818000019f, 0.865999997f, 0.904999971f, 0.933000028f,
    0.961000025f, 0.984000027f, 1.01499999f, 1.03299999f, 1.051f, 1.05599999f,
    1.05999994f, 1.05900002f, 1.04999995f, 1.02999997f, 1.00399995f, 0.971000016f,
    0.939999998f, 0.901000023f, 0.856000006f, 0.810000002f, 0.760999978f, 0.709999979f,
    0.646000028f, 0.574999988f, 0.503000021f, 0.439999998f, 0.393000007f, 0.358999997f,
};
static const float cr_norm_tab_c[32] = {
    0.419f, 0.481000006f, 0.551999986f, 0.629000008f, 0.700999975f, 0.764999986f,
    0.818000019f, 0.865999997f, 0.904999971f, 0.933000028f, 0.961000025f, 0.984000027f,
    1.01499999f, 1.03299999f, 1.051f, 1.05599999f, 1.05999994f, 1.05900002f,
    1.04999995f, 1.02999997f, 1.00399995f, 0.971000016f, 0.939999998f, 0.901000023f,
    0.856000006f, 0.810000002f, 0.760999978f, 0.709999979f, 0.646000028f, 0.574999988f,
    0.503000021f, 0.439999998f,
};
static const float cr_norm_tab_d[32] = {
    0.518000007f, 0.542999983f, 0.58099997f, 0.632000029f, 0.685000002f, 0.736999989f,
    0.787999988f, 0.833999991f, 0.876999974f, 0.916999996f, 0.952000022f, 0.98299998f,
    1.00800002f, 1.028f, 1.04200006f, 1.04900002f, 1.04900002f, 1.04200006f,
    1.028f, 1.00800002f, 0.98299998f, 0.952000022f, 0.916999996f, 0.876999974f,
    0.833999991f, 0.787999988f, 0.736999989f, 0.685000002f, 0.632000029f, 0.58099997f,
    0.542999983f, 0.518000007f,
};
static const float cr_norm_tab_e[32] = {
    0.740999997f, 0.717999995f, 0.717000008f, 0.741999984f, 0.776000023f, 0.813000023f,
    0.851000011f, 0.885999978f, 0.917999983f, 0.947000027f, 0.972000003f, 0.991999984f,
    1.00800002f, 1.01900005f, 1.02699995f, 1.03100002f, 1.03100002f, 1.02699995f,
    1.01900005f, 1.00800002f, 0.991999984f, 0.972000003f, 0.947000027f, 0.917999983f,
    0.885999978f, 0.851000011f, 0.813000023f, 0.776000023f, 0.741999984f, 0.717000008f,
    0.717999995f, 0.740999997f,
};

static int16_t cr_norm_clamp16(float v)
{
    int16_t out = 16320;
    if (v <= 16320.0f) out = (int16_t)(int)v;
    return out;
}

static int16_t cr_norm_clamp16_lo(float v)
{
    int i = (int)v;
    int16_t out = 16320;
    if (i < 16320) {
        out = (int16_t)i;
        if (i < 1) out = 0;
    }
    return out;
}

int cr_norm_2bd60(cr_image *img, const cr_image *mask, const uint8_t *cfg)
{
    int16_t *d = (int16_t *)img->data;
    int w = img->w, h = img->h;
    const uint8_t *md = (const uint8_t *)mask->data;
    int ms = mask->w;

    if (cfg[10] == 1) {
        int nrows = *(const int32_t *)(cfg + 0x18);
        if (nrows < 1) return 0x69;
        int row0 = *(const int32_t *)(cfg + 0x14);

        void *pv = NULL;
        int st = cr_malloc_aligned16(&pv, (size_t)((int64_t)h << 2));
        if (st != 0) return st;
        float *local = (float *)pv;

        for (int row = 0; row < h; row++) {
            int sum = 0;
            for (int i = 0; i < w; i++) sum += d[(size_t)row * w + i];
            local[row] = (float)sum / (float)w;
        }

        float blk = 0.0f;
        for (int i = row0; i < row0 + nrows; i++) blk += local[i];
        float add = blk / (float)nrows;
        for (int row = 0; row < row0; row++) {
            float rm = local[row];
            for (int i = 0; i < w; i++) {
                size_t k = (size_t)row * w + i;
                float v = ((float)(int)d[k] + add) - rm;
                d[k] = cr_norm_clamp16(v);
            }
        }

        int top = h - row0;
        float blk2 = 0.0f;
        for (int i = top - nrows; i < top; i++) blk2 += local[i];
        float add2 = blk2 / (float)nrows;
        for (int row = top; row < h; row++) {
            float rm = local[row];
            for (int i = 0; i < w; i++) {
                size_t k = (size_t)row * w + i;
                float v = ((float)(int)d[k] + add2) - rm;
                d[k] = cr_norm_clamp16(v);
            }
        }

        cr_sized_free(&pv);
    } else if (cfg[10] != 0) {
        return 0x69;
    }

    int mode = cfg[9];
    if (mode == 0) return 0;

    if (mode == 1 || mode == 2 || mode == 3) {
        int x0 = *(const int32_t *)(cfg + 0xc);
        int x1 = *(const int32_t *)(cfg + 0x10) + x0;
        if (!(x1 < w)) return 0x69;
        if (mode != 3 && !(h > 0x1e)) return 0x69;

        const float *tab = NULL;
        int n = 0;
        if (mode == 3) {
            switch (cfg[0xb]) {
            case 0: tab = cr_norm_tab_a; n = 0x23; break;
            case 1: tab = cr_norm_tab_b; n = 0x24; break;
            case 2: tab = cr_norm_tab_c; n = 0x20; break;
            case 3: tab = cr_norm_tab_d; n = 0x20; break;
            case 4: tab = cr_norm_tab_e; n = 0x20; break;
            case 5: tab = cr_norm_tab_e; n = 0x20; break;
            default: return 0x69;
            }
            if (w != n) return 0x69;
        }

        float mean = 0.0f;
        if (x0 < x1) {
            int cnt = 0;
            float sum = 0.0f;
            for (int c = x0; c < x1; c++)
                for (int r = 0; r < h; r++)
                    if (md[(size_t)r * ms + c] & 0xe) {
                        cnt++;
                        sum += (float)(int)d[(size_t)r * w + c];
                    }
            if (cnt != 0) mean = sum / (float)cnt;
        }

        if (w < 1) return 0;

        for (int c = 0; c < w; c++) {
            int cnt = 0;
            float sum = 0.0f;
            for (int r = 0; r < h; r++)
                if (md[(size_t)r * ms + c] & 0xe) {
                    cnt++;
                    sum += (float)(int)d[(size_t)r * w + c];
                }

            if (mode == 2) {
                float off = 0.0f;
                if (cnt != 0 && 0.0f < mean) off = mean - sum / (float)cnt;
                for (int r = 0; r < h; r++) {
                    size_t k = (size_t)r * w + c;
                    d[k] = cr_norm_clamp16_lo((float)(int)d[k] + off);
                }
            } else if (mode == 1) {
                float g = 1.0f;
                if (cnt != 0 && 0.0f < mean && 0.0f < sum)
                    g = mean / (sum / (float)cnt);
                for (int r = 0; r < h; r++) {
                    size_t k = (size_t)r * w + c;
                    d[k] = cr_norm_clamp16((float)(int)d[k] * g);
                }
            } else {
                float s = sum;
                if (cnt != 0 && 0.0f < mean && 0.0f < s) s = s / (float)cnt;
                float scale = tab[c];
                for (int r = 0; r < h; r++) {
                    size_t k = (size_t)r * w + c;
                    d[k] = cr_norm_clamp16(((float)(int)d[k] - s) * scale + mean);
                }
            }
        }
        return 0;
    }

    return 0x69;
}

/* 0x180016b90 — dispatch a point-selection request on cfg[0x24]. */
int cr_pick_dispatch_16b90(void *pts, int *out_n, int npts, int want,
                           const void *src, uint32_t seed, const void *cfg)
{
    switch (((const uint8_t *)cfg)[0x24]) {
    case 0:
        return cr_keypoint_grid_sample((cr_pt8 *)pts, out_n, npts, want,
                                       (const int *)src, seed,
                                       (const uint8_t *)cfg);
    case 1:
        return cr_grid_pick_37460(pts, out_n, npts, want,
                                  (const cr_image *)src, seed, cfg);
    case 2:
        return cr_bin_select_14320(pts, out_n, npts, want, src, seed, cfg);
    default:
        return 0;
    }
}

/* 0x1800317a0 — mask-aware gap inpainting (cfg[0] == 5 or 7).
 *
 * int cr_mask_inpaint_317a0(uint8_t *flag, const cr_image *img,
 *                           const cr_index_list *list, const uint8_t *cfg);
 *
 * cfg[0] == 5: fill the u16-listed pixels of a u8 image with the mean of
 * their neighbourhood, excluding the listed pixels themselves
 * (cr_box_sum_excl).  A count-byte flag array records what has been filled.
 * Windows 3 and 5 sweep the whole list; after that only border pixels
 * (row or column outside [2, n-3]) are revisited, with windows 5, 7 and then
 * 9.  Window 9 is the give-up point: when an unfilled border pixel is still
 * present the remaining flags are checked and 0x3e9 is returned if cfg[1] is
 * set and any pixel is still unset (otherwise 0).
 *
 * cfg[0] == 7: two directional passes over a u8 image.  The first scans each
 * row for an adjacent pair whose squared difference reaches the i32 threshold
 * at cfg+4, and interpolates *vertically* between the rows of two successive
 * detections (run capped by the signed byte cfg[0xc]).  The second is the
 * transposed counterpart: scan each column, interpolate horizontally, cap
 * cfg[0xd]; an over-long run sets *flag = 1 and is skipped.  Both passes use
 * 10-bit fixed point: step = (0x400/(run+1)) * (b-a), emit
 * ((acc + 0x200) >> 10) + a.
 *
 * Any other mode returns 0x410.  Mode 5 with a NULL/empty list returns 0.
 */
int cr_mask_inpaint_317a0(uint8_t *flag, const cr_image *img,
                          const cr_index_list *list, const uint8_t *cfg)
{
    *flag = 0;

    if (cfg[0] == 5) {
        if (list == NULL || list->count == 0)
            return 0;
        if (cfg[1] != 0 && *(const uint16_t *)(cfg + 2) < list->count)
            return 0x3e9;

        uint8_t *flags = NULL;
        int rc = cr_malloc_aligned16((void **)&flags, list->count);
        if (rc != 0)
            return rc;

        int count = list->count;
        for (int i = 0; i < count; i++)
            flags[i] = 0;

        uint8_t *data = (uint8_t *)img->data;
        int W = img->a;
        int H = img->b;
        int win = 3;

        /* Phase 1: whole-list sweeps with windows 3 and 5. */
        for (;;) {
            int pending = 0;
            for (int i = 0; i < count; i++)
                if (flags[i] == 0) { pending = 1; break; }
            if (!pending || win == 7)
                break;

            for (int i = 0; i < count; i++) {
                if (flags[i] != 0)
                    continue;
                uint16_t idx = list->indices[i];
                int cnt;
                float sum;
                cr_box_sum_excl(W, H, data, &list->count, &list->indices,
                                win, (int)idx, &cnt, &sum);
                if (win == 5 ? cnt > 5 : cnt > 0) {
                    data[idx] = (uint8_t)(int)(sum / (float)cnt + 0.5f);
                    flags[i] = (uint8_t)(100 / win);
                }
            }
            win += 2;
        }

        /* Phase 2: border-only retries, windows 5, 7 and 9.  A pass that
         * touches no pixel (all flagged or interior) is the terminal state. */
        win = 5;
        for (;;) {
            int worked = 0;
            for (int i = 0; i < count; i++) {
                if (flags[i] != 0)
                    continue;
                uint16_t idx = list->indices[i];
                long long li = (long long)idx;
                int row = (int)(li / (long long)W);
                int col = (int)(li % (long long)W);
                if (!(row < 2 || row >= H - 2 || col < 2 || col >= W - 2))
                    continue;

                if (win == 9)
                    goto check_flags;

                worked = 1;
                int cnt;
                float sum;
                cr_box_sum_excl(W, H, data, &list->count, &list->indices,
                                win, (int)idx, &cnt, &sum);
                if (cnt > 0) {
                    data[idx] = (uint8_t)(int)(sum / (float)cnt + 0.5f);
                    flags[i] = (uint8_t)cr_floorf_to_int(
                        (1.0f / (float)win) * 100.0f);
                }
            }
            if (!worked)
                break;
            win += 2;
        }

check_flags:
        if (cfg[1] != 0) {
            for (int i = 0; i < count; i++)
                if (flags[i] == 0) {
                    cr_sized_free((void **)&flags);
                    return 0x3e9;
                }
        }
        cr_sized_free((void **)&flags);
        return 0;
    }

    if (cfg[0] != 7)
        return 0x410;

    uint8_t *data = (uint8_t *)img->data;
    int W = img->w;
    int H = img->h;
    int thr = *(const int *)(cfg + 4);
    int cap_a = (int8_t)cfg[0xc];
    int cap_b = (int8_t)cfg[0xd];

    /* ---- pass 1: scan rows, interpolate down the columns ---------------- */
    if (H > 0) {
        uint8_t *prev = NULL;
        int run = 0;

        for (int r = 0; r < H; r++) {
            uint8_t *row = data + (size_t)r * (size_t)W;
            int d2 = 0;
            int gap = 0;

            if (W < 2) {
                d2 = 0;
                gap = (thr <= d2);
            } else {
                int t = (int)row[1] - (int)row[0];
                d2 = t * t;
                if (d2 >= thr) {
                    gap = 1;
                } else {
                    for (int k = 1; k <= W - 2; k++) {
                        t = (int)row[k + 1] - (int)row[k];
                        d2 = t * t;
                        if (d2 >= thr) { gap = 1; break; }
                    }
                }
            }

            if (gap) {
                if (prev != NULL && run != 0 && run <= cap_a) {
                    int stepbase = 0x400 / (run + 1);
                    for (int c = 0; c < W; c++) {
                        int a = prev[c];
                        if (a == 0)
                            continue;
                        int b = row[c];
                        if (b == 0)
                            continue;
                        int step = stepbase * (b - a);
                        int acc = step + 0x200;
                        uint8_t *p = prev + (size_t)W + (size_t)c;
                        for (int k = 1; k <= run; k++) {
                            *p = (uint8_t)((acc >> 10) + a);
                            acc += step;
                            p += W;
                        }
                    }
                }
                prev = row;
                run = 0;
            } else {
                run++;
            }
        }
    }

    /* ---- pass 2: scan columns, interpolate across the rows --------------- */
    *flag = 0;
    if (W > 0) {
        uint8_t *prev = NULL;
        int run = 0;

        for (int c = 0; c < W; c++) {
            uint8_t *col = data + c;
            int d2 = 0;
            int gap = 0;

            if (H < 2) {
                d2 = 0;
                gap = (d2 >= thr);
            } else {
                int t = (int)col[W] - (int)col[0];
                d2 = t * t;
                if (d2 >= thr) {
                    gap = 1;
                } else {
                    for (int k = 2; k < H; k++) {
                        t = (int)col[(size_t)k * (size_t)W] -
                            (int)col[(size_t)(k - 1) * (size_t)W];
                        d2 = t * t;
                        if (d2 >= thr) { gap = 1; break; }
                    }
                }
            }

            if (gap) {
                if (prev == NULL || run == 0) {
                    prev = col;
                    run = 0;
                } else if (run <= cap_b) {
                    int stepbase = 0x400 / (run + 1);
                    if (H > 0) {
                        for (int r = 0; r < H; r++) {
                            uint8_t *pp = prev + (size_t)r * (size_t)W;
                            uint8_t *cc = col + (size_t)r * (size_t)W;
                            int a = *pp;
                            int b = *cc;
                            if (a == 0 || b == 0)
                                continue;
                            int step = (b - a) * stepbase;
                            int acc = step + 0x200;
                            uint8_t *p = pp + 1;
                            for (int k = 1; k <= run; k++) {
                                *p = (uint8_t)(a + (acc >> 10));
                                p++;
                                acc += step;
                            }
                        }
                    }
                    prev = col;
                    run = 0;
                } else {
                    *flag = 1;
                    prev = col;
                    run = 0;
                }
            } else {
                run++;
            }
        }
    }

    return 0;
}

/* 0x18002f2e0 — point-selection wrapper around cr_pick_dispatch_16b90.
 *
 * int cr_pick_points_2f2e0(uint8_t *out_xy, float *out_val, int *out_n,
 *                          const uint8_t *xy_tab, const float *val_tab,
 *                          int npts, int want, const void *src,
 *                          uint32_t seed, const void *cfg);
 *
 * Builds `npts` 8-byte records {int32 index; float value} from the value
 * table, sorts them by value descending (cr_sort_records key_type 1, dir 1),
 * then replaces the value word with the two coordinate bytes
 * {int32 index; int16 x; int16 y} read from xy_tab[index*2].  The scratch
 * array holds (int16)cfg[0x10] records.  The dispatcher then selects up to
 * min(npts, want) records; on success the selected records are copied back to
 * out_xy (2 bytes each) and out_val (the original float at index).  npts == 0
 * returns 0 without allocating.  A negative npts skips the record fill (the
 * vendor does the same) and is otherwise treated like a normal count.
 */
int cr_pick_points_2f2e0(uint8_t *out_xy, float *out_val, int *out_n,
                         const uint8_t *xy_tab, const float *val_tab,
                         int npts, int want, const void *src,
                         uint32_t seed, const void *cfg)
{
    if (npts == 0)
        return 0;

    void *buf = NULL;
    int16_t maxrec = *(const int16_t *)(cfg + 0x10);
    int rc = cr_malloc_aligned16(&buf, (size_t)((int64_t)maxrec * 8));
    if (rc != 0)
        return rc;

    cr_pt8 *rec = (cr_pt8 *)buf;

    if (npts > 0) {
        for (int i = 0; i < npts; i++) {
            rec[i].w[0] = i;
            rec[i].w[1] = *(const int32_t *)(val_tab + i);
        }
        rc = cr_sort_records(rec, npts, 1, 1);
        if (rc != 0)
            goto done;

        for (int i = 0; i < npts; i++) {
            int idx = rec[i].w[0];
            rec[i].s.f4 = (int16_t)xy_tab[(size_t)idx * 2];
            rec[i].s.f6 = (int16_t)xy_tab[(size_t)idx * 2 + 1];
        }
    } else {
        rc = cr_sort_records(rec, npts, 1, 1);
        if (rc != 0)
            goto done;
    }

    int want_eff = (npts > want) ? want : npts;
    rc = cr_pick_dispatch_16b90(rec, out_n, npts, want_eff, src, seed, cfg);
    if (rc != 0)
        goto done;

    if (*out_n > 0) {
        for (int i = 1; i <= *out_n; i++) {
            int idx = rec[i - 1].w[0];
            out_xy[2 * i - 2] = xy_tab[(size_t)idx * 2];
            out_xy[2 * i - 1] = xy_tab[(size_t)idx * 2 + 1];
            out_val[i - 1] = val_tab[idx];
        }
    }

done:
    cr_sized_free(&buf);
    return rc;
}

/* 0x18002b680 — point-selection dispatch for the mask-binning selector.
 *
 * int cr_pick_points_dispatch_2b680(void *a, const void *src,
 *                                   const uint8_t *cfg);
 *
 * Thin wrapper: unless cfg[0x24] == 2 (the cr_bin_select_14320 branch) it
 * returns 0 without touching anything.  Otherwise it forwards the seven
 * fields held in `a` (out_xy at +0x08, out_val at +0x10, out_n at +0x40,
 * xy_tab at +0x20, val_tab at +0x28, npts at +0x44, seed at +0x4c), the
 * caller's `src` and `want = *(int*)(cfg+0x14)` to cr_pick_points_2f2e0.
 */
int cr_pick_points_dispatch_2b680(void *a, const void *src, const uint8_t *cfg)
{
    if (cfg[0x24] != 2)
        return 0;

    const uint8_t *b = (const uint8_t *)a;
    return cr_pick_points_2f2e0(*(uint8_t **)(b + 0x08),
                                *(float **)(b + 0x10),
                                (int *)(b + 0x40),
                                *(const uint8_t **)(b + 0x20),
                                *(const float **)(b + 0x28),
                                *(const int *)(b + 0x44),
                                *(const int *)(cfg + 0x14),
                                src,
                                *(const uint32_t *)(b + 0x4c),
                                cfg);
}


/* 0x18002e060 — multi-scale feature/descriptor score-map builder.
 *
 *   int cr_mscale_score_2e060(uint16_t *out, cr_image *score_out,
 *                             const void *bitmap, const cr_image *src,
 *                             const void *scale_desc);
 *
 * Verbatim from 0x18002e060..0x18002e693 (raw asm + Ghidra).  `score_out` is
 * a w2 x h2 f32 map that the caller has pre-filled with -1.0f; only the
 * centred region is rewritten.  The vendor derives the region origin as
 *   fx = (w2*scale != W) ? (float)(W - (w2*scale - 2*scale)) * 0.5f : 0
 *   x0 = lroundf(fx)
 * (likewise y0 from h2/H) — note w2, not W — and then starts writing at
 * score index (y0 != 0)*w2 + (x0 != 0), i.e. it skips row/column 0 whenever
 * a margin exists instead of dividing the origin by `scale`.
 *
 *   *out        : 0xffff on entry, then (short)(int) of the mean of every
 *                 score pixel != -1.0f.  NaN is *not* filtered.
 *   scale_desc  : +0x0c float sigma, +0x10 int scale, +0x14 float threshold.
 *   bitmap      : +0x00 int stride, +0x08 uint32 *bits, +0x18 int off_col,
 *                 +0x1c int off_row.  Bit index (off_row+y)*stride+off_col+x,
 *                 but the shift is (off_col+x)&31 (the row base is dropped),
 *                 exactly as in cr_bitmap_unpack_boxmax_fir.
 * Returns 0x69 from the geometry guards, otherwise the status of the last
 * callee (0 on success).
 */
int cr_mscale_score_2e060(uint16_t *out, cr_image *score_out,
                          const void *bitmap, const cr_image *src,
                          const void *scale_desc)
{
    const uint8_t *sd = (const uint8_t *)scale_desc;
    const uint8_t *bm = (const uint8_t *)bitmap;

    int W = src->w;
    int H = src->h;
    int scale = *(const int32_t *)(sd + 0x10);

    *out = 0xffff;
    if (!(scale < W && scale < H && 0 < scale))
        return 0x69;

    int w2 = score_out->w;
    int ws = w2 * scale;
    if (W > ws)
        return 0x69;
    int h2 = score_out->h;
    int hs = h2 * scale;
    if (H > hs)
        return 0x69;

    float sigma = *(const float *)(sd + 0x0c);
    float thr   = *(const float *)(sd + 0x14);

    cr_image img1, img2;
    int r = (int)cr_image_set(&img1, NULL, W, H);
    if (r != 0)
        return r;
    r = (int)cr_image_set(&img2, NULL, W, H);
    if (r != 0)
        return r;

    void *pool[2];
    uint32_t sz = (uint32_t)(W * H * 2);
    uint32_t pr = cr_pool_alloc2((void **)pool, &img1.data, sz,
                                 &img2.data, sz);
    if (pr != 0)
        return (int)pr;

    r = cr_gauss_deriv_3img(&img1, &img2, (void *)src, sigma);
    if (r == 0) {
        static const float C590 = 0.5f;     /* 0x18008c590 */
        static const float C5c0 = -1.0f;    /* 0x18008c5c0 */
        static const float C5c4 = 4.0f;     /* 0x18008c5c4 */
        static const float C5c8 = 100.0f;   /* 0x18008c5c8 */

        /* centring origin: 0.5 * (target - (scaled - 2*scale)), rounded.  The
         * vendor uses w2/h2 here, not the source dimensions. */
        float fx = (ws != W) ? (float)(W - (ws + scale * -2)) * C590 : 0.0f;
        int   ty = 0;
        if (hs != H)
            ty = H - (hs + scale * -2);
        int x0 = cr_lroundf(fx);
        int y0 = cr_lroundf((float)ty * C590);

        int16_t *i1 = (int16_t *)img1.data;
        int16_t *i2 = (int16_t *)img2.data;
        int      iw = img1.w;
        float   *so = (float *)score_out->data;

        int stride  = *(const int32_t *)(bm + 0x00);
        const uint32_t *bits = *(uint32_t *const *)(bm + 0x08);
        int off_col = *(const int32_t *)(bm + 0x18);
        int off_row = *(const int32_t *)(bm + 0x1c);

        int Hlim = H - y0;
        int Wlim = W - x0;

        if (y0 < Hlim) {
            int srow = (y0 != 0) * w2;
            int bi = y0;
            do {
                int bi_end = bi + scale;
                if (x0 < Wlim) {
                    int sidx = srow + (x0 != 0);
                    int bj = x0;
                    do {
                        int bj_end = bj + scale;
                        int   cnt = 0;
                        float sa2 = 0.0f, sb2 = 0.0f, sab = 0.0f;

                        int row = bi;
                        int rowidx = bi * iw;
                        do {
                            if (bj < bj_end) {
                                int base = (off_row + row) * stride;
                                int bit  = off_col + bj + base;
                                int k    = 0;
                                do {
                                    if ((bits[bit >> 5] >>
                                         ((bit - base) & 0x1f)) & 1u) {
                                        int a = i1[rowidx + bj + k];
                                        int b = i2[rowidx + bj + k];
                                        cnt++;
                                        sa2 += (float)(a * a);
                                        sb2 += (float)(b * b);
                                        sab += (float)(a * b);
                                    }
                                    bit++;
                                    k++;
                                } while (bit != bj_end + off_col + base);
                            }
                            row++;
                            rowidx += iw;
                        } while (row != bi_end);

                        float score = C5c0;
                        if (scale * scale == cnt) {
                            float N = (float)(scale * scale);
                            float d = sa2 / N - sb2 / N;
                            float root = cr_sqrtf((sab / N) * (sab / N) * C5c4
                                                  + d * d);
                            float S = sb2 / N + sa2 / N;
                            float den = (root + S) * C590;
                            if (den <= 0.0f) {
                                score = C5c0;
                            } else {
                                score = (1.0f - ((S - root) * C590) / den)
                                        * C5c8;
                            }
                        }

                        so[sidx] = score;
                        if (score <= thr && thr != score && 0.0f <= thr) {
                            so[sidx] = C5c0;
                            cr_bitmap_clear_rect((cr_image *)bitmap,
                                                 bi, bi_end, bj, bj_end);
                        }
                        sidx++;
                        bj = bj_end;
                    } while (bj < Wlim);
                }
                srow += w2;
                bi = bi_end;
            } while (bi < Hlim);
        }

        /* mean over every score pixel != -1.0f (NaN is not filtered) */
        int   n = w2 * h2;
        float sum = 0.0f;
        int   cnt = 0;
        for (int i = 0; i < n; i++) {
            if (so[i] != C5c0) {
                sum += so[i];
                cnt++;
            }
        }
        *out = (uint16_t)(int32_t)(sum / (float)cnt);
    }

    cr_sized_free_if((void **)pool);
    return r;
}

/* 0x180016d00 — integer-factor downscale driver for cr_mscale_score_2e060.
 *
 *   int cr_mscale_run_16d00(uint16_t *out, void *bitmap, const cr_image *src,
 *                           const void *scale_desc);
 *
 *   n = *(int *)(scale_desc + 0x10);
 *   X = src->h;  Y = src->w;
 *   if (!(n < X && n < Y && n > 0)) return 0x69;
 *   qY = Y / n;  qX = X / n;
 *   h_arg = (n*qX == Y) ? qX : qX + 2;    // the vendor really does compare
 *   w_arg = (n*qY == X) ? qY : qY + 2;    // qX against Y and qY against X
 *   cr_image_alloc_f32(&tmp, w_arg, h_arg);
 *   cr_rect_fill_f32(&tmp, -1.0f);
 *   r = cr_mscale_score_2e060(out, &tmp, bitmap, src, scale_desc);
 *   cr_cleanup_ptr8_clear_b(&tmp);
 *   return r;
 */
int cr_mscale_run_16d00(uint16_t *out, void *bitmap, const cr_image *src,
                        const void *scale_desc)
{
    int n = *(const int32_t *)((const uint8_t *)scale_desc + 0x10);
    int X = src->h;
    int Y = src->w;

    if (!(n < X && n < Y && 0 < n))
        return 0x69;

    int qY = Y / n;
    int qX = X / n;
    int h_arg = (n * qX == Y) ? qX : qX + 2;
    int w_arg = (n * qY == X) ? qY : qY + 2;

    cr_image tmp;
    int r = cr_image_alloc_f32(&tmp, w_arg, h_arg);
    if (r != 0)
        return r;

    cr_rect_fill_f32(&tmp, -1.0f);
    r = cr_mscale_score_2e060(out, &tmp, bitmap, src, scale_desc);
    cr_cleanup_ptr8_clear_b(&tmp);
    return r;
}

/* 0x1800273a0 — stage-run driver with a per-block projection pass.
 *
 * int cr_stage_run_273a0(float *out, const int *chain, const cr_image *img,
 *                        const cr_sampler *s);
 *
 * chain[2] points at the stage-descriptor array.  When chain[0] == 3 and the
 * descriptors form a three-level pyramid (d[0] == 5, d[0xc] == 3,
 * d[0x18] == 5) the buffer size is
 *     sum over the three 0x30-byte levels of (tag+1)*L[0]*L[1]*(1,2,2)
 * plus 2*first_block[0] when there is at least one block, and the stage runs
 * through cr_pyramid_364c0.  Otherwise the size is
 *     2*trunc((H-tag+1)/2) * ((W-tag+1)/2) * nk + (tag+1)*H,
 * raised to 2*chain[9], and the stage runs through cr_maxpool_stream_21000.
 *
 * Afterwards each of the chain[4] 0x20-byte block descriptors
 * {p0, p1, flag, 0, coef*, bias*} projects the first p0 int16 of the buffer
 * onto p1 outputs: out[r] = (sum_j coef[r*p0+j]*buf[j] + bias[r]*0x4000) >> 15
 * with 32-bit wrapping accumulation; flag == 1 clamps the block non-negative.
 * The p1 results are then copied back over the head of the buffer.  Finally
 * cr_softmax2 writes the single float result from buf[0], buf[1] and the
 * buffer is released.  A stage failure frees the buffer and returns the
 * status unchanged.
 */
int cr_stage_run_273a0(float *out, const int *chain, const cr_image *img,
                       const cr_sampler *s)
{
    const int *d = *(const int *const *)((const char *)chain + 8);
    const int tag = d[0];
    void *buf = NULL;
    int r;

    if (chain[0] == 3 && tag == 5 && d[0xc] == 3 && d[0x18] == 5) {
        int size = 0, mult = 1, t = 5;
        const int *p = d + 2;
        for (;;) {
            size += (t + 1) * p[0] * p[1] * mult;
            if (p + 0xc == d + 0x26)
                break;
            t = p[10];
            mult = 2;
            p += 0xc;
        }
        if (chain[4] > 0)
            size += **(const int *const *)((const char *)chain + 0x18) * 2;
        r = cr_malloc_aligned16(&buf, (size_t)size);
        if (r != 0)
            return r;
        r = 0x69;
        if (chain[0] != 3)
            goto fail;
        r = cr_pyramid_364c0(buf, chain, img, s);
    } else {
        int x = (d[1] - tag) + 1;
        int size = (int)(((uint32_t)x + ((uint32_t)x >> 31)) & 0xfffffffeu)
                 * (((d[2] - tag) + 1) / 2) * d[5]
                 + (tag + 1) * d[1];
        int floorv = *(const int *)((const char *)chain + 0x24) * 2;
        if (size < floorv)
            size = floorv;
        r = cr_malloc_aligned16(&buf, (size_t)size);
        if (r != 0)
            return r;
        r = cr_maxpool_stream_21000(buf, chain, img, s);
    }

    if (r == 0) {
        int16_t *b = (int16_t *)buf;
        const int nblk = chain[4];
        if (nblk > 0) {
            const uint8_t *blk = *(const uint8_t *const *)((const char *)chain + 0x18);
            for (int i = 0; i < nblk; i++) {
                const uint8_t *p = blk + (size_t)i * 0x20;
                const int p0 = *(const int *)(p + 0x00);
                const int p1 = *(const int *)(p + 0x04);
                const int flag = *(const int *)(p + 0x08);
                const int16_t *coef = *(const int16_t *const *)(p + 0x10);
                const int16_t *bias = *(const int16_t *const *)(p + 0x18);
                int16_t *op = b + p0;

                if (p1 >= 1) {
                    int row = 0;
                    for (int i2 = 0; i2 < p1; i2++) {
                        uint32_t sum = 0;
                        if (p0 > 0) {
                            const int16_t *cp = coef + row;
                            for (int j = 0; j < p0; j++)
                                sum += (uint32_t)(int32_t)cp[j]
                                     * (uint32_t)(int32_t)b[j];
                        }
                        row += p0;
                        sum += (uint32_t)(int32_t)bias[i2] << 14;
                        op[i2] = (int16_t)((int32_t)sum >> 15);
                    }
                    if (flag == 1)
                        cr_s16_clamp_nonneg(op, op, p1);
                    for (int j = 0; j < p1; j++)
                        b[j] = op[j];
                } else if (flag == 1) {
                    cr_s16_clamp_nonneg(op, op, p1);
                }
            }
        }
        cr_softmax2(out, chain, b);
        cr_sized_free(&buf);
        return 0;
    }

fail:
    cr_sized_free(&buf);
    return r;
}

/* 0x18000e850 — per-keypoint descriptor packer.
 *
 * int cr_feat_pack_0e850(cr_image *src, cr_feat_obj *obj, const uint8_t *cfg);
 *
 * cfg[0xb] selects the warp/signpack descriptor (cr_desc_get_tag_byte_ptr:
 * only 2 and 4 succeed, both giving M=25, N=16 and a table pointer), cfg[0xe]
 * selects the triple descriptor (cr_desc_get_triple: 0 succeeds empty, 1..4
 * return 1, 5 succeeds with the 16-sample table, >=6 gives 0x69).  With a
 * non-zero cfg[0xe] the two N fields must agree.  obj+0x30 = cfg[0xc],
 * obj+0x31 = the descriptor byte, obj+0x34 = the triple's second int; when it
 * is positive obj+0x38 gets (n+1) u16 slots.  A byte above 0xc in cfg[0xb]
 * returns 0x69.
 *
 * The scratch pair is { N*N bytes, NULL }; the pair array is count 8-byte
 * {index, score} records.  For every keypoint the source is warped into the
 * N x N scratch, sign-packed into obj->rows + b8*i, optionally orientation
 * picked (skipped when cfg[0xc] != 0, because the vendor's coefficient
 * pointer comes from a table the clean-room leaves NULL), and scored into the
 * pair array when the triple has a coefficient table.  The pair array is then
 * sorted ascending by score and the four parallel arrays are permuted; the
 * final (nbins+1)-entry u16 table records, for each threshold, the first
 * sorted index whose score exceeds it.
 *
 * NOTE: the clean-room descriptor getters leave the vendor's read-only table
 * pointers NULL, so cr_signpack_dot returns 0x69 as soon as a point is
 * processed.  Only the guard paths and the count <= 0 success path can be
 * compared; the loop body is transcribed from the disassembly but is not
 * exercised by the difftest.
 */
typedef struct {                 /* warp/signpack descriptor (local_60) */
    int32_t  m;                  /* +0x00 */
    int32_t  n;                  /* +0x04 */
    uint8_t  b8;                 /* +0x08 */
    uint8_t  _pad[7];
    void    *tab;                /* +0x10 */
    void    *tab2;               /* +0x18 */
} cr_ws_desc;

typedef struct {                 /* triple descriptor (local_80) */
    int32_t        a;            /* +0x00 */
    int32_t        b;            /* +0x04 */
    const int16_t *coef;         /* +0x08 */
    const int32_t *thr;          /* +0x10 */
} cr_triple_desc;

int cr_feat_pack_0e850(cr_image *src, cr_feat_obj *obj, const uint8_t *cfg)
{
    cr_ws_desc ws;
    uint64_t r = cr_desc_get_tag_byte_ptr(&ws, (char)cfg[0xb]);
    if ((int32_t)r != 0)
        return (int32_t)r;

    cr_triple_desc td;
    r = cr_desc_get_triple(&td, cfg[0xe]);
    if ((int32_t)r != 0)
        return (int32_t)r;

    if (cfg[0xe] != 0 && ws.n != td.a)
        return 0x69;

    obj->b30 = cfg[0xc];
    obj->b31 = ws.b8;
    obj->nbins = td.b;
    if (td.b > 0) {
        r = cr_malloc_aligned16((void **)&obj->bins,
                                (size_t)(td.b + 1) * 2);
        if ((int32_t)r != 0)
            return (int32_t)r;
    }

    if (cfg[0xb] > 0xc)
        return 0x69;

    void *sp[2] = { NULL, NULL };
    r = cr_malloc_aligned16(&sp[0], (size_t)(ws.n * ws.n));
    if ((int32_t)r != 0)
        return (int32_t)r;

    int32_t *pairs = NULL;
    r = cr_malloc_aligned16((void **)&pairs,
                            (size_t)((uint64_t)(uint32_t)obj->count << 3));
    if ((int32_t)r != 0) {
        cr_free_pair8(sp);
        return (int32_t)r;
    }

    void *coef2 = NULL;
    if (cfg[0xc] == 0) {
        r = cr_desc_get_ptr2_69(&coef2, (char)cfg[0xd]);
        if ((int32_t)r != 0) {
            cr_sized_free((void **)&pairs);
            cr_free_pair8(sp);
            return (int32_t)r;
        }
    }

    int32_t count = obj->count;
    int32_t orient = 0;
    for (int32_t i = 0; i < count; i++) {
        uint8_t *row = obj->rows + (size_t)(ws.b8 * (int8_t)i);
        r = (uint64_t)cr_warp_rotate_u8(sp[0], src,
                                        obj->xy[(size_t)i * 2],
                                        obj->xy[(size_t)i * 2 + 1],
                                        obj->mask[i], (const int *)&ws);
        if ((int32_t)r != 0)
            goto fail;
        r = (uint64_t)cr_signpack_dot(row, (const void *const *)sp,
                                      (const uint8_t *)&ws);
        if ((int32_t)r != 0)
            goto fail;
        if (cfg[0xc] == 0)
            cr_orient_pick(row, obj->mask + i, &orient,
                           (const uint8_t *const *)sp,
                           (const int16_t *)coef2, ws.b8, ws.n);
        if (td.coef != NULL) {
            pairs[(size_t)i * 2] = i;
            cr_norm_corr_score(&pairs[(size_t)i * 2 + 1],
                               (void *const *)sp, td.coef, ws.n, orient);
        }
    }

    if (td.coef != NULL) {
        r = (uint64_t)cr_sort_records(pairs, count, 0, 0);
        if ((int32_t)r != 0)
            goto fail;
        cr_permute_rows(obj->xy, pairs, count, 2);
        r = (uint64_t)cr_permute_rows(obj->f8, pairs, count, 4);
        if ((int32_t)r != 0)
            goto fail;
        r = (uint64_t)cr_permute_rows(obj->mask, pairs, count, 1);
        if ((int32_t)r != 0)
            goto fail;
        r = (uint64_t)cr_permute_rows(obj->rows, pairs, count, obj->b31);
        if ((int32_t)r != 0)
            goto fail;

        uint16_t *bins = obj->bins;
        int32_t nbins = obj->nbins;
        int32_t n = obj->count;
        if (nbins > 1) {
            int32_t pos = 0;
            for (int32_t k = 0; k < nbins - 1; k++) {
                if (pos < n) {
                    int32_t thr = td.thr[k];
                    if (pairs[(size_t)pos * 2 + 1] <= thr) {
                        int32_t j = pos + 1;
                        int found = 0;
                        while (j != n) {
                            pos = j;
                            j++;
                            if (pairs[(size_t)(j - 1) * 2 + 1] > thr) {
                                found = 1;
                                break;
                            }
                        }
                        if (!found)
                            pos = n;
                    }
                }
                bins[k + 1] = (uint16_t)pos;
            }
        }
        bins[0] = 0;
        bins[nbins] = (uint16_t)n;
    }

    cr_sized_free((void **)&pairs);
    cr_free_pair8(sp);
    return 0;

fail:
    cr_sized_free((void **)&pairs);
    cr_free_pair8(sp);
    return (int32_t)r;
}

/* 0x18002a620 — masked illumination flattening with a sharpness accept gate.
 *
 *   int cr_masked_contrast_norm_2a620(cr_image *src, void *params,
 *                                     cr_image *mask);
 *
 * `src` is a full-view f32 image (w/h at +0x10/+0x14, data at +8); `params`
 * supplies the u16 mask at +0x58 and a flag byte at +0x8; `mask` is a u8
 * image whose 0xff bytes mark the *valid* (unmasked) pixels.
 *
 * Pipeline (0x18002a620..0x18002ac2e):
 *   1. Four descriptors i1..i4 (i1/i2 int16, i3/i4 f32) plus one 4-block pool
 *      (n*2, n*2, n*4, n*4 bytes).
 *   2. n > 0: src*64 -> i1 (int16 truncation); i2 = gauss7(i1, sigma 0.7);
 *      i4 = i1 - i2 (image residual); i1 = u16 mask; i2 = gauss7(i1, 0.7);
 *      i3 = i1 - i2 (mask residual).  When flag < 1 the mask residual is
 *      rounded back into i1 (so the "mask" used below becomes the residual).
 *      n <= 0: just the two gauss calls.
 *   3. Interior 10..W-11 x 10..H-11 pixels with mask8 == 0xff accumulate
 *      count / sum / sum-of-squares of the mask residual; every other pixel
 *      zeroes both residuals.
 *   4. scale = (cov / (count*sumsq - sum^2)) / 64, where
 *      cov = sum_i (maskres_i*count - sum) * imres_i; a zero denominator
 *      falls back to 1/64.
 *   5. in_metric = masked sharpness of src; out_i = clamp((src_i -
 *      (mask16_i - mean(mask16))*scale)*mask8_i + (255-mask8_i)*max(src)) / 255
 *      into i4; out_metric = masked sharpness of i4.  Only when
 *      (int)(out_metric*0.8f) <= in_metric is i4 copied back into src.
 * Returns 0 on success, or the first failing callee status.
 */
int cr_masked_contrast_norm_2a620(cr_image *src, void *params, cr_image *mask)
{
    static const float C64  = 64.0f;        /* 0x18008bc04 */
    static const float C255 = 255.0f;       /* 0x18008bc00 */
    static const float C70  = 0.7f;         /* 0x18008bc40 */
    static const float C1_64 = 0.015625f;   /* 0x18008bc10 */
    static const float C80  = 0.8f;         /* 0x18008bc44 */

    int W = src->w;
    int H = src->h;
    float *sdata = (float *)src->data;
    int16_t *mask_u16 = *(int16_t **)((uint8_t *)params + 0x58);
    int8_t flag = *(int8_t *)((uint8_t *)params + 0x8);
    uint8_t *mask8 = (uint8_t *)mask->data;
    int n = H * W;

    cr_image i1, i2, i3, i4;
    int r = cr_image_set(&i1, NULL, W, H);
    if (r != 0) return r;
    r = cr_image_set(&i2, NULL, W, H);
    if (r != 0) return r;
    r = cr_image_set(&i3, NULL, W, H);
    if (r != 0) return r;
    r = cr_image_set(&i4, NULL, W, H);
    if (r != 0) return r;

    void *pool[4];
    uint32_t pr = cr_pool_alloc4(pool, &i1.data, (uint32_t)(n * 2),
                                 &i2.data, (uint32_t)(n * 2),
                                 &i3.data, (uint32_t)(n * 4),
                                 &i4.data, (uint32_t)(n * 4));
    if (pr != 0)
        return (int)pr;

    int16_t *m16 = (int16_t *)i1.data;
    int16_t *g16 = (int16_t *)i2.data;
    float   *mres = (float *)i3.data;
    float   *ires = (float *)i4.data;

    if (n > 0) {
        for (int i = 0; i < n; i++)
            m16[i] = (int16_t)(int32_t)(sdata[i] * C64);

        r = cr_gauss_fir7_apply(&i2, &i1, 0.0f, 0.0f, C70);
        if (r != 0) goto done;

        for (int i = 0; i < n; i++)
            ires[i] = (float)m16[i] - (float)g16[i];

        for (int i = 0; i < n; i++)
            m16[i] = mask_u16[i];

        r = cr_gauss_fir7_apply(&i2, &i1, 0.0f, 0.0f, C70);
        if (r != 0) goto done;

        for (int i = 0; i < n; i++)
            mres[i] = (float)m16[i] - (float)g16[i];

        if (flag < 1) {
            for (int i = 0; i < n; i++)
                m16[i] = (int16_t)(int32_t)mres[i];
        }
    } else {
        r = cr_gauss_fir7_apply(&i2, &i1, 0.0f, 0.0f, C70);
        if (r != 0) goto done;
        r = cr_gauss_fir7_apply(&i2, &i1, 0.0f, 0.0f, C70);
        if (r != 0) goto done;
    }

    {
        float scale = C1_64;
        if (H > 0) {
            int   count = 0;
            float sum = 0.0f, sumsq = 0.0f;

            for (int y = 0; y < H; y++) {
                int row = y * W;
                for (int x = 0; x < W; x++) {
                    if ((int8_t)mask8[row + x] == -1 && y > 9 && y < H - 10
                        && x > 9 && x < W - 10) {
                        float v = mres[row + x];
                        count++;
                        sum += v;
                        sumsq += v * v;
                    } else {
                        mres[row + x] = 0.0f;
                        ires[row + x] = 0.0f;
                    }
                }
            }

            float cnt = (float)count;
            float cov = 0.0f;
            if (n > 0) {
                for (int i = 0; i < n; i++)
                    cov += (mres[i] * cnt - sum) * ires[i];
            }
            float den = sumsq * cnt - sum * sum;
            if (den == 0.0f)
                scale = C1_64;
            else
                scale = (cov / den) * C1_64;
        }

        int in_metric = 0;
        r = cr_masked_sharpness_f32(&in_metric,
                                    (const float *const *)&src->data,
                                    W, H, (void *const *)&mask->data);
        if (r != 0) goto done;

        if (n > 0) {
            float sum_mask = 0.0f, max_src = 0.0f;
            for (int i = 0; i < n; i++) {
                sum_mask += (float)m16[i];
                if (sdata[i] > max_src)
                    max_src = sdata[i];
            }
            float mean_mask = sum_mask / (float)n;

            for (int i = 0; i < n; i++) {
                unsigned mk = mask8[i];
                float v = ((sdata[i] - ((float)m16[i] - mean_mask) * scale)
                           * (float)mk + (float)(int)(0xff - mk) * max_src)
                          / C255;
                if (v > 0.0f) {
                    if (v >= C255)
                        v = C255;
                } else {
                    v = 0.0f;
                }
                ires[i] = v;
            }
        }

        int out_metric = 0;
        r = cr_masked_sharpness_f32(&out_metric,
                                    (const float *const *)&i4.data,
                                    i4.w, i4.h, (void *const *)&mask->data);
        if (r == 0 && (int32_t)((float)out_metric * C80) <= in_metric) {
            int cr2 = (int)cr_image_copy_u32(src, &i4);
            if (cr2 != 0) {
                cr_sized_free_if((void **)pool);
                return cr2;
            }
            r = cr2;
        }
    }

done:
    cr_sized_free_if((void **)pool);
    return r;
}

/* 0x180032580 — mask-build + illumination-flatten dispatcher.
 *
 *   int cr_mask_norm_32580(cr_image *src, void *ctx, void *a3,
 *                          const cr_image *packed, const void *a5,
 *                          int idx, const uint8_t *cfg, int flag);
 *
 *   mode = cfg[0x44]
 *   mode 0 -> return 0
 *   mode 1 -> copy_image_fields(a3, ctx); mask = bitmap_build_masked(packed,cfg);
 *             if (flag == 0 && *(int*)(a5+4) < 1) {
 *                 h = *(void**)(a3 + 0x38 + idx*8);
 *                 if (!h) { r = 0x3ec; goto out; }
 *                 r = feature_extract_step_2db20(ctx, src, h, packed, cfg+0x44);
 *                 if (r) goto out;
 *             }
 *   mode 2 -> copy_image_fields(a3, ctx); mask = bitmap_build_masked(packed,cfg);
 *   else   -> return 0x69
 *   r = masked_contrast_norm_2a620(src, ctx, &mask);
 * out: cleanup_ptr8_a(&mask); return r;
 *
 * `ctx+0x58` is the u16 mask buffer filled by copy_image_fields; `a3+0x28`
 * holds the int16 image descriptor that feeds it and `a3+0x38+idx*8` the
 * optional feature-extract handle.
 */
int cr_mask_norm_32580(cr_image *src, void *ctx, void *a3,
                       const cr_image *packed, const void *a5,
                       int idx, const uint8_t *cfg, int flag)
{
    int8_t mode = *(const int8_t *)(cfg + 0x44);
    cr_image mask = { 0 };
    int r;

    if (mode == 1) {
        r = cr_copy_image_fields(a3, ctx);
        if (r != 0)
            goto out;
        r = cr_bitmap_build_masked(&mask, packed, cfg);
        if (r != 0)
            goto out;
        if (flag == 0 && *(const int32_t *)((const uint8_t *)a5 + 4) < 1) {
            void *h = *(void **)((uint8_t *)a3 + 0x38 + (long)idx * 8);
            if (h == NULL) {
                r = 0x3ec;
                goto out;
            }
            r = cr_feature_extract_step_2db20(ctx, src, h, packed, cfg + 0x44);
            if (r != 0)
                goto out;
        }
    } else if (mode == 2) {
        r = cr_copy_image_fields(a3, ctx);
        if (r != 0)
            goto out;
        r = cr_bitmap_build_masked(&mask, packed, cfg);
        if (r != 0)
            goto out;
    } else {
        return (mode == 0) ? 0 : 0x69;
    }

    r = cr_masked_contrast_norm_2a620(src, ctx, &mask);

out:
    cr_cleanup_ptr8_a(&mask);
    return r;
}

/* 0x180042150 — block-downsample variance-ratio gate + adaptive smoothing.
 *
 *   int cr_block_variance_run_42150(cr_image *img, const uint8_t *cfg,
 *                                   int block_w, float *result);
 *
 * w must be an exact multiple of block_w and strictly greater than it, so
 * ncols = w/block_w >= 2.  Each row is reduced to ncols block means (the first
 * block skips its first 3 pixels, the last its last 3; the divisor is
 * block_w-3 for those two blocks and block_w otherwise) together with a
 * saturation flag that is 1 when any pixel of the block is >= 255.0f.  The
 * block means are box-blurred horizontally (3-tap) and the ratio
 *
 *     ratio = masked_variance(means - blurred) / masked_variance(blurred)
 *
 * is written to *result (0 when the denominator is not positive).  The mask
 * byte 0 means "count this sample", and the mask image is ncols wide.
 *
 * When cfg[0] != 0 and ratio reaches cfg+4 (threshold), the block residual is
 * subtracted from the source, differentiated at the block boundaries (1-tap
 * when ratio < 0.5, 4-tap when >= 0.5 and >= 0.07, 3-tap below 0.07), median
 * filtered across five rows, integrated along the columns with a running sum
 * and added back.  Pixels that were saturated are forced to 255.0f.
 *
 * Finally the image is smoothed and written back to img:
 *   cfg[8] <= 2: clamp to [0,255], then a 7-tap FIR with sigma = cfg+0xc.
 *   cfg[8] >  2: quantise to bytes, box-median of width cfg[8] (must be odd),
 *                copy back, then the same FIR.
 * A non-positive sigma stops after the clamping/median step.
 */
int cr_block_variance_run_42150(cr_image *img, const uint8_t *cfg,
                                int block_w, float *result)
{
    cr_image im[9] = { { 0 } };
    float *p0, *p1, *p2, *p3, *p4, *p5;
    uint8_t *u6, *u7, *u8;
    float *imgd;
    const float *src;
    int w, h, ncols, bw3, total, i, r, c, x, j, k, pass;
    int rc = 0;
    float ratio = 0.0f, thr, sigma;

    if (!img)
        return 0x69;
    w = img->w;
    h = img->h;
    if (block_w < 1)
        return 0x69;
    if (w % block_w != 0)
        return 0x69;
    if (w <= block_w)
        return 0x69;
    ncols = w / block_w;

    rc = cr_image_alloc_f32(&im[0], w, h);
    if (rc != 0) goto cleanup;
    rc = cr_image_alloc_f32(&im[1], ncols - 1, h);
    if (rc != 0) goto cleanup;
    rc = cr_image_alloc_f32(&im[2], ncols - 1, h);
    if (rc != 0) goto cleanup;
    rc = cr_image_alloc_f32(&im[3], ncols, h);
    if (rc != 0) goto cleanup;
    rc = cr_image_alloc_f32(&im[4], ncols, h);
    if (rc != 0) goto cleanup;
    rc = cr_image_alloc_f32(&im[5], ncols, h);
    if (rc != 0) goto cleanup;
    rc = cr_image_alloc_u8((int *)&im[6], w, h);
    if (rc != 0) goto cleanup;
    rc = cr_image_alloc_u8((int *)&im[7], w, h);
    if (rc != 0) goto cleanup;
    rc = cr_image_alloc_u8((int *)&im[8], ncols, h);
    if (rc != 0) goto cleanup;

    p0 = (float *)im[0].data;
    p1 = (float *)im[1].data;
    p2 = (float *)im[2].data;
    p3 = (float *)im[3].data;
    p4 = (float *)im[4].data;
    p5 = (float *)im[5].data;
    u6 = (uint8_t *)im[6].data;
    u7 = (uint8_t *)im[7].data;
    u8 = (uint8_t *)im[8].data;
    imgd = (float *)img->data;
    src = (const float *)img->data;

    /* pass 1: per-block mean and saturation flag. */
    bw3 = block_w - 3;
    for (r = 0; r < h; r++) {
        int rowbase = r * w;
        int obase = r * ncols;
        for (c = 0; c < ncols; c++) {
            int start = (c == 0) ? 3 : 0;
            int end = (c == ncols - 1) ? bw3 : block_w;
            int div = (c == 0 || c == ncols - 1) ? bw3 : block_w;
            float sum = 0.0f;

            for (x = start; x < end; x++)
                sum += src[rowbase + c * block_w + x];
            p3[obase + c] = sum / (float)div;

            u8[obase + c] = 0;
            for (x = 0; x < block_w; x++)
                if (src[rowbase + c * block_w + x] >= 255.0f)
                    u8[obase + c] = 1;
        }
    }

    cr_box_blur_h_f32(&p4, p3, ncols, h, 3);
    total = h * ncols;
    for (i = 0; i < total; i++)
        p5[i] = p3[i] - p4[i];

    {
        float den = cr_masked_variance(p4, ncols, h,
                                       (const uint8_t *const *)&u8);
        if (0.0f < den)
            ratio = cr_masked_variance(p5, ncols, h,
                                       (const uint8_t *const *)&u8) / den;
    }
    *result = ratio;

    if (cfg[0] == 0)
        goto cleanup;

    total = h * w;
    thr = *(const float *)(cfg + 4);

    if (!(thr <= ratio && ratio != thr)) {
        if (total < 1)
            goto mode_dispatch;
        for (i = 0; i < total; i++)
            p0[i] = src[i];
        goto quantize;
    }

    /* ratio >= threshold: refine the residual and smooth adaptively. */
    if (0.03f <= ratio) {
        int win = (0.05f <= ratio) ? 15 : 5;
        cr_box_blur_h_f32(&p4, p3, ncols, h, win);
        for (i = 0; i < h * ncols; i++)
            p5[i] = p3[i] - p4[i];
    }

    if (h < 1)
        goto mode_dispatch;

    for (r = 0; r < h; r++) {
        int rowbase = r * w;
        int obase = r * ncols;
        for (c = 0; c < ncols; c++)
            for (x = 0; x < block_w; x++)
                p0[rowbase + c * block_w + x] =
                    src[rowbase + c * block_w + x] - p5[obase + c];
    }

    if (0.07f <= ratio) {
        if (ratio < 0.5f) {
            for (r = 0; r < h; r++) {
                int rowbase = r * w;
                int obase = r * (ncols - 1);
                for (j = 0; j < ncols - 1; j++) {
                    int b = rowbase + (j + 1) * block_w;
                    p1[obase + j] = p0[b] - p0[b - 1];
                }
            }
        } else {
            for (r = 0; r < h; r++) {
                int rowbase = r * w;
                int obase = r * (ncols - 1);
                for (j = 0; j < ncols - 1; j++) {
                    int b = rowbase + (j + 1) * block_w;
                    p1[obase + j] =
                        ((p0[b + 1] + p0[b]) - p0[b - 1] - p0[b - 2]) * 0.5f;
                }
            }
        }
    } else {
        for (r = 0; r < h; r++) {
            int rowbase = r * w;
            int obase = r * (ncols - 1);
            for (j = 0; j < ncols - 1; j++) {
                int b = rowbase + (j + 1) * block_w;
                p1[obase + j] =
                    (((p0[b] * 3.0f - p0[b - 1] * 3.0f) + p0[b - 2])
                     - p0[b + 1]) * 0.5f;
            }
        }
    }

    /* five-row median of the derivative (descending 4-pass bubble sort). */
    for (j = 0; j < ncols - 1; j++) {
        int obase = j;
        for (r = 0; r < h; r++) {
            float t[5];
            for (k = 0; k < 5; k++) {
                int rr = r + k;
                int ri;
                if (rr < 2) rr = 2;
                ri = rr - 2;
                if (h < rr) ri = h - 1;
                t[k] = p1[ri * (ncols - 1) + obase];
            }
            for (pass = 0; pass < 4; pass++)
                for (k = 0; k < 4; k++)
                    if (t[k] < t[k + 1]) {
                        float tmp = t[k];
                        t[k] = t[k + 1];
                        t[k + 1] = tmp;
                    }
            p2[r * (ncols - 1) + obase] = t[2];
        }
    }

    /* integrate the median along the columns and add it to the residual. */
    for (r = 0; r < h; r++) {
        int obase = r * (ncols - 1);
        int c2 = (ncols - 2) / 2;
        int c3 = (ncols - 3) / 2;
        float f;

        if ((ncols & 1) == 0) {
            f = p2[obase + c2] * -0.5f;
            if (c2 > -1)
                for (k = 0; k <= c2; k++)
                    f += p2[obase + k];
        } else if (c3 < 0) {
            f = 0.0f;
        } else {
            f = 0.0f;
            for (k = 0; k <= c3; k++)
                f += p2[obase + k];
        }
        for (c = 0; c < ncols; c++) {
            int base = r * w + c * block_w;
            for (x = 0; x < block_w; x++)
                p0[base + x] += f;
            if (c + 1 == ncols)
                break;
            f -= p2[obase + c];
        }
    }

    for (i = 0; i < total; i++)
        if (src[i] >= 255.0f)
            p0[i] = 255.0f;

quantize:
    if (cfg[8] > 2) {
        for (i = 0; i < total; i++) {
            float f = p0[i] + 0.5f;
            uint8_t v = 0;
            if (0.0f < f) {
                v = 0xff;
                if (f < 255.0f)
                    v = (uint8_t)(int)f;
            }
            u7[i] = v;
        }
        goto boxmedian;
    }

    for (i = 0; i < total; i++) {
        float f = p0[i];
        if (0.0f < f) {
            if (255.0f <= f)
                f = 255.0f;
        } else {
            f = 0.0f;
        }
        imgd[i] = f;
    }
    if (*(const float *)(cfg + 0xc) <= 0.0f)
        goto cleanup;
    goto fir7;

mode_dispatch:
    if (cfg[8] < 3) {
        sigma = *(const float *)(cfg + 0xc);
        if (sigma <= 0.0f)
            goto cleanup;
        rc = cr_fir7_image_u8(&im[6], &im[7], sigma);
        goto cleanup;
    }

boxmedian:
    {
        uint16_t n = (uint16_t)cfg[8];
        if (n < 2) {
            rc = 0x69;
            goto cleanup;
        }
        if ((n & 1) == 0) {
            rc = 0x69;
            goto cleanup;
        }
        rc = (int)cr_box_median_u8(&im[6], &im[7], n);
        if (rc != 0)
            goto cleanup;
    }
    for (i = 0; i < total; i++)
        imgd[i] = (float)u6[i];
    sigma = *(const float *)(cfg + 0xc);
    if (sigma <= 0.0f)
        goto cleanup;
    if (total > 0)
        goto fir7;
    rc = cr_fir7_image_u8(&im[6], &im[7], sigma);
    goto cleanup;

fir7:
    for (i = 0; i < total; i++)
        u7[i] = (uint8_t)(int8_t)(int)imgd[i];
    rc = cr_fir7_image_u8(&im[6], &im[7], *(const float *)(cfg + 0xc));
    if (rc != 0)
        goto cleanup;
    for (i = 0; i < total; i++)
        imgd[i] = (float)u6[i];

cleanup:
    cr_free_9slot_clear6(im);
    return rc;
}

/* 0x180026410 — masked contrast/sharpness normalisation of a byte image.
 *
 * int cr_masked_contrast_norm_26410(int *out1, int *out2, cr_image *mask,
 *                                  const cr_image *src, const void *ctx);
 *
 * The vendor reads TWO stack slots, arg5 ([RBP+0x30]) and arg6 ([RBP+0x38]),
 * both pointing at the same context blob; the difftest passes one ctx for both.
 * Layout of that blob:
 *   +0x04 float  sigma0            (boxmax blur sigma, used for img1)
 *   +0x08 int8   flag              (>0 -> refptr = ref; <=0 -> refptr = img2)
 *   +0x50 embedded cr_image gsrc   (gauss source; its .data at +0x58 == ref)
 *   +0x58 int16* ref               (== gsrc.data; the reference row)
 * img1 = boxmax(src, sigma0); out1 = sharpness(img1,mask).  img2 = gauss(gsrc,
 * 0.7); img2 -= ref -> residual.  A row-FIR over the masked image yields a
 * regression (cov/denom) -> sharpness.  Finally, for every pixel,
 *   v = (mask - (refptr-mean)*sharpness)*img1 + (255-img1)*max_mask,
 *   v = v/255 + 0.5, then clamp: v<=0 -> img1[i]; v>=255 -> 0xff; else trunc.
 * out2 = sharpness(img1,mask) after the rewrite.  Verified by difftest. */
int cr_masked_contrast_norm_26410(int *out1, int *out2, cr_image *mask,
                                  const cr_image *src, const void *ctx5,
                                  const void *ctx6)
{
    const uint8_t *c = (const uint8_t *)ctx5;
    int w  = mask->w;
    int h  = mask->h;
    uint8_t *mdata = (uint8_t *)mask->data;
    int e;

    cr_image img1;                                   /* u8 scratch (RSP+0xa0) */
    if ((e = cr_image_alloc_u8((int *)&img1, w, h)) != 0)
        return e;

    float sigma0 = *(const float *)((const uint8_t *)ctx6 + 0x4);
    if ((e = cr_bitmap_unpack_boxmax_fir(&img1, src, 1, 1, sigma0)) != 0) {
        cr_cleanup_ptr8_a(&img1);
        return e;
    }
    if ((e = cr_masked_sharpness(out1, mask, &img1.data)) != 0) {
        cr_cleanup_ptr8_a(&img1);
        return e;
    }

    cr_image img2;                                   /* s16 scratch (RSP+0x80) */
    if ((e = cr_image_alloc_s16((int *)&img2, w, h)) != 0) {
        cr_cleanup_ptr8_a(&img1);
        return e;
    }

    const cr_image *gsrc = (const cr_image *)(c + 0x50);
    if ((e = cr_gauss_fir7_apply(&img2, (void *)gsrc, 0.0f, 0.0f, 0.7f)) != 0) {
        cr_cleanup_ptr8_a(&img1);
        cr_cleanup_ptr8_clear(&img2);
        return e;
    }

    int      n = w * h;
    /* +0x58 holds a pointer to the int16 reference row (it is the .data field
     * of the embedded cr_image at +0x50, i.e. == gsrc.data). */
    const int16_t *ref = *(const int16_t * const *)(c + 0x58);
    int16_t *i2  = (int16_t *)img2.data;
    if (n > 0) {
        for (int i = 0; i < n; i++)
            i2[i] = (int16_t)(ref[i] - i2[i]);      /* img2.data = ref - smooth */
    }
    /* flag (signed byte at ctx+0x8) selects which array feeds the regression */
    const int16_t *refptr = (*(const int8_t *)(c + 0x8) > 0) ? ref : i2;

    uint8_t *i1 = (uint8_t *)img1.data;
    int    count = 0;
    float  sum = 0.0f, sumsq = 0.0f;                 /* first windowed loop */
    if (h > 0) {
        for (int r = 0; r < h; r++) {
            if (r <= 9 || r >= h - 10) continue;
            for (int col = 0; col < w; col++) {
                if (col <= 9 || col >= w - 10) continue;
                if (i1[r * w + col] != 0xff) continue;
                int16_t v = i2[r * w + col];
                count++;
                sum   += (float)v;
                sumsq += (float)((int)v * (int)v);
            }
        }
    }

    cr_fir_row_ctx firctx;                            /* RSP+0xc0 */
    if ((e = cr_fir_ctx_init(&firctx, mask, 0.7f, 7, 0)) != 0) {
        cr_cleanup_ptr8_a(&img1);
        cr_cleanup_ptr8_clear(&img2);
        return e;
    }
    int16_t *tmp = NULL;                              /* RSP+0x78, int16[w] */
    if ((e = cr_malloc_aligned16((void **)&tmp,
                                 (size_t)(2u * (uint32_t)w))) != 0) {
        cr_cleanup_ptr8_a(&img1);
        cr_cleanup_ptr8_clear(&img2);
        cr_sized_free((void **)&firctx.base);
        return e;
    }

    float cov = 0.0f;                                /* second windowed loop */
    if (h > 0) {
        for (int r2 = 0; r2 < h; r2++) {
            if ((e = cr_row_fir_i16(tmp, &firctx, mask, r2)) != 0) {
                cr_cleanup_ptr8_a(&img1);
                cr_cleanup_ptr8_clear(&img2);
                cr_sized_free((void **)&firctx.base);
                cr_sized_free((void **)&tmp);
                return e;
            }
            for (int col = 0; col < w; col++)        /* tmp = mask*64 - firval */
                tmp[col] = (int16_t)(((int)mdata[r2 * w + col] << 6)
                                     - (int)tmp[col]);
            if (r2 <= 9 || r2 >= h - 10) continue;
            for (int col = 0; col < w; col++) {
                if (col <= 9 || col >= w - 10) continue;
                if (i1[r2 * w + col] != 0xff) continue;
                int16_t v = i2[r2 * w + col];
                float x = (float)count * (float)v - sum;
                cov += x * (float)(int16_t)tmp[col];
            }
        }
    }

    /* sharpness = 0.015625 if denom==0 else (cov/denom)*0.015625 */
    float denom = (float)count * sumsq - sum * sum;
    float sharpness = (denom == 0.0f)
                          ? 0.015625f
                          : (cov / denom) * 0.015625f;

    float sum2 = 0.0f, max4 = 0.0f;                  /* mean of ref + max mask */
    if (n > 0) {
        for (int i = 0; i < n; i++) {
            sum2 += (float)refptr[i];
            float mv = (float)mdata[i];
            if (mv > max4) max4 = mv;
        }
    }
    float mean = sum2 / (float)n;

    if (n > 0) {                                     /* in-place mask rewrite */
        for (int i = 0; i < n; i++) {
            float maskval = (float)mdata[i];
            float refval  = (float)refptr[i];
            float img1val = (float)i1[i];
            float v = (maskval - (refval - mean) * sharpness) * img1val
                    + (255.0f - img1val) * max4;
            v = v / 255.0f + 0.5f;
            int b;
            if (v <= 0.0f)      b = 0;       /* EAX zeroed at 0x91f: store 0 */
            else if (v >= 255.0f) b = 0xff;  /* AL = 0xff */
            else                 b = (int)v; /* CVTTSS2SI: truncate */
            mdata[i] = (uint8_t)b;
        }
    }

    int ret = cr_masked_sharpness(out2, mask, &img1.data);

    cr_sized_free((void **)&tmp);
    cr_sized_free((void **)&firctx.base);
    cr_cleanup_ptr8_clear(&img2);
    cr_cleanup_ptr8_a(&img1);                         /* vendor frees img1 last */
    return ret;
}

/* 0x1800208a0 — mask/feature stage driver.
 *
 * int cr_mask_stage_208a0(cr_image *dst, cr_image *img, const void *a3,
 *                         const void *a4, void **slots, const uint8_t *cfg,
 *                         int idx, int flag);
 *
 * slots[0] points at a {int16 w; int16 h; ...} descriptor; an int16 image is
 * allocated at that size and filled from slot `idx` (shift 6).  The byte image
 * `img` is cleared to 2, pixels with a non-positive int16 value become 1, and
 * the int16 plane is threshold-marked at *(int16*)(cfg+0x2c) — via
 * cr_thresh_open_mark when cfg[9] == 3, else cr_image_threshold_mark.  The
 * index list at slots[0x0e] is stamped in and the plane is scaled to f32 into
 * `dst`.  When cfg[0x40] is non-zero a masked bitmap is built from `img` and
 * cr_template_remove_25960 blends it into `dst` with selector cfg[0x40].
 * Then cr_mask_norm_32580(dst, a4, slots, img, a3, idx, cfg, flag) flattens,
 * and a positive cfg[0x30] runs the block-variance gate over cfg+0x30 with
 * block width *(int16*)(cfg+6).  Finally cr_mask_pipeline_25050(dst,
 * slots[0x0e], cfg+0xc0, img) returns.  Verified by difftest. */
int cr_mask_stage_208a0(cr_image *dst, cr_image *img, const void *a3,
                        const void *a4, void **slots, const uint8_t *cfg,
                        int idx, int flag)
{
    const int16_t *d = *(const int16_t * const *)slots;
    cr_image local;                                  /* s16 scratch */
    int e = cr_image_alloc_s16((int *)&local, d[0], d[1]);
    if (e != 0)
        return e;

    e = cr_image_fill_desc(slots, idx, 6, &local);
    if (e != 0) {
        cr_cleanup_ptr8_clear(&local);
        return e;
    }

    cr_image_fill_const2(img);
    cr_image_mark_nonpos(img, &local);
    if ((int8_t)cfg[9] == 3) {
        e = cr_thresh_open_mark(img, &local, *(const int16_t *)(cfg + 0x2c));
        if (e != 0) {
            cr_cleanup_ptr8_clear(&local);
            return e;
        }
    } else {
        cr_image_threshold_mark(img, &local, *(const int16_t *)(cfg + 0x2c));
    }
    cr_image_mark_indices(img, (const cr_index_list *)slots[0x0e]);
    cr_i16_to_f32_scaled(dst, &local, 6);
    cr_cleanup_ptr8_clear(&local);

    if (cfg[0x40] != 0) {
        cr_image mask;
        e = cr_bitmap_build_masked(&mask, img, cfg);
        if (e != 0)
            return e;
        e = cr_template_remove_25960(dst, &mask, (int8_t)cfg[0x40]);
        if (e != 0) {
            cr_cleanup_ptr8_clear(&mask);
            return e;
        }
        cr_cleanup_ptr8_clear(&mask);
    }

    e = cr_mask_norm_32580(dst, (void *)a4, slots, img, a3, idx, cfg, flag);
    if (e != 0)
        return e;

    if ((int8_t)cfg[0x30] > 0) {
        float res;
        e = cr_block_variance_run_42150(dst, cfg + 0x30,
                                        *(const int16_t *)(cfg + 6), &res);
        if (e != 0)
            return e;
    }
    return cr_mask_pipeline_25050(dst, slots[0x0e], cfg + 0xc0, img);
}

/* 0x180034ed0 — descriptor/point-grid feature pipeline.
 *
 * int cr_feature_pipeline_34ed0(void *obj, const void *arg2, int arg3,
 *                               const uint8_t *cfg);
 *
 * `out = *(void**)(obj+0x48)` is the output descriptor; its count word at
 * +0x20 is cleared first.  A type descriptor is built from cfg[0xb] (only
 * types 2 and 4 are accepted) and a null cr_image is initialised.  Two
 * scratch buffers are allocated on `out` (+0 the int16 plane of 2*h bytes,
 * +8 the f32 plane of 4*h bytes, h = *(int*)(cfg+0x14)), the grid object at
 * obj+0x20 is constructed over them, populated from obj (cfg dispatch), and
 * the point selector runs.  The resulting count is stored at out+0x20, the
 * grid is released twice, and when arg3 != 0 the obj+0x20 buffer is cleared.
 * out+0x31 = the descriptor's type byte, out+0x30 = cfg[0xc].  With a
 * positive count the angle/field descriptor buffer is allocated at out+0x28
 * (count * type), the field is downsampled, packed, optionally palette
 * remapped (cfg[0x3d] != 0), out+0x58 is zeroed and the bit table allocated
 * at out+0x50.  Returns the first failing status, else 0.  Verified by
 * difftest. */
int cr_feature_pipeline_34ed0(void *obj, const void *arg2, int arg3,
                              const uint8_t *cfg)
{
    uint8_t *o = (uint8_t *)obj;
    uint8_t *out = (uint8_t *)*(void **)(o + 0x48);
    *(uint32_t *)(out + 0x20) = 0;

    uint8_t tdesc[0x20];
    uint64_t r = cr_type_desc_getter(tdesc, (char)cfg[0xb]);
    if ((int)r != 0)
        return (int)r;

    cr_image img;
    r = cr_image_set(&img, NULL, 0, 0);
    if ((int)r != 0)
        return (int)r;

    int quad = cr_read_quad((const int *)obj);

    int e = cr_malloc_aligned16((void **)out,
                                (size_t)(*(const int32_t *)(cfg + 0x14) * 2));
    if (e != 0) {
        cr_free_3ptr_and8((void **)out, &img);
        return e;
    }
    e = cr_malloc_aligned16((void **)(out + 8),
                            (size_t)*(const uint32_t *)(cfg + 0x14) * 4u);
    if (e != 0) {
        cr_free_3ptr_and8((void **)out, &img);
        return e;
    }

    uint8_t grid[0x50];
    e = cr_obj_ctor_20aa0(grid, o + 0x20, *(void **)out, *(void **)(out + 8),
                          quad, cfg);
    if (e != 0) {
        cr_free_4slot_guard(grid);
        cr_free_3ptr_and8((void **)out, &img);
        return e;
    }
    e = cr_grid_populate_dispatch_38020((cr_grid *)grid, (const cr_image *)obj,
                                        o + 0x20, cfg);
    if (e != 0) {
        cr_free_4slot_guard(grid);
        cr_free_3ptr_and8((void **)out, &img);
        return e;
    }
    e = cr_pick_points_dispatch_2b680(grid, o + 0x20, cfg);
    if (e != 0) {
        cr_free_4slot_guard(grid);
        cr_free_3ptr_and8((void **)out, &img);
        return e;
    }

    *(uint32_t *)(out + 0x20) = *(const int32_t *)(grid + 0x40);
    cr_free_4slot_guard(grid);
    cr_free_4slot_guard(grid);
    if (arg3 != 0)
        cr_cleanup_ptr8_b(o + 0x20);
    *(uint8_t *)(out + 0x31) = tdesc[8];
    *(uint8_t *)(out + 0x30) = cfg[0xc];

    if (*(int32_t *)(out + 0x20) > 0) {
        e = cr_malloc_aligned16((void **)(out + 0x28),
                                (size_t)(*(const int32_t *)(out + 0x20)
                                         * (uint32_t)tdesc[8]));
        if (e != 0) {
            cr_free_3ptr_and8((void **)out, &img);
            return e;
        }
        e = cr_angle_field_ds_run((cr_af_ds_desc *)out, (const cr_image *)obj,
                                  cfg);
        if (e != 0) {
            cr_free_3ptr_and8((void **)out, &img);
            return e;
        }
        e = cr_feat_pack_0e850((cr_image *)obj, (cr_feat_obj *)out, cfg);
        if (e != 0) {
            cr_free_3ptr_and8((void **)out, &img);
            return e;
        }
        if ((int8_t)cfg[0x3d] != 0) {
            e = cr_palette_remap(obj, (const cr_image *)arg2, cfg);
            if (e != 0) {
                cr_free_3ptr_and8((void **)out, &img);
                return e;
            }
        }
        *(uint32_t *)(out + 0x58) = 0;
        e = cr_bit_alloc((void **)(out + 0x50), *(const int32_t *)(out + 0x20));
        if (e != 0) {
            cr_free_3ptr_and8((void **)out, &img);
            return e;
        }
    }

    cr_cleanup_ptr8_clear(&img);
    return 0;
}

/* 0x180048310 — sharpness-gated mask refinement.
 *
 * int cr_sharp_gate_48310(void *a1, void *a2, void *a3, void *a4,
 *                         const void *a5, const void *a6, int a7, int a8,
 *                         const void *a9);
 *
 * Returns 0 immediately when `a3` is NULL.  `a1` is overwritten with the
 * block-extreme bitmap of `a2`, and unless the mode byte at `a5+0x44` is 1 or
 * 2 the call also returns 0.  `a4` then receives the image fields of `a3`
 * (cr_copy_image_fields).  In mode 1, when both `*(int*)(a6+4)` and `a7` are
 * zero, the feature-extraction step runs against `*(void**)(a4+0x38+a8*8)`
 * (0x3ec when that handle is NULL) with the config at `a5+0x44`.  The masked
 * contrast normalisation of `a2` against `a1` follows; its two sharpness
 * outputs are compared as `(int)(0.8f * out2) > out1`, and only when that
 * holds is the `a2->a * a2->b`-byte payload of the slot descriptor `a9` copied
 * into `a2->data`.  Verified by difftest. */
int cr_sharp_gate_48310(void *a1, void *a2, void *a3, void *a4,
                        const void *a5, const void *a6, int a7, int a8,
                        const void *a9)
{
    if (a3 == NULL)
        return 0;

    cr_block_extreme_bitmap((cr_image *)a1, (const cr_image *)a2);

    const uint8_t *mode = (const uint8_t *)a5 + 0x44;
    if ((uint8_t)(*mode - 1) > 1u)
        return 0;

    int e = cr_copy_image_fields(a4, a3);
    if (e != 0)
        return e;

    if (*mode == 1 && ((*(const int *)((const uint8_t *)a6 + 4) | a7) == 0)) {
        void *h = *(void **)((uint8_t *)a4 + 0x38 + (size_t)a8 * 8);
        if (h == NULL)
            return 0x3ec;
        e = cr_feature_extract_step_26dc0(a3, (const cr_image *)a2, h,
                                          (const cr_image *)a1, mode);
        if (e != 0)
            return e;
    }

    int o1 = 0, o2 = 0;
    e = cr_masked_contrast_norm_26410(&o1, &o2, (cr_image *)a2,
                                      (const cr_image *)a1, a3, mode);
    if (e != 0)
        return e;

    if ((int)(0.8f * (float)o2) <= o1)
        return 0;

    int n = *(const int *)a2 * *(const int *)((const uint8_t *)a2 + 4);
    if (n <= 0)
        return 0;

    const uint8_t *sdata = *(const uint8_t * const *)((const uint8_t *)a9 + 0x10);
    uint8_t       *ddata = *(uint8_t * const *)((const uint8_t *)a2 + 8);
    for (int i = 0; i < n; i++)
        ddata[i] = sdata[i];
    return 0;
}

/* 0x1800344e0 — mask refine: slot copy, sharpness gate, inpaint, extremes.
 *
 * int cr_mask_refine_344e0(void *a1, void *a2, void *a3, void *a4, void *a5,
 *                          void *a6, void *a7, int a8, int a9);
 *
 * `a6` is the slot table: `a6[a8]` supplies the payload copied byte-for-byte
 * into `a2->data` (a2->a * a2->b bytes) and `a6+0x70` is the index list.
 * The mode byte at `a7+0x44` must be 0, 1 or 2; a negative or larger value
 * returns 0x69.  For modes 1 and 2 cr_sharp_gate_48310 runs with `a3` as its
 * destination image, `a5` as the context, `a4` as the object, `a7` as the
 * config and the same slot index; mode 0 skips it.  Then
 * cr_mask_inpaint_317a0 flags `a1`, inpaints `a2` from the index list using
 * the sub-config at `a7+0xc0`, and cr_block_extreme_bitmap writes the final
 * bitmap into `a3`.  Verified by difftest. */
int cr_mask_refine_344e0(void *a1, void *a2, void *a3, void *a4, void *a5,
                         void *a6, void *a7, int a8, int a9)
{
    void *slot = *(void **)((uint8_t *)a6 + (size_t)a8 * 8);
    void *list = *(void **)((uint8_t *)a6 + 0x70);

    int n = *(const int *)a2 * *(const int *)((const uint8_t *)a2 + 4);
    if (n > 0) {
        const uint8_t *s = *(const uint8_t * const *)((const uint8_t *)slot + 0x10);
        uint8_t       *d = *(uint8_t * const *)((const uint8_t *)a2 + 8);
        for (int i = 0; i < n; i++)
            d[i] = s[i];
    }

    int8_t mode = (int8_t)((const uint8_t *)a7)[0x44];
    if (mode != 0) {
        if (mode < 0 || mode > 2)
            return 0x69;
        int e = cr_sharp_gate_48310(a3, a2, a5, a6, a7, a4, a9, a8, slot);
        if (e != 0)
            return e;
    }

    int e = cr_mask_inpaint_317a0((uint8_t *)a1, (const cr_image *)a2,
                                  (const cr_index_list *)list,
                                  (const uint8_t *)a7 + 0xc0);
    if (e != 0)
        return e;

    cr_block_extreme_bitmap((cr_image *)a3, (const cr_image *)a2);
    return 0;
}

/* 0x180028bc0 — feature pipeline driver.
 *
 * int cr_feature_run_28bc0(void *a1, void *a2, void *a3);
 *
 * Allocates the 0x58-byte wrapper at `a1+8` (cr_alloc_obj_58) and, depending
 * on the selector byte `(*(uint8_t**)(a3+8))[1]`, initialises it from `a2`
 * with cr_obj_init_17ca0 in mode 1 (selector 0, followed by clearing the
 * bitmap image at `a2+0x50`) or mode 0 (selector 1); any other selector
 * destroys the wrapper and returns 0x69.  The wrapper's +0x44 int16 is then
 * stamped from `a1+0x1c` and `a1+0x20` from the wrapper's +0x40, and
 * cr_feature_pipeline_34ed0 runs over the wrapper with `a2+0x30`, the
 * "selector == 0" flag and the config at `a3+0x10`.  When the descriptor at
 * `a3+0x20` has a zero byte at +0x84 the whole bit table of the pipeline's
 * output descriptor is set.  A zero byte at `a3+0x18` plus a +0x78 float that
 * is not exactly 1.0f releases `out+0x28`, and a zero byte at
 * `(*(uint8_t**)(a3+8))[0]` releases `out+8`.  Unless the descriptor's +0x8b
 * byte is 2, `out+0x10` is released too.  Finally, when `a1+0x1c` and
 * `a1+0x20` are at least the descriptor's int16 fields +0x18/+0x1c and
 * `*(int16*)a1` is at least its uint16 at +0x1a, `a1+0x24` is set to 1, and
 * `a1+0x10` is always cleared.  Verified by difftest. */
int cr_feature_run_28bc0(void *a1, void *a2, void *a3)
{
    uint8_t *b = (uint8_t *)a1;
    uint8_t *p = (uint8_t *)a3;
    int e = cr_alloc_obj_58((void **)(b + 8));
    if (e != 0)
        return e;

    uint8_t sel = (*(const uint8_t * const *)(p + 8))[1];

    if (sel == 0) {
        e = cr_obj_init_17ca0(*(void **)(b + 8), a2, 1);
        if (e != 0)
            goto fail;
        cr_cleanup_ptr8_b((uint8_t *)a2 + 0x50);
    } else if (sel != 1) {
        cr_wrap_destroy((void **)(b + 8));
        return 0x69;
    } else {
        e = cr_obj_init_17ca0(*(void **)(b + 8), a2, 0);
        if (e != 0)
            goto fail;
    }

    {
        uint8_t *obj = *(uint8_t **)(b + 8);
        *(int16_t *)(obj + 0x44) = (int16_t)*(const int *)(b + 0x1c);
        *(int *)(b + 0x20) = *(const int *)(obj + 0x40);
    }

    e = cr_feature_pipeline_34ed0(*(void **)(b + 8), (uint8_t *)a2 + 0x30,
                                  (*(const uint8_t * const *)(p + 8))[1] == 0,
                                  *(void **)(p + 0x10));
    if (e != 0)
        goto fail;

    {
        const uint8_t *q = *(const uint8_t * const *)(p + 0x20);
        if (q[0x84] == 0) {
            uint8_t *out = *(uint8_t **)(*(uint8_t **)(b + 8) + 0x48);
            int cnt = *(const int *)(out + 0x20);
            if (cnt > 0) {
                uint8_t *bits = *(uint8_t **)(out + 0x50);
                for (int i = 0; i < cnt; i++)
                    bits[i >> 3] |= (uint8_t)(1u << (i & 7));
            }
        }
    }

    {
        const uint8_t *r = *(const uint8_t * const *)(p + 0x18);
        if (r[4] == 0 && !(1.0f == *(const float *)(r + 0x78)))
            cr_sized_free((void **)(*(uint8_t **)(b + 8) + 0x28));
    }
    if ((*(const uint8_t * const *)(p + 8))[0] == 0)
        cr_sized_free((void **)(*(uint8_t **)(*(uint8_t **)(b + 8) + 0x48) + 8));

    {
        const uint8_t *q = *(const uint8_t * const *)(p + 0x20);
        if (q[0x8b] != 2)
            cr_sized_free((void **)(*(uint8_t **)(*(uint8_t **)(b + 8) + 0x48) + 0x10));

        if (*(const int *)(b + 0x1c) >= (int)*(const int16_t *)(q + 0x18) &&
            *(const int *)(b + 0x20) >= (int)*(const int16_t *)(q + 0x1c) &&
            *(const int16_t *)b >= (int16_t)*(const uint16_t *)(q + 0x1a))
            *(int *)(b + 0x24) = 1;
    }

    *(int *)(b + 0x10) = 0;
    return 0;

fail:
    cr_wrap_destroy((void **)(b + 8));
    return e;
}

/* 0x180039820 — multi-slot mask fusion driver.
 *
 * int cr_mask_dispatch_39820(void *a1, void *a2, void *a3, void *a4,
 *                            void **slots, const void *cfg, int flag);
 *
 * Counts the non-NULL run slots[0..4] (slots[0] is dereferenced up front for
 * the pixel geometry).  A single populated slot is a straight
 * cr_mask_stage_208a0(a1, a2, ..., idx 0) passthrough.  Otherwise three
 * saturation scores gate a selector (0.9*sc1 > sc0 and sc0 < sc2 -> 2), a
 * 4-descriptor block is allocated (f32 dst + three u8 planes), two mask
 * stages run (idx = selector, then idx = 1), two boxmax/FIR bitmaps are built
 * from img[1] and a2, and two blurred-difference images are compared over the
 * pixels both bitmaps cover.  When >74% of those pixels disagree and
 * sc0 > sc1, a second pass stretches and refines the planes and blends them
 * per pixel with a weighted mean; otherwise img[0]/img[1] are copied out
 * verbatim.  Verified by difftest. */
int cr_mask_dispatch_39820(void *a1, void *a2, void *a3, void *a4,
                           void **slots, const void *cfg, int flag)
{
    const cr_pixbuf *s0 = (const cr_pixbuf *)slots[0];
    int w = s0->w;                       /* 0x180039870 (sign-extended 16) */
    int h = s0->h;                       /* 0x18003986b */
    int cnt = 0;
    int sel = 0;
    int ret = 0;
    int e;

    if (slots[0] != NULL) {
        cnt = 1;
        while (cnt < 5 && slots[cnt] != NULL)
            cnt++;
    }

    if (cnt == 1)
        return cr_mask_stage_208a0((cr_image *)a1, (cr_image *)a2, a3, a4,
                                   slots, (const uint8_t *)cfg, 0, flag);

    {
        int sc0 = 0, sc1 = 0, sc2 = 0;
        cr_saturation_score(&sc0, (const cr_pixbuf *)slots[0]);
        cr_saturation_score(&sc1, (const cr_pixbuf *)slots[1]);
        if (cnt != 2) {
            cr_saturation_score(&sc2, (const cr_pixbuf *)slots[2]);
            if ((float)sc1 * 0.9f > (float)sc0) {          /* 0x18008c6d0 */
                sel = 2;
                if (!(sc0 < sc2))
                    sel = 0;
            }
        }

        cr_image img[4];
        cr_image imga, imgb;
        int npix = 0;

        e = cr_image_alloc_f32(&img[0], w, h);
        if (e != 0)
            return e;
        e = cr_image_alloc_u8((int *)&img[1], w, h);
        if (e != 0) {
            cr_cleanup_ptr8_clear_b(&img[0]);              /* 0x180039e60 */
            return e;
        }
        e = cr_image_alloc_u8((int *)&img[2], w, h);
        if (e != 0) {
            cr_cleanup_ptr8_clear_b(&img[0]);              /* 0x180039e90 */
            cr_cleanup_ptr8_a(&img[1]);
            return e;
        }
        e = cr_image_alloc_u8((int *)&img[3], w, h);
        if (e != 0) {
            cr_cleanup_ptr8_clear_b(&img[0]);              /* 0x180039ea7 */
            cr_cleanup_ptr8_a(&img[1]);
            cr_cleanup_ptr8_a(&img[2]);
            return e;
        }

        e = cr_mask_stage_208a0(&img[0], &img[1], a3, a4, slots,
                                (const uint8_t *)cfg, sel, flag);
        if (e != 0)
            goto fail4;
        e = cr_mask_stage_208a0((cr_image *)a1, (cr_image *)a2, a3, a4, slots,
                                (const uint8_t *)cfg, 1, flag);
        if (e != 0)
            goto fail4;

        /* 0x180023900(out, src, maskbyte, k, niter=0, sigma unused) */
        e = cr_mask_boxmax_fir_clear(&img[2], &img[1], 0x0e, 0x0b, 0, 0.0f);
        if (e != 0)
            goto fail4;
        e = cr_mask_boxmax_fir_clear(&img[3], (const cr_image *)a2,
                                     0x0e, 0x07, 0, 0.0f);
        if (e != 0)
            goto fail4;

        e = cr_image_alloc_u8((int *)&imga, img[0].w, img[0].h);
        if (e != 0)
            goto fail4;
        e = cr_image_alloc_u8((int *)&imgb, img[0].w, img[0].h);
        if (e != 0) {
            cr_cleanup_ptr8_a(&imga);                      /* 0x180039f42 */
            goto fail4;
        }

        {
            uint8_t prm[16];
            cr_fill(prm, 0, 0x10);
            *(float *)(prm + 0) = 1.0f;                    /* 0x3f800000 */
            *(float *)(prm + 4) = 1.5f;                    /* 0x3fc00000 */
            prm[0xc] = 0;

            e = cr_blur_diff_norm_u8(&imga, &img[0], prm);
            if (e != 0)
                goto failab;
            e = cr_blur_diff_norm_u8(&imgb, (const cr_image *)a1, prm);
            if (e != 0)
                goto failab;
        }

        /* agreement over the pixels both bitmaps cover */
        {
            const uint8_t *d2 = (const uint8_t *)img[2].data;
            const uint8_t *d3 = (const uint8_t *)img[3].data;
            const uint8_t *da = (const uint8_t *)imga.data;
            const uint8_t *db = (const uint8_t *)imgb.data;
            int agree = 0, total = 0, pct;

            npix = h * w;
            for (int i = 0; i < npix; i++) {
                if (d2[i] == 0)
                    continue;
                if (d3[i] == 0)
                    continue;
                {
                    int a7b = da[i] >> 7;
                    int b7b = (uint8_t)(~(uint32_t)db[i]) >> 7;
                    if (a7b != b7b)
                        agree++;
                }
                total++;
            }

            if (total <= 100)
                goto freeab;                               /* 0x180039ec8 */
            pct = (100 * agree) / total;
            cr_cleanup_ptr8_a(&imga);
            cr_cleanup_ptr8_a(&imgb);
            if (pct <= 0x4a)
                goto post;                                 /* 0x180039edc */

            /* second pass: refine the two bitmap planes, stretch, blend */
            e = cr_fir7_image_u8(&img[2], &img[2], 4.0f);  /* 0x18008c6d4 */
            if (e != 0) {
                ret = e;
                goto fail4;
            }
            e = cr_fir7_image_u8(&img[2], &img[2], 4.0f);
            if (e != 0) {
                ret = e;
                goto fail4;
            }
            e = cr_fir7_image_u8(&img[3], &img[3], 4.0f);
            if (e != 0) {
                ret = e;
                goto fail4;
            }
            e = cr_fir7_image_u8(&img[3], &img[3], 4.0f);
            if (e != 0) {
                ret = e;
                goto fail4;
            }

            e = cr_stretch_f32(&img[0], &img[1], 0x0e, 0.0f, 0.0f, 1);
            if (e != 0) {
                ret = e;
                goto fail4;
            }
            e = cr_stretch_f32((cr_image *)a1, (const cr_image *)a2, 0x0e,
                               0.0f, 0.0f, 1);
            if (e != 0) {
                ret = e;
                goto fail4;
            }

            {
                float       *f0 = (float *)img[0].data;
                uint8_t     *m1 = (uint8_t *)img[1].data;
                const uint8_t *p2 = (const uint8_t *)img[2].data;
                const uint8_t *p3 = (const uint8_t *)img[3].data;
                float       *o0 = (float *)((cr_image *)a1)->data;
                uint8_t     *o1 = (uint8_t *)((cr_image *)a2)->data;

                for (int i = 0; i < npix; i++) {
                    uint8_t mb = m1[i];
                    float   f2 = (float)p2[i];
                    float   v0 = f0[i];
                    uint8_t ob = o1[i];
                    float   f3 = (float)p3[i];
                    float   v1 = o0[i];
                    float   sum = f2 + f3;

                    if ((mb & 0x10) != 0) {
                        if ((ob & 0x10) == 0 && sum != 0.0f) {
                            /* fall through to the weighted mean */
                        } else {
                            o0[i] = 255.0f;            /* 0x18008c6d8 */
                            m1[i] = 0x10;
                            continue;
                        }
                    } else if (sum == 0.0f) {
                        if ((ob & 0x10) != 0) {
                            o0[i] = 255.0f;
                            m1[i] = 0x10;
                            continue;
                        }
                        if (v0 != 0.0f && v1 != 0.0f)
                            o0[i] = (v0 + v1) * 0.5f;  /* 0x18008c6dc */
                        else
                            o0[i] = 0.0f;
                        goto tag;
                    }

                    if (!(sum > 0.0f)) {               /* NaN takes this too */
                        o0[i] = 0.0f;
                    } else {
                        o0[i] = (v0 * f2 + v1 * f3) / sum;
                    }
                tag:
                    if ((mb & 0x04) != 0)
                        m1[i] = 0x04;
                    else if ((mb & 0x11) != 0 && (ob & 0x11) != 0)
                        m1[i] = 0x01;
                    else
                        m1[i] = 0x02;
                }
            }
            goto done;
        }

    freeab:
        cr_cleanup_ptr8_a(&imga);
        cr_cleanup_ptr8_a(&imgb);

    post:
        if (sc0 <= sc1)                                    /* 0x180039edc */
            goto done;
        if (sel != 0) {
            e = cr_mask_stage_208a0((cr_image *)a1, (cr_image *)a2, a3, a4,
                                    slots, (const uint8_t *)cfg, 0, flag);
            if (e != 0) {
                ret = e;
                goto fail4;
            }
            goto done;
        }
        if (npix > 0) {
            const float   *sf = (const float *)img[0].data;
            const uint8_t *sb = (const uint8_t *)img[1].data;
            float         *df = (float *)((cr_image *)a1)->data;
            uint8_t       *db2 = (uint8_t *)((cr_image *)a2)->data;
            for (int i = 0; i < npix; i++) {
                df[i] = sf[i];
                db2[i] = sb[i];
            }
        }
        goto done;

    failab:
        cr_cleanup_ptr8_a(&imga);                          /* 0x180039e6d */
        cr_cleanup_ptr8_a(&imgb);
    fail4:
        ret = e;
    done:
        cr_free_4slot_clear1(img);                         /* 0x180039e81 */
        return ret;
    }
}

/* ---- 0x180011170 helpers ------------------------------------------------ */

/* 0x1800115cb — "usable pixel" score: 1000 - 1000*count(v == thr>>2 || v == 0)/n */
static int cr_slot_usable_score(const cr_image *s16, const uint8_t *cfg)
{
    int n = s16->w * s16->h;
    int16_t t = (int16_t)((int16_t)(*(const uint16_t *)(cfg + 0x2c)) >> 2);
    const int16_t *d = (const int16_t *)s16->data;
    int c = 0;

    for (int j = 0; j < n; j++)
        c += (d[j] == t) | (d[j] == 0);
    return 1000 + (c * -1000) / n;
}

/* 0x180011695 — gradient score: 15x15 box-mean, |plane - plane|, box-mean,
 * count(v > thr<<4) * 1000 / n.  Allocates and frees its own scratch plane. */
static int cr_slot_grad_score(const cr_image *s16, const uint8_t *cfg, int *out)
{
    int n = s16->w * s16->h;
    int16_t *tmp = NULL;
    int e = cr_malloc_aligned16((void **)&tmp, (size_t)(2 * n));
    if (e != 0)
        return e;

    if (n > 0)
        cr_copy(tmp, s16->data, 2 * n);
    cr_boxsum15_s16(tmp, s16->w, s16->h);
    {
        const int16_t *src = (const int16_t *)s16->data;
        for (int j = 0; j < n; j++) {
            int a = tmp[j];
            int b = src[j];
            tmp[j] = (uint16_t)(a < b ? b - a : a - b);
        }
    }
    cr_boxsum15_s16(tmp, s16->w, s16->h);
    {
        int16_t t = (int16_t)((uint16_t)(*(const uint16_t *)(cfg + 0x10a)) << 4);
        int c = 0;
        for (int j = 0; j < n; j++)
            if (tmp[j] > t)
                c++;
        *out = (1000 * c) / n;
    }
    cr_sized_free((void **)&tmp);
    return 0;
}

/* 0x180011170 — per-slot quality ranking + mask-stage dispatcher.
 *
 * int cr_slot_select_11170(cr_image *a1, const cr_image *a2, void *a3,
 *                          void *a4, void **slots, const uint8_t *cfg,
 *                          int flag);
 *
 * `a3` is a state block: +0x00 "advanced" flag, +0x04 current index, +0x08
 * index count, +0x0c the selector byte, +0x10 the index array.  All of
 * slots[0..4] must be populated (a NULL first slot returns 0x3ea) and must
 * match a1's w/h (else 0x82).  The mode byte at cfg+0x108 selects the
 * behaviour: 0 runs one mask stage at index 0, 1 picks index 0/1 from the slot
 * count, 2 walks a ranked index list (computing it on the first call), 3 runs
 * the multi-slot fusion driver.  Finally the f32 scratch is scaled back into
 * a1 with cr_f32_to_i16_scaled(..., 6).  Verified by difftest. */
int cr_slot_select_11170(cr_image *a1, const cr_image *a2, void *a3,
                         void *a4, void **slots, const uint8_t *cfg, int flag)
{
    uint8_t *st = (uint8_t *)a3;
    int *order = (int *)(st + 0x10);
    cr_image img;
    int w, h, cnt, i, e;

    if (a1 == NULL)
        return 0x69;
    *(int *)st = 0;

    w = a1->w;
    h = a1->h;

    cnt = 0;
    for (i = 0; i < 5; i++) {
        const cr_pixbuf *p = (const cr_pixbuf *)slots[i];
        if (p == NULL)
            break;
        if (p->h != h || p->w != w)
            return 0x82;
        cnt = i + 1;
    }
    if (cnt == 0)
        return 0x3ea;

    e = cr_image_alloc_f32(&img, w, h);
    if (e != 0)
        return e;

    {
        uint8_t mode = cfg[0x108];
        int ret = 0;

        if (mode == 3 && cnt != 1) {
            e = cr_mask_dispatch_39820(&img, (void *)a2, a3, a4, slots,
                                       cfg, flag);
            if (e != 0) {
                ret = e;
                goto fail;
            }
            order[*(const int *)(st + 4)] = 1;
            st[0xc] = 1;
            goto emit;
        }

        if (mode == 3 || mode == 0) {
            order[*(const int *)(st + 4)] = 0;
            st[0xc] = 0;
            e = cr_mask_stage_208a0(&img, (cr_image *)a2, a3, a4, slots,
                                    cfg, 0, flag);
            if (e != 0) {
                ret = e;
                goto fail;
            }
            goto emit;
        }

        if (mode == 1) {
            int idx = (cnt == 1) ? 0 : 1;
            st[0xc] = (uint8_t)idx;
            order[*(const int *)(st + 4)] = idx;
            e = cr_mask_stage_208a0(&img, (cr_image *)a2, a3, a4, slots,
                                    cfg, idx, flag);
            if (e != 0) {
                ret = e;
                goto fail;
            }
            goto emit;
        }

        if (mode != 2) {
            ret = 1;
            goto fail;
        }

        /* mode 2 — walk the ranked index list */
        {
            int idx = *(const int *)(st + 4);

            if (idx == 0) {
                if (cnt == 1) {
                    order[0] = 0;
                    *(int *)(st + 8) = cnt;
                    goto mode2_use;
                }
                goto mode2_init;
            }
            if (idx >= *(const int *)(st + 8))
                goto fail_3ea;
            {
                int v = order[idx];
                if (v == -1)
                    goto fail_3ea;
                st[0xc] = (uint8_t)v;
                e = cr_mask_stage_208a0(&img, (cr_image *)a2, a3, a4, slots,
                                        cfg, (uint8_t)v, flag);
                if (e != 0) {
                    ret = e;
                    goto fail;
                }
                {
                    int nx = *(const int *)(st + 4) + 1;
                    *(int *)(st + 4) = nx;
                    if (nx < *(const int *)(st + 8))
                        *(int *)st = 1;
                }
                goto emit;
            }

        mode2_init:
            {
                int *scores = NULL;
                cr_image s16;

                e = cr_malloc_aligned16((void **)&scores, (size_t)((long)cnt * 4));
                if (e != 0) {
                    ret = e;
                    goto fail;
                }
                {
                    const cr_pixbuf *s0 = (const cr_pixbuf *)slots[0];
                    e = cr_image_alloc_s16((int *)&s16, s0->w, s0->h);
                    if (e != 0) {
                        cr_sized_free((void **)&scores);
                        ret = e;
                        goto fail;
                    }
                }

                for (i = 0; i < cnt; i++) {
                    int k;
                    int32_t sh;

                    e = cr_image_fill_desc(slots, i, 4, &s16);
                    if (e != 0)
                        goto init_fail;
                    sh = (int32_t)((uint32_t)*(const int32_t *)(cfg + 0x110) << 12);
                    k = (int)(sh / 100);

                    if (k > 0xfff) {
                        int sc = cr_slot_usable_score(&s16, cfg);
                        scores[i] = (sc * k + 0x800) >> 12;
                    } else {
                        int sca = 0;
                        int wgt;
                        int r = cr_slot_grad_score(&s16, cfg, &sca);
                        if (r != 0) {
                            e = r;
                            goto init_fail;
                        }
                        wgt = (0x1000 - k) * sca;
                        if (k <= 0) {
                            scores[i] = (wgt + 0x800) >> 12;
                        } else {
                            int scb = cr_slot_usable_score(&s16, cfg);
                            scores[i] = (wgt + scb * k + 0x800) >> 12;
                        }
                    }
                    order[i] = i;
                }

                cr_cleanup_ptr8_clear(&s16);

                /* stable descending bubble sort of (score, index) pairs */
                for (;;) {
                    int swapped = 0;
                    for (int j = 0; j + 1 < cnt; j++) {
                        if (scores[j] < scores[j + 1]) {
                            int t = scores[j];
                            scores[j] = scores[j + 1];
                            scores[j + 1] = t;
                            t = order[j];
                            order[j] = order[j + 1];
                            order[j + 1] = t;
                            swapped = 1;
                        }
                    }
                    if (!swapped)
                        break;
                }

                cr_sized_free((void **)&scores);
                *(int *)(st + 8) = cnt;
                goto mode2_use;

            init_fail:
                cr_sized_free((void **)&scores);
                cr_cleanup_ptr8_clear(&s16);
                ret = e;
                goto fail;
            }

        mode2_use:
            {
                int j = *(const int *)(st + 4);
                int v;

                if (j >= *(const int *)(st + 8))
                    goto fail_3ea;
                v = order[j];
                if (v == -1)
                    goto fail_3ea;
                st[0xc] = (uint8_t)v;
                e = cr_mask_stage_208a0(&img, (cr_image *)a2, a3, a4, slots,
                                        cfg, (uint8_t)v, flag);
                if (e != 0) {
                    ret = e;
                    goto fail;
                }
                {
                    int nx = *(const int *)(st + 4) + 1;
                    *(int *)(st + 4) = nx;
                    if (nx < *(const int *)(st + 8))
                        *(int *)st = 1;
                }
                goto emit;
            }
        }

    fail_3ea:
        ret = 0x3ea;
    fail:
        cr_cleanup_ptr8_clear_b(&img);
        return ret;

    emit:
        cr_f32_to_i16_scaled(a1, &img, 6);
        cr_cleanup_ptr8_clear_b(&img);
        return ret;
    }
}
/* 0x180022b70 — per-slot quality ranking over u8 payloads + refine dispatch.
 *
 * int cr_slot_rank_u8_22b70(void *a1, const cr_image *a2, void *a3,
 *                           void *state, const void *a5, void **slots,
 *                           const uint8_t *cfg, int flag);
 *
 * `state` is the same block the ranking dispatcher uses: +0x00 "advanced"
 * flag, +0x04 current index, +0x08 index count, +0x0c selector byte, +0x10
 * the ranked index array.  The function validates the populated run
 * slots[0..4] against a2's a/b geometry (NULL first slot -> 0x3ea, size
 * mismatch -> 0x82), requires cfg[0x108] == 2 (else returns 1), and on the
 * first call builds the ranked list.  Each slot is scored as a 1000-weighted
 * blend of a "usable pixel" score (1000 - 1000*count(v == 0xff)/n) and a
 * 15x15 box-mean gradient score (count(|v - boxmean(v)| re-boxmeaned > thr<<4)
 * * 1000/n), where the weight k is (cfg[0x110] << 12) / 100 clamped to
 * 0..0x1000.  The (score, index) pairs are then stably sorted descending.
 * The call then walks one entry of the list and hands it to
 * cr_mask_refine_344e0 as its a8 selector.  Verified by difftest. */
int cr_slot_rank_u8_22b70(void *a1, const cr_image *a2, void *a3,
                          void *state, const void *a5, void **slots,
                          const uint8_t *cfg, int flag)
{
    uint8_t *st = (uint8_t *)state;
    int *order = (int *)(st + 0x10);
    int w, h, cnt, i, e;

    *(int *)st = 0;                             /* 0x180022b86 */
    if (a2 == NULL)
        return 0x69;

    w = a2->a;                                  /* 0x180022b9b */
    h = a2->b;

    cnt = 0;
    for (i = 0; i < 5; i++) {
        const cr_pixbuf *p = (const cr_pixbuf *)slots[i];
        if (p == NULL)
            break;
        if (p->h != h || p->w != w)
            return 0x82;
        cnt = i + 1;
    }
    if (cnt == 0)
        return 0x3ea;

    if (cfg[0x108] != 2)                        /* 0x180022be5 */
        return 1;

    if (*(const int *)(st + 4) == 0) {
        if (cnt == 1) {
            order[0] = 0;                       /* 0x180022c16 */
            *(int *)(st + 8) = cnt;
        } else {
            int *scores = NULL;
            int32_t sh = (int32_t)((uint32_t)*(const int32_t *)(cfg + 0x110) << 12);
            int k = (int)(sh / 100);            /* 0x180022d6c */

            e = cr_malloc_aligned16((void **)&scores,
                                    (size_t)((long)cnt * 4));
            if (e != 0)
                return e;                       /* 0x180022cff */

            for (i = 0; i < cnt; i++) {
                const cr_pixbuf *s = (const cr_pixbuf *)slots[i];
                const uint8_t *src = (const uint8_t *)s->data;
                int n = (int)s->w * (int)s->h;  /* 0x180022d8e */
                int score;

                if (k > 0xfff) {
                    /* 0x180022d9e — usable-pixel score only */
                    int c = 0, sc;
                    for (int j = 0; j < n; j++)
                        c += (uint8_t)(src[j] - 1) > 0xfdu;   /* v == 0xff */
                    sc = (n > 0) ? 1000 + (c * -1000) / n : 1000;
                    score = (sc * k + 0x800) >> 12;           /* 0x180022df2 */
                } else {
                    uint8_t *scratch = NULL;
                    int sca, wgt, c;
                    int16_t thr = (int16_t)*(const uint16_t *)(cfg + 0x10a);

                    e = cr_malloc_aligned16((void **)&scratch, (size_t)n);
                    if (e != 0) {                           /* 0x180023020 */
                        cr_sized_free((void **)&scores);
                        return e;
                    }
                    for (int j = 0; j < n; j++)
                        scratch[j] = src[j];
                    cr_boxsum15_u8(scratch, (int)s->w, (int)s->h);
                    for (int j = 0; j < n; j++) {
                        int d = (int)scratch[j] - (int)src[j];
                        scratch[j] = (uint8_t)(d < 0 ? -d : d);
                    }
                    cr_boxsum15_u8(scratch, (int)s->w, (int)s->h);

                    c = 0;
                    for (int j = 0; j < n; j++)
                        if ((int)scratch[j] > (int)thr)
                            c++;
                    sca = (n > 0) ? (1000 * c) / n : 0;
                    wgt = (0x1000 - k) * sca;               /* 0x180022fdb */
                    cr_sized_free((void **)&scratch);

                    if (k > 0) {                            /* 0x180023068 */
                        int c2 = 0, scb;
                        for (int j = 0; j < n; j++)
                            c2 += (uint8_t)(src[j] - 1) > 0xfdu;
                        scb = (n > 0) ? 1000 + (c2 * -1000) / n : 1000;
                        score = (wgt + scb * k + 0x800) >> 12;
                    } else {
                        score = (wgt + 0x800) >> 12;
                    }
                }
                scores[i] = score;
                order[i] = i;                           /* 0x180022e0f */
            }

            /* stable descending bubble sort of (score, index) pairs */
            for (;;) {                                  /* 0x180022e39 */
                int swapped = 0;
                for (int j = 0; j + 1 < cnt; j++) {
                    if (scores[j] < scores[j + 1]) {
                        int t = scores[j];
                        scores[j] = scores[j + 1];
                        scores[j + 1] = t;
                        t = order[j];
                        order[j] = order[j + 1];
                        order[j + 1] = t;
                        swapped = 1;
                    }
                }
                if (!swapped)
                    break;
            }
            cr_sized_free((void **)&scores);            /* 0x180023011 */
            *(int *)(st + 8) = cnt;
        }
    }

    {
        int idx = *(const int *)(st + 4);               /* 0x180022c22 */
        int v = order[idx];

        st[0xc] = (uint8_t)v;
        e = cr_mask_refine_344e0(a1, (void *)a2, a3, state, (void *)a5,
                                 slots, (void *)cfg, (int)(uint8_t)v, flag);
        if (e != 0)
            return e;                                   /* 0x180022c75 */

        {
            int nx = *(const int *)(st + 4) + 1;
            *(int *)(st + 4) = nx;
            if (nx < *(const int *)(st + 8))
                *(int *)st = 1;                         /* 0x180022c88 */
        }
    }
    return 0;
}

/* 0x1800222b0 — block texture search + 64-tap 8x8 kernel filter.
 *
 * int cr_block_filter_222b0(cr_image *a1, int32_t *out, const uint8_t *cfg,
 *                           int a4);
 *
 * Two phases.  Phase 1 validates the geometry (h/w against the int32 range
 * fields at cfg+0xc/+0x10/+0x14/+0x18) and scans a `cfg[8]`-step grid of
 * `row_steps`-tall blocks, scoring each by sum((I[x-1]-I[x])^2) over
 * sum((I[x-2]-I[x-1])^2) and stopping at the first block whose ratio exceeds
 * the float at cfg+4; `*out` is set to 100 when one is found.  Phase 2
 * (cfg[2] == 6 only) builds a Q6 mean-subtracted copy of each row, mirrors the
 * right edge, and runs four 64-tap convolutions per block against the 8x8
 * kernel table from 0x180012f30, writing the clamped `(32 + mean + v - conv)
 * >> 6` result back into the image.  Verified by difftest. */
int cr_block_filter_222b0(cr_image *a1, int32_t *out, const uint8_t *cfg,
                          int a4)
{
    const uint8_t *data = (const uint8_t *)a1->data;
    int w = a1->a;
    int h = a1->b;
    int b2  = cfg[2];
    int b10 = cfg[0xa];
    int A   = a4;

    int rl, rh, cl, ch, step;
    int row_lo, row_hi, col_start, col_end, row_steps, rem;
    int s24 = b10, s28 = b10;
    int s2c = 0, s30 = 0, s34 = 0, s38 = 0, s40 = 0, s48 = 0, s50 = 0, s54 = 0;
    int s58 = 0, s74 = 0, s78 = 0, s7c = 0;
    int s8c = 0, s90 = 0, s94 = 0, s98 = 0, sa0 = 0, sa4 = 0;
    int sa8 = 0, sac = 0, sc0 = 0, sc8 = 0, sd0 = 0;
    int mean = 0;
    uint8_t *buf = NULL;
    int16_t *b16 = NULL;
    const int16_t *tab16 = NULL;
    int r14b, r15d, rdi = 0, esi = 0;
    uint8_t al;

    if (b2 != 0) {
        if (b2 != 6 || cfg[9] != 4 || a4 != 0x10 || b10 != 4)
            return 0x69;                        /* 0x1800222e6 */
    }

    rl   = *(const int32_t *)(cfg + 0x0c);
    rh   = *(const int32_t *)(cfg + 0x10);
    cl   = *(const int32_t *)(cfg + 0x14);
    ch   = *(const int32_t *)(cfg + 0x18);
    step = cfg[8];

    if (h < rl || h < rh || w < cl || w < ch)
        return 0x69;
    if (rl >= rh || cl >= ch)
        return 0x69;
    if (step == 0) {                            /* 0x1800223f8 */
        *out = 0;
        return 0;
    }

    row_lo    = rl < 0 ? 0 : rl;
    row_hi    = rh > h - 1 ? h - 1 : rh;
    col_start = ((cl + A - 1) / A) * A;
    if (col_start < A)
        col_start = A;
    col_end   = (ch / A) * A;
    if (col_end > w - A)
        col_end = w - A;
    row_steps = (row_hi - row_lo) / step;
    rem       = (int)((uint8_t)(row_hi + 1 - row_lo) % (uint8_t)step);

    s38 = row_lo;
    s40 = row_lo - row_steps;
    s30 = row_steps;
    s34 = (uint16_t)(w * row_lo);
    s54 = (uint16_t)(w * row_steps);
    s48 = step;
    s2c = 0;
    r14b = (uint8_t)col_start;
    r15d = col_start;
    al   = (uint8_t)rem;

    for (;;) {                                  /* 0x180022460 */
        int edi = (int)al + s38;
        int rowend = s40 + s30;

        s2c++;
        edi += s30;
        if (edi >= rowend) {
            int rowoff = (uint16_t)s34;
            int yend1  = edi + 1;
            int s9 = 0, s10 = 0;
            int y = rowend;

            for (;;) {
                if (col_end >= r14b) {
                    int edx = r15d;
                    do {
                        int idx = (uint16_t)((uint8_t)edx + rowoff);
                        uint8_t c1 = data[idx - 1];
                        int8_t d2 = (int8_t)(uint8_t)(c1 - data[idx]);
                        int8_t d1 = (int8_t)(uint8_t)(data[idx - 2] - c1);
                        s9  += (int)d1 * (int)d1;
                        s10 += (int)d2 * (int)d2;
                        edx += A;
                    } while (col_end >= (int)(uint8_t)edx);
                }
                y++;
                rowoff += w;
                if (y == yend1)
                    break;
            }

            if (s9 != 0 &&
                (float)s10 / (float)s9 > *(const float *)(cfg + 4))
                goto found;
        }

        s30 += row_steps;
        al = 0;
        s34 = (uint16_t)(s34 + s54);
        if (s48 != s2c)
            continue;
        break;
    }

    *out = 0;                                   /* 0x180022537 */
    return 0;

found:
    *out = 100;                                 /* 0x180022562 */
    if (b2 == 0)
        return 0;                               /* 0x180022b5a */

    {                                           /* 0x180022576 */
        int n = h * w;
        int32_t sum = 0;

        for (int y = 0; y < h; y++)
            for (int x = 0; x < w; x++)
                sum += data[y * w + x];
        mean = (int)((int32_t)((uint32_t)sum << 6) / n);
    }

    {
        uint8_t *tab = NULL;
        uint32_t tsz = 0;

        if (cr_desc_get_ptr_size(&tab, &tsz, (char)b2) != 0)
            return 0x69;                        /* 0x180022600 */
        if (tab == NULL)
            return 0x69;

        {
            int r   = a4 % b10;
            int half = (cfg[9] - b10) / 2;
            int bb  = (uint8_t)(b10 - r);
            int total = (bb + half * 2) * a4 + w;

            total *= 2;
            if (cr_malloc_aligned16((void **)&buf, (size_t)total) != 0)
                return 1;                       /* 0x180022680: eax */
            b16 = (int16_t *)buf;
            tab16 = (const int16_t *)tab;

            s94 = 0;
            sa0 = 0;
            s8c = 0;
            s30 = w / a4;                       /* 0x1800226c4 */
            s34 = a4;                           /* 0x180022625 */
            s28 = (int)cfg[9] * a4;
            s90 = a4 * half;
            s50 = b10 * a4;
            sac = (bb + half) * a4 + w;
            s98 = 2 * s90;
            sa8 = w - 1;
            sd0 = 2 * (w - 1 + s90);
            sc8 = 2 * (w + s90);
            sc0 = 2 * ((~w) + sac);
            s40 = 2 * s50;
            s74 = 0;
            s78 = s90;
            s7c = sa0;
            s58 = 0;
            sa4 = h;
        }
    }

    for (;;) {                                  /* 0x1800227be */
        if (w > 0) {
            int cnt = sa8 + 1;
            const uint8_t *src = data + s94;
            int16_t *dst = b16 + (s98 >> 1);

            for (int i = 0; i < cnt; i++)
                dst[i] = (int16_t)(((int)src[i] << 6) - mean);
        }

        if (s90 > 0) {                          /* 0x180022818 */
            for (int k = 0; k < s90; k++)
                b16[s90 - 1 - k] = b16[s90 + k];
        }

        if (w < sac) {                          /* 0x180022868 */
            int i = sd0 >> 1;
            int j = sc8 >> 1;
            int stop = (sd0 - 2 - sc0) >> 1;

            while (i != stop) {
                b16[j] = b16[i];
                i--;
                j++;
            }
        }

        if (b10 != 0) {                         /* 0x1800228bb */
            s74 = 0;
            s58 = 0;
            s78 = s90;
            s7c = sa0;
            rdi = 0;

            for (;;) {                          /* 0x1800228f2 */
                if (s58 >= s30)
                    break;
                s24 = s58;
                s54 = s7c - s78;
                esi = s78;
                rdi = 0;

                for (;;) {                      /* 0x180022940 */
                    const int16_t *tp = tab16 + s74;
                    int eax = 0;

                    /* the vendor splits this into 8-tap groups plus a
                     * remainder, but it is one ascending 64-tap dot
                     * product (s28 = cfg[9] * a4). */
                    for (int k = 0; k < s28; k++)
                        eax += (int)tp[k] * (int)b16[(rdi >> 1) + k];

                    eax >>= 15;

                    if (s34 > 0) {              /* 0x180022a66 */
                        int off = s54 + esi;
                        for (int j = 0; j < s34; j++) {
                            int v = (int)b16[esi + j] - eax;
                            v = 0x20 + mean + v;
                            if (v < 0)
                                v = 0;
                            if (v > 0x3fc0)
                                v = 0x3fc0;
                            ((uint8_t *)a1->data)[off + j] =
                                (uint8_t)(v >> 6);
                        }
                    }

                    s24 += b10;
                    rdi += s40;
                    esi += s50;
                    if (s30 > s24)
                        continue;
                    break;
                }

                s58++;
                s7c += s34;
                s78 += s34;
                s74 += s28;
                if (b10 != s58)
                    continue;
                break;
            }
        }

        s8c++;
        sa0 += w;
        s94 += w;
        if (sa4 != s8c)
            continue;
        break;
    }

    cr_sized_free((void **)&buf);               /* 0x180022b38 */
    return 0;
}

/* ------------------------------------------------------------------------ *
 * 0x180015540 — edge-oriented Gaussian padding.
 *
 *   int fn(cr_image *a1, const cr_image *a2, float sigma)
 *
 * `a2` supplies the orientation field (int16 angles) and `a1` the pixels.
 * The function builds a 17-tap Gaussian from `sigma`, allocates five float
 * planes (17*dim, 17*dim, 9*dim, 9*dim, 27*dim floats, dim = max(w,h)+0x22),
 * then runs four edge passes.  Each pass fits nine orientation hypotheses
 * along one border (top / bottom / left / right), smooths the nine scores with
 * the triangular 9-tap filter, projects the winning hypothesis through the
 * affine basis, and splats the border pixels along the fitted direction with
 * the Gaussian window.  Two division passes per axis then write the padded
 * margin rows / columns of `a1`.
 *
 * The geometry the vendor assumes: the valid region is rows offy..offy+h-1 and
 * columns offx..offx+w-1 of a stride-`a`, `b`-row buffer.  The orientation
 * reads, oddly, use the unpadded coordinates while the pixel reads apply the
 * offsets; both are transcribed verbatim.
 *
 * Float order is load-bearing: the vendor's "pi" is 0x1.921ff2p+1 (thirty
 * ulps above the correctly rounded pi) and every division / negation is kept
 * in the same order.
 * ------------------------------------------------------------------------ */
static const float cr_c15540_pi = 0x1.921ff2p+1f;   /* 3.1415998935699463 */

/* angle = int16 * 1/256, wrapped by +180 when negative, then scaled to
 * radians with the vendor's slightly-off pi. */
static float cr_c15540_angle(int16_t px)
{
    float v = (float)px * 0.00390625f;
    if (0.0f > v)
        v += 180.0f;
    v = v * cr_c15540_pi / 180.0f;
    return v;
}

/* out = clamp(num/den) with the vendor's exact NaN / zero behaviour. */
static int16_t cr_c15540_divclamp(float num, float den)
{
    float q = num / den;
    int32_t v = -32768;
    if (q > -32768.0f) {
        v = 32767;
        if (32767.0f > q)
            v = (int32_t)q;
    }
    return (int16_t)v;
}

int cr_gauss_edge_pad_15540(cr_image *a1, const cr_image *a2, float sigma)
{
    float wnd[17];
    float smp[16];
    float cs, sn;
    void *hdr = NULL, *p0 = NULL, *p1 = NULL, *p2 = NULL, *p3 = NULL,
         *p4 = NULL;
    int status;

    if (a1->a <= a1->w)                     /* 0x180015561 */
        return 0x69;
    if (a1->b <= a1->h)                     /* 0x180015591 */
        return 0x69;

    {                                       /* 0x18001559a: 17-tap window */
        float sg2 = sigma * sigma;
        float g = -0.5f / sg2;
        float sum = 0.0f;
        for (int i = 0; i < 17; i++) {
            float t = (float)i - 8.0f;
            float e = cr_expf(t * (g * t));
            wnd[i] = e;
            sum += e;
        }
        for (int i = 0; i < 17; i++)
            wnd[i] = wnd[i] / sum;
    }

    const int w = a1->w, h = a1->h, ox = a1->offx, oy = a1->offy;
    const int b = a1->b, as = a1->a;
    const int dim = (w > h ? w : h) + 0x22;
    const int s17 = 17 * dim, s9 = 9 * dim, s27 = 27 * dim;
    float *f0, *f1, *f2, *f3, *f4;
    int16_t *d1 = (int16_t *)a1->data;
    const int16_t *d2 = (const int16_t *)a2->data;

    status = cr_pool_alloc5(&hdr, &p0, (uint32_t)s17 * 4,
                            &p1, (uint32_t)s17 * 4,
                            &p2, (uint32_t)s9 * 4,
                            &p3, (uint32_t)s9 * 4,
                            &p4, (uint32_t)s27 * 4);    /* 0x1800156cf */
    if (status != 0)
        return status;                      /* vendor skips the free */

    f0 = (float *)p0; f1 = (float *)p1; f2 = (float *)p2;
    f3 = (float *)p3; f4 = (float *)p4;

    for (int i = 0; i < s17; i++) {         /* 0x1800156e3 */
        f0[i] = 0.0f;
        f1[i] = 0.0f;
    }

    /* ---- pass 1: fit along the top row, splat, write the top margin ---- */
    for (int col = 0; col < w; col++) {     /* 0x180015732 */
        float v = cr_c15540_angle(d2[col]);
        cr_sincos_f32(&cs, &sn, v);
        if (cs > 0.0f)
            cr_line_orient_fit(smp, col, 0, -sn, cs, a1,
                               f4 + 27 * col, f2 + 9 * col);
        else
            cr_line_orient_fit(smp, col, 0, sn, -cs, a1,
                               f4 + 27 * col, f2 + 9 * col);
    }
    cr_tri9_filter(f2, f3, w);              /* 0x1800159b3 */

    for (int col = 0; col < w; col++) {     /* 0x1800159b8 */
        float v;
        cr_affine_transform(smp, f4 + 27 * col, f3 + 9 * col);
        v = cr_c15540_angle(d2[col]);
        cr_sincos_f32(&cs, &sn, v);
        cr_splat_accum16(wnd, smp, -cs, sn, f0, f1,
                         (float)d1[as * oy + ox + col], col);
    }

    for (int col = 0; col < as; col++) {    /* 0x180015b07 */
        const float *q0 = f0 + 17 * (col + 17 - oy);
        const float *q1 = f1 + 17 * (col + 17 - oy);
        for (int k = 0; k < oy; k++) {
            if (q1[k] != 0.0f)
                d1[(oy - 1 - k) * as + col] =
                    cr_c15540_divclamp(q0[k], q1[k]);
        }
    }
    for (int i = 0; i < s17; i++) {         /* 0x180015c00 */
        f0[i] = 0.0f;
        f1[i] = 0.0f;
    }

    /* ---- pass 2: fit along the bottom row, write the bottom margin ---- */
    for (int col = 0; col < w; col++) {     /* 0x180015c52 */
        float v = cr_c15540_angle(d2[a2->w * (h - 1) + col]);
        cr_sincos_f32(&cs, &sn, v);
        if (cs < 0.0f)
            cr_line_orient_fit(smp, col, h - 1, -sn, cs, a1,
                               f4 + 27 * col, f2 + 9 * col);
        else
            cr_line_orient_fit(smp, col, h - 1, sn, -cs, a1,
                               f4 + 27 * col, f2 + 9 * col);
    }
    cr_tri9_filter(f2, f3, w);              /* 0x180015dc3 */

    for (int col = 0; col < w; col++) {     /* 0x180015dc8 */
        float v;
        cr_affine_transform(smp, f4 + 27 * col, f3 + 9 * col);
        v = cr_c15540_angle(d2[a2->w * (h - 1) + col]);
        cr_sincos_f32(&cs, &sn, v);
        cr_splat_accum16(wnd, smp, cs, sn, f0, f1,
                         (float)d1[as * (oy + h - 1) + ox + col], col);
    }

    for (int col = 0; col < as; col++) {    /* 0x180015efe */
        const float *q0 = f0 + 17 * (col + 17 - oy);
        const float *q1 = f1 + 17 * (col + 17 - oy);
        for (int k = 0; k < oy; k++) {
            if (q1[k] != 0.0f)
                d1[(oy + h + k) * as + col] =
                    cr_c15540_divclamp(q0[k], q1[k]);
        }
    }
    for (int i = 0; i < s17; i++) {         /* 0x180015ff0 */
        f0[i] = 0.0f;
        f1[i] = 0.0f;
    }

    /* ---- pass 3: fit along the left column, write the left margin ----- */
    for (int row = 0; row < h; row++) {     /* 0x180016047 */
        float v = cr_c15540_angle(d2[a2->w * row]);
        cr_sincos_f32(&cs, &sn, v);
        cr_line_orient_fit(smp, 0, row, sn, -cs, a1,
                           f4 + 27 * row, f2 + 9 * row);
    }
    cr_tri9_filter(f2, f3, h);              /* 0x180016140 */

    for (int row = 0; row < h; row++) {     /* 0x180016145 */
        float v;
        cr_affine_transform(smp, f4 + 27 * row, f3 + 9 * row);
        v = cr_c15540_angle(d2[a2->w * row]);
        cr_sincos_f32(&cs, &sn, v);
        if (cs > 0.0f)
            cr_splat_accum16(wnd, smp, -sn, cs, f0, f1,
                             (float)d1[as * (oy + row) + ox], row);
        else
            cr_splat_accum16(wnd, smp, sn, -cs, f0, f1,
                             (float)d1[as * (oy + row) + ox], row);
    }

    for (int row = 0; row < b; row++) {     /* 0x1800162e1 */
        const float *q0 = f0 + 17 * (row + 17 - ox);
        const float *q1 = f1 + 17 * (row + 17 - ox);
        for (int k = 1; k <= ox; k++) {
            if (q1[k - 1] != 0.0f)
                d1[(ox - k) + as * row] =
                    cr_c15540_divclamp(q0[k - 1], q1[k - 1]);
        }
    }
    for (int i = 0; i < s17; i++) {         /* 0x1800163d7 */
        f0[i] = 0.0f;
        f1[i] = 0.0f;
    }

    /* ---- pass 4: fit along the right column, write the right margin --- */
    for (int row = 0; row < h; row++) {     /* 0x180016424 */
        float v = cr_c15540_angle(d2[a2->w * row + (w - 1)]);
        cr_sincos_f32(&cs, &sn, v);
        cr_line_orient_fit(smp, w - 1, row, -sn, cs, a1,
                           f4 + 27 * row, f2 + 9 * row);
    }
    cr_tri9_filter(f2, f3, h);              /* 0x18001654a */

    for (int row = 0; row < h; row++) {     /* 0x18001655b */
        float v;
        cr_affine_transform(smp, f4 + 27 * row, f3 + 9 * row);
        v = cr_c15540_angle(d2[a2->w * row + (w - 1)]);
        cr_sincos_f32(&cs, &sn, v);
        /* the vendor's jbe takes the >= branch for NaN, hence !(cs < 0) */
        if (!(cs < 0.0f))
            cr_splat_accum16(wnd, smp, sn, cs, f0, f1,
                             (float)d1[as * (oy + row) + ox + (w - 1)], row);
        else
            cr_splat_accum16(wnd, smp, -sn, -cs, f0, f1,
                             (float)d1[as * (oy + row) + ox + (w - 1)], row);
    }

    for (int row = 0; row < b; row++) {     /* 0x180015880 */
        const float *q0 = f0 + 17 * (row + 17 - ox);
        const float *q1 = f1 + 17 * (row + 17 - ox);
        for (int k = 0; k < ox; k++) {
            if (q1[k] != 0.0f)
                d1[(w + ox + k) + as * row] =
                    cr_c15540_divclamp(q0[k], q1[k]);
        }
    }

    cr_sized_free_if(&hdr);                 /* 0x18001596c */
    return status;                          /* 0 */
}

/* ------------------------------------------------------------------------ *
 * 0x180012aa0 — pad an image to a kernel-sized border, then correlate it with
 * the descriptor's 9x9 kernel bank under a per-pixel orientation map.
 *
 *   Args (ms_abi): rcx = a1 (in/out image; its pixels are the correlation
 *                  source and its data receives the normalised int16 result),
 *                  rdx = a2 (orientation map, int16 degrees*256, rescaled in
 *                  place), r8d = mode (only the low byte is compared),
 *                  r9b = descriptor selector.
 *
 *   cr_desc_get_tag_ptr(sel) must succeed and yield an odd kernel size K
 *   (tag[0] low dword; selector 0 gives 9 with a 501-kernel bank in tag[1]).
 *
 *   The padded image is allocated as ((w + K + 2) & ~3) x (h + K - 1) and the
 *   source is blitted into it with a margin of m = (K-1)/2 on every side:
 *       mode 0: extend, then the (w x h) subview is edge-padded by the
 *               orientation-aware Gaussian (sigma 8) driven by a2
 *       mode 1: fill border with 0
 *       mode 2: extend
 *       mode 3: mirror
 *   a2's map is then rescaled in place by (v + 0x5a00) * (count-1)/46080,
 *   which maps the -90..+90 degree range onto kernel indices 0..count-1, and
 *   cr_corr_kbank correlates the padded image with kernel[map[i]].
 *
 *   The int32 correlations are normalised to int16 by
 *       range = max - min;  scale = range/16384 + 1;
 *       a1->data[i] = (corr[i] - min + scale/2) / scale.
 *
 *   Every failure after the two allocations frees both and returns the status
 *   (the descriptor failure returns immediately, the bad-mode path frees the
 *   image before the scratch buffer).
 * ------------------------------------------------------------------------ */
int cr_pad_filter_12aa0(cr_image *a1, const cr_image *a2, int mode, int8_t sel)
{
    uint64_t tag[2] = { 0, 0 };
    void    *slot = NULL;
    cr_image img;
    cr_image sub;
    uint32_t st;
    int      K, m, w, h, npix;

    st = (uint32_t)cr_desc_get_tag_ptr(tag, sel);         /* 0x180012acf */
    if (st != 0)
        return (int)st;

    K = (int)(uint32_t)tag[0];
    if (!(K & 1))
        return 0x69;                                      /* 0x180012ae2 */

    w    = a1->w;
    h    = a1->h;
    npix = w * h;

    st = (uint32_t)cr_malloc_aligned16(&slot, (size_t)((int64_t)npix * 4));
    if (st != 0)
        return (int)st;                                   /* 0x180012b25 */

    st = (uint32_t)cr_image_alloc_s16((int *)&img, (w + K + 2) & ~3,
                                      h + K - 1);
    if (st != 0) {                                        /* 0x180012d2b */
        cr_sized_free(&slot);
        return (int)st;
    }

    m = (K - 1) >> 1;                                     /* 0x180012b7b */
    switch ((int8_t)mode) {
    case 0:                                               /* 0x180012d49 */
        st = cr_blit_extend_s16(&img, a1, m, m, m, img.w - w - m);
        if (st != 0) goto fail_slot_img;
        cr_image_subview(&sub, &img, m, m, w, h);
        st = (uint32_t)cr_gauss_edge_pad_15540(&sub, a2, 8.0f);
        if (st != 0) goto fail_slot_img;
        break;
    case 1:                                               /* 0x180012e10 */
        st = cr_blit_fillborder_s16(&img, a1, m, m, m, img.w - w - m, 0);
        if (st != 0) goto fail_slot_img;
        break;
    case 2:                                               /* 0x180012e70 */
        st = cr_blit_extend_s16(&img, a1, m, m, m, img.w - w - m);
        if (st != 0) goto fail_slot_img;
        break;
    case 3:                                               /* 0x180012ba6 */
        st = cr_blit_mirror_s16(&img, a1, m, m, m, img.w - w - m);
        if (st != 0) goto fail_slot_img;
        break;
    default:                                              /* 0x180012e50 */
        st = 0x69;
        goto fail_img_slot;
    }

    /* 0x180012bd7 — rescale the orientation map in place */
    if (npix > 0) {
        float scale = ((float)(int32_t)(tag[0] >> 32) - 1.0f) / 46080.0f;
        int16_t *p = (int16_t *)a2->data;
        for (int i = 0; i < npix; i++) {
            float f = (float)((int32_t)p[i] + 0x5a00);
            f = f * scale;
            p[i] = (int16_t)(int32_t)f;
        }
    }

    st = (uint32_t)cr_corr_kbank((int32_t *)slot, (const int16_t *)img.data,
                                 (const int16_t *)tag[1],
                                 (const int16_t *)a2->data,
                                 (long long)(int32_t)(tag[0] >> 32),
                                 w, h, img.w, img.h, K);
    if (st != 0) goto fail_slot_img;                      /* 0x180012df1 */

    cr_cleanup_ptr8_clear(&img);                          /* 0x180012c9c */

    if (npix > 0) {
        const int32_t *c = (const int32_t *)slot;
        int32_t max = (int32_t)0x80000000, min = 0x7fffffff;
        int32_t range, sc, half;
        int16_t *o = (int16_t *)a1->data;

        for (int i = 0; i < npix; i++) {                  /* 0x180012cc0 */
            if (max < c[i]) max = c[i];
            if (min > c[i]) min = c[i];
        }
        range = (int32_t)((uint32_t)max - (uint32_t)min);
        /* 0x180012ce7 — vendor magic-multiply sequence (0x80020009); it is a
         * signed division by 16384 with the +1 folded in, kept verbatim here */
        {
            int64_t  prod = (int64_t)range * (-2147352567LL);
            uint32_t acc  = (uint32_t)((uint64_t)prod >> 32) + (uint32_t)range;
            sc = ((int32_t)acc >> 13) - (range >> 31) + 1;
        }
        half  = (sc + (sc < 0 ? 1 : 0)) >> 1;             /* 0x180012d03 */
        for (int i = 0; i < npix; i++)                    /* 0x180012d10 */
            o[i] = (int16_t)((c[i] - min + half) / sc);
    }

    cr_sized_free(&slot);                                 /* 0x180012d2b */
    return 0;

fail_slot_img:                                            /* 0x180012dd0 */
    cr_sized_free(&slot);
    cr_cleanup_ptr8_clear(&img);
    return (int)st;

fail_img_slot:
    cr_cleanup_ptr8_clear(&img);
    cr_sized_free(&slot);
    return (int)st;
}

/* ------------------------------------------------------------------------ *
 * 0x18001ba60 — orientation-encode front end: structure tensor, then the
 * kernel-bank pad/correlate stage.
 *
 *   Args (ms_abi): rcx = a1 (in/out image, even w/h), rdx = a2 (byte mask),
 *                  r8d = a3 (and-mask, only the low byte used),
 *                  r9 = a4 (float pair + byte selector object for the blur),
 *                  [rsp+0x28] = cfg.
 *
 *   Odd width or height is rejected with 0x69 before anything is allocated.
 *   A scratch image of the same size is always allocated; then cfg[0] picks:
 *       0: encode straight from a1
 *       1: copy a1 into a second scratch image (shift 0), run the blurred-pair
 *          difference normaliser on it with a4, then encode from that copy
 *       else: free and return 1
 *   The encoder is cr_structure_orient_dispatch_2cfd0, driven by cfg[0x10].
 *   Finally cr_pad_filter_12aa0(a1, scratch, (int8_t)cfg[0x0e],
 *   (int8_t)cfg[0x11]) writes the normalised correlation into a1->data.
 * ------------------------------------------------------------------------ */
int cr_orient_encode_1ba60(cr_image *a1, const cr_image *a2, int a3,
                           const void *a4, const uint8_t *cfg)
{
    cr_image A, B;
    int st;

    if ((a1->w & 1) || (a1->h & 1))                      /* 0x18001ba6a */
        return 0x69;

    st = cr_image_alloc_s16((int *)&A, a1->w, a1->h);     /* 0x18001baaf */
    if (st != 0)
        return st;

    if (cfg[0] == 0) {                                    /* 0x18001bb60 */
        st = cr_structure_orient_dispatch_2cfd0(&A, a1, a2, (uint8_t)a3, cfg);
        if (st != 0) {
            cr_cleanup_ptr8_clear(&A);
            return st;
        }
    } else if (cfg[0] == 1) {                             /* 0x18001bad3 */
        st = cr_image_alloc_s16((int *)&B, a1->w, a1->h);
        if (st != 0) {                                    /* 0x18001bb9c */
            cr_cleanup_ptr8_clear(&A);
            return st;
        }
        st = cr_copy_u16_shl_guarded(&B, a1, 0);
        if (st == 0)
            st = cr_blur_diff_norm(&B, a4);
        if (st == 0)
            st = cr_structure_orient_dispatch_2cfd0(&A, &B, a2,
                                                    (uint8_t)a3, cfg);
        if (st != 0) {                                    /* 0x18001bbd1 */
            cr_cleanup_ptr8_clear(&A);
            cr_cleanup_ptr8_clear(&B);
            return st;
        }
        cr_cleanup_ptr8_clear(&B);                        /* 0x18001bb54 */
    } else {
        cr_cleanup_ptr8_clear(&A);                        /* 0x18001bbc2 */
        return 1;
    }

    st = cr_pad_filter_12aa0(a1, &A, (int8_t)cfg[0x0e],
                             (int8_t)cfg[0x11]);          /* 0x18001bb93 */
    cr_cleanup_ptr8_clear(&A);                            /* 0x18001bb9f */
    return st;
}

/* ------------------------------------------------------------------------ *
 * 0x180018c60 — orientation post-processing selector.
 *
 *   Args (ms_abi): rcx = a1 (in/out int16 image), rdx = a2 (float weights for
 *                  the FFT path), r8 = cfg, r9 = a4 (byte mask image),
 *                  [rsp+0x28] = a5 (and-mask), [rsp+0x30] = a6 (selector bank).
 *
 *   sel = a6 ? cfg[1] : cfg[0]  (a byte; >6 -> 0x69, 0 -> 0, 3 -> 0x69)
 *       1: FFT-weighted filter (weights = a2->data, cfg+0xa4), then
 *          cr_stretch_14bit(a1, a4, (uint8_t)a5, cfg[0xb8], cfg[0xbc], cfg[3])
 *          -- the stretch result is returned directly, a6 is not consulted
 *       2: cr_blur_diff_norm(a1, cfg+0xe4)
 *       4: blur, then stretch
 *       5: cr_orient_encode_1ba60(a1, a4, (uint8_t)a5, cfg+0xe4, cfg+0xf4),
 *          then stretch
 *       6: blur, then cr_blur_divnorm_stretch(a1, cfg+0x2c0)
 *   Modes 2/4/5/6 end with `a6 ? cr_bitmap_filter_apply_s16(a1, a4, cfg) : 0`.
 * ------------------------------------------------------------------------ */
int cr_orient_pipeline_18c60(cr_image *a1, const cr_image *a2,
                             const uint8_t *cfg, const cr_image *a4,
                             int a5, int a6)
{
    const uint8_t *c = cfg;
    uint8_t sel = a6 ? c[1] : c[0];
    int st;

    if (sel > 6)                                          /* 0x180018e00 */
        return 0x69;
    if (sel == 0)
        return 0;
    if (sel == 3)
        return 0x69;

    switch (sel) {
    case 1:                                               /* 0x180018cd2 */
        st = cr_fft_weighted_apply_32af0((int *)a1,
                                         (const float *)a2->data, c + 0xa4);
        if (st != 0)
            return st;
        return cr_stretch_14bit(a1, a4, (uint8_t)a5,
                                *(const float *)(c + 0xb8),
                                *(const float *)(c + 0xbc),
                                (int8_t)c[3]);
    case 2:                                               /* 0x180018de0 */
        st = cr_blur_diff_norm(a1, c + 0xe4);
        break;
    case 4:                                               /* 0x180018d30 */
        st = cr_blur_diff_norm(a1, c + 0xe4);
        if (st == 0)
            st = cr_stretch_14bit(a1, a4, (uint8_t)a5,
                                  *(const float *)(c + 0xb8),
                                  *(const float *)(c + 0xbc),
                                  (int8_t)c[3]);
        break;
    case 5:                                               /* 0x180018d90 */
        st = cr_orient_encode_1ba60(a1, a4, a5, c + 0xe4, c + 0xf4);
        if (st == 0)
            st = cr_stretch_14bit(a1, a4, (uint8_t)a5,
                                  *(const float *)(c + 0xb8),
                                  *(const float *)(c + 0xbc),
                                  (int8_t)c[3]);
        break;
    default:                                              /* 6 — 0x180018cb0 */
        st = cr_blur_diff_norm(a1, c + 0xe4);
        if (st == 0)
            st = cr_blur_divnorm_stretch(a1, c + 0x2c0);
        break;
    }

    if (st != 0)
        return st;
    if (a6)                                               /* 0x180018e15 */
        return cr_bitmap_filter_apply_s16(a1, a4, c);
    return 0;
}

/* Extended bitmap descriptor used by 0x1800195d0: stride@0, words@8,
 * offx@0x18, offy@0x1c (the first five fields match cr_bitmap_desc). */

/* ------------------------------------------------------------------------ *
 * 0x1800195d0 — block orientation / run-length descriptor.
 *
 *   Args (ms_abi):
 *     rcx = a1   int16 out: average masked quality (-1 on entry)
 *     rdx = a2   float grid 0        r8  = a3  float grid 1
 *     r9  = a4   float grid 2        [0x28] = a5 float grid 3
 *     [0x30] = a6  float grid 4 *and* the grid geometry (w/h)
 *     [0x38] = arg7 float[4] scratch (per-block run statistics)
 *     [0x40] = arg8 bitmap (stride@0, words@8, offx@0x18, offy@0x1c)
 *     [0x48] = arg9 int16 source image
 *     [0x50] = arg10 config: X@0x10, sigma@0xc, qthr@0x14, bounds@0x18..0x54
 *
 *   Requires W > X and H > X and X > 0.  Computes the gradient pair with
 *   cr_gauss_deriv_3img, then walks an X-sized block grid inset by
 *   x0 = lroundf(ox/2), y0 = lroundf(oy/2) where
 *   ox = W - (gw*X - 2X), oy = H - (gh*X - 2X).
 *
 *   Per block: sums B^2, C^2, B*C (as floats of the int32 products) and the
 *   bitmap population count.  Unless every bit is set the five grids receive
 *   -1.0f; otherwise the 2x2 tensor is eigen-decomposed, an oriented X x X
 *   patch is sampled from the source, its column means are thresholded at the
 *   midpoint of the local-extrema means, and the resulting binary runs give
 *   four statistics written to the grids.  The block's coherence (times 100)
 *   is scaled by a config mask, accumulated, and the block is cleared from the
 *   bitmap when it falls below cfg[0x14].  Finally the four grids are reduced
 *   with cr_masked_median_f32 and a1 receives the mean masked quality.
 * ------------------------------------------------------------------------ */
int cr_block_orient_195d0(int16_t *a1, cr_image *a2, cr_image *a3,
                          cr_image *a4, cr_image *a5, cr_image *a6,
                          float *out4, const void *bmp,
                          const cr_image *src, const uint8_t *cfg)
{
    const cr_image *bm = (const cr_image *)bmp;
    const uint32_t *bw = (const uint32_t *)bm->data;
    const float *cf = (const float *)cfg;
    int X = *(const int32_t *)(cfg + 0x10);
    int W = src->w, H = src->h;
    int nS, N;
    cr_image A, B, C;
    void *pool = NULL;
    uint32_t st;

    *(int16_t *)a1 = -1;                                  /* 0x180019669 */
    if (W <= X || H <= X || X <= 0)
        return 0x69;

    st = cr_image_set(&A, NULL, X, X);                    /* 0x180019739 */
    if (st) return (int)st;
    st = cr_image_set(&B, NULL, W, H);                    /* 0x18001975e */
    if (st) return (int)st;
    st = cr_image_set(&C, NULL, W, H);                    /* 0x180019783 */
    if (st) return (int)st;

    nS = X * X;
    N  = W * H;
    st = (uint32_t)cr_pool_alloc3(&pool, &B.data, (uint32_t)(N * 2),
                                  &C.data, (uint32_t)(N * 2),
                                  &A.data, (uint32_t)(nS * 2));
    if (st) return (int)st;                               /* 0x18001968a */

    st = (uint32_t)cr_gauss_deriv_3img(&B, &C, (void *)src, cf[3]);
    if (st) {                                             /* 0x18001a408 */
        cr_sized_free_if(&pool);
        return (int)st;
    }

    {
        int ox = 0, oy = 0;                               /* 0x18001980a */
        if (a6->w * X != W) ox = W - (a6->w * X - 2 * X);
        if (a6->h * X != H) oy = H - (a6->h * X - 2 * X);
        int x0 = cr_lroundf((float)ox * 0.5f);            /* 0x180019857 */
        int y0 = cr_lroundf((float)oy * 0.5f);            /* 0x180019871 */
        int f1 = (x0 != 0);                               /* 0x180019884 */
        int f2 = (y0 != 0);                               /* 0x180019894 */
        int xmax = W - x0, ymax = H - y0;
        int rowacc = y0 * W;                              /* 0x64 */
        float qsum = 0.0f;
        int qcount = 0;

        if (y0 < ymax) {
            for (int yb = y0; ; yb += X) {
                int y_end = yb + X;
                if (x0 < xmax) {
                    for (int x = x0; ; x += X) {
                        uint32_t pop = 0;
                        float sBB = 0.0f, sCC = 0.0f, sBC = 0.0f;
                        float *g2 = (float *)a2->data;
                        float *g3 = (float *)a3->data;
                        float *g4 = (float *)a4->data;
                        float *g5 = (float *)a5->data;
                        float *g6 = (float *)a6->data;
                        int idx, r;
                        float qual = 0.0f;
                        float *buf0 = NULL, *buf1 = NULL;

                        for (r = 0; r < X; r++) {         /* 0x1800199e5 */
                            int y = yb + r;
                            const int16_t *Bp =
                                (const int16_t *)B.data + rowacc
                                + (size_t)r * W;
                            const int16_t *Cp =
                                (const int16_t *)C.data + rowacc
                                + (size_t)r * W;
                            int bi = (bm->offy + y) * bm->a + (bm->offx + x);
                            for (int i = 0; i < X; i++) {
                                int32_t b = Bp[x + i];
                                int32_t c = Cp[x + i];
                                sBB += (float)(int32_t)(b * b);
                                sCC += (float)(int32_t)(c * c);
                                sBC += (float)(int32_t)(b * c);
                                pop += (bw[bi >> 5] >>
                                        ((bm->offx + x + i) & 31)) & 1u;
                                bi++;
                            }
                        }

                        idx = (x / X) + (yb / X + f1) * a6->w + f2;
                        if (pop != (uint32_t)nS)
                            goto blk_sentinel;

                        {
                            float nSf = (float)nS;
                            float varB = sBB / nSf;       /* 0x180019c5e */
                            float varC = sCC / nSf;       /* 0x180019c66 */
                            float cov  = sBC / nSf;       /* 0x180019c5a */
                            float d1, b1, ratio, ang;
                            float co, si, m[6];
                            float hc, hp, xc, yc, rad;
                            float thr;
                            int i, j, first, last;

                            if (cov * cov >= 1e-12f) {    /* 0x180019eb8 */
                                float mean = (varB + varC) * 0.5f;
                                float det  = varB * varC - cov * cov;
                                float s    = cr_sqrtf(mean * mean - det);
                                float lam1 = mean + s;
                                float lam2 = mean - s;
                                d1 = lam1 - varB;
                                b1 = cov;
                                if (!(lam1 > 0.0f))
                                    goto blk_sentinel;
                                ratio = lam2 / lam1;
                            } else {                      /* 0x180019c7f */
                                if (!(varB > 0.0f))
                                    goto blk_sentinel;
                                d1 = 0.0f;
                                b1 = 1.0f;
                                ratio = varC / varB;
                            }
                            qual  = (1.0f - ratio) * 100.0f;   /* 0x180019d51 */
                            ang   = cr_atan2_deg(d1, b1);      /* 0x180019d5f */
                            rad   = ang * 3.14159274f / 180.0f;
                            hc    = ((float)X - 1.0f) * 0.5f;
                            hp    = (float)(X - 1) * 0.5f;
                            yc    = (float)yb + hc;
                            xc    = (float)x + hc;
                            cr_sincos_f32(&co, &si, rad);
                            m[0] = co;
                            m[1] = -si;
                            m[2] = xc - (co - si) * hp;
                            m[3] = si;
                            m[4] = co;
                            m[5] = yc - (co + si) * hp;
                            cr_affine_sample_s16_nn(&A, src, m, -16000);

                            out4[0] = out4[1] = out4[2] = out4[3] = 0.0f;
                            st = (uint32_t)cr_malloc_aligned16(
                                     (void **)&buf0, 4);
                            if (st) {                 /* 0x180019e9b */
                                cr_sized_free_if(&pool);
                                return (int)st;
                            }
                            st = (uint32_t)cr_malloc_aligned16(
                                     (void **)&buf1, (size_t)X * 4);
                            if (st) {                 /* 0x18001a0f4 */
                                cr_sized_free((void **)&buf0);
                                cr_sized_free_if(&pool);
                                return (int)st;
                            }

                            for (j = 0; j < X; j++) { /* 0x180019f62 */
                                int sum = 0, cnt = 0;
                                const int16_t *Ad = (const int16_t *)A.data;
                                for (i = 0; i < X; i++) {
                                    int16_t v = Ad[i * X + j];
                                    if (v != -16000) { sum += v; cnt++; }
                                }
                                buf1[j] = cnt
                                    ? (float)sum / (float)cnt
                                    : 3.4028234663852886e+38f;
                            }

                            if (X - 1 <= 1) {         /* 0x180019fcb */
                                thr = 3.4028234663852886e+38f;
                            } else {
                                float smax = 0.0f, smin = 0.0f;
                                int cmax = 0, cmin = 0;
                                for (i = 1; i < X - 1; i++) {
                                    float cur = buf1[i];
                                    float prv = buf1[i - 1];
                                    float nxt = buf1[i + 1];
                                    if (cur > prv && !(cur < nxt)) {
                                        smax += cur; cmax++;
                                    }
                                    if (prv > cur && !(nxt < cur)) {
                                        smin += cur; cmin++;
                                    }
                                }
                                if ((int16_t)cmin == 0 || (int16_t)cmax == 0)
                                    thr = 3.4028234663852886e+38f;
                                else
                                    thr = (smax / (float)(int16_t)cmax +
                                           smin / (float)(int16_t)cmin) * 0.5f;
                            }
                            buf0[0] = thr;

                            first = 0;                /* 0x18001a076 */
                            last  = X - 1;
                            for (i = 0; i < X; i++) {
                                if (buf1[i] == 3.4028234663852886e+38f)
                                    continue;
                                buf1[i] = (buf1[i] > thr) ? 1.0f : 0.0f;
                                if (first == 0) {
                                    if (i != 0 && buf1[i] != buf1[i - 1]) {
                                        last = i; first = i;
                                    }
                                } else {
                                    if (i != 0 && buf1[i] != buf1[i - 1])
                                        last = i;
                                }
                            }

                            if (first >= last) {      /* 0x18001a495 */
                                out4[0] = -1.0f;
                                out4[1] = -1.0f;
                                out4[2] = -1.0f;
                                out4[3] = -1.0f;
                            } else {
                                float ones = 0.0f, zeros = 0.0f;
                                float t10 = 0.0f, t01 = 0.0f;
                                for (i = first; i < last; i++) {
                                    float v = buf1[i], nx = buf1[i + 1];
                                    if (v == 1.0f) {
                                        ones += 1.0f;
                                        if (nx == 0.0f) t10 += 1.0f;
                                    } else if (v == 0.0f) {
                                        zeros += 1.0f;
                                        if (nx == 1.0f) t01 += 1.0f;
                                    }
                                }
                                if (!(zeros > 0.0f) && !(ones > 0.0f)) {
                                    out4[0] = -1.0f;
                                    out4[1] = -1.0f;
                                    out4[2] = -1.0f;
                                    out4[3] = -1.0f;
                                } else {
                                    out4[0] = (t10 + t01) /
                                              (2.0f * (zeros + ones));
                                    if (!(t10 > 0.0f)) {
                                        out4[1] = -1.0f;
                                        if (!(t01 > 0.0f)) {
                                            out4[2] = -1.0f;
                                            out4[3] = -1.0f;
                                        } else {
                                            out4[2] = zeros / t01;
                                            out4[3] = -1.0f; /* 0x18001a42a */
                                        }
                                    } else {
                                        out4[1] = ones / t10;
                                        if (!(t01 > 0.0f)) {
                                            out4[2] = -1.0f;
                                            out4[3] = -1.0f;
                                        } else {
                                            out4[2] = zeros / t01;
                                            out4[3] = out4[2] / out4[1];
                                        }
                                    }
                                }
                            }

                            cr_sized_free((void **)&buf0);   /* 0x18001a1f6 */
                            cr_sized_free((void **)&buf1);
                        }

                        g2[idx] = out4[0];                /* 0x18001a25d */
                        g3[idx] = out4[1];
                        g4[idx] = out4[2];
                        g5[idx] = out4[3];
                        g6[idx] = qual;                   /* 0x18001a2a3 */

                        {
                            float mask = 0.5f;            /* 0x18001a29c */
                            if (!(out4[1] > cf[0x30 / 4] ||
                                  cf[0x2c / 4] > out4[1] ||
                                  out4[2] > cf[0x40 / 4] ||
                                  cf[0x3c / 4] > out4[2] ||
                                  out4[0] > cf[0x20 / 4] ||
                                  cf[0x1c / 4] > out4[0] ||
                                  out4[3] > cf[0x50 / 4]))
                                mask = (out4[3] < cf[0x4c / 4])
                                     ? 0.5f : 1.0f;
                            if (out4[1] > cf[0x34 / 4] ||
                                cf[0x28 / 4] > out4[1] ||
                                out4[2] > cf[0x44 / 4] ||
                                cf[0x38 / 4] > out4[2] ||
                                out4[0] > cf[0x24 / 4] ||
                                cf[0x18 / 4] > out4[0] ||
                                out4[3] > cf[0x54 / 4] ||
                                out4[3] < cf[0x48 / 4])
                                mask = 0.0f;          /* 0x18001a3ef */
                            qual *= mask;
                            qcount++;
                            qsum += qual;
                            if (cf[0x14 / 4] > qual &&
                                !(cf[0x14 / 4] < 0.0f))
                                cr_bitmap_clear_rect((cr_image *)bmp, yb,
                                                     y_end, x, x + X);
                        }
                        goto next_x;

blk_sentinel:                                     /* 0x180019a6d */
                        g2[idx] = -1.0f;
                        g3[idx] = -1.0f;
                        g4[idx] = -1.0f;
                        g5[idx] = -1.0f;
                        g6[idx] = -1.0f;
next_x:
                        if (!(xmax > x + X))
                            break;
                    }
                }
                rowacc += W * X;                          /* 0x180019b35 */
                if (!(ymax > y_end))
                    break;
            }
        }

        {
            /* One scratch float, zeroed once at entry (0x180019673) and
             * reused for all four reductions, so a failed call leaves the
             * previous median in place. */
            float med = 0.0f;
            for (int i = 0; i < 4; i++) {                 /* 0x180019b80 */
                float *g = (float *)(i == 0 ? a2->data
                                : i == 1 ? a3->data
                                : i == 2 ? a4->data : a5->data);
                cr_masked_median_f32(&med, g, a6->w * a6->h, -1.0f);
                out4[i] = med;
            }
        }
        if (qcount != 0)
            *(int16_t *)a1 = (int16_t)(int32_t)(qsum / (float)qcount);
        else
            *(int16_t *)a1 = (int16_t)(int32_t)(qsum / 0.0f);
    }

    cr_sized_free_if(&pool);                              /* 0x180019c44 */
    return 0;
}
