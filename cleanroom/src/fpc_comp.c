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
