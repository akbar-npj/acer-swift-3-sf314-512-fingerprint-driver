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
