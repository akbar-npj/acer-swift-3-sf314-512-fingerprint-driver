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
