#define _GNU_SOURCE
/*
 * difftest — differential test for the clean-room rewrite.
 *
 * Loads the vendor fpc_enclave.dll with the same minimal PE loader the native
 * rehost uses, then for every rewritten function runs a battery of inputs
 * through BOTH the vendor function (at its RVA, called with the Microsoft x64
 * ABI) and the clean-room implementation, and compares the results bit-for-bit.
 *
 * This is the correctness oracle for the whole clean-room effort: a function is
 * "done" only when difftest reports zero mismatches.
 *
 * Build/run on x86-64 only (ms_abi).  See Makefile.
 */
#include "fpc_bep.h"
#include "pe_loader.h"
#include "win32_shims.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <pthread.h>
#include <unistd.h>
#include <asm/prctl.h>

#define WINAPI __attribute__((ms_abi))

/* ---- fake TEB (same as native/fpc_recon.c) ----------------------------- */
struct fake_teb {
    u64 exception_list, stack_base, stack_limit, subsystem_tib, fiber_data,
        arbitrary_user, self, environment_pointer;
    u32 client_pid, client_tid;
    u64 tls_pointer, peb;
    u64 pad[64];
};
static struct fake_teb g_teb;
static void setup_teb(void)
{
    pthread_attr_t attr; void *addr = NULL; size_t size = 0;
    if (pthread_getattr_np(pthread_self(), &attr) == 0 &&
        pthread_attr_getstack(&attr, &addr, &size) == 0) {
        g_teb.stack_limit = (u64)addr;
        g_teb.stack_base  = (u64)addr + size;
        pthread_attr_destroy(&attr);
    } else {
        g_teb.stack_base = (u64)&attr;
        g_teb.stack_limit = g_teb.stack_base - (8u << 20);
    }
    g_teb.exception_list = ~0ULL;
    g_teb.self = (u64)&g_teb;
    g_teb.client_pid = (u32)getpid();
    g_teb.client_tid = (u32)syscall(SYS_gettid);
    syscall(SYS_arch_prctl, ARCH_SET_GS, (unsigned long)&g_teb);
}

static u8 *g_base;

/* The image is mapped at its preferred base 0x180000000; convert an absolute
 * vendor VA to the RVA the loader is based on. */
#define RVA(va) ((u32)((va) - 0x180000000u))

static void *fn_at(u32 rva) { return (void *)(g_base + rva); }

/* ---- result accounting ------------------------------------------------- */
static int g_pass, g_fail;
static const char *g_cur;

static void begin(const char *name) { g_cur = name; }

static void mismatch(const char *what, unsigned long long in, unsigned long long v, unsigned long long c)
{
    if (g_fail < 40)
        printf("  MISMATCH %-28s %s in=%#llx vendor=%#llx clean=%#llx\n",
               g_cur, what, in, v, c);
    g_fail++;
}

static void end(void)
{
    g_pass++;
    printf("  ok  %s\n", g_cur);
}

/* ---- float battery ----------------------------------------------------- */
typedef float (WINAPI *v_ff)(float);
typedef int   (WINAPI *v_if)(float);

static void test_float_fn(const char *name, u32 rva,
                          void *clean, int ret_int)
{
    begin(name);
    void *p = fn_at(rva);
    int bad = g_fail;

    /* deterministic sweep over raw bit patterns (both signs) */
    for (u64 i = 0; i < 0x100000000ULL; i += 0x10001ULL) {
        u32 bits = (u32)i;
        float x = cr_u2f(bits);
        if (ret_int) {
            int v = ((v_if)p)(x), c = ((int (*)(float))clean)(x);
            if (v != c) mismatch("int", bits, (u32)v, (u32)c);
        } else {
            float v = ((v_ff)p)(x), c = ((float (*)(float))clean)(x);
            if (cr_f2u(v) != cr_f2u(c)) mismatch("bits", bits, cr_f2u(v), cr_f2u(c));
        }
    }
    /* targeted values */
    static const float specials[] = {
        0.0f, -0.0f, 1.0f, -1.0f, 0.5f, -0.5f, 2.0f, 3.0f, 4.0f, 0.25f,
        1e-30f, 1e30f, 3.4028235e38f, 1.1754944e-38f, 88.7228f, -87.3365f,
        88.0f, -88.0f, 100.0f, -100.0f, 700.0f, -700.0f, 0.6931f, -0.6931f,
        1e-45f, 2.5f, -2.5f, 3.5f, -3.5f, 0.4999999f, 1e-8f,
    };
    for (size_t i = 0; i < sizeof specials / sizeof specials[0]; i++) {
        float x = specials[i];
        if (ret_int) {
            int v = ((v_if)p)(x), c = ((int (*)(float))clean)(x);
            if (v != c) mismatch("int-sp", cr_f2u(x), (u32)v, (u32)c);
        } else {
            float v = ((v_ff)p)(x), c = ((float (*)(float))clean)(x);
            if (cr_f2u(v) != cr_f2u(c)) mismatch("bits-sp", cr_f2u(x), cr_f2u(v), cr_f2u(c));
        }
    }
    if (g_fail == bad) end(); else printf("  FAIL %s\n", name);
}

/* ---- buffer / metadata battery ---------------------------------------- */
typedef int  (WINAPI *v_pp)(void *);
typedef bool (WINAPI *v_bp)(const void *);
typedef int  (WINAPI *v_meta_put)(void *, u32, u32, char);
typedef int  (WINAPI *v_meta_get)(void *, u32, u32 *);
typedef bool (WINAPI *v_slot)(const void *, u32);

/* deterministic PRNG so both runs get identical inputs */
static u32 rng_state = 0x12345678u;
static u32 rnd(void) { rng_state = rng_state * 1103515245u + 12345u; return rng_state >> 8; }

static void test_type_predicates(void)
{
    struct { const char *name; u32 rva; bool (*clean)(const void *); } fns[] = {
        { "cr_buf_is_pixels",         RVA(0x1800490d0), cr_buf_is_pixels },
        { "cr_buf_is_metadata_class", RVA(0x180049120), cr_buf_is_metadata_class },
        { "cr_buf_is_debug_class",    RVA(0x1800490f0), cr_buf_is_debug_class },
    };
    for (size_t k = 0; k < sizeof fns / sizeof fns[0]; k++) {
        begin(fns[k].name);
        int bad = g_fail;
        v_bp vp = (v_bp)fn_at(fns[k].rva);
        u32 tags[] = { 0,1,2,3,7,8,9,10,11,15,16,21,0x7fffffff,0xffffffff };
        for (size_t i = 0; i < sizeof tags / sizeof tags[0]; i++) {
            u32 b = tags[i];
            bool v = vp(&b), c = fns[k].clean(&b);
            if (v != c) mismatch("tag", b, v, c);
        }
        /* NULL */
        if (vp(NULL) != fns[k].clean(NULL)) mismatch("null", 0, vp(NULL), fns[k].clean(NULL));
        if (g_fail == bad) end(); else printf("  FAIL %s\n", fns[k].name);
    }
}

static void test_metadata(void)
{
    v_meta_put vput = (v_meta_put)fn_at(RVA(0x18004b670));
    v_meta_get vget = (v_meta_get)fn_at(RVA(0x18004b4e0));

    begin("cr_meta_put_u32");
    int bad = g_fail;
    for (int trial = 0; trial < 20000; trial++) {
        u8 sv[128], sc[128];
        memset(sv, 0xAA, sizeof sv); memset(sc, 0xAA, sizeof sc);
        u32 cap  = (rnd() % 120u) + 8u;
        u32 used = rnd() % (cap + 1u);
        if (used > 100u) used = 100u;
        /* fill a plausible record region */
        for (u32 off = 0; off < used && off + 12 <= 100; ) {
            u32 step = 12;
            *(u32 *)(sv + 0xc + off) = rnd() % 6u;
            *(u32 *)(sv + 0xc + off + 4) = 4;
            *(u32 *)(sv + 0xc + off + 8) = rnd();
            off += step;
        }
        if (used > 100u) used = 100u;
        memcpy(sc, sv, sizeof sv);
        *(u32 *)(sv + 4) = cap; *(u32 *)(sv + 8) = used; *(u32 *)(sv + 0) = 8;
        *(u32 *)(sc + 4) = cap; *(u32 *)(sc + 8) = used; *(u32 *)(sc + 0) = 8;

        u32 key = rnd() % 6u, val = rnd(), ow = rnd() & 1u;
        int rv = vput(sv, key, val, (char)ow);
        int rc = cr_meta_put_u32(sc, key, val, (bool)ow);
        if (rv != rc || memcmp(sv, sc, sizeof sv) != 0)
            mismatch("put", ((u64)key << 32) | val, (u32)rv, (u32)rc);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_meta_put_u32\n");

    begin("cr_meta_get_u32");
    bad = g_fail;
    for (int trial = 0; trial < 20000; trial++) {
        u8 sv[128], sc[128];
        memset(sv, 0, sizeof sv); memset(sc, 0, sizeof sc);
        u32 cap = (rnd() % 120u) + 8u;
        u32 used = rnd() % (cap + 1u);
        if (used > 100u) used = 100u;
        for (u32 off = 0; off < used && off + 12 <= 100; ) {
            *(u32 *)(sv + 0xc + off) = rnd() % 6u;
            *(u32 *)(sv + 0xc + off + 4) = 4;
            *(u32 *)(sv + 0xc + off + 8) = rnd();
            off += 12;
        }
        memcpy(sc, sv, sizeof sv);
        *(u32 *)(sv + 4) = cap; *(u32 *)(sv + 8) = used; *(u32 *)(sv + 0) = 8;
        *(u32 *)(sc + 4) = cap; *(u32 *)(sc + 8) = used; *(u32 *)(sc + 0) = 8;

        u32 key = rnd() % 6u;
        u32 ov = 0xdeadbeef, oc = 0xdeadbeef;
        int rv = vget(sv, key, &ov);
        int rc = cr_meta_get_u32(sc, key, &oc);
        if (rv != rc || ov != oc)
            mismatch("get", key, (u32)rv, (u32)rc);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_meta_get_u32\n");
}

static void test_image_slots(void)
{
    v_slot vdef = (v_slot)fn_at(RVA(0x18004aa70));
    v_slot vemp = (v_slot)fn_at(RVA(0x18004a250));

    begin("cr_image_slot_defined/empty");
    int bad = g_fail;
    u8 defs[0x10 + 22 * 8];
    u8 objs[22][16];
    for (int trial = 0; trial < 4000; trial++) {
        memset(defs, 0, sizeof defs);
        for (u32 i = 0; i < 22; i++) {
            u32 r = rnd() % 3u;
            if (r == 0) continue;                 /* NULL slot */
            *(int *)(objs[i] + 8) = (r == 1) ? 0 : (int)rnd();
            *(u64 *)(defs + 0x10 + i * 8) = (u64)(uintptr_t)objs[i];
        }
        u32 idx = rnd() % 26u;
        if (vdef(defs, idx) != cr_image_slot_defined(defs, idx)) mismatch("defined", idx, 0, 0);
        if (vemp(defs, idx) != cr_image_slot_empty(defs, idx))   mismatch("empty", idx, 0, 0);
    }
    if (g_fail == bad) end(); else printf("  FAIL image slots\n");
}

/* ---- util / image leaf battery ---------------------------------------- */
typedef uint32_t (WINAPI *v_u_pc)(void *, char);
typedef uint32_t (WINAPI *v_u_p)(const void *);
typedef void     (WINAPI *v_v_pui)(void *, uint8_t, int);
typedef void     (WINAPI *v_v_ppi)(void *, const void *, int);
typedef float    (WINAPI *v_f_ffp)(float, float *);
typedef uint32_t (WINAPI *v_u_pii)(const void *, int, int);
typedef uint32_t (WINAPI *v_u_iii)(int, int, int);
typedef void     (WINAPI *v_v_p)(void *);
typedef uint32_t (WINAPI *v_u_ppii)(void *, void *, int, int);
typedef void     (WINAPI *v_v_ppiiii)(void *, const void *, int, int, int, int);
typedef void     (WINAPI *v_v_pp)(void *, const void *);
typedef void     (WINAPI *v_v_ppi_s)(void *, const void *, int16_t);
typedef float    (WINAPI *v_f_fi)(float, int);
typedef int      (WINAPI *v_i_plii)(uint64_t *, int, int);
typedef uint32_t (WINAPI *v_u_i)(uint32_t);
typedef void     (WINAPI *v_v_ipp)(int32_t *, int32_t *, uint32_t);
typedef float    (WINAPI *v_f_ppi)(const float *, const float *, int);
typedef void     (WINAPI *v_v_pb)(void *, uint8_t);
typedef void     (WINAPI *v_v_pw)(void *, uint16_t);
typedef void     (WINAPI *v_v_pf)(void *, float);
typedef void     (WINAPI *v_v_piiii)(void *, int, int, int, int);
typedef void     (WINAPI *v_v_pfpp)(const float *, uint8_t *const *,
                                    const uint16_t *, const uint16_t *const *);
typedef uint64_t (WINAPI *v_u64_ppii)(void *, const void *, int, int);
typedef void     (WINAPI *v_v_pli)(uint64_t *, int);
typedef uint64_t (WINAPI *v_u64_pc)(void *, char);

/* batch 5 */
typedef uint64_t (WINAPI *v_u64_pp)(void *, const void *);
typedef void     (WINAPI *v_v_ppb)(void *, const void *, uint8_t);
typedef float    (WINAPI *v_f_piipp)(const float *, int, int,
                                     const uint8_t *const *);
typedef int      (WINAPI *v_i_p)(const void *);
typedef uint64_t (WINAPI *v_u64_ppuiii)(void *, const void *, uint32_t,
                                        int, int, int);
typedef void     (WINAPI *v_v_ppp)(float *, const float *, const float *);
typedef void     (WINAPI *v_v_piiiiu)(void *, int, int, int, int, uint16_t);

/* batch 6 */
typedef float    (WINAPI *v_fff)(float, float);
typedef void     (WINAPI *v_v_pppii)(void *, const void *, const void *, int, int);
typedef void     (WINAPI *v_v_ppppp)(void *, void *, void *, const void *, const void *);
typedef void     (WINAPI *v_v_pppppii)(void *, void *, void *, const void *,
                                       const void *, int, int);

/* batch 7 */
typedef int      (WINAPI *v_i_ppipii_p)(const float *, int, int,
                                        const float *, int, int, float *);
typedef void     (WINAPI *v_v_pppi)(float *, float *, const void *, int);
typedef void     (WINAPI *v_v_pppppb)(void *, void *, void *, const void *,
                                      const void *, uint8_t);

/* batch 9 */
typedef void     (WINAPI *v_v_ppiii)(void *, const void *, int, int, int);
typedef void     (WINAPI *v_v_ppppbii)(void *, void *, const void *, const void *,
                                       uint8_t, int, int);

/* batch 11 */
typedef int      (WINAPI *v_i_pph)(void *, const void *, int16_t);

/* batch 14 */
typedef void     (WINAPI *v_v_piiii)(void *, int, int, int, int);
typedef void     (WINAPI *v_v_pi)(int *, const void *);

/* batch 16 */
typedef int      (WINAPI *v_i_ppz)(void *, size_t);

/* batch 17 */
typedef void     (WINAPI *v_v_ppim)(void *, const void *, int);

/* batch 18 */
typedef void     (WINAPI *v_v_ppp_fir)(void *, const void *, const void *, int, int);

/* compare a whole buffer; report the first differing byte */
static void cmp_buf(const char *what, const unsigned char *a, const unsigned char *b, size_t n, u32 seed)
{
    if (memcmp(a, b, n) != 0) {
        size_t i = 0;
        while (i < n && a[i] == b[i]) i++;
        mismatch(what, seed, a[i], b[i]);
    }
}

static void test_status_helpers(void)
{
    v_u_pc vflag = (v_u_pc)fn_at(RVA(0x180016720));
    begin("cr_status_from_flag");
    int bad = g_fail;
    for (int f = -128; f < 256; f++) {
        /* vendor signature is (unused, char flag): flag lives in dl */
        uint32_t v = vflag(NULL, (char)f), c = cr_status_from_flag((char)f);
        if (v != c) mismatch("flag", (u32)f, v, c);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_status_from_flag\n");

    v_u_p vctx = (v_u_p)fn_at(RVA(0x1800216d0));
    begin("cr_status_from_ctx");
    bad = g_fail;
    for (int t = 0; t < 3000; t++) {
        unsigned char blk[0x100];
        memset(blk, 0, sizeof blk);
        blk[0x3c] = (unsigned char)(rnd() & 0xff);
        void *inner = blk;
        unsigned char ctx[0x100];
        memset(ctx, 0, sizeof ctx);
        *(void **)(ctx + 0x78) = inner;
        uint32_t v = vctx(ctx), c = cr_status_from_ctx(ctx);
        if (v != c) mismatch("ctx", blk[0x3c], v, c);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_status_from_ctx\n");
}

static void test_fill_copy(void)
{
    v_v_pui vfill = (v_v_pui)fn_at(RVA(0x180011000));
    v_v_ppi vcopy = (v_v_ppi)fn_at(RVA(0x180040de0));

    begin("cr_fill");
    int bad = g_fail;
    for (int t = 0; t < 4000; t++) {
        unsigned char a[256], b[256];
        memset(a, 0x5A, sizeof a); memset(b, 0x5A, sizeof b);
        int n = (int)(rnd() % 200u) - 60;          /* include n<=0 */
        uint8_t val = (uint8_t)rnd();
        vfill(a, val, n);
        cr_fill(b, val, n);
        cmp_buf("fill", a, b, sizeof a, (u32)n);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_fill\n");

    begin("cr_copy");
    bad = g_fail;
    for (int t = 0; t < 4000; t++) {
        unsigned char src[256], a[256], b[256];
        for (size_t i = 0; i < sizeof src; i++) src[i] = (unsigned char)rnd();
        memset(a, 0x33, sizeof a); memset(b, 0x33, sizeof b);
        int n = (int)(rnd() % 200u) - 60;
        vcopy(a, src, n);
        cr_copy(b, src, n);
        cmp_buf("copy", a, b, sizeof a, (u32)n);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_copy\n");
}

static void test_modff(void)
{
    v_f_ffp v = (v_f_ffp)fn_at(RVA(0x180040e20));
    begin("cr_modff");
    int bad = g_fail;
    for (u64 i = 0; i < 0x100000000ULL; i += 0x10001ULL) {
        u32 bits = (u32)i;
        float x = cr_u2f(bits), iv, ic;
        float rv = v(x, &iv);
        float rc = cr_modff(x, &ic);
        if (cr_f2u(rv) != cr_f2u(rc) || cr_f2u(iv) != cr_f2u(ic))
            mismatch("modff", bits, cr_f2u(rv), cr_f2u(rc));
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_modff\n");
}

static void test_bitmap_bitmask(void)
{
    v_u_pii vget = (v_u_pii)fn_at(RVA(0x180027380));
    v_u_iii vmask = (v_u_iii)fn_at(RVA(0x18003c540));

    begin("cr_bitmap_get");
    int bad = g_fail;
    for (int t = 0; t < 6000; t++) {
        unsigned char bm[0x40];
        memset(bm, 0, sizeof bm);
        int width = (int)(rnd() % 200u) + 1;
        *(int *)bm = width;
        uint32_t words[512];      /* idx can reach (63*200+63)>>5 = 395 */
        for (int i = 0; i < 512; i++) words[i] = rnd();
        *(void **)(bm + 8) = words;
        int x = (int)(rnd() % 64u);
        int y = (int)(rnd() % 64u);
        uint32_t v = vget(bm, x, y), c = cr_bitmap_get(bm, x, y);
        if (v != c) mismatch("bitmap", ((u64)(u32)x << 32) | (u32)y, v, c);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_bitmap_get\n");

    begin("cr_bitmask_range");
    bad = g_fail;
    for (int t = 0; t < 200000; t++) {
        int word  = (int)(rnd() % 6u) - 1;
        int start = (int)(rnd() % 130u) - 32;
        int end   = (int)(rnd() % 130u) - 32;
        uint32_t v = vmask(word, start, end), c = cr_bitmask_range(word, start, end);
        if (v != c) mismatch("mask", ((u64)(u32)start << 32) | (u32)end, v, c);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_bitmask_range\n");
}

/* ---- batch 3: more math / util leaves ---------------------------------- */
static void test_ldexpf(void)
{
    v_f_fi v = (v_f_fi)fn_at(RVA(0x1800413a0));
    begin("cr_ldexpf");
    int bad = g_fail;
    static const int ks[] = { 0, 1, -1, 23, -23, 127, -127, 128, 255, -128,
                              0x7fffffff, (int)0x80000000, 5, -5, 64, -64 };
    for (u64 i = 0; i < 0x100000000ULL; i += 0x10003ULL) {
        u32 bits = (u32)i;
        float x = cr_u2f(bits);
        for (size_t j = 0; j < sizeof ks / sizeof ks[0]; j++) {
            float rv = v(x, ks[j]);
            float rc = cr_ldexpf(x, ks[j]);
            if (cr_f2u(rv) != cr_f2u(rc))
                mismatch("ldexp", ((u64)bits << 32) | (u32)ks[j], cr_f2u(rv), cr_f2u(rc));
        }
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_ldexpf\n");
}

static void test_s16_clamp(void)
{
    v_v_ppi v = (v_v_ppi)fn_at(RVA(0x180012060));
    begin("cr_s16_clamp_nonneg");
    int bad = g_fail;
    for (int t = 0; t < 6000; t++) {
        int16_t sv[64], va[64], ca[64];
        int n = (int)(rnd() % 66u) - 2;            /* include n<=0 */
        for (int i = 0; i < 64; i++) {
            sv[i] = (int16_t)rnd();
            va[i] = (int16_t)(rnd() ^ 0x5A5A);
            ca[i] = va[i];
        }
        v(va, sv, n);
        cr_s16_clamp_nonneg(ca, sv, n);
        cmp_buf("clamp", (unsigned char *)va, (unsigned char *)ca, sizeof va, (u32)n);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_s16_clamp_nonneg\n");
}

static void test_prng_range(void)
{
    v_i_plii v = (v_i_plii)fn_at(RVA(0x18002fd00));
    begin("cr_prng_range");
    int bad = g_fail;
    for (int t = 0; t < 200000; t++) {
        uint64_t sv = ((uint64_t)rnd() << 32) | rnd();
        uint64_t sc = sv;
        int lo = (int)rnd() - (int)(rnd() & 0xff);
        int hi = (rnd() % 3u == 0) ? lo : (int)rnd() - (int)(rnd() & 0xff);
        int rv = v(&sv, lo, hi);
        int rc = cr_prng_range(&sc, lo, hi);
        if (rv != rc || sv != sc)
            mismatch("prng", ((u64)(u32)lo << 32) | (u32)hi, (u32)rv, (u32)rc);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_prng_range\n");
}

static void test_clz(void)
{
    v_u_i v = (v_u_i)fn_at(RVA(0x1800393b0));
    begin("cr_clz");
    int bad = g_fail;
    /* structured: 0..0xffff, all powers of two and their neighbours */
    for (u32 x = 0; x <= 0xffffu; x++) {
        u32 rv = v(x), rc = cr_clz(x);
        if (rv != rc) mismatch("clz", x, rv, rc);
    }
    for (int b = 0; b < 32; b++) {
        u32 p = 1u << b;
        u32 xs[3] = { p, p - 1u, p + 1u };
        for (int k = 0; k < 3; k++) {
            u32 rv = v(xs[k]), rc = cr_clz(xs[k]);
            if (rv != rc) mismatch("clz-pow", xs[k], rv, rc);
        }
    }
    /* wide deterministic sweep */
    for (u64 i = 0; i < 0x100000000ULL; i += 0x1001ULL) {
        u32 x = (u32)i;
        u32 rv = v(x), rc = cr_clz(x);
        if (rv != rc) mismatch("clz-sweep", x, rv, rc);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_clz\n");
}

static void test_sincos(void)
{
    v_v_ipp v = (v_v_ipp)fn_at(RVA(0x18001b990));
    begin("cr_sincos");
    int bad = g_fail;
    for (u32 ph = 0; ph < 256; ph++) {
        int32_t va = 0, vb = 0, ca = 0, cb = 0;
        v(&va, &vb, ph);
        cr_sincos(&ca, &cb, ph);
        if (va != ca || vb != cb)
            mismatch("sincos", ph, (u32)va ^ (u32)vb, (u32)ca ^ (u32)cb);
    }
    for (int t = 0; t < 100000; t++) {
        u32 ph = rnd();
        int32_t va = 0, vb = 0, ca = 0, cb = 0;
        v(&va, &vb, ph);
        cr_sincos(&ca, &cb, ph);
        if (va != ca || vb != cb)
            mismatch("sincos-r", ph, (u32)va ^ (u32)vb, (u32)ca ^ (u32)cb);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_sincos\n");
}

static void test_dot_f32(void)
{
    v_f_ppi v = (v_f_ppi)fn_at(RVA(0x18003b800));
    begin("cr_dot_f32");
    int bad = g_fail;
    for (int t = 0; t < 200000; t++) {
        float a[32], b[32];
        int n = (int)(rnd() % 34u) - 2;            /* include n<=0 */
        for (int i = 0; i < 32; i++) {
            a[i] = cr_u2f(rnd());
            b[i] = cr_u2f(rnd());
        }
        float rv = v(a, b, n), rc = cr_dot_f32(a, b, n);
        if (cr_f2u(rv) != cr_f2u(rc))
            mismatch("dot", (u32)n, cr_f2u(rv), cr_f2u(rc));
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_dot_f32\n");
}

/* ---- FFT forward/inverse (0x18003d490 / 0x1800244a0) ------------------ */
typedef uint32_t (WINAPI *v_u32_pppu)(float *, const float *, uint32_t);

static void test_fft(void)
{
    v_u32_pppu vf = (v_u32_pppu)fn_at(RVA(0x18003d490));
    v_u32_pppu vi = (v_u32_pppu)fn_at(RVA(0x1800244a0));
    static const uint32_t ns[] = { 8, 16, 32, 64, 128, 256 };

    for (int k = 0; k < (int)(sizeof ns / sizeof ns[0]); k++) {
        uint32_t n = ns[k];

        begin("cr_fft_fwd");
        int bad = g_fail;
        for (int t = 0; t < 6000; t++) {
            float inv[512], inc[512], outv[512], outc[512];
            for (uint32_t i = 0; i < 2u * n; i++) { inv[i] = cr_u2f(rnd()); inc[i] = inv[i]; }
            memset(outv, 0x55, sizeof outv);
            memset(outc, 0x55, sizeof outc);
            uint32_t rv = vf(outv, inv, n);
            uint32_t rc = cr_fft_fwd(outc, inc, n);
            if (rv != rc) mismatch("ret", n, rv, rc);
            cmp_buf("out", (const unsigned char *)outv, (const unsigned char *)outc,
                    2u * n * sizeof(float), (u32)t);
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_fft_fwd\n");

        begin("cr_fft_inv");
        bad = g_fail;
        for (int t = 0; t < 6000; t++) {
            float inv[512], inc[512], outv[512], outc[512];
            for (uint32_t i = 0; i < 2u * n; i++) { inv[i] = cr_u2f(rnd()); inc[i] = inv[i]; }
            memset(outv, 0x55, sizeof outv);
            memset(outc, 0x55, sizeof outc);
            uint32_t rv = vi(outv, inv, n);
            uint32_t rc = cr_fft_inv(outc, inc, n);
            if (rv != rc) mismatch("ret", n, rv, rc);
            cmp_buf("out", (const unsigned char *)outv, (const unsigned char *)outc,
                    2u * n * sizeof(float), (u32)t);
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_fft_inv\n");
    }

    /* invalid sizes: vendor returns 0x69 and leaves out untouched */
    static const uint32_t badn[] = { 0, 1, 2, 3, 4, 5, 6, 7, 9, 15, 31, 255, 257, 512, 1024 };
    begin("cr_fft_invalid");
    int bad = g_fail;
    for (int t = 0; t < (int)(sizeof badn / sizeof badn[0]); t++) {
        uint32_t n = badn[t];
        float inv[1024], inc[1024], outv[1024], outc[1024];
        for (uint32_t i = 0; i < 1024u; i++) { inv[i] = cr_u2f(rnd()); inc[i] = inv[i]; }
        memset(outv, 0x55, sizeof outv);
        memset(outc, 0x55, sizeof outc);
        uint32_t rv = vf(outv, inv, n);
        uint32_t rc = cr_fft_fwd(outc, inc, n);
        if (rv != 0x69u || rc != 0x69u) mismatch("ret_bad", n, rv, rc);
        cmp_buf("untouched", (const unsigned char *)outv, (const unsigned char *)outc,
                sizeof outv, n);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_fft_invalid\n");
}

/* ---- calibration/data blob accessor (0x180030340) ---------------------- */
typedef uint32_t (WINAPI *v_u32_pppu8)(uint64_t *, uint32_t *, uint8_t);

static void test_calib_blob(void)
{
    v_u32_pppu8 v = (v_u32_pppu8)fn_at(RVA(0x180030340));
    begin("cr_get_calib_blob");
    int bad = g_fail;
    static const uint8_t sels[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 255 };
    for (int t = 0; t < (int)(sizeof sels / sizeof sels[0]); t++) {
        uint8_t sel = sels[t];
        uint64_t vp1 = 0, cp1 = 0;
        uint32_t vp2 = 0, cp2 = 0;
        uint32_t rv = v(&vp1, &vp2, sel);
        uint32_t rc = cr_get_calib_blob(&cp1, &cp2, sel);
        if (rv != rc) mismatch("ret", sel, rv, rc);
        if (vp1 != cp1) mismatch("p1", sel, vp1, cp1);
        if (vp2 != cp2) mismatch("p2", sel, vp2, cp2);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_get_calib_blob\n");
}

/* ---- batch 63: Gaussian-windowed FIR orchestration (0x180046610 / 0x180044a20) --
 * The descriptors these functions read are NOT cr_image: they are a 0x20-byte
 * record with tag(+0x00) == qword(+0x10), data ptr(+0x08), L(+0x14), and a
 * mandatory zero qword(+0x18).  W/L are taken from the *second* (source)
 * descriptor. */
typedef int (WINAPI *v_gf_apply)(void *, void *, int, uint16_t, float, float, float);
typedef int (WINAPI *v_gf7_apply)(void *, void *, float, float, float);

static void mk_gf_desc(unsigned char *d, void *data, int W, int L)
{
    uint64_t tag = (uint64_t)(uint32_t)W | ((uint64_t)(uint32_t)L << 32);
    *(uint64_t *)(d + 0x00) = tag;   /* +0x00 tag (== +0x10)   */
    *(void **)(d + 0x08) = data;     /* +0x08 data pointer     */
    *(uint64_t *)(d + 0x10) = tag;   /* +0x10 qword: W(LSW)/L  */
    *(uint64_t *)(d + 0x18) = 0;     /* +0x18 must be 0        */
}

static void test_gauss_fir(void)
{
    v_gf_apply v = (v_gf_apply)fn_at(RVA(0x180046610));
    static const uint16_t counts[] = { 1, 3, 5, 7, 9, 11, 15, 31, 63, 127 };

    begin("cr_gauss_fir_apply");
    int bad = g_fail;
    for (int t = 0; t < 4000; t++) {
        int W = (int)(rnd() % 64u) + 1;
        int L = (int)(rnd() % 64u) + 1;
        uint16_t count = counts[rnd() % (uint32_t)(sizeof counts / sizeof counts[0])];
        float sigma = cr_u2f(rnd());
        int n = W * L;
        int16_t av[4096], ac[4096], bv[4096], bc[4096];
        for (int i = 0; i < n; i++) {
            int16_t s = (int16_t)(rnd() & 0xffffu); av[i] = s; ac[i] = s;
            s = (int16_t)(rnd() & 0xffffu); bv[i] = s; bc[i] = s;
        }
        unsigned char dv[0x20], dc[0x20], adv[0x20], adc[0x20];
        mk_gf_desc(dv, bv, W, L);  mk_gf_desc(dc, bc, W, L);
        mk_gf_desc(adv, av, W, L); mk_gf_desc(adc, ac, W, L);
        int rv = v(adv, dv, 0, count, 0.0f, 0.0f, sigma);
        int rc = cr_gauss_fir_apply(adc, dc, 0, count, 0.0f, 0.0f, sigma);
        if (rv != rc) mismatch("ret", t, (u32)rv, (u32)rc);
        cmp_buf("a_data", (const unsigned char *)av, (const unsigned char *)ac,
                (uint32_t)n * sizeof(int16_t), (u32)t);
    }
    /* invalid descriptor (corrupt +0x18 on the destination) -> 0x69, data intact */
    for (int t = 0; t < 8; t++) {
        int16_t av[16], ac[16], bv[16], bc[16];
        for (int i = 0; i < 16; i++) { av[i] = ac[i] = bv[i] = bc[i] = (int16_t)(rnd() & 0xffffu); }
        unsigned char dv[0x20], dc[0x20], adv[0x20], adc[0x20];
        mk_gf_desc(dv, bv, 4, 4);  mk_gf_desc(dc, bc, 4, 4);
        mk_gf_desc(adv, av, 4, 4); mk_gf_desc(adc, ac, 4, 4);
        *(uint64_t *)(adv + 0x18) = 1; *(uint64_t *)(adc + 0x18) = 1;
        int rv = v(adv, dv, 0, 7, 0.0f, 0.0f, 1.0f);
        int rc = cr_gauss_fir_apply(adc, dc, 0, 7, 0.0f, 0.0f, 1.0f);
        if (rv != 0x69 || rc != 0x69) mismatch("ret_bad", t, (u32)rv, (u32)rc);
        cmp_buf("a_untouched", (const unsigned char *)av, (const unsigned char *)ac,
                sizeof av, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_gauss_fir_apply\n");
}

static void test_gauss_fir7(void)
{
    v_gf7_apply v = (v_gf7_apply)fn_at(RVA(0x180044a20));

    begin("cr_gauss_fir7_apply");
    int bad = g_fail;
    for (int t = 0; t < 4000; t++) {
        /* the fixed 7-tap reflect FIRs are only defined for W>=4 and the
         * column twin for L>=4 (a 7-tap window over a span < 7 folds past the
         * edge into the next row/column, which the closed form cannot follow).
         * This matches the validated domain of cr_fir7_reflect/cr_vfir7_cols. */
        int W = (int)(rnd() % 61u) + 4;
        int L = (int)(rnd() % 61u) + 4;
        float sigma = cr_u2f(rnd());
        int n = W * L;
        int16_t av[4096], ac[4096], bv[4096], bc[4096];
        for (int i = 0; i < n; i++) {
            int16_t s = (int16_t)(rnd() & 0xffffu); av[i] = s; ac[i] = s;
            s = (int16_t)(rnd() & 0xffffu); bv[i] = s; bc[i] = s;
        }
        unsigned char dv[0x20], dc[0x20], adv[0x20], adc[0x20];
        mk_gf_desc(dv, bv, W, L);  mk_gf_desc(dc, bc, W, L);
        mk_gf_desc(adv, av, W, L); mk_gf_desc(adc, ac, W, L);
        int rv = v(adv, dv, 0.0f, 0.0f, sigma);
        int rc = cr_gauss_fir7_apply(adc, dc, 0.0f, 0.0f, sigma);
        if (rv != rc) mismatch("ret", t, (u32)rv, (u32)rc);
        cmp_buf("a_data", (const unsigned char *)av, (const unsigned char *)ac,
                (uint32_t)n * sizeof(int16_t), (u32)t);
    }
    /* invalid descriptor -> 0x69, data intact */
    for (int t = 0; t < 8; t++) {
        int16_t av[16], ac[16], bv[16], bc[16];
        for (int i = 0; i < 16; i++) { av[i] = ac[i] = bv[i] = bc[i] = (int16_t)(rnd() & 0xffffu); }
        unsigned char dv[0x20], dc[0x20], adv[0x20], adc[0x20];
        mk_gf_desc(dv, bv, 4, 4);  mk_gf_desc(dc, bc, 4, 4);
        mk_gf_desc(adv, av, 4, 4); mk_gf_desc(adc, ac, 4, 4);
        *(uint64_t *)(adv + 0x18) = 1; *(uint64_t *)(adc + 0x18) = 1;
        int rv = v(adv, dv, 0.0f, 0.0f, 1.0f);
        int rc = cr_gauss_fir7_apply(adc, dc, 0.0f, 0.0f, 1.0f);
        if (rv != 0x69 || rc != 0x69) mismatch("ret_bad", t, (u32)rv, (u32)rc);
        cmp_buf("a_untouched", (const unsigned char *)av, (const unsigned char *)ac,
                sizeof av, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_gauss_fir7_apply\n");
}

/* ---- batch 64: image-data dump + pixel-buffer setup -------------------- */

/* Build a defs table with metadata-class slot pointers, matching the vendor's
 * image-definition layout: defs+0x10 holds an array of 22 (ptr) slots. */
static void test_image_data_dump(void)
{
    typedef uint32_t (WINAPI *v_u_ppu)(const void *, uint32_t, void *);
    v_u_ppu v = (v_u_ppu)fn_at(RVA(0x18004a680));
    begin("cr_image_data_dump");
    int bad = g_fail;
    static u8 defs[0x10 + 22 * 8];
    static u8 meta[22][0x40];
    for (int t = 0; t < 8000; t++) {
        memset(defs, 0, sizeof defs);
        for (int i = 0; i < 22; i++) {
            int kind = (int)(rnd() % 4u);
            if (kind == 0) continue;          /* NULL slot */
            memset(meta[i], 0, sizeof meta[i]);
            /* tag: even and >= 8 → metadata-class true; odd or < 8 → false */
            if (kind == 1)
                *(u32 *)meta[i] = 8u + 2u * (rnd() % 8u);   /* valid */
            else if (kind == 2)
                *(u32 *)meta[i] = 9u + 2u * (rnd() % 8u);   /* odd >= 8 → invalid */
            else
                *(u32 *)meta[i] = rnd() % 8u;                /* < 8 → invalid */
            /* fill some fields the function reads */
            *(u32 *)(meta[i] + 4) = (rnd() % 200u) + 0x20u;
            *(u32 *)(meta[i] + 0x0c) = rnd();
            *(u32 *)(meta[i] + 0x10) = rnd();
            *(u32 *)(meta[i] + 0x14) = rnd();
            *(u32 *)(meta[i] + 0x18) = rnd();
            *(void **)(defs + 0x10 + (size_t)i * 8) = meta[i];
        }
        u32 idx = rnd() % 26u;
        u8 ov[0x40], oc[0x40];   /* cr_image_data_dump writes 0x38 bytes (0x20 + cr_image_buf_desc) */
        memset(ov, 0xA5, sizeof ov); memset(oc, 0xA5, sizeof oc);
        uint32_t rv = v(defs, idx, ov);
        uint32_t rc = cr_image_data_dump(defs, idx, oc);
        if (rv != rc) mismatch("idd-ret", idx, rv, rc);
        /* Only compare the first 0x20 bytes (the packed header up to but not
         * including the cr_image_buf_desc output at +0x20, which shares the
         * same defs context so pointers match). Actually the full 0x30 is
         * deterministic from defs+meta. */
        cmp_buf("idd", ov, oc, sizeof ov, (u32)t);
    }
    /* NULL defs */
    {
        u8 ov[0x40], oc[0x40];
        memset(ov, 0xA5, sizeof ov); memset(oc, 0xA5, sizeof oc);
        uint32_t rv = v(NULL, 0, ov);
        uint32_t rc = cr_image_data_dump(NULL, 0, oc);
        if (rv != rc) mismatch("idd-null", 0, rv, rc);
        cmp_buf("idd-null", ov, oc, sizeof ov, 0);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_image_data_dump\n");
}

static void test_pixel_buf_setup(void)
{
    typedef uint32_t (WINAPI *v_u_puii)(const void *, uint32_t, int, int);
    v_u_puii v = (v_u_puii)fn_at(RVA(0x18003d840));
    begin("cr_pixel_buf_setup");
    int bad = g_fail;
    static u8 defs[0x10 + 22 * 8];
    static u8 objs[22][0x20];
    for (int t = 0; t < 8000; t++) {
        memset(defs, 0, sizeof defs);
        for (int i = 0; i < 22; i++) {
            u32 r = rnd() % 3u;
            if (r == 0) continue;
            memset(objs[i], 0, sizeof objs[i]);
            *(int *)(objs[i] + 8) = (r == 1) ? 0 : (int)rnd();
            *(u64 *)(defs + 0x10 + (size_t)i * 8) = (u64)(uintptr_t)objs[i];
        }
        u32 idx = rnd() % 26u;
        int rows = (int)(rnd() % 30u) + 1;
        int cols = (int)(rnd() % 30u) + 1;
        uint32_t rv = v(defs, idx, rows, cols);
        uint32_t rc = cr_pixel_buf_setup(defs, idx, rows, cols);
        if (rv != rc) mismatch("pbs-ret", idx, rv, rc);
    }
    {
        uint32_t rv = v(NULL, 0, 4, 4);
        uint32_t rc = cr_pixel_buf_setup(NULL, 0, 4, 4);
        if (rv != rc) mismatch("pbs-null", 0, rv, rc);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_pixel_buf_setup\n");
}

/* ---- batch 66: image-set descriptor constructor (0x180013340) ----------- *
 * Builds a defs table whose 22 slots point at random-class metadata buffers
 * (metadata / debug / pixels / NULL), then runs the constructor on both the
 * vendor and clean implementations.  The meta buffers are *shared* between the
 * two calls (so dp pointers compare equal), and are snapshotted/restored
 * around each call so both see the identical pristine input; the post-call
 * meta state is also compared (it captures the pixel-buffer side effects).
 * Output slots 0..6 and 0xe hold freshly-allocated blocks (compared by
 * content); the remaining slots hold dp pointers into the shared meta table
 * (compared by value). */
static void test_obj_init_13340(void)
{
    typedef uint32_t (WINAPI *v_u_ppi)(const void *, void *, int);
    v_u_ppi v = (v_u_ppi)fn_at(RVA(0x180013340));
    v_v_p vsfree = (v_v_p)fn_at(RVA(0x18003bf40));
    begin("cr_obj_init_13340");
    int bad = g_fail;

    static u8 defs[0x10 + 22 * 8];
    static u8 meta[22][0x40];
    static u8 pristine[22][0x40], postv[22][0x40], postc[22][0x40];
    static u8 ov[0x80], oc[0x80];

    /* Block-valued output slots (0x38 bytes each; out[0xe] is 0x18). */
    static const int blocks[] = { 0, 1, 2, 3, 4, 5, 6, 0xe };
    const size_t nblocks = sizeof blocks / sizeof blocks[0];

    for (int t = 0; t < 4000; t++) {
        memset(defs, 0, sizeof defs);
        for (int i = 0; i < 22; i++) {
            int kind = (int)(rnd() % 4u);
            if (kind == 0) continue;                 /* NULL slot */
            memset(meta[i], 0, sizeof meta[i]);
            if (kind == 1)      *(u32 *)meta[i] = 8u + 2u * (rnd() % 8u); /* metadata */
            else if (kind == 2) *(u32 *)meta[i] = 9u + 2u * (rnd() % 8u); /* debug */
            else                *(u32 *)meta[i] = 1u;                     /* pixels */
            *(u32 *)(meta[i] + 4)    = 0x18u + (rnd() % 0x20u); /* capacity */
            /* rows/cols are kept tiny (0..2) on purpose: cr_pixel_buf_setup
             * memmoves rows*2*cols bytes into meta_dp+0x24, and our meta
             * buffers are only 0x40 bytes, so a large geometry would run off
             * the end of the slot.  Keeping it <= 8 keeps the copy in bounds. */
            *(u32 *)(meta[i] + 0x0c) = rnd() % 3u;                /* rows */
            *(u32 *)(meta[i] + 0x10) = rnd() % 3u;                /* cols */
            *(u32 *)(meta[i] + 0x14) = rnd();
            *(u32 *)(meta[i] + 0x18) = rnd();
            *(void **)(defs + 0x10 + (size_t)i * 8) = meta[i];
        }
        int flag = (int)(rnd() % 2u);

        memcpy(pristine, meta, sizeof meta);
        memset(ov, 0xA5, sizeof ov); memset(oc, 0xA5, sizeof oc);

        uint32_t rv = v(defs, ov, flag);
        memcpy(postv, meta, sizeof meta);
        memcpy(meta, pristine, sizeof meta);

        uint32_t rc = cr_obj_init_13340(defs, oc, flag);
        memcpy(postc, meta, sizeof meta);
        memcpy(meta, pristine, sizeof meta);

        if (rv != rc) mismatch("ret", (u32)t, rv, rc);

        /* side effects on the shared meta table must be identical */
        cmp_buf("meta", (const unsigned char *)postv,
                (const unsigned char *)postc, sizeof postv, (u32)t);

        for (int k = 0; k < 16; k++) {
            void *pv = *(void **)(ov + (size_t)k * 8);
            void *pc = *(void **)(oc + (size_t)k * 8);
            u32 in = (u32)t * 16u + (u32)k;
            if ((pv != NULL) != (pc != NULL)) {
                mismatch("null", in, 0, 0);
                continue;
            }
            if (!pv) continue;
            int isblk = 0;
            for (size_t j = 0; j < nblocks; j++)
                if (blocks[j] == k) isblk = 1;
            if (isblk) {
                u32 len = (k == 0xe) ? 0x18u : 0x38u;
                cmp_buf("blk", (const unsigned char *)pv,
                        (const unsigned char *)pc, len, in);
            } else if (pv != pc) {
                mismatch("dp", in, (u32)(uintptr_t)pv, (u32)(uintptr_t)pc);
            }
        }

        /* free the owned blocks (mirroring the vendor's ownership) */
        for (size_t j = 0; j < nblocks; j++) {
            int k = blocks[j];
            vsfree((void **)(ov + (size_t)k * 8));
            cr_sized_free((void **)(oc + (size_t)k * 8));
        }
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_obj_init_13340\n");
}

/* ---- batch 65: object constructor (0x180020aa0) ------------------------ */
static void test_obj_ctor_20aa0(void)
{
    typedef int (WINAPI *v_i_ppppip)(void *, void *, void *, void *, int, const void *);
    v_i_ppppip v = (v_i_ppppip)fn_at(RVA(0x180020aa0));
    v_v_p vsfree = (v_v_p)fn_at(RVA(0x18003bf40));
    begin("cr_obj_ctor_20aa0");
    int bad = g_fail;
    for (int t = 0; t < 8000; t++) {
        static u8 desc[0x30];
        static u8 ov[0x60], oc[0x60];
        static u8 bufv[0x50], bufc[0x50];
        for (size_t i = 0; i < sizeof desc; i++) desc[i] = (u8)rnd();
        u8 sel = (rnd() % 2u) ? 2 : 5;
        desc[0x24] = sel;
        if (sel == 5) {
            *(int32_t *)(desc + 0x14) = (int32_t)(rnd() % 32u) + 1;
            desc[0x25] = (u8)(rnd() % 8u) + 1;
            desc[0x26] = (u8)(rnd() % 8u) + 1;
        } else {
            *(int16_t *)(desc + 0x10) = (int16_t)((rnd() % 32u) + 1);
        }
        void *a3 = (void *)(uintptr_t)(0x1000 + (rnd() & 0xfffu));
        void *a4 = (void *)(uintptr_t)(0x2000 + (rnd() & 0xfffu));
        int a5 = (int)(rnd() % 0x1000u);

        memset(ov, 0xA5, sizeof ov); memset(oc, 0xA5, sizeof oc);
        memset(bufv, 0xA5, sizeof bufv); memset(bufc, 0xA5, sizeof bufc);
        int rv = v(ov, bufv, a3, a4, a5, desc);
        int rc = cr_obj_ctor_20aa0(oc, bufc, a3, a4, a5, desc);
        if (rv != rc) mismatch("ret", (u32)t, (u32)rv, (u32)rc);
        /* scalar fields the function is known to write (4-byte each) */
        uint32_t fv, fc;
        #define CMPFIELD(off) do { \
            fv = *(uint32_t *)(ov + (off)); fc = *(uint32_t *)(oc + (off)); \
            if (fv != fc) mismatch("f" #off, (u32)t, fv, fc); \
        } while (0)
        CMPFIELD(0x30); CMPFIELD(0x34); CMPFIELD(0x38); CMPFIELD(0x3c);
        CMPFIELD(0x40); CMPFIELD(0x48); CMPFIELD(0x4c);
        #undef CMPFIELD
        /* pointer slots: compare nullness only */
        if ((*(void **)(ov + 0x00) != NULL) != (*(void **)(oc + 0x00) != NULL))
            mismatch("p0", (u32)t, 0, 0);
        if ((*(void **)(ov + 0x08) != NULL) != (*(void **)(oc + 0x08) != NULL))
            mismatch("p8", (u32)t, 0, 0);
        if ((*(void **)(ov + 0x10) != NULL) != (*(void **)(oc + 0x10) != NULL))
            mismatch("p10", (u32)t, 0, 0);
        if ((*(void **)(ov + 0x18) != NULL) != (*(void **)(oc + 0x18) != NULL))
            mismatch("p18", (u32)t, 0, 0);
        if ((*(void **)(ov + 0x20) != NULL) != (*(void **)(oc + 0x20) != NULL))
            mismatch("p20", (u32)t, 0, 0);
        if ((*(void **)(ov + 0x28) != NULL) != (*(void **)(oc + 0x28) != NULL))
            mismatch("p28", (u32)t, 0, 0);
        /* case 5: compare the records buffer at +0x00 */
        if (sel == 5 && rv == 0 && *(void **)(ov + 0x00)) {
            int total = (int)desc[0x25] * (int)desc[0x26];
            cmp_buf("records", *(void **)(ov + 0x00), *(void **)(oc + 0x00),
                    (u32)(8u * (uint32_t)total), (u32)t);
            vsfree((void **)(ov + 0x00)); cr_sized_free((void **)(oc + 0x00));
            vsfree((void **)(ov + 0x18)); cr_sized_free((void **)(oc + 0x18));
        }
        if (sel == 2 && rv == 0) {
            if (*(void **)(ov + 0x20)) { vsfree((void **)(ov + 0x20)); cr_sized_free((void **)(oc + 0x20)); }
            if (*(void **)(ov + 0x28)) { vsfree((void **)(ov + 0x28)); cr_sized_free((void **)(oc + 0x28)); }
        }
    }
    /* invalid selector -> 0x69 */
    {
        static u8 desc[0x30];
        for (size_t i = 0; i < sizeof desc; i++) desc[i] = (u8)rnd();
        desc[0x24] = 3;  /* != 2, != 5 */
        static u8 ov[0x60], oc[0x60], bufv[0x50], bufc[0x50];
        memset(ov, 0xA5, sizeof ov); memset(oc, 0xA5, sizeof oc);
        int rv = v(ov, bufv, NULL, NULL, 0, desc);
        int rc = cr_obj_ctor_20aa0(oc, bufc, NULL, NULL, 0, desc);
        if (rv != rc) mismatch("ret-bad", 0, (u32)rv, (u32)rc);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_obj_ctor_20aa0\n");
}

/* ---- batch 66: Gaussian-windowed 2-pass reflect FIR orchestrator -------- */
static void test_gaussian_fir_2pass(void)
{
    typedef int (WINAPI *v_i_ppf)(void *, void *, float);
    v_i_ppf v = (v_i_ppf)fn_at(RVA(0x18002f620));
    begin("cr_gaussian_fir_2pass");
    int bad = g_fail;
    static int16_t outV[256*256], outC[256*256], inV[256*256], inC[256*256];

    for (int t = 0; t < 8000; t++) {
        /* NB: the vendor's plain (unguarded) FIR fast-path overflows its fixed
         * stack scratch for dimensions well above the production max (image is
         * 64x176).  Cap at 176 so we stay inside the range the real callers use
         * and the vendor is guaranteed not to overflow. */
        int W = 16 + (int)(rnd() % 161u);
        int R = 16 + (int)(rnd() % 161u);
        /* force both aligned (W%8==0) and unaligned paths */
        if ((rnd() & 1u) && (W % 8 != 0)) W += (8 - (W % 8));   /* align */
        else if (W % 8 == 0) W += 1;                              /* misalign */
        float sigma = (float)(0.2 + (double)(rnd() % 1000u) / 200.0);
        int n = W * R;

        for (int i = 0; i < n; i++) {
            int16_t s = (int16_t)rnd();
            outV[i] = s; outC[i] = s;
            s = (int16_t)rnd();
            inV[i]  = s; inC[i]  = s;
        }

        static uint8_t a1v[0x20], a1c[0x20], a2v[0x20], a2c[0x20];
        memset(a1v, 0, sizeof a1v); memset(a1c, 0, sizeof a1c);
        memset(a2v, 0, sizeof a2v); memset(a2c, 0, sizeof a2c);

        /* arg2: self-link pointer == (R<<32)|W; data@+8; tail@+0x18 = 0 */
        uint64_t packed = ((uint64_t)(uint32_t)R << 32) | (uint32_t)W;
        *(uint64_t *)(a2v + 0) = packed; *(uint64_t *)(a2v + 0x10) = packed;
        *(uint64_t *)(a2c + 0) = packed; *(uint64_t *)(a2c + 0x10) = packed;
        *(uint64_t *)(a2v + 0x8) = (uintptr_t)inV;  *(uint64_t *)(a2c + 0x8) = (uintptr_t)inC;
        *(uint64_t *)(a2v + 0x18) = 0;              *(uint64_t *)(a2c + 0x18) = 0;

        uint64_t base1 = (uint64_t)(0x1000 + ((rnd() & 0xfffu) << 4));
        *(uint64_t *)(a1v + 0) = base1; *(uint64_t *)(a1v + 0x10) = base1;
        *(uint64_t *)(a1c + 0) = base1; *(uint64_t *)(a1c + 0x10) = base1;
        *(uint64_t *)(a1v + 0x8) = (uintptr_t)outV; *(uint64_t *)(a1c + 0x8) = (uintptr_t)outC;
        *(uint64_t *)(a1v + 0x18) = 0;              *(uint64_t *)(a1c + 0x18) = 0;

        int corrupt = (rnd() % 4u) == 0;
        if (corrupt) {
            *(uint64_t *)(a1v + 0x10) = base1 + 1; *(uint64_t *)(a1c + 0x10) = base1 + 1;
        }

        int rv = v(corrupt ? a1v : a1v, a2v, sigma);
        int rc = cr_gaussian_fir_2pass(corrupt ? a1c : a1c, a2c, sigma);
        if (rv != rc) mismatch("ret", (u32)t, (u32)rv, (u32)rc);
        if (!corrupt) {
            cmp_buf("out", (const unsigned char *)outV, (const unsigned char *)outC, (u32)(n * 2), (u32)t);
            cmp_buf("in",  (const unsigned char *)inV,  (const unsigned char *)inC,  (u32)(n * 2), (u32)t);
        }
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_gaussian_fir_2pass\n");
}

/* ---- batch 66: feature/quality check (0x180048ab0) ----------------------- */
static void test_feature_qualify(void)
{
    /* Microsoft x64 ABI assigns registers by argument POSITION: arg1->rcx/xmm0,
     * arg2->rdx/xmm1, arg3->r8/xmm2, arg4->r9/xmm3.  The vendor reads
     * rcx=p1, xmm1=k, r8=p3, so its real signature is (void*, float, void*). */
    typedef int (WINAPI *v_pfp)(void *, float, void *);
    v_pfp v = (v_pfp)fn_at(RVA(0x180048ab0));
    begin("cr_feature_qualify");
    int bad = g_fail;
    static int16_t srcV[1024], srcC[1024];
    static int16_t c20V[1024], c20C[1024], c38V[1024], c38C[1024];
    static int16_t d30V[1024], d30C[1024], d28V[1024], d28C[1024];

    for (int t = 0; t < 8000; t++) {
        for (int i = 0; i < 1024; i++) {
            int16_t s = (int16_t)(rnd() % 200u);          /* < 0xfa */
            srcV[i] = s; srcC[i] = s;
            int16_t c = (int16_t)(rnd() % 50u);
            c20V[i] = c; c20C[i] = c; c38V[i] = c; c38C[i] = c;
            int16_t d = (int16_t)rnd();
            d30V[i] = d; d30C[i] = d; d28V[i] = d; d28C[i] = d;
        }

        static uint8_t a1v[0x70], a1c[0x70], a3v[0x30], a3c[0x30];
        memset(a1v, 0, sizeof a1v); memset(a1c, 0, sizeof a1c);
        memset(a3v, 0, sizeof a3v); memset(a3c, 0, sizeof a3c);

        int a60 = (int)(rnd() % 32u) + 1;
        int a64 = (int)(rnd() % 32u) + 1;
        int f40 = (int)(rnd() % 180u) + 21;     /* > 20; odd->pathA even->pathB */
        float k = (float)(rnd() % 1000u) / 50.0f;
        uint8_t flag0 = (uint8_t)(rnd() & 1u);

        *(int *)(a1v + 0x40) = f40; *(int *)(a1c + 0x40) = f40;
        *(int *)(a1v + 0x60) = a60; *(int *)(a1c + 0x60) = a60;
        *(int *)(a1v + 0x64) = a64; *(int *)(a1c + 0x64) = a64;
        *(uint8_t *)(a1v + 8) = flag0; *(uint8_t *)(a1c + 8) = flag0;
        *(uint64_t *)(a1v + 0x10) = (uint64_t)srcV; *(uint64_t *)(a1c + 0x10) = (uint64_t)srcC;
        *(uint64_t *)(a1v + 0x20) = (uint64_t)d30V; *(uint64_t *)(a1c + 0x20) = (uint64_t)d30C;
        *(uint64_t *)(a1v + 0x28) = (uint64_t)d28V; *(uint64_t *)(a1c + 0x28) = (uint64_t)d28C;
        *(uint64_t *)(a1v + 0x30) = (uint64_t)c20V; *(uint64_t *)(a1c + 0x30) = (uint64_t)c20C;
        *(uint64_t *)(a1v + 0x38) = (uint64_t)c38V; *(uint64_t *)(a1c + 0x38) = (uint64_t)c38C;

        int my = (int)(rnd() % 3u), mx = (int)(rnd() % 3u);
        float thr = (float)(rnd() % 100u) / 7.0f;
        int16_t lim = (int16_t)(int)(rnd() % 400u);   /* single int16 limit value */
        *(int *)(a3v + 0x10) = my; *(int *)(a3c + 0x10) = my;
        *(int *)(a3v + 0x14) = mx; *(int *)(a3c + 0x14) = mx;
        *(int16_t *)(a3v + 0x24) = lim; *(int16_t *)(a3c + 0x24) = lim;
        *(float *)(a3v + 0x28) = thr; *(float *)(a3c + 0x28) = thr;

        int rv = v(a1v, k, a3v);
        int rc = cr_feature_qualify(a1c, a3c, k);
        if (rv != rc) mismatch("ret", (u32)t, (u32)rv, (u32)rc);
        if (a1v[8] != a1c[8]) mismatch("flag", (u32)t, a1v[8], a1c[8]);
        cmp_buf("src", (const unsigned char *)srcV, (const unsigned char *)srcC, 2048, (u32)t);
        cmp_buf("c20", (const unsigned char *)c20V, (const unsigned char *)c20C, 2048, (u32)t);
        cmp_buf("c38", (const unsigned char *)c38V, (const unsigned char *)c38C, 2048, (u32)t);
        cmp_buf("d30", (const unsigned char *)d30V, (const unsigned char *)d30C, 2048, (u32)t);
        cmp_buf("d28", (const unsigned char *)d28V, (const unsigned char *)d28C, 2048, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_feature_qualify\n");
}

/* ---- batch 67: image/scan object-graph initialiser (0x180017ca0) -------- */
static void setup_p2_17ca0(u8 *p2, u8 *img, u32 *bm, int16_t *ns,
                           int w, int h, int bw, int tag, int p78,
                           int n, int src_offx)
{
    memset(p2, 0x5A, 0x90);
    *(int *)(p2 + 0x00) = tag;
    *(int *)(p2 + 0x10) = w;   *(int *)(p2 + 0x14) = h;      /* src cr_image a,b */
    *(void **)(p2 + 0x18) = img;
    *(int *)(p2 + 0x20) = w;   *(int *)(p2 + 0x24) = h;
    *(int *)(p2 + 0x28) = 0;   *(int *)(p2 + 0x2c) = 0;
    *(int *)(p2 + 0x50) = bw;  *(int *)(p2 + 0x54) = h;      /* bmp cr_image a,b */
    *(void **)(p2 + 0x58) = bm;
    *(int *)(p2 + 0x60) = bw;  *(int *)(p2 + 0x64) = h;
    *(int *)(p2 + 0x68) = src_offx;  *(int *)(p2 + 0x6c) = 0;
    *(int *)(p2 + 0x78) = p78;
    *(int16_t *)(p2 + 0x80) = (int16_t)n;
    *(void **)(p2 + 0x88) = ns;
}

static void test_obj_init_17ca0(void)
{
    typedef int (WINAPI *v_i_ppi)(void *, void *, int);
    v_i_ppi v = (v_i_ppi)fn_at(RVA(0x180017ca0));
    v_v_p vsfree = (v_v_p)fn_at(RVA(0x18003bf40));
    begin("cr_obj_init_17ca0");
    int bad = g_fail;

    static u8 p1v[0x58], p1c[0x58], p2v[0x90], p2c[0x90];
    static u8 imgV[4096], imgC[4096];
    static u32 bmV[2048], bmC[2048];
    static int16_t nsV[64], nsC[64];

    for (int t = 0; t < 4000; t++) {
        int mode = (int)(rnd() % 2u);
        int w = (int)(rnd() % 24u) + 1;
        int h = (int)(rnd() % 4u) + 1;
        int n = (int)(rnd() % 16u);
        int bw = (w + 0x1f) & ~0x1f;
        int tag = (int)(rnd() % 0x10000u) + 1;
        int p78 = (int)(rnd() % 0x1000u);
        int sox = (int)(rnd() % 32u);

        for (size_t i = 0; i < sizeof imgV; i++) { u8 x = (u8)rnd(); imgV[i] = x; imgC[i] = x; }
        for (size_t i = 0; i < 2048; i++) { u32 x = rnd(); bmV[i] = x; bmC[i] = x; }
        for (int i = 0; i < 64; i++) { int16_t x = (int16_t)rnd(); nsV[i] = x; nsC[i] = x; }

        memset(p1v, 0xA5, sizeof p1v); memset(p1c, 0xA5, sizeof p1c);
        setup_p2_17ca0(p2v, imgV, bmV, nsV, w, h, bw, tag, p78, n, sox);
        setup_p2_17ca0(p2c, imgC, bmC, nsC, w, h, bw, tag, p78, n, sox);

        int rv = v(p1v, p2v, mode);
        int rc = cr_obj_init_17ca0(p1c, p2c, mode);
        if (rv != rc) mismatch("ret", (u32)t, (u32)rv, (u32)rc);

        /* scalars */
        if (*(int *)(p1v + 0x40) != *(int *)(p1c + 0x40))
            mismatch("f40", (u32)t, *(u32 *)(p1v + 0x40), *(u32 *)(p1c + 0x40));
        if (*(int16_t *)(p1v + 0x44) != *(int16_t *)(p1c + 0x44))
            mismatch("f44", (u32)t, (u32)*(int16_t *)(p1v + 0x44),
                     (u32)*(int16_t *)(p1c + 0x44));
        if (*(int *)(p1v + 0x50) != *(int *)(p1c + 0x50))
            mismatch("f50", (u32)t, *(u32 *)(p1v + 0x50), *(u32 *)(p1c + 0x50));
        /* image #1 descriptor +0..0x1c, image #2 +0x20..0x3c.
         * Skip BOTH halves of each `data` pointer (+8/+0xc and +0x28/+0x2c):
         * the two heaps live at different addresses, so comparing the high 32
         * bits of the pointers is meaningless and ASLR-dependent (it used to
         * make this test flake when the two arenas straddled a 4 GiB
         * boundary). */
        for (int off = 0; off < 0x40; off += 4) {
            if (off == 8 || off == 0xc || off == 0x28 || off == 0x2c)
                continue;   /* pointers compared below */
            u32 a = *(u32 *)(p1v + off), b = *(u32 *)(p1c + off);
            if (a != b) mismatch("img", (u32)t, a, b);
        }
        /* pointer nullness */
        if ((*(void **)(p1v + 8) != NULL) != (*(void **)(p1c + 8) != NULL))
            mismatch("p8", (u32)t, 0, 0);
        if ((*(void **)(p1v + 0x28) != NULL) != (*(void **)(p1c + 0x28) != NULL))
            mismatch("p28", (u32)t, 0, 0);
        if ((*(void **)(p1v + 0x48) != NULL) != (*(void **)(p1c + 0x48) != NULL))
            mismatch("p48", (u32)t, 0, 0);

        if (rv == 0) {
            /* image #1 data (allocated only in mode!=1) */
            if (mode != 1 && *(void **)(p1v + 8) && *(void **)(p1c + 8))
                cmp_buf("img1", *(void **)(p1v + 8), *(void **)(p1c + 8),
                        (u32)(w * h), (u32)t);
            /* packed bitmap data */
            if (*(void **)(p1v + 0x28) && *(void **)(p1c + 0x28))
                cmp_buf("bmp", *(void **)(p1v + 0x28), *(void **)(p1c + 0x28),
                        (u32)((bw >> 5) * h * 4), (u32)t);
            /* helper fields + int16 payload */
            u8 *hv = *(u8 **)(p1v + 0x48), *hc = *(u8 **)(p1c + 0x48);
            if (hv && hc) {
                if (*(int16_t *)(hv + 0x40) != *(int16_t *)(hc + 0x40))
                    mismatch("hn", (u32)t, (u32)*(int16_t *)(hv + 0x40),
                             (u32)*(int16_t *)(hc + 0x40));
                if (n > 0 && *(void **)(hv + 0x48) && *(void **)(hc + 0x48))
                    cmp_buf("hbuf", *(void **)(hv + 0x48), *(void **)(hc + 0x48),
                            (u32)(2 * n), (u32)t);
            }
        }

        /* free, mirroring the object's ownership */
        if (rv == 0) {
            u8 *hv = *(u8 **)(p1v + 0x48), *hc = *(u8 **)(p1c + 0x48);
            if (hv && n > 0 && *(void **)(hv + 0x48)) {
                vsfree((void **)(hv + 0x48)); cr_sized_free((void **)(hc + 0x48));
            }
            if (mode != 1) { vsfree((void **)(p1v + 8)); cr_sized_free((void **)(p1c + 8)); }
            vsfree((void **)(p1v + 0x28)); cr_sized_free((void **)(p1c + 0x28));
            vsfree((void **)(p1v + 0x48)); cr_sized_free((void **)(p1c + 0x48));
        }
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_obj_init_17ca0\n");
}

/* ---- batch 67b: three-image gaussian/derivative dispatcher -------------- */
static void mk_img2(u8 *d, int16_t *data, int w, int h)
{
    memset(d, 0, 0x20);
    *(int *)(d + 0x00) = w;
    *(int *)(d + 0x04) = h;
    *(void **)(d + 0x08) = data;
    *(int *)(d + 0x10) = w;
    *(int *)(d + 0x14) = h;
}

static void test_gauss_deriv_3img(void)
{
    typedef int (WINAPI *v_i_pppf)(void *, void *, void *, float);
    v_i_pppf v = (v_i_pppf)fn_at(RVA(0x18003eb00));
    begin("cr_gauss_deriv_3img");
    int bad = g_fail;

    static int16_t d1v[4096], d1c[4096], d2v[4096], d2c[4096],
                   d3v[4096], d3c[4096];
    static u8 i1v[0x20], i1c[0x20], i2v[0x20], i2c[0x20], i3v[0x20], i3c[0x20];

    for (int t = 0; t < 3000; t++) {
        int w = 16 + (int)(rnd() % 3u) * 8 + (int)(rnd() & 1u);  /* 16..33 */
        int h = 16 + (int)(rnd() % 17u);                         /* 16..32 */
        float sigma = (float)(rnd() % 220u) / 100.0f;            /* 0..2.19 */

        for (int i = 0; i < w * h; i++) {
            int16_t x = (int16_t)rnd();
            d1v[i] = x; d1c[i] = x; d2v[i] = x; d2c[i] = x;
            d3v[i] = x; d3c[i] = x;
        }
        mk_img2(i1v, d1v, w, h); mk_img2(i1c, d1c, w, h);
        mk_img2(i2v, d2v, w, h); mk_img2(i2c, d2c, w, h);
        mk_img2(i3v, d3v, w, h); mk_img2(i3c, d3c, w, h);

        int rv = v(i1v, i2v, i3v, sigma);
        int rc = cr_gauss_deriv_3img(i1c, i2c, i3c, sigma);
        if (rv != rc) mismatch("ret", (u32)t, (u32)rv, (u32)rc);
        cmp_buf("d1", (const unsigned char *)d1v, (const unsigned char *)d1c,
                (u32)(w * h * 2), (u32)t);
        cmp_buf("d2", (const unsigned char *)d2v, (const unsigned char *)d2c,
                (u32)(w * h * 2), (u32)t);
    }

    /* corrupted descriptors must yield the 0x69 guard in both implementations */
    for (int c = 0; c < 3; c++) {
        static int16_t dd[1024];
        for (int i = 0; i < 1024; i++) dd[i] = (int16_t)rnd();
        u8 a[0x20], b[0x20], d[0x20], a2[0x20], b2[0x20], d2[0x20];
        mk_img2(a, dd, 24, 24); mk_img2(b, dd, 24, 24); mk_img2(d, dd, 24, 24);
        memcpy(a2, a, 0x20); memcpy(b2, b, 0x20); memcpy(d2, d, 0x20);
        if (c == 0) { *(int *)(a + 0x10) = 25; *(int *)(a2 + 0x10) = 25; }  /* a != w */
        if (c == 1) { *(int *)(b + 0x18) = 3;  *(int *)(b2 + 0x18) = 3;  }  /* offx != 0 */
        if (c == 2) { *(int *)(d + 0x00) = 0;  *(int *)(d2 + 0x00) = 0;  }  /* tag != w */
        int rv = v(a, b, d, 1.5f);
        int rc = cr_gauss_deriv_3img(a2, b2, d2, 1.5f);
        if (rv != rc) mismatch("ret-bad", (u32)c, (u32)rv, (u32)rc);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_gauss_deriv_3img\n");
}

/* ---- batch 68: Q15 bilinear warp of an int16 image ---------------------- */
static void mk_image(unsigned char *d, void *data, int stride, int w, int h,
                     int offx, int offy);
static void *v_sized_alloc(v_i_ppz vmalloc, size_t S, int sz);
static void *c_sized_alloc(size_t S, int sz);
static void test_warp_bilinear_q15(void)
{
    typedef void (WINAPI *v_v_ppp)(void *, void *, const float *);
    v_v_ppp v = (v_v_ppp)fn_at(RVA(0x18001fd10));
    begin("cr_warp_bilinear_q15");
    int bad = g_fail;

    static int16_t sv[4096], dv[4096], dc[4096];
    static u8 sd[0x20], ddv[0x20], ddc[0x20];

    for (int t = 0; t < 4000; t++) {
        int sw = 16 + (int)(rnd() % 17u);        /* 16..32 */
        int sh = 16 + (int)(rnd() % 17u);
        int dw = 16 + (int)(rnd() % 17u);
        int dh = 16 + (int)(rnd() % 17u);
        int offx = (t & 1) ? (int)(rnd() % 3u) : 0;
        int offy = (t & 1) ? (int)(rnd() % 3u) : 0;

        for (int i = 0; i < 4096; i++) sv[i] = (int16_t)rnd();
        for (int i = 0; i < 4096; i++) { dv[i] = 0x5A5A; dc[i] = 0x5A5A; }

        float coef[6];
        for (int i = 0; i < 6; i++)
            coef[i] = (float)((int)(rnd() % 2001u) - 1000) / 100.0f;  /* -10..10 */

        mk_image(sd,  sv,  sw, sw, sh, 0, 0);
        mk_image(ddv, dv, dw, dw, dh, offx, offy);
        mk_image(ddc, dc, dw, dw, dh, offx, offy);

        v(ddv, sd, coef);
        cr_warp_bilinear_q15((cr_image *)ddc, (const cr_image *)sd, coef);

        cmp_buf("dst", (const unsigned char *)dv, (const unsigned char *)dc,
                (u32)(dw * dh * 2), (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_warp_bilinear_q15\n");
}

/* ---- batch 68: table-driven CORDIC angle --------------------------------- */
static void test_cordic_atan_q15(void)
{
    typedef void (WINAPI *v_v_pppii)(int16_t *, const int16_t *, const int16_t *,
                                     int, int);
    v_v_pppii v = (v_v_pppii)fn_at(RVA(0x18002ba80));
    begin("cr_cordic_atan_q15");
    int bad = g_fail;

    static int16_t av[600], bv[600], ov[600], oc[600];

    for (int t = 0; t < 3000; t++) {
        int n = 1 + (int)(rnd() % 300u);
        for (int i = 0; i < n; i++) {
            /* mix random values with the -32768 / 0 / +-1 edge cases */
            uint32_t r = rnd();
            int16_t val;
            if ((r & 15u) == 0)      val = (int16_t)0x8000;
            else if ((r & 15u) == 1) val = (int16_t)((int)(rnd() % 5u) - 2);
            else                     val = (int16_t)rnd();
            av[i] = val;
            bv[i] = ((r & 15u) == 0) ? (int16_t)0x8000 : (int16_t)rnd();
        }
        int tsel = (int)(rnd() % 6u);
        for (int i = 0; i < n; i++) { ov[i] = 0x7; oc[i] = 0x7; }

        v(ov, bv, av, n, tsel);
        cr_cordic_atan_q15(oc, bv, av, n, tsel);

        cmp_buf("out", (const unsigned char *)ov, (const unsigned char *)oc,
                (u32)(n * 2), (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_cordic_atan_q15\n");
}

/* ---- batch 68: three-output gaussian-derivative triple ------------------- */
static void test_gauss_deriv_triple(void)
{
    typedef int (WINAPI *v_i_ppppf)(void *, void *, void *, void *, float);
    v_i_ppppf v = (v_i_ppppf)fn_at(RVA(0x18002f770));
    begin("cr_gauss_deriv_triple");
    int bad = g_fail;

    static int16_t src[4096], o1v[4096], o2v[4096], o3v[4096],
                   o1c[4096], o2c[4096], o3c[4096];
    static u8 d4[0x20], d1v[0x20], d2v[0x20], d3v[0x20],
              d1c[0x20], d2c[0x20], d3c[0x20];

    for (int t = 0; t < 2000; t++) {
        int   w = 16 + (int)(rnd() % 33u);       /* 16..48 */
        int   h = 16 + (int)(rnd() % 33u);
        float sigma = (float)(rnd() % 220u) / 100.0f;

        for (int i = 0; i < w * h; i++) src[i] = (int16_t)rnd();
        for (int i = 0; i < 4096; i++)
            o1v[i] = o1c[i] = o2v[i] = o2c[i] = o3v[i] = o3c[i] = 0x5A5A;

        mk_image(d4,  src, w, w, h, 0, 0);
        mk_image(d1v, o1v, w, w, h, 0, 0);
        mk_image(d2v, o2v, w, w, h, 0, 0);
        mk_image(d3v, o3v, w, w, h, 0, 0);
        mk_image(d1c, o1c, w, w, h, 0, 0);
        mk_image(d2c, o2c, w, w, h, 0, 0);
        mk_image(d3c, o3c, w, w, h, 0, 0);

        int rv = v(d1v, d2v, d3v, d4, sigma);
        int rc = cr_gauss_deriv_triple(d1c, d2c, d3c, d4, sigma);
        if (rv != rc) mismatch("ret", (u32)t, (u32)rv, (u32)rc);
        cmp_buf("o1", (const unsigned char *)o1v, (const unsigned char *)o1c,
                (u32)(w * h * 2), (u32)t);
        cmp_buf("o2", (const unsigned char *)o2v, (const unsigned char *)o2c,
                (u32)(w * h * 2), (u32)t);
        cmp_buf("o3", (const unsigned char *)o3v, (const unsigned char *)o3c,
                (u32)(w * h * 2), (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_gauss_deriv_triple\n");
}

/* ---- batch 61: validated 3-output Gaussian-derivative triple ------------- */
static void test_gauss_deriv_triple_guarded(void)
{
    typedef int (WINAPI *v_i_ppppf)(void *, void *, void *, void *, float);
    v_i_ppppf v = (v_i_ppppf)fn_at(RVA(0x180030070));
    begin("cr_gauss_deriv_triple_guarded");
    int bad = g_fail;

    static int16_t src[4096], o1v[4096], o2v[4096], o3v[4096],
                   o1c[4096], o2c[4096], o3c[4096];
    static u8 d4[0x20], d1v[0x20], d2v[0x20], d3v[0x20],
              d1c[0x20], d2c[0x20], d3c[0x20];

    for (int t = 0; t < 3000; t++) {
        /* even t: 8-aligned width (manual path); odd t: misaligned (delegate) */
        int   w = 16 + (int)(rnd() % 5u) * 8;                 /* 16..48 */
        if (t & 1)
            w += (int)(rnd() % 7u) + 1;                       /* 17..55 */
        int   h = 16 + (int)(rnd() % 33u);                    /* 16..48 */
        float sigma = (float)(rnd() % 220u) / 100.0f;         /* 0..2.19 */

        for (int i = 0; i < w * h; i++) src[i] = (int16_t)rnd();
        for (int i = 0; i < 4096; i++)
            o1v[i] = o1c[i] = o2v[i] = o2c[i] = o3v[i] = o3c[i] = 0x5A5A;

        mk_img2(d4,  src, w, h);
        mk_img2(d1v, o1v, w, h); mk_img2(d2v, o2v, w, h); mk_img2(d3v, o3v, w, h);
        mk_img2(d1c, o1c, w, h); mk_img2(d2c, o2c, w, h); mk_img2(d3c, o3c, w, h);

        int rv = v(d1v, d2v, d3v, d4, sigma);
        int rc = cr_gauss_deriv_triple_guarded(d1c, d2c, d3c, d4, sigma);
        if (rv != rc) mismatch("ret", (u32)t, (u32)rv, (u32)rc);
        cmp_buf("o1", (const unsigned char *)o1v, (const unsigned char *)o1c,
                (u32)(w * h * 2), (u32)t);
        cmp_buf("o2", (const unsigned char *)o2v, (const unsigned char *)o2c,
                (u32)(w * h * 2), (u32)t);
        cmp_buf("o3", (const unsigned char *)o3v, (const unsigned char *)o3c,
                (u32)(w * h * 2), (u32)t);
    }

    /* each corrupted descriptor must yield the 0x69 guard in both impls */
    for (int c = 0; c < 4; c++) {
        static int16_t dd[1024];
        for (int i = 0; i < 1024; i++) dd[i] = (int16_t)rnd();
        u8 a[0x20], b[0x20], e[0x20], d[0x20];
        u8 a2[0x20], b2[0x20], e2[0x20], d2[0x20];
        mk_img2(a, dd, 24, 24); mk_img2(b, dd, 24, 24);
        mk_img2(e, dd, 24, 24); mk_img2(d, dd, 24, 24);
        memcpy(a2, a, 0x20); memcpy(b2, b, 0x20);
        memcpy(e2, e, 0x20); memcpy(d2, d, 0x20);
        if (c == 0) { *(int *)(a + 0x10) = 25; *(int *)(a2 + 0x10) = 25; }
        if (c == 1) { *(int *)(b + 0x18) = 3;  *(int *)(b2 + 0x18) = 3;  }
        if (c == 2) { *(int *)(e + 0x00) = 0;  *(int *)(e2 + 0x00) = 0;  }
        if (c == 3) { *(int *)(d + 0x00) = 0;  *(int *)(d2 + 0x00) = 0;  }
        int rv = v(a, b, e, d, 1.5f);
        int rc = cr_gauss_deriv_triple_guarded(a2, b2, e2, d2, 1.5f);
        if (rv != rc) mismatch("ret-bad", (u32)c, (u32)rv, (u32)rc);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_gauss_deriv_triple_guarded\n");
}

/* ---- batch 72c: coefficient-plane Gaussian-derivative triple (0x18002d550) */
static void test_gauss_deriv_triple_coef(void)
{
    typedef uint64_t (WINAPI *fn_t)(const void *, const void *, const void *,
                                    const void *, float);
    fn_t v = (fn_t)fn_at(RVA(0x18002d550));
    begin("cr_gauss_deriv_triple_coef");
    int bad = g_fail;

    static int16_t src[4096], o1v[4096], o2v[4096], o3v[4096],
                   o1c[4096], o2c[4096], o3c[4096];
    static u8 d4[0x20], d1v[0x20], d2v[0x20], d3v[0x20],
              d1c[0x20], d2c[0x20], d3c[0x20];

    for (int t = 0; t < 3000; t++) {
        /* even t: 8-aligned W (guarded path); odd t: any W (plain path) */
        int   w = (t & 1) ? (16 + (int)(rnd() % 33u))
                          : (16 + (int)(rnd() % 5u) * 8);   /* 16..48 */
        int   h = 16 + (int)(rnd() % 33u);                  /* 16..48 */
        float sigma = (float)(rnd() % 220u) / 100.0f;       /* 0..2.19 */

        for (int i = 0; i < w * h; i++) src[i] = (int16_t)rnd();
        for (int i = 0; i < 4096; i++)
            o1v[i] = o1c[i] = o2v[i] = o2c[i] = o3v[i] = o3c[i] = 0x5A5A;

        mk_img2(d4,  src, w, h);
        mk_img2(d1v, o1v, w, h); mk_img2(d2v, o2v, w, h); mk_img2(d3v, o3v, w, h);
        mk_img2(d1c, o1c, w, h); mk_img2(d2c, o2c, w, h); mk_img2(d3c, o3c, w, h);

        uint64_t rv = v(d1v, d2v, d3v, d4, sigma);
        uint64_t rc = cr_gauss_deriv_triple_coef(d1c, d2c, d3c, d4, sigma);
        if ((int)rv != (int)rc) mismatch("ret", (u32)t, (u32)rv, (u32)rc);
        cmp_buf("o1", (const unsigned char *)o1v, (const unsigned char *)o1c, (u32)(w * h * 2), (u32)t);
        cmp_buf("o2", (const unsigned char *)o2v, (const unsigned char *)o2c, (u32)(w * h * 2), (u32)t);
        cmp_buf("o3", (const unsigned char *)o3v, (const unsigned char *)o3c, (u32)(w * h * 2), (u32)t);
    }

    /* each corrupted descriptor must yield the 0x69 guard in both impls */
    for (int c = 0; c < 4; c++) {
        static int16_t dd[4096];
        for (int i = 0; i < 4096; i++) dd[i] = (int16_t)rnd();
        u8 a[0x20], b[0x20], e[0x20], d[0x20];
        u8 a2[0x20], b2[0x20], e2[0x20], d2[0x20];
        mk_img2(a, dd, 24, 24); mk_img2(b, dd, 24, 24);
        mk_img2(e, dd, 24, 24); mk_img2(d, dd, 24, 24);
        memcpy(a2, a, 0x20); memcpy(b2, b, 0x20);
        memcpy(e2, e, 0x20); memcpy(d2, d, 0x20);
        if (c == 0) { *(int *)(a + 0x10) = 25; *(int *)(a2 + 0x10) = 25; }
        if (c == 1) { *(int *)(b + 0x18) = 3;  *(int *)(b2 + 0x18) = 3;  }
        if (c == 2) { *(int *)(e + 0x00) = 0;  *(int *)(e2 + 0x00) = 0;  }
        if (c == 3) { *(int *)(d + 0x00) = 0;  *(int *)(d2 + 0x00) = 0;  }
        uint64_t rv = v(a, b, e, d, 1.5f);
        uint64_t rc = cr_gauss_deriv_triple_coef(a2, b2, e2, d2, 1.5f);
        if ((int)rv != (int)rc) mismatch("ret-bad", (u32)c, (u32)rv, (u32)rc);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_gauss_deriv_triple_coef\n");
}

/* ---- batch 61: structure-tensor anisotropy image ------------------------- */
static void test_struct_tensor_aniso(void)
{
    typedef int (WINAPI *v_i_pp)(void *, void *);
    v_i_pp v = (v_i_pp)fn_at(RVA(0x1800331f0));
    begin("cr_struct_tensor_aniso");
    int bad = g_fail;

    static int16_t srcv[4096], srcc[4096], dstv[4096], dstc[4096];
    static u8 sv[0x20], sc[0x20], dv[0x20], dc[0x20];

    for (int t = 0; t < 2000; t++) {
        int w = 16 + (int)(rnd() % 33u);              /* 16..48 */
        int h = 16 + (int)(rnd() % 33u);              /* 16..48 */

        for (int i = 0; i < w * h; i++) {
            int16_t x = (int16_t)rnd();
            srcv[i] = x; srcc[i] = x;
        }
        for (int i = 0; i < 4096; i++)
            dstv[i] = dstc[i] = (int16_t)0x5A5A;

        mk_img2(sv, srcv, w, h);
        mk_img2(sc, srcc, w, h);
        mk_img2(dv, dstv, w, h);
        mk_img2(dc, dstc, w, h);

        int rv = v(dv, sv);
        int rc = cr_struct_tensor_aniso((cr_image *)dc, (const cr_image *)sc);
        if (rv != rc) mismatch("ret", (u32)t, (u32)rv, (u32)rc);
        cmp_buf("dst", (const unsigned char *)dstv, (const unsigned char *)dstc,
                (u32)(w * h * 2), (u32)t);
    }

    /* non-canonical src must trip the triple's 0x69 guard in both impls */
    {
        static int16_t dd[2048];
        u8 a[0x20], b[0x20], a2[0x20], b2[0x20];
        for (int i = 0; i < 2048; i++) dd[i] = (int16_t)rnd();
        mk_img2(a, dd, 24, 24); mk_img2(b, dd, 24, 24);
        memcpy(a2, a, 0x20); memcpy(b2, b, 0x20);
        *(int *)(b + 0x18) = 5; *(int *)(b2 + 0x18) = 5;   /* offx != 0 */
        int rv = v(a, b);
        int rc = cr_struct_tensor_aniso((cr_image *)a2, (const cr_image *)b2);
        if (rv != rc) mismatch("ret-bad", 0, (u32)rv, (u32)rc);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_struct_tensor_aniso\n");
}

/* ---- batch 61: flag-gated structure-tensor dispatcher -------------------- */
static void test_struct_tensor_dispatch(void)
{
    typedef int (WINAPI *v_i_ppp)(void *, void *, void *);
    v_i_ppp v = (v_i_ppp)fn_at(RVA(0x18003ced0));
    begin("cr_struct_tensor_dispatch");
    int bad = g_fail;

    static int16_t srcv[4096], srcc[4096], dstv[4096], dstc[4096];
    static u8 sv[0x20], sc[0x20], dv[0x20], dc[0x20];
    static u8 fv[0x40], fc[0x40];

    for (int t = 0; t < 400; t++) {
        int w = 16 + (int)(rnd() % 33u);
        int h = 16 + (int)(rnd() % 33u);
        for (int i = 0; i < w * h; i++) {
            int16_t x = (int16_t)rnd();
            srcv[i] = x; srcc[i] = x;
        }
        for (int i = 0; i < 4096; i++)
            dstv[i] = dstc[i] = (int16_t)0x5A5A;
        mk_img2(sv, srcv, w, h); mk_img2(sc, srcc, w, h);
        mk_img2(dv, dstv, w, h); mk_img2(dc, dstc, w, h);

        u8 flag = (t % 5 == 0) ? 0 : (t % 5 == 1) ? 1 : (u8)rnd();
        memset(fv, 0, sizeof fv); memset(fc, 0, sizeof fc);
        fv[0x3d] = flag; fc[0x3d] = flag;

        int rv = v(dv, sv, fv);
        int rc = cr_struct_tensor_dispatch((cr_image *)dc, (const cr_image *)sc, fc);
        if (rv != rc) mismatch("ret", (u32)t, (u32)rv, (u32)rc);
        cmp_buf("dst", (const unsigned char *)dstv, (const unsigned char *)dstc,
                (u32)(w * h * 2), (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_struct_tensor_dispatch\n");
}

/* ---- batch 61: masked float histogram percentile range (0x18003c7f0) ---- */
static void test_hist_percentiles_f32(void)
{
    typedef int (WINAPI *v_histf)(float *, float *, int *, const void *,
                                  const void *, int, float, float, int);
    v_histf v = (v_histf)fn_at(RVA(0x18003c7f0));
    begin("cr_masked_hist_percentiles_f32");
    int bad = g_fail;

    enum { MAXW = 40, MAXH = 40, NP = MAXW * MAXH };
    static float   pix[NP];
    static uint8_t mbuf[NP];
    static cr_image img, maskimg;

    for (int t = 0; t < 5000; t++) {
        int w = 1 + (int)(rnd() % MAXW);
        int h = 1 + (int)(rnd() % MAXH);
        int total = w * h;
        int mode = (int)(rnd() % 8);

        for (int i = 0; i < total; i++)
            pix[i] = (float)((int)(rnd() % 4001) - 2000) * 0.125f;
        for (int i = 0; i < total; i++)
            mbuf[i] = (uint8_t)rnd();

        if (mode == 1) {                     /* force fmin == fmax */
            float c = (float)((int)(rnd() % 4001) - 2000) * 0.125f;
            for (int i = 0; i < total; i++) pix[i] = c;
        }

        int use_mask = (int)(rnd() % 3) != 0;
        int and_mask = (int)(rnd() % 256);
        if (mode == 2) and_mask = 0;         /* count == 0 when masked */

        float f_lo = (float)(rnd() % 201) / 200.0f;   /* 0.0 .. 1.0 */
        float f_hi = (float)(rnd() % 201) / 200.0f;
        int nbin = 2 + (int)(rnd() % 512);            /* nm1 >= 1 */

        cr_image_set(&img, pix, w, h);
        cr_image_set(&maskimg, mbuf, w, h);
        const cr_image *mp = use_mask ? &maskimg : NULL;

        float lo_v = -1.0f, hi_v = -2.0f;
        float lo_c = -1.0f, hi_c = -2.0f;
        int ct_v = 0x33333333, ct_c = 0x33333333;

        int rv = v(&lo_v, &hi_v, &ct_v, &img, mp, and_mask, f_lo, f_hi, nbin);
        int rc = cr_masked_hist_percentiles_f32(&lo_c, &hi_c, &ct_c, &img, mp,
                                                (uint8_t)and_mask, f_lo, f_hi,
                                                nbin);
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }
        cmp_buf("lo", (const unsigned char *)&lo_v, (const unsigned char *)&lo_c,
                4, (u32)t);
        cmp_buf("hi", (const unsigned char *)&hi_v, (const unsigned char *)&hi_c,
                4, (u32)t);
        if (ct_v != ct_c) mismatch("ct", (u32)t, (u32)ct_v, (u32)ct_c);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_masked_hist_percentiles_f32\n");
}

/* ---- batch 62: float 0..255 percentile stretch (0x180023cb0) ------------- */
static void test_stretch_f32(void)
{
    typedef int (WINAPI *v_strf)(void *, const void *, int, float, float, int);
    v_strf v = (v_strf)fn_at(RVA(0x180023cb0));
    begin("cr_stretch_f32");
    int bad = g_fail;

    enum { MAXW = 32, MAXH = 32, NP = MAXW * MAXH };
    static float   pv[NP], pc[NP];
    static uint8_t mbuf[NP];
    static cr_image iv, ic, mv, mc;

    for (int t = 0; t < 6000; t++) {
        int w = 1 + (int)(rnd() % MAXW);
        int h = 1 + (int)(rnd() % MAXH);
        int total = w * h;
        int mode = (int)(rnd() % 5);                    /* 0..4 incl. 0x69 */
        int and_mask = (int)(rnd() % 256);
        int use_mask = (int)(rnd() % 3) != 0;
        float f_lo = (float)(rnd() % 201) / 200.0f;
        float f_hi = (float)(rnd() % 201) / 200.0f;

        for (int i = 0; i < total; i++) {
            pv[i] = pc[i] = (float)((int)(rnd() % 4001) - 2000) * 0.125f;
            mbuf[i] = (uint8_t)rnd();
        }
        if ((mode == 1 || mode == 2) && (rnd() % 4) == 0) {
            /* constant image -> hi == lo -> the clamp-only branch */
            float c = (float)((int)(rnd() % 4001) - 2000) * 0.125f;
            for (int i = 0; i < total; i++) pv[i] = pc[i] = c;
        }

        cr_image_set(&iv, pv, w, h);
        cr_image_set(&ic, pc, w, h);
        cr_image_set(&mv, mbuf, w, h);
        cr_image_set(&mc, mbuf, w, h);
        const cr_image *mpv = use_mask ? &mv : NULL;
        const cr_image *mpc = use_mask ? &mc : NULL;

        int rv = v(&iv, mpv, and_mask, f_lo, f_hi, mode);
        int rc = cr_stretch_f32(&ic, mpc, and_mask, f_lo, f_hi, mode);
        if (rv != rc) mismatch("ret", (u32)t, (u32)rv, (u32)rc);
        cmp_buf("f32", (const unsigned char *)pv, (const unsigned char *)pc,
                (u32)(total * 4), (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_stretch_f32\n");
}


/* ---- batch 61: Harris-style corner response (0x1800305f0) ---------------- */
static void test_harris_response(void)
{
    typedef int (WINAPI *v_i_ppff)(void *, void *, float, float);
    v_i_ppff v = (v_i_ppff)fn_at(RVA(0x1800305f0));
    begin("cr_harris_response");
    int bad = g_fail;

    static uint8_t sbuf[4096];
    static float   dv[4096], dc[4096];
    static u8 sv[0x20], sc[0x20], dvv[0x20], dcc[0x20];

    for (int t = 0; t < 1500; t++) {
        int w = 16 + (int)(rnd() % 33u);
        /* NOTE: heights must be EVEN.  The vendor's u8->u16 widening
         * (0x1800337e0) walks rows in pairs and its tail fix-up re-writes the
         * penultimate row, so for an ODD height the final row of its internal
         * d[5] buffer is left at whatever the allocator handed back.  That
         * makes the vendor's Harris output for odd heights depend on
         * uninitialised memory, so it cannot be matched bit-for-bit (nor
         * tested deterministically).  Even heights exercise the whole path. */
        int h = 16 + (int)(rnd() % 33u);
        h &= ~1;
        float coef  = (float)(rnd() % 100u) / 1000.0f;          /* 0..0.099 */
        float sigma = 0.72f + (float)(rnd() % 150u) / 100.0f;   /* 0.72..2.21 */

        for (int i = 0; i < w * h; i++) sbuf[i] = (uint8_t)rnd();
        for (int i = 0; i < 4096; i++) dv[i] = dc[i] = 123.25f;

        mk_img2(sv,  (int16_t *)sbuf, w, h);
        mk_img2(sc,  (int16_t *)sbuf, w, h);
        mk_img2(dvv, (int16_t *)dv, w, h);
        mk_img2(dcc, (int16_t *)dc, w, h);

        int rv = v(dvv, sv, coef, sigma);
        int rc = cr_harris_response((cr_image *)dcc, (const cr_image *)sc,
                                    coef, sigma);
        if (rv != rc) mismatch("ret", (u32)t, (u32)rv, (u32)rc);
        cmp_buf("dst", (const unsigned char *)dv, (const unsigned char *)dc,
                (u32)(w * h * 4), (u32)t);
    }

    /* non-canonical src trips the u8->u16 guard in both impls */
    {
        static uint8_t dd[2048];
        u8 a[0x20], b[0x20], a2[0x20], b2[0x20];
        for (int i = 0; i < 2048; i++) dd[i] = (uint8_t)rnd();
        mk_img2(a, (int16_t *)dd, 24, 24); mk_img2(b, (int16_t *)dd, 24, 24);
        memcpy(a2, a, 0x20); memcpy(b2, b, 0x20);
        *(int *)(b + 0x18) = 5; *(int *)(b2 + 0x18) = 5;
        int rv = v(a, b, 0.04f, 1.5f);
        int rc = cr_harris_response((cr_image *)a2, (const cr_image *)b2,
                                    0.04f, 1.5f);
        if (rv != rc) mismatch("ret-bad", 0, (u32)rv, (u32)rc);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_harris_response\n");
}

/* ---- batch 69: Harris response -> masked local-maxima grid (0x180023e70) -- */
struct hmax_state {
    cr_grid_node nodes[64];
    int16_t next[16];
    float   values[16];
    uint8_t coords[32];
    float   values2[16];
    uint8_t coords2[32];
    cr_grid g;
    cr_harris_max_cfg cfg;
};

static void test_harris_local_max_grid(void)
{
    typedef int (WINAPI *v_i_pppp)(void *, const void *, const void *,
                                   const void *);
    v_i_pppp v = (v_i_pppp)fn_at(RVA(0x180023e70));
    begin("cr_harris_local_max_grid");
    int bad = g_fail;

    static uint8_t  sbuf[4096];
    static uint32_t mbits[4096];
    static u8 sv[0x20], sc[0x20], smv[0x20], smc[0x20];

    for (int t = 0; t < 3000; t++) {
        int w = 8 + (int)(rnd() % 24u);            /* 8..31 */
        int h = (8 + (int)(rnd() % 24u)) & ~1;     /* even, 8..30 */
        int offx = (int)(rnd() % 6u);
        int offy = (int)(rnd() % 6u);
        int stride_bits = (2 + (int)(rnd() % 3u)) * 32;   /* 64..128 bits */
        /* border (interior margin) must be >= 1: with c == 0 the vendor scans
         * the whole image and reads one pixel past it on every side (row -1 /
         * row h / col -1 / col w).  The vendor's pooled allocator absorbs that
         * over-read, but our malloc'd buffer does not — ASan flags a
         * heap-buffer-overflow, and the out-of-bounds value can't be matched
         * anyway.  c == 0 is a degenerate margin, so skip it. */
        int border = 1 + (int)(rnd() % 3u);        /* 1..3 */
        float coef  = (float)(rnd() % 100u) / 1000.0f;
        float sigma = 0.72f + (float)(rnd() % 150u) / 100.0f;
        int W = 1 + (int)(rnd() % 6u);
        int H = 1 + (int)(rnd() % 6u);
        int cap = 1 + (int)(rnd() % 8u);
        int cap2 = (int)(rnd() % 17u);
        int divx = 1 + (int)(rnd() % 512u);
        int divy = 1 + (int)(rnd() % 512u);
        int mode = ((int)(rnd() % 4) == 0) ? 2
                 : ((int)(rnd() % 8) == 0) ? 7 : 5;

        for (int i = 0; i < w * h; i++) sbuf[i] = (uint8_t)rnd();
        for (int i = 0; i < 4096; i++) mbits[i] = rnd();

        mk_img2(sv, (int16_t *)sbuf, w, h);
        mk_img2(sc, (int16_t *)sbuf, w, h);
        /* mask bitmap: a = stride in bits, data = mbits, offx/offy origin */
        mk_img2(smv, (int16_t *)mbits, 0, 0);
        *(int *)(smv + 0x00) = stride_bits;
        *(int *)(smv + 0x18) = offx;
        *(int *)(smv + 0x1c) = offy;
        memcpy(smc, smv, 0x20);

        struct hmax_state gv, gc;
        memset(&gv, 0, sizeof gv);
        gv.g.nodes = gv.nodes; gv.g.coords = gv.coords; gv.g.values = gv.values;
        gv.g.next = gv.next; gv.g.coords2 = gv.coords2; gv.g.values2 = gv.values2;
        gv.g.W = W; gv.g.H = H; gv.g.divx = divx; gv.g.divy = divy;
        gv.g.count = 0; gv.g.count2 = 0; gv.g.cap = cap;
        gv.cfg.border = (int8_t)border;
        gv.cfg.cap2 = (int16_t)cap2;
        gv.cfg.coef = coef;
        gv.cfg.sigma = sigma;
        gv.cfg.mode = (uint8_t)mode;
        for (int k = 0; k < W * H; k++) {
            gv.nodes[k].key = 0; gv.nodes[k].head = -1;
            gv.nodes[k].val = (float)(1 + (int)(rnd() % 1000)) * 0.001f;
        }
        for (int k = 0; k < cap; k++) {
            gv.next[k] = -1; gv.values[k] = 0.0f;
            gv.coords[2 * k] = gv.coords[2 * k + 1] = 0;
        }
        for (int k = 0; k < cap2; k++) {
            gv.values2[k] = 0.0f;
            gv.coords2[2 * k] = gv.coords2[2 * k + 1] = 0;
        }
        gc = gv;
        gc.g.nodes = gc.nodes; gc.g.coords = gc.coords; gc.g.values = gc.values;
        gc.g.next = gc.next; gc.g.coords2 = gc.coords2; gc.g.values2 = gc.values2;

        int rv = v(&gv.g, sv, smv, &gv.cfg);
        int rc = cr_harris_local_max_grid(&gc.g, (const cr_image *)sc,
                                          (const cr_image *)smc, &gc.cfg);
        if (rv != rc) mismatch("ret", (u32)t, (u32)rv, (u32)rc);

        size_t nn = sizeof(cr_grid_node) * (size_t)(W * H);
        if (memcmp(gv.nodes, gc.nodes, nn))
            cmp_buf("nodes", (unsigned char *)gv.nodes,
                    (unsigned char *)gc.nodes, nn, (u32)t);
        if (memcmp(gv.values, gc.values, sizeof(float) * (size_t)cap))
            cmp_buf("values", (unsigned char *)gv.values,
                    (unsigned char *)gc.values, sizeof(float) * (size_t)cap,
                    (u32)t);
        if (memcmp(gv.next, gc.next, sizeof(int16_t) * (size_t)cap))
            cmp_buf("next", (unsigned char *)gv.next,
                    (unsigned char *)gc.next, sizeof(int16_t) * (size_t)cap,
                    (u32)t);
        if (memcmp(gv.coords, gc.coords, 2 * (size_t)cap))
            cmp_buf("coords", gv.coords, gc.coords, 2 * (size_t)cap, (u32)t);
        if (memcmp(gv.values2, gc.values2, sizeof(float) * (size_t)cap2))
            cmp_buf("values2", (unsigned char *)gv.values2,
                    (unsigned char *)gc.values2, sizeof(float) * (size_t)cap2,
                    (u32)t);
        if (memcmp(gv.coords2, gc.coords2, 2 * (size_t)cap2))
            cmp_buf("coords2", gv.coords2, gc.coords2, 2 * (size_t)cap2, (u32)t);
        if (gv.g.count != gc.g.count || gv.g.count2 != gc.g.count2)
            mismatch("count", (u64)t, (u32)gv.g.count, (u32)gc.g.count);
    }

    /* negative source width trips the allocator guard in both impls */
    {
        struct hmax_state gv, gc;
        memset(&gv, 0, sizeof gv);
        gv.g.nodes = gv.nodes; gv.g.coords = gv.coords; gv.g.values = gv.values;
        gv.g.next = gv.next; gv.g.coords2 = gv.coords2; gv.g.values2 = gv.values2;
        gv.g.W = 1; gv.g.H = 1; gv.g.divx = 1; gv.g.divy = 1;
        gv.g.cap = 1; gv.nodes[0].key = 0; gv.nodes[0].head = -1;
        gc = gv;
        gc.g.nodes = gc.nodes; gc.g.coords = gc.coords; gc.g.values = gc.values;
        gc.g.next = gc.next; gc.g.coords2 = gc.coords2; gc.g.values2 = gc.values2;
        u8 a[0x20], b[0x20];
        mk_img2(a, (int16_t *)sbuf, -4, 8);
        mk_img2(b, (int16_t *)sbuf, -4, 8);
        mk_img2(smv, (int16_t *)mbits, 0, 0);
        *(int *)(smv + 0x00) = 32;
        int rv = v(&gv.g, a, smv, &gv.cfg);
        int rc = cr_harris_local_max_grid(&gc.g, (const cr_image *)b,
                                          (const cr_image *)smv, &gc.cfg);
        if (rv != rc) mismatch("ret-neg", 0, (u32)rv, (u32)rc);
    }

    if (g_fail == bad) end(); else printf("  FAIL cr_harris_local_max_grid\n");
}

/* ---- batch 69b: Harris response -> masked local min/max grid (0x18000f000) -
 * The min/max twin of the test above: same inputs, same grid comparison, but
 * the routine also accepts strict local minima (value = |response|). */
static void test_harris_local_minmax_grid(void)
{
    typedef int (WINAPI *v_i_pppp)(void *, const void *, const void *,
                                   const void *);
    v_i_pppp v = (v_i_pppp)fn_at(RVA(0x18000f000));
    begin("cr_harris_local_minmax_grid");
    int bad = g_fail;

    static uint8_t  sbuf[4096];
    static uint32_t mbits[4096];
    static u8 sv[0x20], sc[0x20], smv[0x20], smc[0x20];

    for (int t = 0; t < 3000; t++) {
        int w = 8 + (int)(rnd() % 24u);            /* 8..31 */
        int h = (8 + (int)(rnd() % 24u)) & ~1;     /* even, 8..30 */
        int offx = (int)(rnd() % 6u);
        int offy = (int)(rnd() % 6u);
        int stride_bits = (2 + (int)(rnd() % 3u)) * 32;   /* 64..128 bits */
        /* border >= 1 for the same reason as cr_harris_local_max_grid: with
         * c == 0 the vendor scans the whole image and reads one pixel past it
         * on every side, which our malloc'd buffer cannot match. */
        int border = 1 + (int)(rnd() % 3u);        /* 1..3 */
        float coef  = (float)(rnd() % 100u) / 1000.0f;
        float sigma = 0.72f + (float)(rnd() % 150u) / 100.0f;
        int W = 1 + (int)(rnd() % 6u);
        int H = 1 + (int)(rnd() % 6u);
        int cap = 1 + (int)(rnd() % 8u);
        int cap2 = (int)(rnd() % 17u);
        int divx = 1 + (int)(rnd() % 512u);
        int divy = 1 + (int)(rnd() % 512u);
        int mode = ((int)(rnd() % 4) == 0) ? 2
                 : ((int)(rnd() % 8) == 0) ? 7 : 5;

        for (int i = 0; i < w * h; i++) sbuf[i] = (uint8_t)rnd();
        for (int i = 0; i < 4096; i++) mbits[i] = rnd();

        mk_img2(sv, (int16_t *)sbuf, w, h);
        mk_img2(sc, (int16_t *)sbuf, w, h);
        mk_img2(smv, (int16_t *)mbits, 0, 0);
        *(int *)(smv + 0x00) = stride_bits;
        *(int *)(smv + 0x18) = offx;
        *(int *)(smv + 0x1c) = offy;
        memcpy(smc, smv, 0x20);

        struct hmax_state gv, gc;
        memset(&gv, 0, sizeof gv);
        gv.g.nodes = gv.nodes; gv.g.coords = gv.coords; gv.g.values = gv.values;
        gv.g.next = gv.next; gv.g.coords2 = gv.coords2; gv.g.values2 = gv.values2;
        gv.g.W = W; gv.g.H = H; gv.g.divx = divx; gv.g.divy = divy;
        gv.g.count = 0; gv.g.count2 = 0; gv.g.cap = cap;
        gv.cfg.border = (int8_t)border;
        gv.cfg.cap2 = (int16_t)cap2;
        gv.cfg.coef = coef;
        gv.cfg.sigma = sigma;
        gv.cfg.mode = (uint8_t)mode;
        for (int k = 0; k < W * H; k++) {
            gv.nodes[k].key = 0; gv.nodes[k].head = -1;
            gv.nodes[k].val = (float)(1 + (int)(rnd() % 1000)) * 0.001f;
        }
        for (int k = 0; k < cap; k++) {
            gv.next[k] = -1; gv.values[k] = 0.0f;
            gv.coords[2 * k] = gv.coords[2 * k + 1] = 0;
        }
        for (int k = 0; k < cap2; k++) {
            gv.values2[k] = 0.0f;
            gv.coords2[2 * k] = gv.coords2[2 * k + 1] = 0;
        }
        gc = gv;
        gc.g.nodes = gc.nodes; gc.g.coords = gc.coords; gc.g.values = gc.values;
        gc.g.next = gc.next; gc.g.coords2 = gc.coords2; gc.g.values2 = gc.values2;

        int rv = v(&gv.g, sv, smv, &gv.cfg);
        int rc = cr_harris_local_minmax_grid(&gc.g, (const cr_image *)sc,
                                             (const cr_image *)smc, &gc.cfg);
        if (rv != rc) mismatch("ret", (u32)t, (u32)rv, (u32)rc);

        size_t nn = sizeof(cr_grid_node) * (size_t)(W * H);
        if (memcmp(gv.nodes, gc.nodes, nn))
            cmp_buf("nodes", (unsigned char *)gv.nodes,
                    (unsigned char *)gc.nodes, nn, (u32)t);
        if (memcmp(gv.values, gc.values, sizeof(float) * (size_t)cap))
            cmp_buf("values", (unsigned char *)gv.values,
                    (unsigned char *)gc.values, sizeof(float) * (size_t)cap,
                    (u32)t);
        if (memcmp(gv.next, gc.next, sizeof(int16_t) * (size_t)cap))
            cmp_buf("next", (unsigned char *)gv.next,
                    (unsigned char *)gc.next, sizeof(int16_t) * (size_t)cap,
                    (u32)t);
        if (memcmp(gv.coords, gc.coords, 2 * (size_t)cap))
            cmp_buf("coords", gv.coords, gc.coords, 2 * (size_t)cap, (u32)t);
        if (memcmp(gv.values2, gc.values2, sizeof(float) * (size_t)cap2))
            cmp_buf("values2", (unsigned char *)gv.values2,
                    (unsigned char *)gc.values2, sizeof(float) * (size_t)cap2,
                    (u32)t);
        if (memcmp(gv.coords2, gc.coords2, 2 * (size_t)cap2))
            cmp_buf("coords2", gv.coords2, gc.coords2, 2 * (size_t)cap2, (u32)t);
        if (gv.g.count != gc.g.count || gv.g.count2 != gc.g.count2)
            mismatch("count", (u64)t, (u32)gv.g.count, (u32)gc.g.count);
    }

    /* negative source width trips the allocator guard in both impls */
    {
        struct hmax_state gv, gc;
        memset(&gv, 0, sizeof gv);
        gv.g.nodes = gv.nodes; gv.g.coords = gv.coords; gv.g.values = gv.values;
        gv.g.next = gv.next; gv.g.coords2 = gv.coords2; gv.g.values2 = gv.values2;
        gv.g.W = 1; gv.g.H = 1; gv.g.divx = 1; gv.g.divy = 1;
        gv.g.cap = 1; gv.nodes[0].key = 0; gv.nodes[0].head = -1;
        gc = gv;
        gc.g.nodes = gc.nodes; gc.g.coords = gc.coords; gc.g.values = gc.values;
        gc.g.next = gc.next; gc.g.coords2 = gc.coords2; gc.g.values2 = gc.values2;
        u8 a[0x20], b[0x20];
        mk_img2(a, (int16_t *)sbuf, -4, 8);
        mk_img2(b, (int16_t *)sbuf, -4, 8);
        mk_img2(smv, (int16_t *)mbits, 0, 0);
        *(int *)(smv + 0x00) = 32;
        int rv = v(&gv.g, a, smv, &gv.cfg);
        int rc = cr_harris_local_minmax_grid(&gc.g, (const cr_image *)b,
                                             (const cr_image *)smv, &gc.cfg);
        if (rv != rc) mismatch("ret-neg", 0, (u32)rv, (u32)rc);
    }

    if (g_fail == bad) end(); else printf("  FAIL cr_harris_local_minmax_grid\n");
}

/* ---- batch 68: global bio-context getter --------------------------------- */
static void test_bio_init(void)
{
    typedef void *(WINAPI *v_p_v)(void);
    v_p_v v = (v_p_v)fn_at(RVA(0x180048d40));
    begin("cr_bio_init");
    int bad = g_fail;

    void *rv = v();
    void *rc = cr_bio_init();
    if (rv != rc)
        mismatch("ptr", 0, (u32)(uintptr_t)rv, (u32)(uintptr_t)rc);
    /* and it must be exactly the mapped global plus 8 */
    void *gv = *(void **)((char *)g_base + 0x16f4c8);
    if (rc != (char *)gv + 8)
        mismatch("plus8", 0, (u32)(uintptr_t)((char *)gv + 8),
                 (u32)(uintptr_t)rc);

    if (g_fail == bad) end(); else printf("  FAIL cr_bio_init\n");
}

/* ---- batch 68: bio-context fetch ----------------------------------------- */
static void test_bio_get_ctx(void)
{
    typedef int (WINAPI *v_i_ppw)(void **, unsigned);
    v_i_ppw v = (v_i_ppw)fn_at(RVA(0x180045860));
    begin("cr_bio_get_ctx");
    int bad = g_fail;

    static u8 ctx[0x20];
    void **slot = (void **)(g_base + 0x16f4c8);
    void *saved = *slot;
    *(void **)ctx = (void *)(uintptr_t)0x1111222233334444ULL;
    *(void **)(ctx + 8) = (void *)(uintptr_t)0xAABBCCDDEEFF0011ULL;
    *slot = ctx;

    void *ov = NULL, *oc = NULL;
    int rv = v(&ov, 0);
    int rc = cr_bio_get_ctx(&oc, 0);
    if (rv != rc) mismatch("ret", 0, (u32)rv, (u32)rc);
    if (ov != oc) mismatch("out", 0, (u32)(uintptr_t)ov, (u32)(uintptr_t)oc);

    /* flag != 0 must short-circuit to 1 without touching *out */
    ov = (void *)1; oc = (void *)1;
    rv = v(&ov, 5);
    rc = cr_bio_get_ctx(&oc, 5);
    if (rv != rc) mismatch("ret-nz", 5, (u32)rv, (u32)rc);
    if (ov != (void *)1 || oc != (void *)1)
        mismatch("out-nz", 5, (u32)(uintptr_t)ov, (u32)(uintptr_t)oc);

    *slot = saved;
    if (g_fail == bad) end(); else printf("  FAIL cr_bio_get_ctx\n");
}

/* ---- batch 68: bio-context linked-list lookup ---------------------------- */
static void test_ctx_find_node(void)
{
    typedef int (WINAPI *v_i_ppu)(void **, unsigned);
    v_i_ppu v = (v_i_ppu)fn_at(RVA(0x180016f90));
    begin("cr_ctx_find_node");
    int bad = g_fail;

    static u8 gbuf[0x20];
    static u8 nodes[4][0x100];
    void **slot = (void **)(g_base + 0x16f4c8);
    void *saved = *slot;
    *slot = gbuf;                         /* vendor global */
    *(void **)(gbuf + 8) = nodes[0];      /* ctx = global+8 -> *ctx = head */

    unsigned keys[4] = { 100u, 200u, 300u, 400u };
    for (int i = 0; i < 4; i++) {
        *(uint32_t *)nodes[i] = keys[i];
        *(void **)(nodes[i] + 0xd8) = (i < 3) ? nodes[i + 1] : NULL;
    }

    for (int i = 0; i < 6; i++) {
        unsigned key = (i < 4) ? keys[i] : (i == 4 ? 999u : 0u);
        void *ov = NULL, *oc = NULL;
        int rv = v(&ov, key);
        int rc = cr_ctx_find_node(&oc, key);
        if (rv != rc) mismatch("ret", key, (u32)rv, (u32)rc);
        if (ov != oc) mismatch("out", key, (u32)(uintptr_t)ov, (u32)(uintptr_t)oc);
    }

    /* single-node list, and empty list */
    *(void **)(nodes[0] + 0xd8) = NULL;
    { void *ov = NULL, *oc = NULL;
      int rv = v(&ov, 100u), rc = cr_ctx_find_node(&oc, 100u);
      if (rv != rc) mismatch("ret1", 100u, (u32)rv, (u32)rc);
      if (ov != oc) mismatch("out1", 100u, (u32)(uintptr_t)ov, (u32)(uintptr_t)oc); }
    *(void **)(gbuf + 8) = NULL;
    { void *ov = (void *)7, *oc = (void *)7;
      int rv = v(&ov, 100u), rc = cr_ctx_find_node(&oc, 100u);
      if (rv != rc) mismatch("ret0", 100u, (u32)rv, (u32)rc);
      if (ov != (void *)7 || oc != (void *)7)
          mismatch("out0", 100u, (u32)(uintptr_t)ov, (u32)(uintptr_t)oc); }

    *slot = saved;
    if (g_fail == bad) end(); else printf("  FAIL cr_ctx_find_node\n");
}

/* ---- batch 68: streaming-FIR context initialiser ----------------------- */
static void test_fir_ctx_init(void)
{
    typedef int (WINAPI *v_i_ppfii)(void *, const void *, float, int, int);
    v_i_ppfii v = (v_i_ppfii)fn_at(RVA(0x180021700));
    v_v_p vsfree = (v_v_p)fn_at(RVA(0x18003bf40));
    begin("cr_fir_ctx_init");
    int bad = g_fail;

    enum { MAXD = 8192 };
    static u8 img[MAXD];

    for (int t = 0; t < 2000; t++) {
        int w = 3 + (int)(rnd() % 62);           /* 3..64 */
        int h = 3 + (int)(rnd() % 62);
        int n = 3 + 2 * (int)(rnd() % 7);        /* odd 3..15 */
        float sigma = (float)(rnd() % 1000) / 500.0f;
        int flag = (int)(rnd() % 4);
        int square = (int)(rnd() % 5) != 0;      /* usually a==w, b==h */
        int nooff  = (int)(rnd() % 5) != 0;

        for (int i = 0; i < w * h && i < MAXD; i++)
            img[i] = (u8)rnd();

        cr_image dv, dc;
        cr_image_set(&dv, img, w, h);
        cr_image_set(&dc, img, w, h);
        if (!square) { dv.a = w + 1; dc.a = w + 1; }
        if (!nooff)  { dv.offx = 3;  dc.offx = 3; }

        cr_fir_row_ctx cv, cc;
        memset(&cv, 0xAA, sizeof cv);
        memset(&cc, 0xAA, sizeof cc);

        int rv = v(&cv, &dv, sigma, n, flag);
        int rc = cr_fir_ctx_init(&cc, &dc, sigma, n, flag);

        if (rv != rc) {
            mismatch("ret", (u32)t, (u32)rv, (u32)rc);
        } else if (rv == 0) {
            if (cv.n != cc.n || cv.row != cc.row ||
                cv.coef_off != cc.coef_off || cv.out_off != cc.out_off ||
                cv.scratch_off != cc.scratch_off)
                mismatch("ctx", (u32)t, (u32)cv.out_off, (u32)cc.out_off);

            cmp_buf("coef", (u8 *)cv.base, (u8 *)cc.base,
                    (size_t)(4 * n - 2), (u32)t);
            cmp_buf("ring", (u8 *)cv.base + 4 * n, (u8 *)cc.base + 4 * n,
                    (size_t)(2 * n * w), (u32)t);
            cmp_buf("scr", (u8 *)cv.base + 2 * n * (w + 2),
                    (u8 *)cc.base + 2 * n * (w + 2),
                    (size_t)(2 * (w + n - 1)), (u32)t);

            if (cv.base) vsfree(&cv.base);
            if (cc.base) cr_sized_free(&cc.base);
        }
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_fir_ctx_init\n");
}

/* 0x180035be0 — stream a 7-tap vertical FIR over src into dst. */
static void test_fir7_image_u8(void)
{
    typedef int (WINAPI *fn_t)(void *, const void *, float);
    fn_t v = (fn_t)fn_at(RVA(0x180035be0));
    begin("cr_fir7_image_u8");
    int bad = g_fail;

    enum { MAXW = 32, MAXH = 32, NP = MAXW * MAXH };
    static u8 sbuf[NP], dbv[NP], dbc[NP];
    static cr_image sv, sc, dv, dc;

    for (int t = 0; t < 3000; t++) {
        int w = 7 + (int)(rnd() % (MAXW - 7));   /* >= 7 for the 7-tap ctx */
        int h = 7 + (int)(rnd() % (MAXH - 7));
        float sigma = (float)(rnd() % 1000) / 500.0f;

        for (int i = 0; i < NP; i++) sbuf[i] = (u8)rnd();
        memset(dbv, 0xAA, sizeof dbv); memset(dbc, 0xAA, sizeof dbc);

        cr_image_set(&sv, sbuf, w, h);
        cr_image_set(&sc, sbuf, w, h);
        cr_image_set(&dv, dbv, w, h);
        cr_image_set(&dc, dbc, w, h);

        int rv = v(&dv, &sv, sigma);
        int rc = cr_fir7_image_u8(&dc, &sc, sigma);
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }
        cmp_buf("out", dbv, dbc, sizeof dbv, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_fir7_image_u8\n");
}

/* 0x18001f2f0 — separable box SUM of a byte image (window k, edge-clamped). */
static void test_box_sum_u8(void)
{
    typedef int (WINAPI *fn_t)(void **, const void *, int);
    fn_t v = (fn_t)fn_at(RVA(0x18001f2f0));
    begin("cr_box_sum_u8");
    int bad = g_fail;

    enum { MAXW = 32, MAXH = 32, NP = MAXW * MAXH };
    static u8 sbuf[NP], dbv[NP], dbc[NP];
    static cr_image sv, sc, dv, dc;
    static void *pvv, *pvc;

    for (int t = 0; t < 3000; t++) {
        int w = 3 + (int)(rnd() % (MAXW - 3));
        int h = 3 + (int)(rnd() % (MAXH - 3));
        int kmax = (w < h ? w : h) - 1;             /* require w,h >= k+1 */
        if (kmax < 1) kmax = 1;
        int k = 1 + (int)(rnd() % kmax);

        for (int i = 0; i < NP; i++) sbuf[i] = (u8)rnd();
        memset(dbv, 0xAA, sizeof dbv); memset(dbc, 0xAA, sizeof dbc);

        cr_image_set(&sv, sbuf, w, h);
        cr_image_set(&sc, sbuf, w, h);
        cr_image_set(&dv, dbv, w, h);
        cr_image_set(&dc, dbc, w, h);

        pvv = dv.data; pvc = dc.data;
        int rv = v(&pvv, &sv, k);
        int rc = cr_box_sum_u8(&pvc, &sc, k);
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }
        cmp_buf("out", dbv, dbc, sizeof dbv, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_box_sum_u8\n");
}

/* ---- batch 68: byte-output streaming-FIR ctx initialiser ---------------- */
static void test_fir_ctx_init_i8(void)
{
    typedef int (WINAPI *v_i_ppfii)(void *, const void *, float, int, int);
    v_i_ppfii v = (v_i_ppfii)fn_at(RVA(0x18003a6b0));
    v_v_p vsfree = (v_v_p)fn_at(RVA(0x18003bf40));
    begin("cr_fir_ctx_init_i8");
    int bad = g_fail;

    enum { MAXD = 8192 };
    static u8 img[MAXD];

    for (int t = 0; t < 2000; t++) {
        int w = 4 * (1 + (int)(rnd() % 16));     /* 4..64, multiple of 4 */
        int h = 3 + (int)(rnd() % 62);
        int n = 3 + 2 * (int)(rnd() % 7);        /* odd 3..15 */
        float sigma = (float)(rnd() % 1000) / 500.0f;
        int flag = (int)(rnd() % 4);
        int square = (int)(rnd() % 5) != 0;
        int nooff  = (int)(rnd() % 5) != 0;
        int unaligned = (int)(rnd() % 8) == 0;   /* break w%4==0 */

        for (int i = 0; i < w * h && i < MAXD; i++)
            img[i] = (u8)rnd();

        cr_image dv, dc;
        cr_image_set(&dv, img, w, h);
        cr_image_set(&dc, img, w, h);
        if (!square) { dv.a = w + 1; dc.a = w + 1; }
        if (!nooff)  { dv.offx = 3;  dc.offx = 3; }
        if (unaligned) {                 /* keep a == w but break w%4==0 */
            dv.a = w + 1; dv.w = w + 1;
            dc.a = w + 1; dc.w = w + 1;
        }

        cr_fir_row_ctx cv, cc;
        memset(&cv, 0xAA, sizeof cv);
        memset(&cc, 0xAA, sizeof cc);

        int rv = v(&cv, &dv, sigma, n, flag);
        int rc = cr_fir_ctx_init_i8(&cc, &dc, sigma, n, flag);

        if (rv != rc) {
            mismatch("ret", (u32)t, (u32)rv, (u32)rc);
        } else if (rv == 0) {
            if (cv.n != cc.n || cv.row != cc.row ||
                cv.coef_off != cc.coef_off || cv.out_off != cc.out_off ||
                cv.scratch_off != cc.scratch_off)
                mismatch("ctx", (u32)t, (u32)cv.out_off, (u32)cc.out_off);

            cmp_buf("coef", (u8 *)cv.base, (u8 *)cc.base,
                    (size_t)(4 * n - 2), (u32)t);
            cmp_buf("ring", (u8 *)cv.base + 4 * n, (u8 *)cc.base + 4 * n,
                    (size_t)(w * n), (u32)t);
            cmp_buf("scr", (u8 *)cv.base + w * n + 4 * n,
                    (u8 *)cc.base + w * n + 4 * n,
                    (size_t)(w + n - 1), (u32)t);

            if (cv.base) vsfree(&cv.base);
            if (cc.base) cr_sized_free(&cc.base);
        }
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_fir_ctx_init_i8\n");
}

/* ---- batch 68: downscale an s16 and a u8 image together (0x180018000) --- */
static void test_resize_pair_18000(void)
{
    typedef int (WINAPI *v_i_ppii)(void *, void *, int, int);
    v_i_ppii v = (v_i_ppii)fn_at(RVA(0x180018000));
    begin("cr_resize_pair_18000");
    int bad = g_fail;

    /* a1 is an int16 image (2 bytes/px): cr_copy_u16_shl_guarded reads it as
     * int16 and the warp writes 2*a3*a4 bytes back, so its buffer must hold
     * 2*w*h bytes.  a2 is a byte image (w*h). */
    enum { MAXW = 26, MAXH = 26,
           CAP1 = 2 * MAXW * MAXH + 64, CAP2 = MAXW * MAXH + 64 };
    static u8 b1v[CAP1], b1c[CAP1], b2v[CAP2], b2c[CAP2];

    for (int t = 0; t < 3000; t++) {
        int w = 3 + (int)(rnd() % 24);
        int h = 3 + (int)(rnd() % 24);
        int a3 = 1 + (int)(rnd() % (w + 1));     /* 1..w  (w -> invalid) */
        int a4 = 1 + (int)(rnd() % (h + 1));

        for (int i = 0; i < CAP1; i++) { b1v[i] = (u8)rnd(); b1c[i] = b1v[i]; }
        for (int i = 0; i < CAP2; i++) { b2v[i] = (u8)rnd(); b2c[i] = b2v[i]; }

        cr_image a1v, a1c, a2v, a2c;
        cr_image_set(&a1v, b1v, w, h);
        cr_image_set(&a1c, b1c, w, h);
        cr_image_set(&a2v, b2v, w, h);
        cr_image_set(&a2c, b2c, w, h);

        int rv = v(&a1v, &a2v, a3, a4);
        int rc = cr_resize_pair_18000(&a1c, &a2c, a3, a4);
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }
        if (rv != 0) continue;

        if (a1v.a != a1c.a || a1v.b != a1c.b || a1v.w != a1c.w || a1v.h != a1c.h ||
            a2v.a != a2c.a || a2v.b != a2c.b || a2v.w != a2c.w || a2v.h != a2c.h)
            mismatch("dims", (u32)t, (u32)a1v.w, (u32)a1c.w);

        cmp_buf("o16", b1v, b1c, (size_t)(2 * a3 * a4), (u32)t);
        cmp_buf("o8",  b2v, b2c, (size_t)(a3 * a4), (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_resize_pair_18000\n");
}

/* ---- batch 69: masked histogram percentile range (0x18001a7c0) --------- */
static void test_hist_percentiles(void)
{
    typedef int (WINAPI *v_hist)(int *, int *, int *, const void *,
                                 const void *, int, float, float, int);
    v_hist v = (v_hist)fn_at(RVA(0x18001a7c0));
    begin("cr_masked_hist_percentiles");
    int bad = g_fail;

    enum { MAXW = 40, MAXH = 40, NP = MAXW * MAXH };
    static int16_t pix[NP];
    static uint8_t mbuf[NP];
    static cr_image img, maskimg;

    for (int t = 0; t < 5000; t++) {
        int w = 1 + (int)(rnd() % MAXW);
        int h = 1 + (int)(rnd() % MAXH);
        int total = w * h;
        int mode = (int)(rnd() % 8);

        for (int i = 0; i < total; i++)
            pix[i] = (int16_t)((int)(rnd() % 0x10000) - 0x8000);
        for (int i = 0; i < total; i++)
            mbuf[i] = (uint8_t)rnd();

        if (mode == 1) {                    /* force x == y */
            int16_t c = (int16_t)((int)(rnd() % 0x10000) - 0x8000);
            for (int i = 0; i < total; i++) pix[i] = c;
        }

        int use_mask = (int)(rnd() % 3) != 0;
        int and_mask = (int)(rnd() % 256);
        if (mode == 2) and_mask = 0;        /* count == 0 when masked */

        float f_lo = (float)(rnd() % 201) / 200.0f;   /* 0.0 .. 1.0 */
        float f_hi = (float)(rnd() % 201) / 200.0f;
        int nbin = 2 + (int)(rnd() % 512);            /* nm1 >= 1, no /0 */

        cr_image_set(&img, pix, w, h);
        cr_image_set(&maskimg, mbuf, w, h);
        const cr_image *mp = use_mask ? &maskimg : NULL;

        int lo_v = 0x11111111, hi_v = 0x22222222, ct_v = 0x33333333;
        int lo_c = 0x11111111, hi_c = 0x22222222, ct_c = 0x33333333;

        int rv = v(&lo_v, &hi_v, &ct_v, &img, mp, and_mask, f_lo, f_hi, nbin);
        int rc = cr_masked_hist_percentiles(&lo_c, &hi_c, &ct_c, &img, mp,
                                            and_mask, f_lo, f_hi, nbin);
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }
        if (lo_v != lo_c) mismatch("lo", (u32)t, (u32)lo_v, (u32)lo_c);
        if (hi_v != hi_c) mismatch("hi", (u32)t, (u32)hi_v, (u32)hi_c);
        if (ct_v != ct_c) mismatch("ct", (u32)t, (u32)ct_v, (u32)ct_c);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_masked_hist_percentiles\n");
}

/* ---- batch 70b: masked byte-intensity histogram percentiles (0x18002fd40) - */
static void test_hist_percentiles_u8(void)
{
    typedef int (WINAPI *v_hist_u8)(int *, int *, int *, const void *,
                                    const void *, float, float, int);
    v_hist_u8 v = (v_hist_u8)fn_at(RVA(0x18002fd40));
    begin("cr_masked_hist_percentiles_u8");
    int bad = g_fail;

    enum { MAXW = 40, MAXH = 40, NP = MAXW * MAXH, MAXW_WORDS = 512 };
    static uint8_t  pix[NP];
    static uint32_t bits[MAXW_WORDS];
    static cr_image img, bm;

    for (int t = 0; t < 6000; t++) {
        int w = 1 + (int)(rnd() % MAXW);
        int h = 1 + (int)(rnd() % MAXH);
        int total = w * h;
        int mode = (int)(rnd() % 8);
        int offx = (int)(rnd() % 6);
        int offy = (int)(rnd() % 6);
        int stride_bits = (2 + (int)(rnd() % 3)) * 32;   /* 64..128 bits */

        for (int i = 0; i < total; i++) pix[i] = (uint8_t)rnd();
        if (mode == 1) {                                 /* force min == max */
            uint8_t c = (uint8_t)rnd();
            for (int i = 0; i < total; i++) pix[i] = c;
        }
        for (int i = 0; i < MAXW_WORDS; i++) bits[i] = rnd();
        if (mode == 2) {                                 /* force count == 0 */
            for (int i = 0; i < MAXW_WORDS; i++) bits[i] = 0;
        }

        float f_lo = (float)(rnd() % 201) / 200.0f;      /* 0.0 .. 1.0 */
        float f_hi = (float)(rnd() % 201) / 200.0f;
        int nbin = 2 + (int)(rnd() % 512);               /* nm1 >= 1, no /0 */

        cr_image_set(&img, pix, w, h);
        cr_image_set(&bm, bits, w, h);
        bm.a = stride_bits;
        bm.offx = offx;
        bm.offy = offy;

        int lo_v = 0x11111111, hi_v = 0x22222222, ct_v = 0x33333333;
        int lo_c = 0x11111111, hi_c = 0x22222222, ct_c = 0x33333333;

        int rv = v(&lo_v, &hi_v, &ct_v, &img, &bm, f_lo, f_hi, nbin);
        int rc = cr_masked_hist_percentiles_u8(&lo_c, &hi_c, &ct_c, &img, &bm,
                                               f_lo, f_hi, nbin);
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }
        if (lo_v != lo_c) mismatch("lo", (u32)t, (u32)lo_v, (u32)lo_c);
        if (hi_v != hi_c) mismatch("hi", (u32)t, (u32)hi_v, (u32)hi_c);
        if (ct_v != ct_c) mismatch("ct", (u32)t, (u32)ct_v, (u32)ct_c);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_masked_hist_percentiles_u8\n");
}

/* 0x180011020 — in-place contrast stretch of a u8 image using a mask bitmap. */
static void test_stretch_u8_mode(void)
{
    typedef int (WINAPI *v_stretch)(void *, const void *, float, float, int);
    v_stretch v = (v_stretch)fn_at(RVA(0x180011020));
    begin("cr_stretch_u8_mode");
    int bad = g_fail;

    enum { MAXW = 32, MAXH = 32, NP = MAXW * MAXH, MAXW_WORDS = 512 };
    static uint8_t  pv[NP], pc[NP];
    static uint32_t bits[MAXW_WORDS];
    static unsigned char iv[0x20], ic[0x20], bmv[0x20], bmc[0x20];

    for (int t = 0; t < 20000; t++) {
        int w = (int)(rnd() % MAXW);
        int h = (int)(rnd() % MAXH);
        int total = w * h;
        int mode = (int)(rnd() % 6);
        int offx = (int)(rnd() % 6);
        int offy = (int)(rnd() % 6);
        int stride_bits = (2 + (int)(rnd() % 3)) * 32;   /* 64..128 bits */

        for (int i = 0; i < NP; i++) { uint8_t b = (uint8_t)rnd(); pv[i] = b; pc[i] = b; }
        if ((rnd() & 3) == 0 && total > 0) {             /* sometimes force min == max */
            uint8_t c = (uint8_t)rnd();
            for (int i = 0; i < total; i++) { pv[i] = c; pc[i] = c; }
        }
        for (int i = 0; i < MAXW_WORDS; i++) bits[i] = rnd();
        if ((rnd() % 8) == 0)                            /* sometimes force count == 0 */
            for (int i = 0; i < MAXW_WORDS; i++) bits[i] = 0;

        float f_lo = (float)(rnd() % 201) / 200.0f;      /* 0.0 .. 1.0 */
        float f_hi = (float)(rnd() % 201) / 200.0f;

        mk_image(iv,  pv,   w, w, h, 0, 0);
        mk_image(ic,  pc,   w, w, h, 0, 0);
        mk_image(bmv, bits, stride_bits, w, h, offx, offy);
        mk_image(bmc, bits, stride_bits, w, h, offx, offy);

        int rv = v(iv, bmv, f_lo, f_hi, mode);
        int rc = cr_stretch_u8_mode((cr_image *)ic, (const cr_image *)bmc,
                                    f_lo, f_hi, mode);
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }
        cmp_buf("px", pv, pc, NP, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_stretch_u8_mode\n");
}

/* 0x180018800 — mean gradient magnitude over a masked interior region. */
static void test_grad_mag_score(void)
{
    typedef int (WINAPI *fn_t)(void *, const void *, const void *, int, int,
                               const void *);
    fn_t v = (fn_t)fn_at(RVA(0x180018800));
    begin("cr_grad_mag_score");
    int bad = g_fail;

    enum { MAXW = 40, MAXH = 40, NP = MAXW * MAXH };
    static int16_t sbuf[NP];
    static uint8_t mbuf[NP];
    static uint8_t cfg[0x40];
    static cr_image sv, sc, mv, mc;

    for (int t = 0; t < 4000; t++) {
        int w = 4 + (int)(rnd() % (MAXW - 4));   /* 4..39 for cr_sep_fir_pair */
        int h = 4 + (int)(rnd() % (MAXH - 4));
        int lim = (w < h ? w : h) / 2;
        int m = (int)(rnd() % (unsigned)(lim + 1));
        int match = (int)(rnd() & 0xff);
        int shift = (int)(rnd() % 6);

        for (int i = 0; i < NP; i++) sbuf[i] = (int16_t)rnd();
        for (int i = 0; i < NP; i++) {
            int r = (int)(rnd() & 0xff);
            mbuf[i] = (rnd() % 4 == 0) ? (uint8_t)match : (uint8_t)r;
        }
        memset(cfg, 0, sizeof cfg);
        *(uint16_t *)(cfg + 0x2a) = (uint16_t)m;

        cr_image_set(&sv, sbuf, w, h);
        cr_image_set(&sc, sbuf, w, h);
        cr_image_set(&mv, mbuf, w, h);
        cr_image_set(&mc, mbuf, w, h);

        uint8_t ov = 0xAA, oc = 0xAA;
        int rv = v(&ov, &sv, &mv, match, shift, cfg);
        int rc = cr_grad_mag_score(&oc, &sc, &mc, match, shift, cfg);
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }
        if (ov != oc) mismatch("out", (u32)t, (u32)ov, (u32)oc);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_grad_mag_score\n");
}

/* ---- batch 70: in-place 14-bit contrast stretch (0x1800281a0) ---------- */
static void test_stretch_14bit(void)
{
    typedef int (WINAPI *v_stretch)(void *, void *, int, float, float, int);
    v_stretch v = (v_stretch)fn_at(RVA(0x1800281a0));
    begin("cr_stretch_14bit");
    int bad = g_fail;

    enum { MAXW = 32, MAXH = 32, NP = MAXW * MAXH };
    static int16_t pv[NP], pc[NP];
    static uint8_t mbuf[NP];
    static cr_image iv, ic, mv, mc;

    for (int t = 0; t < 5000; t++) {
        int w = 1 + (int)(rnd() % MAXW);
        int h = 1 + (int)(rnd() % MAXH);
        int total = w * h;

        for (int i = 0; i < total; i++) {
            int16_t x = (int16_t)((int)(rnd() % 0x10000) - 0x8000);
            pv[i] = x; pc[i] = x;
        }
        for (int i = 0; i < total; i++) mbuf[i] = (uint8_t)rnd();

        int use_mask = (int)(rnd() % 3) != 0;
        int and_mask = (int)(rnd() % 256);
        float f4 = (float)(rnd() % 201) / 200.0f;
        float f5 = (float)(rnd() % 201) / 200.0f;
        int mode = (int)(rnd() % 5);            /* 0..4 */
        if (rnd() % 3 == 0) mode |= 0x100;      /* exercise byte masking */

        cr_image_set(&iv, pv, w, h);
        cr_image_set(&ic, pc, w, h);
        cr_image_set(&mv, mbuf, w, h);
        cr_image_set(&mc, mbuf, w, h);
        const cr_image *mp = use_mask ? &mv : NULL;

        int rv = v(&iv, mp, and_mask, f4, f5, mode);
        int rc = cr_stretch_14bit(&ic, mp, and_mask, f4, f5, mode);
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }
        if (rv != 0) continue;

        if (iv.w != ic.w || iv.h != ic.h)
            mismatch("dims", (u32)t, (u32)iv.w, (u32)ic.w);
        cmp_buf("px", (u8 *)pv, (u8 *)pc, (size_t)(2 * total), (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_stretch_14bit\n");
}

/* ---- batch 71: two-scale band-pass difference (0x180019080) ------------ */
static void test_bandpass_diff_i8(void)
{
    typedef int (WINAPI *v_bp)(void *, const void *, const void *);
    v_bp v = (v_bp)fn_at(RVA(0x180019080));
    begin("cr_bandpass_diff_i8");
    int bad = g_fail;

    enum { MAXW = 64, MAXH = 40, NP = MAXW * MAXH };
    static uint8_t inbuf[NP], ov[NP], oc[NP];
    static cr_image iv, ovv, ovc;
    static cr_bandpass_cfg cfg;

    for (int t = 0; t < 3000; t++) {
        int w = 4 * (4 + (int)(rnd() % 13));   /* 16..64, multiple of 4 */
        int h = 16 + (int)(rnd() % 24);        /* 16..39 */
        if (rnd() % 5 == 0) w = 4 * (1 + (int)(rnd() % 3));  /* 4..12 */
        if (rnd() % 5 == 0) h = 4 + (int)(rnd() % 12);       /* 4..15 */

        for (int i = 0; i < NP; i++) inbuf[i] = (uint8_t)rnd();
        for (int i = 0; i < NP; i++) { ov[i] = (uint8_t)rnd(); oc[i] = ov[i]; }

        cr_image_set(&iv, inbuf, w, h);
        if (rnd() % 6 == 0) iv.a = w + 1;       /* break a==w invariant */
        if (rnd() % 6 == 0) iv.offx = 1;        /* break offset invariant */

        cr_image_set(&ovv, ov, w, h);
        cr_image_set(&ovc, oc, w, h);

        cfg.sigma9  = 0.5f + (float)(rnd() % 200) / 100.0f;
        cfg.sigma15 = 0.5f + (float)(rnd() % 200) / 100.0f;
        cfg._pad    = 0;
        cfg.flag    = (int8_t)((rnd() % 4 == 0) ? (int)(rnd() % 256) : 0);

        int rv = v(&ovv, &iv, &cfg);
        int rc = cr_bandpass_diff_i8(&ovc, &iv, &cfg);
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }
        if (rv != 0) continue;
        cmp_buf("out", ov, oc, (size_t)(w * h), (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_bandpass_diff_i8\n");
}

/* ---- batch 72: band-pass type dispatch (0x180012f10) ------------------- */
static void test_bandpass_dispatch(void)
{
    typedef int (WINAPI *v_disp)(void *, void *);
    v_disp v = (v_disp)fn_at(RVA(0x180012f10));
    begin("cr_bandpass_dispatch");
    int bad = g_fail;

    enum { MAXW = 48, MAXH = 32, NP = MAXW * MAXH, CFGBUF = 0x100 };
    static uint8_t pv[NP], pc[NP];
    static uint8_t av[CFGBUF], ac[CFGBUF];
    static cr_image iv, ic;

    for (int t = 0; t < 2000; t++) {
        int w = 4 * (4 + (int)(rnd() % 9));    /* 16..48, multiple of 4 */
        int h = 16 + (int)(rnd() % 16);         /* 16..31 */
        if (rnd() % 6 == 0) h = 4 + (int)(rnd() % 12);   /* sometimes too small */

        for (int i = 0; i < NP; i++) { pv[i] = (uint8_t)rnd(); pc[i] = pv[i]; }
        for (int i = 0; i < CFGBUF; i++) { av[i] = (uint8_t)rnd(); ac[i] = av[i]; }

        int type = (int)(rnd() % 4);
        av[0] = (uint8_t)type; ac[0] = (uint8_t)type;

        float s9  = 0.5f + (float)(rnd() % 200) / 100.0f;
        float s15 = 0.5f + (float)(rnd() % 200) / 100.0f;
        *(float *)(av + 0xe4) = s9;  *(float *)(ac + 0xe4) = s9;
        *(float *)(av + 0xe8) = s15; *(float *)(ac + 0xe8) = s15;
        av[0xf0] = 0; ac[0xf0] = 0;             /* cfg->flag */

        cr_image_set(&iv, pv, w, h);
        cr_image_set(&ic, pc, w, h);

        int rv = v(&iv, av);
        int rc = cr_bandpass_dispatch(&ic, ac);
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }
        if (rv != 0) continue;
        cmp_buf("out", pv, pc, (size_t)(w * h), (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_bandpass_dispatch\n");
}

/* ---- batch 73: 16-block Haar orientation accumulator (0x180014e70) ------ */
static void test_haar16_orient(void)
{
    typedef int (WINAPI *v_h16)(void *, void *, void *, void *);
    v_h16 v = (v_h16)fn_at(RVA(0x180014e70));
    begin("cr_haar16_orient");
    int bad = g_fail;

    enum { MAXW = 16, MAXH = 16, SRCCAP = 8192, OUTN = 20 * 20 };
    static uint8_t srcbuf[SRCCAP];
    static uint8_t ptbufv[0x40], ptbufc[0x40];
    static int16_t rv1[OUTN], rv2[OUTN], cv1[OUTN], cv2[OUTN];
    static cr_image rev, rimv, cev, cimv, sv, sc;

    for (int t = 0; t < 4000; t++) {
        int w = 1 + (int)(rnd() % MAXW);
        int h = 1 + (int)(rnd() % MAXH);
        if (t % 11 == 0) h = -(int)(rnd() % 4);       /* exercise h<=0 */
        if (t % 13 == 0) w = -(int)(rnd() % 4);       /* exercise w<=0 */

        for (int i = 0; i < SRCCAP; i++) srcbuf[i] = (uint8_t)rnd();
        for (int i = 0; i < OUTN; i++) {
            int16_t a = (int16_t)rnd();
            rv1[i] = a; cv1[i] = a;
            rv2[i] = (int16_t)rnd(); cv2[i] = rv2[i];
        }
        for (int i = 0; i < 0x40; i++) { ptbufv[i] = (uint8_t)rnd(); ptbufc[i] = ptbufv[i]; }

        int stride = 4 * w + 4 * (int)(rnd() % 3);     /* 4w .. 4w+8 */
        if (stride < 4) stride = 4;                    /* keep w<=0 sane */
        int offx = (int)(rnd() % 4), offy = (int)(rnd() % 4);
        int dx = (int)(rnd() % 4), dy = (int)(rnd() % 4);
        *(int32_t *)(ptbufv + 0x28) = dx; *(int32_t *)(ptbufc + 0x28) = dx;
        *(int32_t *)(ptbufv + 0x2c) = dy; *(int32_t *)(ptbufc + 0x2c) = dy;

        rev.a = w; rev.b = h; rev.data = rv1; rev.w = w; rev.h = h;
        rev.offx = 0; rev.offy = 0;
        cev = rev; cev.data = cv1;
        rimv.a = w; rimv.b = h; rimv.data = rv2; rimv.w = w; rimv.h = h;
        rimv.offx = 0; rimv.offy = 0;
        cimv = rimv; cimv.data = cv2;

        sv.a = stride; sv.b = 0; sv.data = srcbuf; sv.w = 0; sv.h = 0;
        sv.offx = offx; sv.offy = offy;
        sc = sv;

        v(&rev, &rimv, &sv, ptbufv);
        cr_haar16_orient(&cev, &cimv, &sc, ptbufc);

        if (w > 0 && h > 0) {
            cmp_buf("re", (u8 *)rv1, (u8 *)cv1, (size_t)(2 * w * h), (u32)t);
            cmp_buf("im", (u8 *)rv2, (u8 *)cv2, (size_t)(2 * w * h), (u32)t);
        }
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_haar16_orient\n");
}

/* ---- batch 74: orientation field + threshold/open/mark ------------------ */
static void test_orient_map_haar(void)
{
    typedef int (WINAPI *v_om)(void *, void *, float);
    v_om v = (v_om)fn_at(RVA(0x18003f970));
    begin("cr_orient_map_haar");
    int bad = g_fail;

    enum { MAXW = 12, MAXH = 12, SRCCAP = 8192, NPC = 16 * 16 };
    static uint8_t srcbuf[SRCCAP];
    static uint8_t iv[NPC], ic[NPC];
    static cr_orient_ctx cv, cc;
    static cr_image sv, sc;

    for (int t = 0; t < 3000; t++) {
        int w = 8 + (int)(rnd() % (MAXW - 8));   /* 8..11 */
        int h = 8 + (int)(rnd() % (MAXH - 8));   /* 8..11 */
        int stride = 4 * w;

        for (int i = 0; i < SRCCAP; i++) srcbuf[i] = (uint8_t)rnd();
        for (int i = 0; i < NPC; i++) { iv[i] = (uint8_t)rnd(); ic[i] = iv[i]; }

        int offx = (int)(rnd() % 3), offy = (int)(rnd() % 3);
        int dx = (int)(rnd() % 3), dy = (int)(rnd() % 3);
        float sigma = (float)(1 + (int)(rnd() % 12)) * 0.5f;

        memset(&cv, 0, sizeof cv); memset(&cc, 0, sizeof cc);
        cv.img.a = w; cv.img.b = h; cv.img.w = w; cv.img.h = h; cv.img.data = iv;
        cv.dx = dx; cv.dy = dy;
        cc.img = cv.img; cc.img.data = ic; cc.dx = dx; cc.dy = dy;

        memset(&sv, 0, sizeof sv); memset(&sc, 0, sizeof sc);
        sv.a = stride; sv.data = srcbuf; sv.offx = offx; sv.offy = offy;
        sc = sv;

        int rv = v(&cv, &sv, sigma);
        int rc = cr_orient_map_haar(&cc, &sc, sigma);
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }
        cmp_buf("img", iv, ic, (size_t)(w * h), (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_orient_map_haar\n");
}

static void test_thresh_open_mark(void)
{
    typedef int (WINAPI *v_tom)(void *, void *, int);
    v_tom v = (v_tom)fn_at(RVA(0x18003f780));
    begin("cr_thresh_open_mark");
    int bad = g_fail;

    enum { MAXW = 24, MAXH = 24, NPC = 32 * 32 };
    static int16_t sbuf[NPC];
    static uint8_t iv[NPC], ic[NPC];
    static cr_image iv_i, ic_i, sv, sc;

    for (int t = 0; t < 4000; t++) {
        int w = 1 + (int)(rnd() % MAXW);
        int h = 1 + (int)(rnd() % MAXH);
        if (t % 7 == 0) h = -(int)(rnd() % 4);       /* exercise h<=0 */
        if (t % 9 == 0) w = -(int)(rnd() % 4);       /* exercise w<=0 */

        for (int i = 0; i < NPC; i++) sbuf[i] = (int16_t)rnd();
        for (int i = 0; i < NPC; i++) { iv[i] = (uint8_t)rnd(); ic[i] = iv[i]; }

        int thresh = (int)(rnd() % 0x10000) - 0x8000;   /* int16 range */

        iv_i.a = w; iv_i.b = h; iv_i.data = iv; iv_i.w = w; iv_i.h = h;
        iv_i.offx = 0; iv_i.offy = 0;
        ic_i = iv_i; ic_i.data = ic;
        memset(&sv, 0, sizeof sv); memset(&sc, 0, sizeof sc);
        sv.data = sbuf; sv.w = w; sv.h = h;
        sc = sv;

        int rv = v(&iv_i, &sv, thresh);
        int rc = cr_thresh_open_mark(&ic_i, &sc, thresh);
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }
        if (w > 0 && h > 0)
            cmp_buf("img", iv, ic, (size_t)(w * h), (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_thresh_open_mark\n");
}

/* ---- 0x18003fe20: quarter-res orientation field + coord-pair resample ---- */
static void test_angle_field_downsample(void)
{
    typedef int (WINAPI *v_afd)(void *, void *, void *);
    v_afd v = (v_afd)fn_at(RVA(0x18003fe20));
    begin("cr_angle_field_downsample");
    int bad = g_fail;

    enum { MAXW = 40, MAXH = 40, NPC = 64 * 64, CFGN = 0x40 };
    static uint8_t coords[NPC];       /* in_coords: 2*count (x,y) bytes */
    static uint8_t av_out[NPC];       /* vendor output buffer */
    static uint8_t ac_out[NPC];       /* clean output buffer */
    static int16_t sbuf[NPC];         /* a2 source (sw,sh up to 47) */
    static cr_image sv, sc;
    static cr_af_ds_desc av_d, ac_d;  /* a1 descriptor (NOT a cr_image) */
    static uint8_t cfg[CFGN];

    for (int t = 0; t < 4000; t++) {
        /* Keep a2 large enough that its quarter field is >= 4x4: the 7-tap
         * blur reads x[0..2] up front and x[n-1] in its tail, so fields with a
         * dimension < 4 make the vendor (and any faithful copy) read past the
         * malloc'd field buffer -- an allocator-dependent result that cannot be
         * matched bit-for-bit.  The real caller always passes large images. */
        int sw = 20 + (int)(rnd() % (MAXW - 12));
        int sh = 20 + (int)(rnd() % (MAXH - 12));
        int h  = 1 + (int)(rnd() % (MAXH / 2));
        if (t % 11 == 0) h = 0;            /* exercise count<=0 (no loop) */

        int qw = (sw > 4 ? sw - 4 : sw - 1) >> 2;
        int qh = (sh > 4 ? sh - 4 : sh - 1) >> 2;
        if (qw < 1) qw = 1;
        if (qh < 1) qh = 1;

        /* The resample loop reads 2*count coord bytes (x@2i, y@2i+1) and writes
         * count angle bytes. Coordinates must stay inside the quarter field (as
         * the real caller guarantees); out-of-range coords make the vendor
         * sample out of bounds. */
        for (int i = 0; i < h * 2; i++)
            coords[i] = (uint8_t)(rnd() % (uint32_t)(i & 1 ? qh : qw));
        for (int i = 0; i < NPC; i++) sbuf[i] = (int16_t)rnd();
        for (int i = 0; i < CFGN; i++) cfg[i] = (uint8_t)rnd();
        *(float *)(cfg + 0x30) = (float)((rnd() % 1000) * 0.01f - 5.0f);

        memset(av_out, 0, sizeof av_out);
        memset(ac_out, 0, sizeof ac_out);
        av_d.in_coords = coords; av_d.pad08 = 0;
        av_d.out_buf   = av_out; av_d.pad18 = 0; av_d.count = h;
        ac_d = av_d; ac_d.out_buf = ac_out;

        memset(&sv, 0, sizeof sv); memset(&sc, 0, sizeof sc);
        sv.data = sbuf; sv.w = sw; sv.h = sh; sv.offx = 0; sv.offy = 0;
        sc = sv;

        int rv = v(&av_d, &sv, cfg);
        int rc = cr_angle_field_downsample(&ac_d, &sc, cfg);
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }
        if (rv == 0 && h > 0)
            cmp_buf("a1", av_out, ac_out, (size_t)h, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_angle_field_downsample\n");
}

static void test_angle_field_ds_run(void)
{
    typedef int (WINAPI *v_afd)(void *, void *, void *);
    v_afd v = (v_afd)fn_at(RVA(0x1800302f0));
    begin("cr_angle_field_ds_run");
    int bad = g_fail;

    enum { MAXW = 40, MAXH = 40, NPC = 64 * 64, CFGN = 0x40 };
    static uint8_t coords[NPC];
    static int16_t sbuf[NPC];
    static cr_image sv, sc;
    static cr_af_ds_desc av_d, ac_d;
    static uint8_t cfg[CFGN];

    for (int t = 0; t < 3000; t++) {
        /* field must be >= 4x4 (see test_angle_field_downsample) */
        int sw = 20 + (int)(rnd() % (MAXW - 12));
        int sh = 20 + (int)(rnd() % (MAXH - 12));
        int h  = 1 + (int)(rnd() % (MAXH / 2));

        int qw = (sw - 4) >> 2, qh = (sh - 4) >> 2;
        if (qw < 1) qw = 1;
        if (qh < 1) qh = 1;

        for (int i = 0; i < h * 2; i++)
            coords[i] = (uint8_t)(rnd() % (uint32_t)(i & 1 ? qh : qw));
        for (int i = 0; i < NPC; i++) sbuf[i] = (int16_t)rnd();
        for (int i = 0; i < CFGN; i++) cfg[i] = (uint8_t)rnd();
        *(float *)(cfg + 0x30) = (float)((rnd() % 1000) * 0.01f - 5.0f);
        /* cfg[9] gates the dispatch: 2 runs the downsample, anything else 0x69 */
        cfg[9] = (t % 4 == 3) ? (uint8_t)(rnd() & 0xff) : 2;

        /* out_buf is allocated by the function; NULL it in */
        av_d.in_coords = coords; av_d.pad08 = 0;
        av_d.out_buf   = NULL;   av_d.pad18 = 0; av_d.count = h;
        ac_d = av_d;

        memset(&sv, 0, sizeof sv); memset(&sc, 0, sizeof sc);
        sv.data = sbuf; sv.w = sw; sv.h = sh; sv.offx = 0; sv.offy = 0;
        sc = sv;

        int rv = v(&av_d, &sv, cfg);
        int rc = cr_angle_field_ds_run(&ac_d, &sc, cfg);
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }
        if (rv == 0 && h > 0 && av_d.out_buf && ac_d.out_buf)
            cmp_buf("a1", (u8 *)av_d.out_buf, (u8 *)ac_d.out_buf,
                    (size_t)h, (u32)t);
        /* deliberately leak the buffers (the vendor's own 0x69 path leaks too) */
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_angle_field_ds_run\n");
}

/* ---- batch 68: n-point real transform from an (n/2)-point complex FFT --- */
static void test_fft_real_n(void)
{
    typedef int (WINAPI *v_i_ppf)(float *, float *, int);
    v_i_ppf v = (v_i_ppf)fn_at(RVA(0x180018330));
    begin("cr_fft_real_n");
    int bad = g_fail;
    enum { MAXN = 512 };
    static float a1v[MAXN], a2v[MAXN], a1c[MAXN], a2c[MAXN];

    for (int t = 0; t < 400; t++) {
        int n;
        if (t % 4 == 3) {
            n = (int)(rnd() % 600);                    /* often invalid */
        } else {
            n = 1 << (4 + (int)(rnd() % 6));           /* 16..512 pow2 */
        }
        for (int i = 0; i < MAXN; i++) {
            float f = (float)((int)(rnd() % 2001) - 1000) / 500.0f;
            a1v[i] = f; a1c[i] = f;
            a2v[i] = 123.0f; a2c[i] = 123.0f;
        }
        int rv = v(a1v, a2v, n);
        int rc = cr_fft_real_n(a1c, a2c, n);
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }
        if (rv == 0) {
            cmp_buf("a1", (u8 *)a1v, (u8 *)a1c, sizeof(float) * (size_t)n, (u32)t);
            cmp_buf("a2", (u8 *)a2v, (u8 *)a2c, sizeof(float) * (size_t)n, (u32)t);
        }
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_fft_real_n\n");
}

/* ---- batch 69: scaled real FFT front-end (0x180029510) ----------------- */
static void test_fft_real_fwd(void)
{
    typedef int (WINAPI *v_i_pup)(float *, unsigned, float *);
    v_i_pup v = (v_i_pup)fn_at(RVA(0x180029510));
    begin("cr_fft_real_fwd");
    int bad = g_fail;
    enum { MAXN = 512 };
    static float a1v[MAXN], a3v[MAXN], a1c[MAXN], a3c[MAXN];

    for (int t = 0; t < 400; t++) {
        unsigned n;
        if (t % 4 == 3) {
            n = rnd() % 700u;                          /* often invalid */
        } else {
            n = 1u << (4 + (rnd() % 6));               /* 16..512 pow2 */
        }
        for (int i = 0; i < MAXN; i++) {
            float f = (float)((int)(rnd() % 2001) - 1000) / 500.0f;
            a1v[i] = f; a1c[i] = f;
            a3v[i] = 123.0f; a3c[i] = 123.0f;
        }
        int rv = v(a1v, n, a3v);
        int rc = cr_fft_real_fwd(a1c, n, a3c);
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }
        if (rv == 0) {
            cmp_buf("a1", (u8 *)a1v, (u8 *)a1c, sizeof(float) * (size_t)n, (u32)t);
            cmp_buf("a3", (u8 *)a3v, (u8 *)a3c, sizeof(float) * (size_t)n, (u32)t);
        }
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_fft_real_fwd\n");
}

/* ---- batch 61: inverse real FFT front-end (0x180045490) ---------------- */
static void test_fft_real_inv(void)
{
    typedef int (WINAPI *v_i_ppu)(float *, float *, unsigned);
    v_i_ppu v = (v_i_ppu)fn_at(RVA(0x180045490));
    begin("cr_fft_real_inv");
    int bad = g_fail;
    enum { MAXN = 512 };
    static float p1v[MAXN], p2v[MAXN], p1c[MAXN], p2c[MAXN];

    for (int t = 0; t < 400; t++) {
        unsigned n;
        if (t % 4 == 3) {
            n = rnd() % 700u;                          /* often invalid */
        } else {
            n = 1u << (4 + (rnd() % 6));               /* 16..512 pow2 */
        }
        for (int i = 0; i < MAXN; i++) {
            float f = (float)((int)(rnd() % 2001) - 1000) / 500.0f;
            p1v[i] = f; p1c[i] = f;
            p2v[i] = 123.0f; p2c[i] = 123.0f;
        }
        int rv = v(p1v, p2v, n);
        int rc = cr_fft_real_inv(p1c, p2c, n);
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }
        if (rv == 0) {
            cmp_buf("p1", (u8 *)p1v, (u8 *)p1c, sizeof(float) * (size_t)n, (u32)t);
            cmp_buf("p2", (u8 *)p2v, (u8 *)p2c, sizeof(float) * (size_t)n, (u32)t);
        }
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_fft_real_inv\n");
}

/* ---- batch 63: scaled inverse real FFT (0x18001d050) ------------------- */
static void test_fft_real_bwd(void)
{
    typedef int (WINAPI *v_i_pup)(float *, unsigned, float *);
    v_i_pup v = (v_i_pup)fn_at(RVA(0x18001d050));
    begin("cr_fft_real_bwd");
    int bad = g_fail;
    enum { MAXN = 512 };
    static float a1v[MAXN], a3v[MAXN], a1c[MAXN], a3c[MAXN];

    for (int t = 0; t < 400; t++) {
        unsigned n;
        if (t % 4 == 3) {
            n = rnd() % 700u;
        } else {
            n = 1u << (4 + (rnd() % 6));               /* 16..512 pow2 */
        }
        for (int i = 0; i < MAXN; i++) {
            float f = (float)((int)(rnd() % 2001) - 1000) / 500.0f;
            a1v[i] = f; a1c[i] = f;
            a3v[i] = 123.0f; a3c[i] = 123.0f;
        }
        int rv = v(a1v, n, a3v);
        int rc = cr_fft_real_bwd(a1c, n, a3c);
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }
        if (rv == 0) {
            cmp_buf("a1", (u8 *)a1v, (u8 *)a1c, sizeof(float) * (size_t)n, (u32)t);
            cmp_buf("a3", (u8 *)a3v, (u8 *)a3c, sizeof(float) * (size_t)n, (u32)t);
        }
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_fft_real_bwd\n");
}

/* ---- batch 62: 5x5 filter-bank + 2x2 max-pool (0x18002b100) ------------ */
static void test_filter_bank_max5x5(void)
{
    typedef int (WINAPI *v_i_ppiiP)(void *, const void *, int, int, int *);
    v_i_ppiiP v = (v_i_ppiiP)fn_at(RVA(0x18002b100));
    begin("cr_filter_bank_max5x5");
    int bad = g_fail;
    enum { INMAX = 8192, OUTMAX = 2048, KMAX = 64 };
    static int16_t in_v[INMAX], in_c[INMAX];
    static int16_t out_v[OUTMAX], out_c[OUTMAX];
    static int16_t ktab[KMAX * 25], btab[KMAX];
    static int desc_v[16], desc_c[16];

    for (int t = 0; t < 300; t++) {
        int H = 6 + (int)(rnd() % 15);
        int W = 6 + (int)(rnd() % 15);
        int nk = 1 + (int)(rnd() % 3);
        int nch = 1 + (int)(rnd() % 3);
        int stride = (t % 5 == 0) ? 0 : W;
        int offset = (int)(rnd() % 5);
        int flag = (int)(rnd() & 1);
        int nkt = nch * nk;

        for (int i = 0; i < nkt * 25; i++)
            ktab[i] = (int16_t)((int)(rnd() % 60001) - 30000);
        for (int i = 0; i < nch; i++)
            btab[i] = (int16_t)((int)(rnd() % 2001) - 1000);
        for (int i = 0; i < INMAX; i++) {
            int16_t x = (int16_t)((int)(rnd() % 40001) - 20000);
            in_v[i] = x; in_c[i] = x;
        }
        for (int i = 0; i < OUTMAX; i++) { out_v[i] = 0x7fff; out_c[i] = 0x7fff; }

        for (int i = 0; i < 16; i++) desc_v[i] = desc_c[i] = 0;
        desc_v[0] = desc_c[0] = (t % 37 == 0) ? 4 : 5;   /* bad tag sometimes */
        desc_v[1] = desc_c[1] = H;
        desc_v[2] = desc_c[2] = W;
        desc_v[3] = desc_c[3] = nk;
        desc_v[5] = desc_c[5] = nch;
        desc_v[6] = desc_c[6] = flag;
        *(int16_t **)((char *)desc_v + 0x20) = ktab;
        *(int16_t **)((char *)desc_c + 0x20) = ktab;
        *(int16_t **)((char *)desc_v + 0x28) = btab;
        *(int16_t **)((char *)desc_c + 0x28) = btab;

        int rv = v(out_v, in_v, offset, stride, desc_v);
        int rc = cr_filter_bank_max5x5(out_c, in_c, offset, stride, desc_c);
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }
        if (rv == 0) {
            size_t n = (size_t)(((H - 4) >> 1) * ((W - 4) >> 1) * nch);
            cmp_buf("out", (u8 *)out_v, (u8 *)out_c, n * 2, (u32)t);
        }
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_filter_bank_max5x5\n");
}

/* ---- batch 64: 3x3 float filter-bank + 2x2 max-pool (0x180045a50) ------ */
static void test_filter_bank_max3x3_f32(void)
{
    typedef int (WINAPI *v_i_ppP)(void *, const void *, int *);
    v_i_ppP v = (v_i_ppP)fn_at(RVA(0x180045a50));
    begin("cr_filter_bank_max3x3_f32");
    int bad = g_fail;
    enum { INMAX = 4096, OUTMAX = 1024, KMAX = 48 };
    static float in_v[INMAX], in_c[INMAX];
    static float out_v[OUTMAX], out_c[OUTMAX];
    static float ktab[KMAX * 9], btab[KMAX];
    static int desc_v[16], desc_c[16];

    for (int t = 0; t < 300; t++) {
        int H = 4 + (int)(rnd() % 13);           /* 4..16 */
        int W = 4 + (int)(rnd() % 13);
        int nk = 1 + (int)(rnd() % 3);
        int nch = 1 + (int)(rnd() % 3);
        int mode = (int)(rnd() % 3);             /* 0,1,2 */
        int nkt = nch * nk;

        for (int i = 0; i < nkt * 9; i++)
            ktab[i] = (float)((int)(rnd() % 2001) - 1000) / 250.0f;
        for (int i = 0; i < nch; i++)
            btab[i] = (float)((int)(rnd() % 2001) - 1000) / 100.0f;
        for (int i = 0; i < INMAX; i++) {
            float x = (float)((int)(rnd() % 4001) - 2000) / 100.0f;
            in_v[i] = x; in_c[i] = x;
        }
        for (int i = 0; i < OUTMAX; i++) { out_v[i] = 7.5f; out_c[i] = 7.5f; }

        for (int i = 0; i < 16; i++) desc_v[i] = desc_c[i] = 0;
        desc_v[1] = desc_c[1] = H;
        desc_v[2] = desc_c[2] = W;
        desc_v[3] = desc_c[3] = nk;
        desc_v[5] = desc_c[5] = nch;
        desc_v[6] = desc_c[6] = mode;
        *(float **)((char *)desc_v + 0x20) = ktab;
        *(float **)((char *)desc_c + 0x20) = ktab;
        *(float **)((char *)desc_v + 0x28) = btab;
        *(float **)((char *)desc_c + 0x28) = btab;

        int rv = v(out_v, in_v, desc_v);
        int rc = cr_filter_bank_max3x3_f32(out_c, in_c, desc_c);
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }
        if (rv == 0) {
            size_t n = (size_t)(((H - 2) >> 1) * ((W - 2) >> 1) * nch);
            cmp_buf("out", (u8 *)out_v, (u8 *)out_c, n * 4, (u32)t);
        }
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_filter_bank_max3x3_f32\n");
}

/* ---- batch 65: 5x5 float filter-bank + 2x2 max-pool (0x180044ee0) ------ */
static void test_filter_bank_max5x5_f32(void)
{
    typedef int (WINAPI *v_i_ppiiP)(void *, const void *, int, int, int *);
    v_i_ppiiP v = (v_i_ppiiP)fn_at(RVA(0x180044ee0));
    begin("cr_filter_bank_max5x5_f32");
    int bad = g_fail;
    enum { INMAX = 8192, OUTMAX = 2048, KMAX = 64 };
    static float in_v[INMAX], in_c[INMAX];
    static float out_v[OUTMAX], out_c[OUTMAX];
    static float ktab[KMAX * 25], btab[KMAX];
    static int desc_v[16], desc_c[16];

    for (int t = 0; t < 300; t++) {
        int H = 6 + (int)(rnd() % 15);           /* 6..20 */
        int W = 6 + (int)(rnd() % 15);
        int nk = 1 + (int)(rnd() % 3);
        int nch = 1 + (int)(rnd() % 3);
        int stride = (t % 5 == 0) ? 0 : W;
        int offset = (int)(rnd() % 5);
        int mode = (int)(rnd() % 3);
        int nkt = nch * nk;

        for (int i = 0; i < nkt * 25; i++)
            ktab[i] = (float)((int)(rnd() % 2001) - 1000) / 250.0f;
        for (int i = 0; i < nch; i++)
            btab[i] = (float)((int)(rnd() % 2001) - 1000) / 100.0f;
        for (int i = 0; i < INMAX; i++) {
            float x = (float)((int)(rnd() % 4001) - 2000) / 100.0f;
            in_v[i] = x; in_c[i] = x;
        }
        for (int i = 0; i < OUTMAX; i++) { out_v[i] = 7.5f; out_c[i] = 7.5f; }

        for (int i = 0; i < 16; i++) desc_v[i] = desc_c[i] = 0;
        desc_v[0] = desc_c[0] = (t % 37 == 0) ? 4 : 5;   /* bad tag sometimes */
        desc_v[1] = desc_c[1] = H;
        desc_v[2] = desc_c[2] = W;
        desc_v[3] = desc_c[3] = nk;
        desc_v[5] = desc_c[5] = nch;
        desc_v[6] = desc_c[6] = mode;
        *(float **)((char *)desc_v + 0x20) = ktab;
        *(float **)((char *)desc_c + 0x20) = ktab;
        *(float **)((char *)desc_v + 0x28) = btab;
        *(float **)((char *)desc_c + 0x28) = btab;

        int rv = v(out_v, in_v, offset, stride, desc_v);
        int rc = cr_filter_bank_max5x5_f32(out_c, in_c, offset, stride, desc_c);
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }
        if (rv == 0) {
            size_t n = (size_t)(((H - 4) >> 1) * ((W - 4) >> 1) * nch);
            cmp_buf("out", (u8 *)out_v, (u8 *)out_c, n * 4, (u32)t);
        }
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_filter_bank_max5x5_f32\n");
}

/* ---- batch 66: float filter-chain runner (0x180037d20) ----------------- */
static void test_filter_chain_run(void)
{
    typedef int (WINAPI *v_i_ppPii)(void *, const int *, const int *, int, int);
    v_i_ppPii v = (v_i_ppPii)fn_at(RVA(0x180037d20));
    begin("cr_filter_chain_run");
    int bad = g_fail;
    enum { BUFN = 65536, NSMAX = 4 };
    static float buf_v[BUFN], buf_c[BUFN];
    static float in0_v[4096], in0_c[4096];
    static int stage_v[NSMAX * 12], stage_c[NSMAX * 12];
    static int chain_v[16], chain_c[16], ind_v[16], ind_c[16];
    static float kt[NSMAX][9 * 25], bt[NSMAX][9];

    for (int t = 0; t < 200; t++) {
        int ns  = 1 + (int)(rnd() % NSMAX);
        int off = (int)(rnd() % 3);
        int row = (int)(rnd() % 2);

        for (int i = 0; i < BUFN; i++) {
            float x = (float)((int)(rnd() % 4001) - 2000) / 100.0f;
            buf_v[i] = x; buf_c[i] = x;
        }
        for (int i = 0; i < 4096; i++) {
            float x = (float)((int)(rnd() % 4001) - 2000) / 100.0f;
            in0_v[i] = x; in0_c[i] = x;
        }
        for (int i = 0; i < 16; i++) {
            chain_v[i] = chain_c[i] = 0;
            ind_v[i] = ind_c[i] = 0;
        }

        int stride0 = 0;
        for (int s = 0; s < ns; s++) {
            int tag = (s == 0) ? 5 : ((int)(rnd() % 3) == 0 ? 3 : 5);
            if (t % 53 == 0 && s == ns - 1) tag = 4;      /* bad tag sometimes */
            int H   = 8 + (int)(rnd() % 10);              /* 8..17 */
            int W   = 8 + (int)(rnd() % 10);
            int nk  = 1 + (int)(rnd() % 2);
            int nch = 1 + (int)(rnd() % 2);
            int mode = (int)(rnd() % 3);
            int nkt = nch * nk;
            for (int i = 0; i < nkt * 25; i++)
                kt[s][i] = (float)((int)(rnd() % 2001) - 1000) / 250.0f;
            for (int i = 0; i < nch; i++)
                bt[s][i] = (float)((int)(rnd() % 2001) - 1000) / 100.0f;
            for (int k = 0; k < 12; k++) { stage_v[s*12+k] = 0; stage_c[s*12+k] = 0; }
            stage_v[s*12+0] = stage_c[s*12+0] = tag;
            stage_v[s*12+1] = stage_c[s*12+1] = H;
            stage_v[s*12+2] = stage_c[s*12+2] = W;
            stage_v[s*12+3] = stage_c[s*12+3] = nk;
            stage_v[s*12+5] = stage_c[s*12+5] = nch;
            stage_v[s*12+6] = stage_c[s*12+6] = mode;
            *(float **)((char *)&stage_v[s*12] + 0x20) = kt[s];
            *(float **)((char *)&stage_c[s*12] + 0x20) = kt[s];
            *(float **)((char *)&stage_v[s*12] + 0x28) = bt[s];
            *(float **)((char *)&stage_c[s*12] + 0x28) = bt[s];
            if (s == 0) stride0 = W;
        }
        chain_v[0] = chain_c[0] = ns;
        *(const int **)((char *)chain_v + 8) = stage_v;
        *(const int **)((char *)chain_c + 8) = stage_c;
        ind_v[0] = ind_c[0] = stride0;
        *(const float **)((char *)ind_v + 8) = in0_v;
        *(const float **)((char *)ind_c + 8) = in0_c;

        int rv = v(buf_v, chain_v, ind_v, off, row);
        int rc = cr_filter_chain_run(buf_c, chain_c, ind_c, off, row);
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }
        if (rv == 0)
            cmp_buf("buf", (u8 *)buf_v, (u8 *)buf_c, BUFN * 4, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_filter_chain_run\n");
}

/* ---- batch 67: 3x3 int16 filter-bank + 2x2 max-pool (0x180038080) ------ */
static void test_filter_bank_max3x3_i16(void)
{
    typedef int (WINAPI *v_i_ppP)(void *, const void *, int *);
    v_i_ppP v = (v_i_ppP)fn_at(RVA(0x180038080));
    begin("cr_filter_bank_max3x3_i16");
    int bad = g_fail;
    enum { INMAX = 8192, OUTMAX = 2048, KMAX = 64 };
    static int16_t in_v[INMAX], in_c[INMAX];
    static int16_t out_v[OUTMAX], out_c[OUTMAX];
    static int16_t ktab[KMAX * 9], btab[KMAX];
    static int desc_v[16], desc_c[16];

    for (int t = 0; t < 300; t++) {
        int H = 4 + (int)(rnd() % 15);           /* 4..18 */
        int W = 4 + (int)(rnd() % 15);
        int nk = 1 + (int)(rnd() % 3);
        int nch = 1 + (int)(rnd() % 3);
        int flag = (int)(rnd() & 1);
        int nkt = nch * nk;

        for (int i = 0; i < nkt * 9; i++)
            ktab[i] = (int16_t)((int)(rnd() % 60001) - 30000);
        for (int i = 0; i < nch; i++)
            btab[i] = (int16_t)((int)(rnd() % 2001) - 1000);
        for (int i = 0; i < INMAX; i++) {
            int16_t x = (int16_t)((int)(rnd() % 40001) - 20000);
            in_v[i] = x; in_c[i] = x;
        }
        for (int i = 0; i < OUTMAX; i++) { out_v[i] = 0x7fff; out_c[i] = 0x7fff; }

        for (int i = 0; i < 16; i++) desc_v[i] = desc_c[i] = 0;
        desc_v[1] = desc_c[1] = H;
        desc_v[2] = desc_c[2] = W;
        desc_v[3] = desc_c[3] = nk;
        desc_v[5] = desc_c[5] = nch;
        desc_v[6] = desc_c[6] = flag;
        *(int16_t **)((char *)desc_v + 0x20) = ktab;
        *(int16_t **)((char *)desc_c + 0x20) = ktab;
        *(int16_t **)((char *)desc_v + 0x28) = btab;
        *(int16_t **)((char *)desc_c + 0x28) = btab;

        int rv = v(out_v, in_v, desc_v);
        int rc = cr_filter_bank_max3x3_i16(out_c, in_c, desc_c);
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }
        if (rv == 0) {
            size_t n = (size_t)(((H - 2) >> 1) * ((W - 2) >> 1) * nch);
            cmp_buf("out", (u8 *)out_v, (u8 *)out_c, n * 2, (u32)t);
        }
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_filter_bank_max3x3_i16\n");
}

/* ---- batch 67b: int16 filter-chain runner (0x1800120c0) ---------------- */
static void test_filter_chain_run_i16(void)
{
    typedef int (WINAPI *v_i_ppii)(void *, const int *, int, int);
    v_i_ppii v = (v_i_ppii)fn_at(RVA(0x1800120c0));
    begin("cr_filter_chain_run_i16");
    int bad = g_fail;
    enum { BUFN = 65536, NSMAX = 5 };
    static int16_t buf_v[BUFN], buf_c[BUFN];
    static int stage_v[NSMAX * 12], stage_c[NSMAX * 12];
    static int chain_v[16], chain_c[16];
    static int16_t kt[NSMAX][9 * 25], bt[NSMAX][9];

    for (int t = 0; t < 200; t++) {
        int ns = 1 + (int)(rnd() % NSMAX);
        int start = (int)(rnd() % ns);
        int end   = (t % 23 == 0) ? start - 1 : start + (int)(rnd() % (ns - start));

        for (int i = 0; i < BUFN; i++) {
            int16_t x = (int16_t)((int)(rnd() % 40001) - 20000);
            buf_v[i] = x; buf_c[i] = x;
        }
        for (int i = 0; i < 16; i++) chain_v[i] = chain_c[i] = 0;

        for (int s = 0; s < ns; s++) {
            int tag = ((int)(rnd() % 3) == 0 ? 3 : 5);
            if (t % 53 == 0 && s == ns - 1) tag = 4;      /* bad tag sometimes */
            int H   = 6 + (int)(rnd() % 10);              /* 6..15 */
            int W   = 6 + (int)(rnd() % 10);
            int nk  = 1 + (int)(rnd() % 2);
            int nch = 1 + (int)(rnd() % 2);
            int flag = (int)(rnd() & 1);
            int nkt = nch * nk;
            for (int i = 0; i < nkt * 25; i++)
                kt[s][i] = (int16_t)((int)(rnd() % 60001) - 30000);
            for (int i = 0; i < nch; i++)
                bt[s][i] = (int16_t)((int)(rnd() % 2001) - 1000);
            for (int k = 0; k < 12; k++) { stage_v[s*12+k] = 0; stage_c[s*12+k] = 0; }
            stage_v[s*12+0] = stage_c[s*12+0] = tag;
            stage_v[s*12+1] = stage_c[s*12+1] = H;
            stage_v[s*12+2] = stage_c[s*12+2] = W;
            stage_v[s*12+3] = stage_c[s*12+3] = nk;
            stage_v[s*12+5] = stage_c[s*12+5] = nch;
            stage_v[s*12+6] = stage_c[s*12+6] = flag;
            *(int16_t **)((char *)&stage_v[s*12] + 0x20) = kt[s];
            *(int16_t **)((char *)&stage_c[s*12] + 0x20) = kt[s];
            *(int16_t **)((char *)&stage_v[s*12] + 0x28) = bt[s];
            *(int16_t **)((char *)&stage_c[s*12] + 0x28) = bt[s];
        }
        *(const int **)((char *)chain_v + 8) = stage_v;
        *(const int **)((char *)chain_c + 8) = stage_c;

        int rv = v(buf_v, chain_v, start, end);
        int rc = cr_filter_chain_run_i16(buf_c, chain_c, start, end);
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }
        if (rv == 0)
            cmp_buf("buf", (u8 *)buf_v, (u8 *)buf_c, BUFN * 2, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_filter_chain_run_i16\n");
}

/* ---- batch 67c: 2-D real inverse FFT (0x180040930) --------------------- */
static void test_fft2d_real_bwd(void)
{
    typedef int (WINAPI *v_i_piipuu)(void *, int, int, void *, unsigned, unsigned);
    v_i_piipuu v = (v_i_piipuu)fn_at(RVA(0x180040930));
    begin("cr_fft2d_real_bwd");
    int bad = g_fail;
    enum { MAXN = 256 };
    static float in_v[MAXN*MAXN], in_c[MAXN*MAXN];
    static float out_v[MAXN*MAXN], out_c[MAXN*MAXN];

    for (int t = 0; t < 120; t++) {
        int nrows = 16 << (int)(rnd() % 5);          /* 16,32,64,128,256 */
        int ncols = 16 << (int)(rnd() % 5);
        int orows = 1 + (int)(rnd() % nrows);
        int ocols = 1 + (int)(rnd() % ncols);

        for (int i = 0; i < nrows * ncols; i++) {
            float x = (float)((int)(rnd() % 4001) - 2000) / 100.0f;
            in_v[i] = x; in_c[i] = x;
        }
        for (int i = 0; i < orows * ocols; i++) { out_v[i] = 3.25f; out_c[i] = 3.25f; }

        int rv = v(out_v, orows, ocols, in_v, nrows, ncols);
        int rc = cr_fft2d_real_bwd(out_c, orows, ocols, in_c, nrows, ncols);
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }
        if (rv == 0) {
            cmp_buf("out", (u8 *)out_v, (u8 *)out_c, (size_t)orows * ocols * 4, (u32)t);
            cmp_buf("in",  (u8 *)in_v,  (u8 *)in_c,  (size_t)nrows * ncols * 4, (u32)t);
        }
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_fft2d_real_bwd\n");
}

/* ---- batch 69: morphological margin extract (0x180044d10) -------------- */
/* Allocates a round_up(w+43,32) x (h+12) scratch bitmap, blits src at (6,6),
 * dilates(5)/erodes(5)/extent-fills/borders(6)/erodes(10), then extracts the
 * 6-margin window into dst.  `dst` needs offx==offy==0 and src->a >= dst->a. */
static void test_bitmap_margin_extract(void)
{
    typedef int (WINAPI *fn_t)(void *, const void *);
    fn_t v = (fn_t)fn_at(RVA(0x180044d10));
    begin("cr_bitmap_margin_extract");
    int bad = g_fail;

    enum { MAXW = 48, MAXH = 24, NP = 4096 };
    static uint32_t sbuf[NP], dbuf[NP], dbufc[NP];
    static cr_image sv, sc, dv, dc;

    for (int t = 0; t < 20000; t++) {
        int w  = 1 + (int)(rnd() % MAXW);        /* src->w */
        int h  = 1 + (int)(rnd() % MAXH);        /* src->h */
        int sa = ((w + 31) >> 5) << 5;           /* src stride (bits) */
        /* The scratch is (src->h + 12) rows tall and the final extract reads
         * dst->h rows starting at row 6, so dst->h must be <= src->h + 6.
         * Past that the vendor reads beyond its own scratch — harmless in the
         * Windows pool, but an ASan heap-buffer-overflow (and unmatchable
         * garbage) against our malloc'd buffer.  Keep dst->h in the window. */
        int dh = 1 + (int)(rnd() % (h + 6));     /* 1 .. src->h + 6 */
        int dw = 1 + (int)(rnd() % MAXW);        /* dst->w */
        int da = ((dw + 31) >> 5) << 5;          /* dst stride (bits) */

        for (int i = 0; i < NP; i++) {
            uint32_t u = (uint32_t)rnd();
            sbuf[i] = u; dbuf[i] = u; dbufc[i] = u;
        }

        memset(&sv, 0, sizeof sv); memset(&sc, 0, sizeof sc);
        sv.a = sa; sv.b = h; sv.data = sbuf; sv.w = w; sv.h = h;
        sv.offx = 0; sv.offy = 0;
        sc = sv;

        memset(&dv, 0, sizeof dv); memset(&dc, 0, sizeof dc);
        dv.a = da; dv.b = dh; dv.data = dbuf; dv.w = dw; dv.h = dh;
        dv.offx = 0; dv.offy = 0;
        dc = dv; dc.data = dbufc;

        /* exercise the two guards on ~1/8 of the runs */
        switch (t & 15) {
        case 1:  sv.offx = 1; sc.offx = 1; break;              /* copy_shift 0x69 */
        case 2:  dv.a = (((w + 43) >> 5) << 5) + 32;           /* src->a < dst->a */
                 dc.a = dv.a; break;
        default: break;
        }

        int rv = v(&dv, &sv);
        int rc = cr_bitmap_margin_extract(&dc, &sc);
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }
        cmp_buf("dst", (unsigned char *)dbuf, (unsigned char *)dbufc,
                sizeof dbuf, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_bitmap_margin_extract\n");
}

/* 0x180010110 — bitmap filter pipeline + 7-tap FIR blur. */
static void test_bitmap_filter_fir(void)
{
    typedef int (WINAPI *fn_t)(void *, const void *, int, float, int);
    fn_t v = (fn_t)fn_at(RVA(0x180010110));
    begin("cr_bitmap_filter_fir");
    int bad = g_fail;

    enum { MAXW = 24, MAXH = 24, NP = MAXW * MAXH };
    static u8 sbuf[NP], obv[NP], obc[NP];
    static cr_image sv, sc, ov, oc;

    for (int t = 0; t < 4000; t++) {
        int w = 8 + (int)(rnd() % (MAXW - 8));   /* >= 8: the 7-tap FIR needs it */
        int h = 8 + (int)(rnd() % (MAXH - 8));
        int n = 1 + (int)(rnd() % 5);
        int flag = (int)(rnd() & 1u);
        float sigma = (float)(rnd() % 1000) / 500.0f;

        for (int i = 0; i < NP; i++) sbuf[i] = (u8)rnd();
        memset(obv, 0xAA, sizeof obv);
        memset(obc, 0xAA, sizeof obc);

        cr_image_set(&sv, sbuf, w, h);
        cr_image_set(&sc, sbuf, w, h);
        cr_image_set(&ov, obv, w, h);
        cr_image_set(&oc, obc, w, h);

        int rv = v(&ov, &sv, n, sigma, flag);
        int rc = cr_bitmap_filter_fir(&oc, &sc, n, sigma, flag);
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }
        cmp_buf("out", obv, obc, sizeof obv, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_bitmap_filter_fir\n");
}

/* 0x18003f360 — mask an int16 image through the bitmap filter pipeline. */
static void test_bitmap_filter_apply_s16(void)
{
    typedef int (WINAPI *fn_t)(void *, const void *, const void *);
    fn_t v = (fn_t)fn_at(RVA(0x18003f360));
    begin("cr_bitmap_filter_apply_s16");
    int bad = g_fail;

    enum { MAXW = 24, MAXH = 24, NP = MAXW * MAXH };
    static u8  sbuf[NP];
    static int16_t dv[NP], dc[NP];
    static u8  cfgv[16], cfgc[16];
    static cr_image sv, sc, ov, oc;

    for (int t = 0; t < 4000; t++) {
        int w = 8 + (int)(rnd() % (MAXW - 8));   /* >= 8 for the 7-tap FIR */
        int h = 8 + (int)(rnd() % (MAXH - 8));

        for (int i = 0; i < NP; i++) sbuf[i] = (u8)rnd();
        for (int i = 0; i < NP; i++) {
            int16_t val = (int16_t)((int)(rnd() % 65536) - 32768);
            dv[i] = val; dc[i] = val;
        }
        memset(cfgv, 0, sizeof cfgv); memset(cfgc, 0, sizeof cfgc);
        cfgv[8] = (u8)(rnd() & 1u);
        cfgc[8] = cfgv[8];

        cr_image_set(&sv, sbuf, w, h);
        cr_image_set(&sc, sbuf, w, h);
        memset(&ov, 0, sizeof ov); memset(&oc, 0, sizeof oc);
        ov.a = w; ov.b = h; ov.data = dv; ov.w = w; ov.h = h;
        oc = ov; oc.data = dc;

        int rv = v(&ov, &sv, cfgv);
        int rc = cr_bitmap_filter_apply_s16(&oc, &sc, cfgc);
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }
        cmp_buf("pix", (const unsigned char *)dv, (const unsigned char *)dc,
                sizeof dv, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_bitmap_filter_apply_s16\n");
}

/* 0x180032af0 — weighted 2-D FFT filter of an int16 image. */
static void test_fft_weighted_apply_32af0(void)
{
    typedef int (WINAPI *fn_t)(void *, const void *, const void *);
    fn_t v = (fn_t)fn_at(RVA(0x180032af0));
    begin("cr_fft_weighted_apply_32af0");
    int bad = g_fail;

    enum { MAXWH = 24, NP = MAXWH * MAXWH, NW = 32 * 32 };
    static int16_t dv[NP], dc[NP];
    static float wts[NW];
    static u8 cfgv[16], cfgc[16];
    static cr_image ov, oc;

    for (int t = 0; t < 3000; t++) {
        int wa = 1 + (int)(rnd() % MAXWH);
        /* The pipeline's cr_fft2d_prep_1e920 reads `img.data` with stride
         * desc[4] and width desc[5]=hb; when the padded width W exceeds 3*hb it
         * reads past the hb*wa-float source buffer (harmless in the Windows
         * pool, unmatchable against our malloc'd buffer).  With hb >= 6,
         * W = round_up_pow2(max(hb,9)) <= 3*hb, so every read stays in bounds. */
        int hb = 6 + (int)(rnd() % (MAXWH - 5));

        for (int i = 0; i < NP; i++) {
            int16_t val = (int16_t)((int)(rnd() % 65536) - 32768);
            dv[i] = val; dc[i] = val;
        }
        for (int i = 0; i < NW; i++)
            wts[i] = (float)((int)(rnd() % 2000) - 1000) * 0.001f;
        for (int i = 0; i < 16; i++) cfgv[i] = (u8)rnd();
        cfgv[4] = (u8)(rnd() % 3u);   /* 0/1: run the pipeline; 2: early 0x1 */
        for (int i = 0; i < 16; i++) cfgc[i] = cfgv[i];

        memset(&ov, 0, sizeof ov); memset(&oc, 0, sizeof oc);
        ov.a = wa; ov.b = hb; ov.data = dv; ov.w = wa; ov.h = hb;
        oc = ov; oc.data = dc;

        int rv = v(&ov, wts, cfgv);
        int rc = cr_fft_weighted_apply_32af0((int *)&oc, wts, cfgc);
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }
        cmp_buf("pix", (const unsigned char *)dv, (const unsigned char *)dc,
                (u32)(wa * hb * 2), (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_fft_weighted_apply_32af0\n");
}

/* ---- batch 70: grid-bucketed keypoint sampler (0x1800466f0) ------------- */
/* Buckets `npts` keypoint records into a rows x cols grid, shuffles the cell
 * order, then emits up to `maxout` head payloads (record+4) into `pts[out].f0`.
 * `maxout` must be <= npts (else the vendor spins) and `(int16)cfg[0x10]` must
 * be >= npts. */
static void test_keypoint_grid_sample(void)
{
    typedef int (WINAPI *fn_t)(void *, int *, int, int, const int *,
                               uint32_t, const uint8_t *);
    fn_t v = (fn_t)fn_at(RVA(0x1800466f0));
    begin("cr_keypoint_grid_sample");
    int bad = g_fail;

    enum { NP = 64, CB = 0x28 };
    static cr_pt8 pv[NP], pc[NP];
    static int    dims[6];
    static uint8_t cfg[CB];

    for (int t = 0; t < 20000; t++) {
        int npts   = 1 + (int)(rnd() % NP);
        int cols   = 1 + (int)(rnd() % 8);
        int rows   = 1 + (int)(rnd() % 8);
        int cap    = npts + (int)(rnd() % 8);
        int maxout = 1 + (int)(rnd() % npts);
        int W      = 1 + (int)(rnd() % 200);
        int H      = 1 + (int)(rnd() % 200);

        memset(cfg, 0, sizeof cfg);
        *(int16_t *)(cfg + 0x10) = (int16_t)cap;
        cfg[0x25] = (uint8_t)cols;
        cfg[0x26] = (uint8_t)rows;
        memset(dims, 0, sizeof dims);
        dims[4] = W;
        dims[5] = H;

        for (int i = 0; i < NP; i++) {
            pv[i].s.f0 = (int32_t)rnd();
            pv[i].s.f4 = (int16_t)rnd();
            pv[i].s.f6 = (int16_t)rnd();
            pc[i] = pv[i];
        }

        uint32_t seed = (uint32_t)rnd();
        int ov = -12345, oc = -12345;
        int rv = v(pv, &ov, npts, maxout, dims, seed, cfg);
        int rc = cr_keypoint_grid_sample(pc, &oc, npts, maxout, dims, seed, cfg);
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }
        if (ov != oc) mismatch("cnt", (u32)t, (u32)ov, (u32)oc);
        cmp_buf("pts", (unsigned char *)pv, (unsigned char *)pc,
                sizeof pv, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_keypoint_grid_sample\n");
}

/* ---- batch 71: normalized int16 FIR down each column (0x180011a70) ------ */
/* Vertical separable-blur pass: for each of `stride` columns gather `count`
 * row-major samples (stride `stride`), run a normalized FIR of `klen` (odd)
 * taps, writing back in place.  Needs count >= klen so the gather stays in
 * bounds; the kernel must keep every cumulative denominator non-zero. */
static void test_fir_norm_s16(void)
{
    typedef int (WINAPI *fn_t)(void *, const void *, const void *,
                               int, int, int);
    fn_t v = (fn_t)fn_at(RVA(0x180011a70));
    begin("cr_fir_norm_s16");
    int bad = g_fail;

    enum { MAXW = 40, MAXH = 40, NP = MAXW * MAXH, KMAX = 15 };
    static int16_t iv[NP], ic[NP], ov[NP], oc[NP], kern[KMAX];

    for (int t = 0; t < 20000; t++) {
        int klen = 1 + 2 * (int)(rnd() % ((KMAX + 1) / 2));  /* odd 1..15 */
        int h    = klen >> 1;
        int W    = 1 + (int)(rnd() % MAXW);                  /* leading dim */
        int H    = klen + (int)(rnd() % (MAXH - klen + 1));  /* >= klen */

        /* pick a kernel whose every cumulative denominator is non-zero */
        int ok = 0;
        for (int attempt = 0; attempt < 40 && !ok; attempt++) {
            for (int k = 0; k < klen; k++)
                kern[k] = (int16_t)rnd();
            int64_t d = kern[h];
            ok = (d != 0);
            for (int k = 1; k <= h && ok; k++) {
                d += 2LL * kern[h - k];
                if (d == 0) ok = 0;
            }
        }
        if (!ok) continue;

        for (int i = 0; i < W * H; i++) {
            int16_t x = (int16_t)rnd();
            iv[i] = x; ic[i] = x; ov[i] = 0x7f; oc[i] = 0x7f;
        }
        if (t % 23 == 0) W = -1;   /* exercise the stride<=0 early-out */

        int rv = v(ov, iv, kern, klen, W, H);
        int rc = cr_fir_norm_s16(oc, ic, kern, klen, W, H);
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }
        if (W > 0)
            cmp_buf("out", (unsigned char *)ov, (unsigned char *)oc,
                    (size_t)W * H * 2, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_fir_norm_s16\n");
}

/* ---- 0x18001e400: horizontal twin of cr_fir_norm_s16 ------------------- */
static void test_fir_norm_rows_s16(void)
{
    typedef int (WINAPI *fn_t)(void *, const void *, const void *,
                               int, int, int);
    fn_t v = (fn_t)fn_at(RVA(0x18001e400));
    begin("cr_fir_norm_rows_s16");
    int bad = g_fail;

    enum { MAXW = 40, MAXH = 40, NP = MAXW * MAXH, KMAX = 15 };
    static int16_t iv[NP], ic[NP], ov[NP], oc[NP], kern[KMAX];

    for (int t = 0; t < 20000; t++) {
        int klen = 1 + 2 * (int)(rnd() % ((KMAX + 1) / 2));  /* odd 1..15 */
        int h    = klen >> 1;
        int W    = klen + (int)(rnd() % (MAXW - klen + 1));  /* >= klen */
        int H    = 1 + (int)(rnd() % MAXH);

        int ok = 0;
        for (int attempt = 0; attempt < 40 && !ok; attempt++) {
            for (int k = 0; k < klen; k++)
                kern[k] = (int16_t)rnd();
            int64_t d = kern[h];
            ok = (d != 0);
            for (int k = 1; k <= h && ok; k++) {
                d += 2LL * kern[h - k];
                if (d == 0) ok = 0;
            }
        }
        if (!ok) continue;

        for (int i = 0; i < W * H; i++) {
            int16_t x = (int16_t)rnd();
            iv[i] = x; ic[i] = x; ov[i] = 0x7f; oc[i] = 0x7f;
        }

        int rv = v(ov, iv, kern, klen, W, H);
        int rc = cr_fir_norm_rows_s16(oc, ic, kern, klen, W, H);
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }
        cmp_buf("out", (unsigned char *)ov, (unsigned char *)oc,
                (size_t)W * H * 2, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_fir_norm_rows_s16\n");
}

/* ---- 0x1800278f0: separable Q15 Gaussian blur (int16) ------------------ */
static void test_sep_gauss_blur_s16(void)
{
    typedef int (WINAPI *fn_t)(void *, const void *, float, unsigned);
    fn_t v = (fn_t)fn_at(RVA(0x1800278f0));
    begin("cr_sep_gauss_blur_s16");
    int bad = g_fail;

    enum { MAXD = 40, NP = MAXD * MAXD };
    static int16_t sv[NP], sc[NP], dv[NP], dc[NP];
    static cr_image sdv, sdc, ddv, ddc;

    for (int t = 0; t < 6000; t++) {
        int klen = 1 + 2 * (int)(rnd() % 7);                 /* odd 1..13 */
        int W = klen + (int)(rnd() % (MAXD - klen + 1));
        int H = klen + (int)(rnd() % (MAXD - klen + 1));
        float sigma = 0.5f + (float)(rnd() % 400) / 100.0f;

        for (int i = 0; i < W * H; i++) {
            int16_t x = (int16_t)rnd();
            sv[i] = x; sc[i] = x; dv[i] = 0x7f; dc[i] = 0x7f;
        }
        memset(&sdv, 0, sizeof sdv); memset(&sdc, 0, sizeof sdc);
        sdv.a = W; sdv.b = H; sdv.data = sv; sdv.w = W; sdv.h = H;
        sdc.a = W; sdc.b = H; sdc.data = sc; sdc.w = W; sdc.h = H;
        memset(&ddv, 0, sizeof ddv); memset(&ddc, 0, sizeof ddc);
        ddv.a = W; ddv.b = H; ddv.data = dv; ddv.w = W; ddv.h = H;
        ddc.a = W; ddc.b = H; ddc.data = dc; ddc.w = W; ddc.h = H;

        /* exercise the guards */
        switch (t & 15) {
        case 1: ddv.a = W + 1; ddc.a = W + 1; break;    /* dst a != w */
        case 2: sdv.offx = 1;  sdc.offx = 1;  break;    /* src offx != 0 */
        case 3: klen = 2 + 2 * (int)(rnd() % 6); break; /* even klen */
        default: break;
        }

        int rv = v(&ddv, &sdv, sigma, (unsigned)klen);
        int rc = cr_sep_gauss_blur_s16(&ddc, &sdc, sigma, (unsigned)klen);
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }
        if (rv == 0)
            cmp_buf("dst", (unsigned char *)dv, (unsigned char *)dc,
                    (size_t)W * H * 2, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_sep_gauss_blur_s16\n");
}

/* ---- batch 69c: separable Gaussian blur, reflect borders (0x180013a30) --- */
static void test_sep_gauss_blur_reflect(void)
{
    typedef int (WINAPI *fn_t)(void *, const void *, float, int);
    fn_t v = (fn_t)fn_at(RVA(0x180013a30));
    begin("cr_sep_gauss_blur_s16_reflect");
    int bad = g_fail;

    enum { MAXD = 40, NP = MAXD * MAXD };
    static int16_t sv[NP], sc[NP], dv[NP], dc[NP];
    static cr_image sdv, sdc, ddv, ddc;

    for (int t = 0; t < 6000; t++) {
        /* klen is kept odd: the reflect scratch is sized w-1+klen, so an even
         * klen writes one sample past it (in the vendor as well as here). */
        int klen = 1 + 2 * (int)(rnd() % 7);                 /* odd 1..13 */
        int W = klen + (int)(rnd() % (MAXD - klen + 1));
        int H = klen + (int)(rnd() % (MAXD - klen + 1));
        float sigma = 0.5f + (float)(rnd() % 400) / 100.0f;

        for (int i = 0; i < W * H; i++) {
            int16_t x = (int16_t)rnd();
            sv[i] = x; sc[i] = x; dv[i] = 0x7f; dc[i] = 0x7f;
        }
        memset(&sdv, 0, sizeof sdv); memset(&sdc, 0, sizeof sdc);
        sdv.a = W; sdv.b = H; sdv.data = sv; sdv.w = W; sdv.h = H;
        sdc.a = W; sdc.b = H; sdc.data = sc; sdc.w = W; sdc.h = H;
        memset(&ddv, 0, sizeof ddv); memset(&ddc, 0, sizeof ddc);
        ddv.a = W; ddv.b = H; ddv.data = dv; ddv.w = W; ddv.h = H;
        ddc.a = W; ddc.b = H; ddc.data = dc; ddc.w = W; ddc.h = H;

        /* exercise the guards (never an even klen — see above) */
        switch (t & 15) {
        case 1: ddv.a = W + 1; ddc.a = W + 1; break;    /* dst a != w */
        case 2: sdv.offx = 1;  sdc.offx = 1;  break;    /* src offx != 0 */
        case 3: sdv.b = H + 1; sdc.b = H + 1; break;    /* src b != h */
        default: break;
        }

        int rv = v(&ddv, &sdv, sigma, klen);
        int rc = cr_sep_gauss_blur_s16_reflect(&ddc, &sdc, sigma, klen);
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }
        if (rv == 0)
            cmp_buf("dst", (unsigned char *)dv, (unsigned char *)dc,
                    (size_t)W * H * 2, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_sep_gauss_blur_s16_reflect\n");
}

/* ---- batch 72: filter chain -> linear layers -> 2-way softmax ---------- */
static void test_linear_softmax2(void)
{
    typedef int (WINAPI *fn_t)(float *, const int *, const int *, int, int);
    fn_t v = (fn_t)fn_at(RVA(0x18002ee10));
    begin("cr_linear_softmax2");
    int bad = g_fail;

    enum { INMAX = 4096, NLM = 2 };
    static float in0[INMAX];
    static int   stage[12];
    static int   desc_v[16], desc_c[16], ind_v[16], ind_c[16];
    static int   lin_v[8 * NLM], lin_c[8 * NLM];
    /* The stage-0 5x5 filter bank's kernel table holds nch*nk kernels of 25
     * floats (nk and nch are each 1..2 here, so up to 4 kernels).  A 2-kernel
     * table made the vendor/clean-room read past it -> ASan
     * global-buffer-overflow in cr_filter_bank_max5x5_f32. */
    static float kt[4 * 25], bt[2];
    static float lw[NLM][3 * 64], lb[NLM][3];

    for (int t = 0; t < 400; t++) {
        int off  = (int)(rnd() % 3);
        int row  = (int)(rnd() % 2);
        int H    = 8 + (int)(rnd() % 6);       /* 8..13 */
        int W    = 8 + (int)(rnd() % 6);
        int nk   = 1 + (int)(rnd() % 2);
        int nch  = 1 + (int)(rnd() % 2);
        int nlin = (int)(rnd() % 3);           /* 0..2 layers */
        int nout = ((H - 4) >> 1) * ((W - 4) >> 1) * nch;

        for (int i = 0; i < INMAX; i++)
            in0[i] = (float)((int)(rnd() % 4001) - 2000) / 100.0f;
        for (int i = 0; i < 4 * 25; i++)
            kt[i] = (float)((int)(rnd() % 2001) - 1000) / 250.0f;
        for (int i = 0; i < 2; i++)
            bt[i] = (float)((int)(rnd() % 2001) - 1000) / 100.0f;

        /* stage 0: 5x5 float filter bank writing `nout` floats into buf */
        for (int i = 0; i < 12; i++) stage[i] = 0;
        stage[0] = 5; stage[1] = H; stage[2] = W;
        stage[3] = nk; stage[5] = nch; stage[6] = 0;
        *(float **)((char *)stage + 0x20) = kt;
        *(float **)((char *)stage + 0x28) = bt;

        /* stacked linear layers, each consuming the previous layer's output */
        memset(lin_v, 0, sizeof lin_v);
        int cur = nout;
        for (int l = 0; l < nlin; l++) {
            int nl   = (int)(rnd() % 4);       /* nrows 0..3 */
            int post = (int)(rnd() % 3);       /* 0..2 (2 -> 0x69) */
            int wmax = (nl > 0 && cur > 0) ? nl * cur : 0;
            for (int i = 0; i < wmax; i++)
                lw[l][i] = (float)((int)(rnd() % 4001) - 2000) / 200.0f;
            for (int i = 0; i < nl; i++)
                lb[l][i] = (float)((int)(rnd() % 2001) - 1000) / 50.0f;
            lin_v[l * 8 + 0] = cur;
            lin_v[l * 8 + 1] = nl;
            lin_v[l * 8 + 2] = post;
            *(float **)((char *)&lin_v[l * 8] + 0x10) = lw[l];
            *(float **)((char *)&lin_v[l * 8] + 0x18) = lb[l];
            cur = nl;
        }
        memcpy(lin_c, lin_v, sizeof lin_v);

        memset(desc_v, 0, sizeof desc_v); memset(desc_c, 0, sizeof desc_c);
        memset(ind_v, 0, sizeof ind_v);   memset(ind_c, 0, sizeof ind_c);
        desc_v[0] = desc_c[0] = 1;                        /* one chain stage */
        *(const int **)((char *)desc_v + 0x08) = stage;
        *(const int **)((char *)desc_c + 0x08) = stage;
        desc_v[4] = desc_c[4] = nlin;
        *(const int **)((char *)desc_v + 0x18) = lin_v;
        *(const int **)((char *)desc_c + 0x18) = lin_c;
        desc_v[8] = desc_c[8] = 64;                       /* scratch floats  */
        ind_v[0] = ind_c[0] = W;
        *(const float **)((char *)ind_v + 0x08) = in0;
        *(const float **)((char *)ind_c + 0x08) = in0;

        float ov = 0.0f, oc = 0.0f;
        int rv = v(&ov, desc_v, ind_v, off, row);
        int rc = cr_linear_softmax2(&oc, desc_c, ind_c, off, row);
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }
        if (rv == 0 && cr_f2u(ov) != cr_f2u(oc))
            mismatch("out", (u32)t, cr_f2u(ov), cr_f2u(oc));
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_linear_softmax2\n");
}

/* ---- batch 72b: int16 image normalise -> chain classifier (0x180016bd0) -- */
static void test_chain_classify_i16(void)
{
    typedef int (WINAPI *fn_t)(float *, const int *, const void *, int, int);
    fn_t v = (fn_t)fn_at(RVA(0x180016bd0));
    begin("cr_chain_classify_i16");
    int bad = g_fail;

    enum { INMAX = 4096, NLM = 2 };
    static int16_t src[INMAX];
    static int   stage[12];
    static int   chain_v[16], chain_c[16], src_v[16], src_c[16];
    static int   lin_v[8 * NLM], lin_c[8 * NLM];
    static float kt[2 * 25], bt[2];
    static float lw[NLM][3 * 64], lb[NLM][3];

    for (int t = 0; t < 400; t++) {
        int off  = (int)(rnd() % 3);
        int row  = (int)(rnd() % 2);
        int H    = 8 + (int)(rnd() % 6);       /* 8..13 */
        int W    = 8 + (int)(rnd() % 6);
        int nk   = 1;                          /* chain input is one W x H plane */
        (void)rnd();                           /* keep the RNG stream aligned    */
        int nch  = 1 + (int)(rnd() % 2);
        int nlin = (int)(rnd() % 3);           /* 0..2 layers */
        int stride = W + (int)(rnd() % 3);
        int nout = ((H - 4) >> 1) * ((W - 4) >> 1) * nch;

        for (int i = 0; i < INMAX; i++)
            src[i] = (int16_t)((int)(rnd() % 65536) - 32768);
        for (int i = 0; i < 2 * 25; i++)
            kt[i] = (float)((int)(rnd() % 2001) - 1000) / 250.0f;
        for (int i = 0; i < 2; i++)
            bt[i] = (float)((int)(rnd() % 2001) - 1000) / 100.0f;

        for (int i = 0; i < 12; i++) stage[i] = 0;
        stage[0] = 5; stage[1] = H; stage[2] = W;
        stage[3] = nk; stage[5] = nch; stage[6] = 0;
        *(float **)((char *)stage + 0x20) = kt;
        *(float **)((char *)stage + 0x28) = bt;

        memset(lin_v, 0, sizeof lin_v);
        int cur = nout;
        for (int l = 0; l < nlin; l++) {
            int nl   = (int)(rnd() % 4);
            int post = (int)(rnd() % 3);
            int wmax = (nl > 0 && cur > 0) ? nl * cur : 0;
            for (int i = 0; i < wmax; i++)
                lw[l][i] = (float)((int)(rnd() % 4001) - 2000) / 200.0f;
            for (int i = 0; i < nl; i++)
                lb[l][i] = (float)((int)(rnd() % 2001) - 1000) / 50.0f;
            lin_v[l * 8 + 0] = cur;
            lin_v[l * 8 + 1] = nl;
            lin_v[l * 8 + 2] = post;
            *(float **)((char *)&lin_v[l * 8] + 0x10) = lw[l];
            *(float **)((char *)&lin_v[l * 8] + 0x18) = lb[l];
            cur = nl;
        }
        memcpy(lin_c, lin_v, sizeof lin_v);

        memset(chain_v, 0, sizeof chain_v); memset(chain_c, 0, sizeof chain_c);
        memset(src_v, 0, sizeof src_v);     memset(src_c, 0, sizeof src_c);
        chain_v[0] = chain_c[0] = 1;
        *(const int **)((char *)chain_v + 0x08) = stage;
        *(const int **)((char *)chain_c + 0x08) = stage;
        chain_v[4] = chain_c[4] = nlin;
        *(const int **)((char *)chain_v + 0x18) = lin_v;
        *(const int **)((char *)chain_c + 0x18) = lin_c;
        chain_v[8] = chain_c[8] = 64;
        *(const int16_t **)((char *)src_v + 0x08) = src;
        *(const int16_t **)((char *)src_c + 0x08) = src;
        *(int *)((char *)src_v + 0x10) = stride;
        *(int *)((char *)src_c + 0x10) = stride;

        float ov = 0.0f, oc = 0.0f;
        int rv = v(&ov, chain_v, src_v, off, row);
        int rc = cr_chain_classify_i16(&oc, chain_c, src_c, off, row);
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }
        if (rv == 0 && cr_f2u(ov) != cr_f2u(oc))
            mismatch("out", (u32)t, cr_f2u(ov), cr_f2u(oc));
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_chain_classify_i16\n");
}

/* ---- batch 73: structure-tensor score over a mask (0x180029870) ---------- */
static void test_structure_tensor_score(void)
{
    typedef uint64_t (WINAPI *fn_t)(int16_t *, int *, void *, void *);
    fn_t v = (fn_t)fn_at(RVA(0x180029870));
    begin("cr_structure_tensor_score");
    int bad = g_fail;

    static int16_t src[4096];
    static int16_t ov[4], oc[4];
    static u8 geo[0x20];
    static u8 md[0x20];
    static u32 bits[512];
    static u8 obj[0x10];

    for (int t = 0; t < 3000; t++) {
        int w = 8 + (int)(rnd() % 25u);        /* 8..32 */
        int h = 8 + (int)(rnd() % 25u);        /* 8..32 */

        for (int i = 0; i < w * h; i++)
            src[i] = (int16_t)((int)(rnd() % 65536) - 32768);

        /* geo: cr_image-shaped, data = coefficient plane, W=w, H=h */
        memset(geo, 0, 0x20);
        *(int *)(geo + 0x00) = w;
        *(int *)(geo + 0x04) = h;
        *(void **)(geo + 0x08) = src;
        *(int *)(geo + 0x10) = w;
        *(int *)(geo + 0x14) = h;

        /* mask descriptor: stride = *mask, bits at +8, x/y offset at +0x18/1c */
        int stride = w;
        for (int i = 0; i < 512; i++) bits[i] = 0;
        for (int y = 0; y < h; y++)
            for (int x = 0; x < w; x++) {
                int bi = y * stride + x;
                if (rnd() & 1u)
                    bits[bi >> 5] |= 1u << (bi & 31);
            }
        memset(md, 0, 0x20);
        *(int *)(md + 0x00) = stride;
        *(void **)(md + 0x08) = bits;
        *(int *)(md + 0x18) = 0;               /* xoff */
        *(int *)(md + 0x1c) = 0;               /* yoff */

        *(float *)(obj + 8) = 0.5f + (float)(rnd() % 300u) / 100.0f;

        ov[0] = oc[0] = 0x1234;
        uint64_t rv = v(ov, (int *)md, geo, obj);
        uint64_t rc = cr_structure_tensor_score(oc, (const int *)md,
                                                (const cr_image *)geo,
                                                (const char *)obj);
        if ((int)rv != (int)rc) mismatch("ret", (u32)t, (u32)rv, (u32)rc);
        if (ov[0] != oc[0])
            mismatch("out", (u32)t, (u32)(uint16_t)ov[0], (u32)(uint16_t)oc[0]);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_structure_tensor_score\n");
}

/* ---- batch 73b: fixed-point 2D conv block (0x1800231a0) ----------------- */
static void test_block_conv_231a0(void)
{
    typedef uint64_t (WINAPI *fn_t)(int16_t *, intptr_t *, void *);
    fn_t v = (fn_t)fn_at(RVA(0x1800231a0));
    begin("cr_block_conv_231a0");
    int bad = g_fail;

    /* Kernel table: the function advances the kernel base by K*9 shorts for
     * each of the R slices, so it holds R*K rows of 3x3 (R,K are each 1..6).
     * A single-slice K*9 table made it read past the end -> ASan
     * global-buffer-overflow in cr_block_conv_231a0. */
    static int16_t kbuf[6 * 6 * 9];                    /* kernel, R*K 3x3 rows */
    static int16_t sbuf[16];                           /* bias source        */
    static int16_t dbuf[4][(16 + 8) * 8 + 32];         /* 4 data buffers     */
    static int16_t ov[256], oc[256];
    static long long desc[8];                          /* 8-byte aligned     */

    for (int t = 0; t < 4000; t++) {
        int R    = 1 + (int)(rnd() % 6u);              /* 1..6  */
        int K    = 1 + (int)(rnd() % 6u);              /* 1..6  */
        int Wout = 1 + (int)(rnd() % 16u);             /* 1..16 */
        int line = Wout + 8;

        for (int i = 0; i < R * K * 9; i++)
            kbuf[i] = (int16_t)((int)(rnd() % 65536) - 32768);
        for (int i = 0; i < R + 2; i++)
            sbuf[i] = (int16_t)((int)(rnd() % 65536) - 32768);
        for (int j = 0; j < 4; j++)
            for (int i = 0; i < line * K + 16; i++)
                dbuf[j][i] = (int16_t)((int)(rnd() % 65536) - 32768);

        memset(desc, 0, sizeof(desc));
        char *d = (char *)desc;
        *(int *)(d + 0x08) = line;
        *(int *)(d + 0x0c) = K;
        *(int *)(d + 0x10) = Wout;
        *(int *)(d + 0x14) = R;
        *(int *)(d + 0x18) = (rnd() & 1u) ? 1 : 0;
        *(void **)(d + 0x20) = kbuf;
        *(void **)(d + 0x28) = sbuf;

        intptr_t ptrs[4];
        for (int j = 0; j < 4; j++) ptrs[j] = (intptr_t)dbuf[j];

        memset(ov, 0, sizeof(ov));
        memset(oc, 0, sizeof(oc));
        uint64_t rv = v(ov, ptrs, d);
        uint64_t rc = cr_block_conv_231a0(oc, (const intptr_t *)ptrs, d);
        if ((int)rv != (int)rc)
            mismatch("ret", (u32)t, (u32)rv, (u32)rc);
        int n = Wout * R;
        cmp_buf("out", (const unsigned char *)ov, (const unsigned char *)oc,
                (u32)(n * 2), (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_block_conv_231a0\n");
}

/* ---- batch 73c: structure-tensor from u8 image (0x180044270) ----------- */
static void test_structure_tensor_score_img(void)
{
    typedef uint64_t (WINAPI *fn_t)(int16_t *, int *, void *, uint64_t);
    fn_t v = (fn_t)fn_at(RVA(0x180044270));
    begin("cr_structure_tensor_score_img");
    int bad = g_fail;

    static uint8_t sbuf[4096];
    static int16_t ov[4], oc[4];
    static u8      geo[0x20];                 /* mask descriptor  */
    static u8      obj[0x10];
    static u8      srcimg[0x30];              /* cr_image-shaped u8 source */
    static u32     bits[512];

    for (int t = 0; t < 3000; t++) {
        int w = 8 + (int)(rnd() % 25u);        /* 8..32 */
        int h = 8 + (int)(rnd() % 25u);        /* 8..32 */

        for (int i = 0; i < w * h; i++)
            sbuf[i] = (uint8_t)(rnd() % 256);

        /* src cr_image: a=w, b=h, data=sbuf, w, h, offx=0, offy=0 */
        memset(srcimg, 0, 0x30);
        *(int *)(srcimg + 0x00) = w;
        *(int *)(srcimg + 0x04) = h;
        *(void **)(srcimg + 0x08) = sbuf;
        *(int *)(srcimg + 0x10) = w;
        *(int *)(srcimg + 0x14) = h;
        *(int *)(srcimg + 0x18) = 0;           /* offx */
        *(int *)(srcimg + 0x1c) = 0;           /* offy */

        /* mask descriptor (geo): stride = w, bits plane, x/y offset = 0 */
        int stride = w;
        for (int i = 0; i < 512; i++) bits[i] = 0;
        for (int y = 0; y < h; y++)
            for (int x = 0; x < w; x++) {
                int bi = y * stride + x;
                if (rnd() & 1u)
                    bits[bi >> 5] |= 1u << (bi & 31);
            }
        memset(geo, 0, 0x20);
        *(int *)(geo + 0x00) = stride;
        *(void **)(geo + 0x08) = bits;
        *(int *)(geo + 0x18) = 0;
        *(int *)(geo + 0x1c) = 0;

        *(float *)(obj + 8) = 0.5f + (float)(rnd() % 300u) / 100.0f;

        ov[0] = oc[0] = 0x1234;
        uint64_t rv = v(ov, (int *)geo, srcimg, (uint64_t)obj);
        uint64_t rc = cr_structure_tensor_score_img(oc, (int *)geo,
                                                   (const cr_image *)srcimg,
                                                   (uint64_t)obj);
        if ((int)rv != (int)rc)
            mismatch("ret", (u32)t, (u32)rv, (u32)rc);
        if (ov[0] != oc[0])
            mismatch("out", (u32)t, (u32)(uint16_t)ov[0], (u32)(uint16_t)oc[0]);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_structure_tensor_score_img\n");
}

/* ---- batch 73d: column-major template NCC (0x180035150) ----------------- */
static void test_template_ncc_35150(void)
{
    typedef int (WINAPI *fn_t)(int16_t *, int16_t *, int16_t *, uint32_t, int, int);
    fn_t v = (fn_t)fn_at(RVA(0x180035150));
    begin("cr_template_ncc_35150");
    int bad = g_fail;

    static int16_t data[256 * 16];
    /* radius runs up to `rows` (max 67), so ref must hold at least 68 shorts
     * (the twin test uses 128).  A 64-entry table overflowed -> ASan
     * global-buffer-overflow. */
    static int16_t ref[128];
    static int16_t ov[256 * 16], oc[256 * 16];

    for (int t = 0; t < 3000; t++) {
        int w    = 4 + (int)(rnd() % 13u);              /* 4..16   */
        int rows = 8 + (int)(rnd() % 60u);              /* 8..67   */
        int radius = (int)(rnd() % (uint32_t)(rows + 1));/* 0..rows  */
        for (int i = 0; i < w * rows; i++)
            data[i] = (int16_t)((int)(rnd() % 65536) - 32768);
        for (int i = 0; i < radius; i++)
            ref[i] = (int16_t)((int)(rnd() % 65536) - 32768);

        memset(ov, 0, sizeof ov);
        memset(oc, 0, sizeof oc);
        int rv = v(ov, data, ref, (uint32_t)radius, w, rows);
        int rc = cr_template_ncc_35150(oc, data, ref, (uint32_t)radius, w, rows);
        if (rv != rc)
            mismatch("ret", (u32)t, (u32)rv, (u32)rc);
        cmp_buf("out", (const unsigned char *)ov, (const unsigned char *)oc,
                (u32)(w * rows * 2), (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_template_ncc_35150\n");
}

/* ---- batch 73e: column-major template NCC twin (0x1800283d0) ------------- */
static void test_template_ncc_283d0(void)
{
    typedef int (WINAPI *fn_t)(int16_t *, int16_t *, int16_t *, uint32_t, int, int);
    fn_t v = (fn_t)fn_at(RVA(0x1800283d0));
    begin("cr_template_ncc_283d0");
    int bad = g_fail;

    /* NOTE: data/out are COLUMN-MAJOR: element (r,c) at r + c*rows. */
    static int16_t data[256 * 16];
    static int16_t ref[128];
    static int16_t ov[256 * 16], oc[256 * 16];

    for (int t = 0; t < 3000; t++) {
        int w    = 4 + (int)(rnd() % 13u);              /* 4..16   */
        int rows = 8 + (int)(rnd() % 60u);              /* 8..67   */
        int radius = (int)(rnd() % (uint32_t)(rows + 1));/* 0..rows  */
        for (int c = 0; c < w; c++)
            for (int r = 0; r < rows; r++)
                data[r + c * rows] = (int16_t)((int)(rnd() % 65536) - 32768);
        for (int i = 0; i < radius; i++)
            ref[i] = (int16_t)((int)(rnd() % 65536) - 32768);

        memset(ov, 0, sizeof ov);
        memset(oc, 0, sizeof oc);
        int rv = v(ov, data, ref, (uint32_t)radius, rows, w);
        int rc = cr_template_ncc_283d0(oc, data, ref, (uint32_t)radius, rows, w);
        if (rv != rc)
            mismatch("ret", (u32)t, (u32)rv, (u32)rc);
        cmp_buf("out", (const unsigned char *)ov, (const unsigned char *)oc,
                (u32)(w * rows * 2), (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_template_ncc_283d0\n");
}

/* ---- batch 73f: 2D-FFT prep (0x18001e920) ------------------------------- */
static void test_fft2d_prep_1e920(void)
{
    typedef int (WINAPI *fn_t)(float *, uint32_t, uint32_t, float *, int, int);
    fn_t v = (fn_t)fn_at(RVA(0x18001e920));
    begin("cr_fft2d_prep_1e920");
    int bad = g_fail;

    static float out[512 * 512];
    static float src[512 * 512];
    static float ov[512 * 512], oc[512 * 512];

    for (int t = 0; t < 2000; t++) {
        int e     = (int)(rnd() % 3u);                 /* 0,1,2 pad each side */
        int nrows = 16 + (int)(rnd() % 185u);          /* 16..200           */
        int ncols = 16 + (int)(rnd() % 145u);          /* 16..160           */
        if (ncols + e > nrows || ncols - 2 * e < 1 || nrows - 2 * e < 1)
            e = 0;                                     /* keep everything in-bounds */
        int w = ncols - 2 * e;
        int h = nrows - 2 * e;
        for (int i = 0; i < nrows * ncols; i++)
            out[i] = (float)((int)(rnd() % 2000) - 1000) * 0.001f;
        for (int i = 0; i < w * h; i++)
            src[i] = (float)((int)(rnd() % 2000) - 1000) * 0.001f;
        memcpy(ov, out, (size_t)nrows * ncols * 4);
        memcpy(oc, out, (size_t)nrows * ncols * 4);
        int rv = v(ov, (uint32_t)ncols, (uint32_t)nrows, src, w, h);
        int rc = cr_fft2d_prep_1e920(oc, (uint32_t)ncols, (uint32_t)nrows, src, w, h);
        if (rv != rc)
            mismatch("ret", (u32)t, (u32)rv, (u32)rc);
        cmp_buf("out", (const unsigned char *)ov, (const unsigned char *)oc,
                (u32)(nrows * ncols * 4), (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_fft2d_prep_1e920\n");
}

/* ---- batch 73g: NCC apply wrapper (0x18000f8b0) ------------------------- */
static void test_ncc_apply_f8b0(void)
{
    typedef int (WINAPI *fn_t)(uint64_t *, uint64_t *, uint16_t);
    fn_t v = (fn_t)fn_at(RVA(0x18000f8b0));
    begin("cr_ncc_apply_f8b0");
    int bad = g_fail;

    static int16_t inb[128 * 128];
    static int16_t outb[128 * 128];
    static int16_t ov[128 * 128], oc[128 * 128];
    static uint64_t d1[4], d2[4];

    for (int t = 0; t < 3000; t++) {
        int w  = 2 + (int)(rnd() % 48u);            /* 2..49   */
        int h  = 2 + (int)(rnd() % 48u);            /* 2..49   */
        int mn = w < h ? w : h;
        int radius = 1 + (int)(rnd() % (uint32_t)(mn - 1));
        int mode = (int)(rnd() % 3u);               /* 0 ok, 1 bad-struct, 2 big-radius */

        for (int i = 0; i < w * h; i++)
            inb[i] = (int16_t)((int)(rnd() % 65536) - 32768);
        memset(outb, 0, (size_t)w * h * 2);

        d1[2] = (uint64_t)(uint32_t)w | ((uint64_t)(uint32_t)h << 32);
        d1[1] = (uint64_t)(uintptr_t)outb;
        d1[3] = 0;
        d1[0] = (mode == 1) ? (d1[2] ^ 1) : d1[2];   /* flip to force 0x69 */
        d2[2] = d1[2];
        d2[1] = (uint64_t)(uintptr_t)inb;
        d2[3] = 0;
        d2[0] = d2[2];

        uint16_t r = (mode == 2) ? (uint16_t)w : (uint16_t)radius;
        memcpy(ov, outb, (size_t)w * h * 2);
        memcpy(oc, outb, (size_t)w * h * 2);
        int rv = v(d1, d2, r);
        int rc = cr_ncc_apply_f8b0(d1, d2, r);
        if (rv != rc)
            mismatch("ret", (u32)t, (u32)rv, (u32)rc);
        if (mode == 0)
            cmp_buf("out", (const unsigned char *)ov, (const unsigned char *)oc,
                    (u32)(w * h * 2), (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_ncc_apply_f8b0\n");
}

/* ---- batch 73h: NCC apply wrapper (0x180034390) ------------------------ */
static void test_ncc_apply_34390(void)
{
    typedef int (WINAPI *fn_t)(uint64_t *, uint64_t *, float, uint16_t);
    fn_t v = (fn_t)fn_at(RVA(0x180034390));
    begin("cr_ncc_apply_34390");
    int bad = g_fail;

    static int16_t inb[128 * 128];
    static int16_t outb[128 * 128];
    static int16_t ov[128 * 128], oc[128 * 128];
    static uint64_t d1[4], d2[4];

    for (int t = 0; t < 3000; t++) {
        int w  = 2 + (int)(rnd() % 48u);
        int h  = 2 + (int)(rnd() % 48u);
        int mn = w < h ? w : h;
        int n  = 1 + (int)(rnd() % (uint32_t)(mn - 1));
        float sigma = (float)((int)(rnd() % 2000) - 1000) * 0.01f;
        int mode = (int)(rnd() % 3u);

        for (int i = 0; i < w * h; i++)
            inb[i] = (int16_t)((int)(rnd() % 65536) - 32768);
        memset(outb, 0, (size_t)w * h * 2);

        d1[2] = (uint64_t)(uint32_t)w | ((uint64_t)(uint32_t)h << 32);
        d1[1] = (uint64_t)(uintptr_t)outb;
        d1[3] = 0;
        d1[0] = (mode == 1) ? (d1[2] ^ 1) : d1[2];
        d2[2] = d1[2];
        d2[1] = (uint64_t)(uintptr_t)inb;
        d2[3] = 0;
        d2[0] = d2[2];

        uint16_t nn = (mode == 2) ? (uint16_t)w : (uint16_t)n;
        memcpy(ov, outb, (size_t)w * h * 2);
        memcpy(oc, outb, (size_t)w * h * 2);
        int rv = v(d1, d2, sigma, nn);
        int rc = cr_ncc_apply_34390(d1, d2, sigma, nn);
        if (rv != rc)
            mismatch("ret", (u32)t, (u32)rv, (u32)rc);
        if (mode == 0)
            cmp_buf("out", (const unsigned char *)ov, (const unsigned char *)oc,
                    (u32)(w * h * 2), (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_ncc_apply_34390\n");
}

/* ---- batch 73i: 2D separable Gaussian correlation (0x180034930) -------- */
static void test_correlate_34930(void)
{
    typedef int (WINAPI *fn_t)(uint64_t *, uint64_t *, float, int);
    fn_t v = (fn_t)fn_at(RVA(0x180034930));
    begin("cr_correlate_34930");
    int bad = g_fail;

    static int16_t inb[128 * 128];
    static int16_t outb[128 * 128];
    static int16_t ov[128 * 128], oc[128 * 128];
    static uint64_t d1[4], d2[4];

    for (int t = 0; t < 3000; t++) {
        int w  = 2 + (int)(rnd() % 48u);            /* 2..49   */
        int h  = 2 + (int)(rnd() % 48u);            /* 2..49   */
        int mn = w < h ? w : h;
        /* odd n only: the vendor routine writes one short past its scratch
         * buffer when n is even, which corrupts its allocator; Gaussian
         * windows are odd-length in practice anyway. */
        int n  = 1 + 2 * (int)(rnd() % (uint32_t)(mn / 2));  /* 1,3,5,.. < mn */
        float sigma = (float)((int)(rnd() % 4000) - 2000) * 0.01f;
        int mode = (int)(rnd() % 2u);               /* 0 ok, 1 bad-struct */

        for (int i = 0; i < w * h; i++)
            inb[i] = (int16_t)((int)(rnd() % 65536) - 32768);

        d1[2] = (uint64_t)(uint32_t)w | ((uint64_t)(uint32_t)h << 32);
        d1[1] = (uint64_t)(uintptr_t)outb;
        d1[3] = 0;
        d1[0] = (mode == 1) ? (d1[2] ^ 1) : d1[2];
        d2[2] = d1[2];
        d2[1] = (uint64_t)(uintptr_t)inb;
        d2[3] = 0;
        d2[0] = d2[2];

        /* DLL run */
        memset(outb, 0, (size_t)w * h * 2);
        int rv = v(d1, d2, sigma, n);
        memcpy(ov, outb, (size_t)w * h * 2);
        /* clean-room run (same inputs, outb reset) */
        memset(outb, 0, (size_t)w * h * 2);
        int rc = cr_correlate_34930(d1, d2, sigma, n);
        memcpy(oc, outb, (size_t)w * h * 2);

        if (rv != rc)
            mismatch("ret", (u32)t, (u32)rv, (u32)rc);
        if (mode == 0)
            cmp_buf("out", (const unsigned char *)ov, (const unsigned char *)oc,
                    (u32)(w * h * 2), (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_correlate_34930\n");
}

/* ---- batch 73k: blur/kernel-apply dispatcher (0x18001c6a0) -------------- */
static void test_blur_dispatch_1c6a0(void)
{
    /* FUN_18001c6a0 is a leaf tail-jump dispatcher with signature
     *   int fn(void *a, void *b, float sigma, int count, int sel)
     * Under the MS x64 ABI a float at position 3 goes to xmm2, the position-4
     * int to r9, and the position-5 int (sel) on the stack at [rsp+0x28] —
     * exactly the registers the vendor reads (a=rcx, b=rdx, sigma=xmm2,
     * count=r9 zero-extended to 16 bits, sel=[rsp+0x28]).  It overwrites r8 with
     * the jump-table base and jumps through the table @ 0x18008c4b0 (dumped):
     *   sel 0 -> cr_gauss_fir_apply            (0x20 gf_desc)
     *   sel 1 -> cr_sep_gauss_blur_s16_reflect (full cr_image)
     *   sel 2 -> cr_correlate_34930            (4-qword desc)
     *   sel 3 -> cr_ncc_apply_34390            (4-qword desc)
     *   sel 4 -> cr_sep_gauss_blur_s16         (full cr_image)
     *   sel > 4 (unsigned low byte) -> return 0x69
     * Every target reads sigma from xmm2 and count from r9. */
    typedef int (WINAPI *v_disp_t)(void *a, void *b, float sigma, int count,
                                   int sel);
    v_disp_t v = (v_disp_t)fn_at(RVA(0x18001c6a0));
    begin("cr_blur_dispatch_1c6a0");
    int bad = g_fail;

    /* gf_desc (sel 0) */
    static unsigned char gfa[0x20], gfb[0x20], gca[0x20], gcb[0x20];
    static int16_t gav[4096], gac[4096], gbv[4096], gbc[4096];
    static const uint16_t gf_counts[] = {1,3,5,7,9,11,15,31,63,127};
    /* full-view cr_image (sel 1/4) */
    enum { MAXD = 40, NP = MAXD * MAXD };
    static int16_t sv[NP], sc[NP], dv[NP], dc[NP];
    static cr_image sdv, sdc, ddv, ddc;
    /* 4-qword desc (sel 2/3): d[2]=w|h<<32, d[1]=data, d[3]=0, d[0]=d[2] */
    static uint64_t d1v[4], d2v[4], d1c[4], d2c[4];
    static int16_t inb[128*128], outbv[128*128], outbc[128*128];

    for (int sel = 0; sel < 8; sel++) {
        int s = (sel < 6) ? sel : (sel == 6 ? 0xff : 0x100);   /* incl. high-byte */
        int niter = (s >= 5 && (s & 0xff) > 4) ? 32 : 1500;
        for (int t = 0; t < niter; t++) {
            int rv, rc;
            u32 tag = (u32)((sel << 24) | t);

            if ((s & 0xff) == 0) {                   /* gauss_fir (gf_desc) */
                int W = (int)(rnd() % 64u) + 1;
                int L = (int)(rnd() % 64u) + 1;
                uint16_t count = gf_counts[rnd() %
                                 (uint32_t)(sizeof gf_counts / sizeof gf_counts[0])];
                float sigma = cr_u2f(rnd());
                int n = W * L;
                for (int i = 0; i < n; i++) {
                    int16_t x = (int16_t)(rnd() & 0xffffu); gav[i] = x; gac[i] = x;
                    x = (int16_t)(rnd() & 0xffffu); gbv[i] = x; gbc[i] = x;
                }
                mk_gf_desc(gfa, gav, W, L); mk_gf_desc(gfb, gbv, W, L);
                mk_gf_desc(gca, gac, W, L); mk_gf_desc(gcb, gbc, W, L);
                rv = v(gfa, gfb, sigma, (int)count, s);
                rc = cr_blur_dispatch_1c6a0(gca, gcb, sigma, (int)count, s);
                if (rv != rc) { mismatch("ret", tag, (u32)rv, (u32)rc); continue; }
                if (rv == 0)
                    cmp_buf("dst", (unsigned char *)gav, (unsigned char *)gac,
                            (u32)(n * 2), tag);
            } else if ((s & 0xff) == 1 || (s & 0xff) == 4) {  /* sep_gauss */
                int klen = 1 + 2 * (int)(rnd() % 7);
                int W = klen + (int)(rnd() % (MAXD - klen + 1));
                int H = klen + (int)(rnd() % (MAXD - klen + 1));
                float sigma = 0.5f + (float)(rnd() % 400) / 100.0f;
                for (int i = 0; i < W * H; i++) {
                    int16_t x = (int16_t)rnd();
                    sv[i] = x; sc[i] = x; dv[i] = 0x7f; dc[i] = 0x7f;
                }
                memset(&sdv, 0, sizeof sdv); memset(&sdc, 0, sizeof sdc);
                sdv.a = W; sdv.b = H; sdv.data = sv; sdv.w = W; sdv.h = H;
                sdc.a = W; sdc.b = H; sdc.data = sc; sdc.w = W; sdc.h = H;
                memset(&ddv, 0, sizeof ddv); memset(&ddc, 0, sizeof ddc);
                ddv.a = W; ddv.b = H; ddv.data = dv; ddv.w = W; ddv.h = H;
                ddc.a = W; ddc.b = H; ddc.data = dc; ddc.w = W; ddc.h = H;
                rv = v(&ddv, &sdv, sigma, klen, s);
                rc = cr_blur_dispatch_1c6a0(&ddc, &sdc, sigma, klen, s);
                if (rv != rc) { mismatch("ret", tag, (u32)rv, (u32)rc); continue; }
                if (rv == 0)
                    cmp_buf("dst", (unsigned char *)dv, (unsigned char *)dc,
                            (u32)(W * H * 2), tag);
            } else if ((s & 0xff) == 2 || (s & 0xff) == 3) {  /* ncc/correlate */
                int w = 2 + (int)(rnd() % 48u);
                int h = 2 + (int)(rnd() % 48u);
                int mn = w < h ? w : h;
                int n = 1 + 2 * (int)(rnd() % (uint32_t)(mn / 2));   /* odd */
                float sigma = ((s & 0xff) == 3)
                    ? (float)((int)(rnd() % 2000) - 1000) * 0.01f
                    : (float)((int)(rnd() % 4000) - 2000) * 0.01f;
                for (int i = 0; i < w * h; i++)
                    inb[i] = (int16_t)((int)(rnd() % 65536) - 32768);
                memset(outbv, 0, (size_t)w * h * 2);
                memset(outbc, 0, (size_t)w * h * 2);
                uint64_t wh = (uint64_t)(uint32_t)w | ((uint64_t)(uint32_t)h << 32);
                d1v[2] = wh; d1v[1] = (uint64_t)(uintptr_t)outbv; d1v[3] = 0; d1v[0] = wh;
                d2v[2] = wh; d2v[1] = (uint64_t)(uintptr_t)inb;   d2v[3] = 0; d2v[0] = wh;
                d1c[2] = wh; d1c[1] = (uint64_t)(uintptr_t)outbc; d1c[3] = 0; d1c[0] = wh;
                d2c[2] = wh; d2c[1] = (uint64_t)(uintptr_t)inb;   d2c[3] = 0; d2c[0] = wh;
                rv = v(d1v, d2v, sigma, n, s);
                rc = cr_blur_dispatch_1c6a0(d1c, d2c, sigma, n, s);
                if (rv != rc) { mismatch("ret", tag, (u32)rv, (u32)rc); continue; }
                if (rv == 0)
                    cmp_buf("dst", (unsigned char *)outbv, (unsigned char *)outbc,
                            (u32)(w * h * 2), tag);
            } else {                                  /* default -> 0x69, no touch */
                int W = 4, H = 4;
                for (int i = 0; i < W * H; i++) {
                    int16_t x = (int16_t)rnd();
                    sv[i] = x; sc[i] = x; dv[i] = 0x7f; dc[i] = 0x7f;
                }
                memset(&sdv, 0, sizeof sdv); memset(&sdc, 0, sizeof sdc);
                sdv.a = W; sdv.b = H; sdv.data = sv; sdv.w = W; sdv.h = H;
                sdc.a = W; sdc.b = H; sdc.data = sc; sdc.w = W; sdc.h = H;
                memset(&ddv, 0, sizeof ddv); memset(&ddc, 0, sizeof ddc);
                ddv.a = W; ddv.b = H; ddv.data = dv; ddv.w = W; ddv.h = H;
                ddc.a = W; ddc.b = H; ddc.data = dc; ddc.w = W; ddc.h = H;
                rv = v(&ddv, &sdv, 0.5f, 5, s);
                rc = cr_blur_dispatch_1c6a0(&ddc, &sdc, 0.5f, 5, s);
                if (rv != rc) { mismatch("ret", tag, (u32)rv, (u32)rc); continue; }
                if (rv == 0x69)
                    cmp_buf("dst", (unsigned char *)dv, (unsigned char *)dc,
                            (u32)(W * H * 2), tag);
            }
        }
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_blur_dispatch_1c6a0\n");
}


/* ---- batch 74: blurred-pair difference normaliser (0x18001ee30) -------- */
static void test_blur_diff_norm(void)
{
    /* FUN_18001ee30:
     *   int fn(cr_image *src, const float *obj)
     * Two pointers -> rcx, rdx (plain MS x64 ABI, no float positions).  Blurs
     * src twice (sigma obj[0] / obj[1], selector byte obj+12, count 0xf) and
     * writes the scaled, clamped difference of the two blurs back into
     * src->data in place.  src must be a valid descriptor (a==w, b==h,
     * offx==offy==0) because the blur dispatcher validates it. */
    typedef int (WINAPI *v_bdn_t)(cr_image *src, const void *obj);
    v_bdn_t v = (v_bdn_t)fn_at(RVA(0x18001ee30));
    begin("cr_blur_diff_norm");
    int bad = g_fail;

    enum { MAXN = 64 * 64 };
    static int16_t sv[MAXN], sc[MAXN];
    static cr_image srcv, srcc;
    static unsigned char obj[16];

    for (int sel = 0; sel < 7; sel++) {
        int s = (sel < 5) ? sel : (sel == 5 ? 5 : 0xff);
        for (int t = 0; t < 400; t++) {
            int W = 24 + (int)(rnd() % 25u);          /* 24..48 */
            int H = 24 + (int)(rnd() % 25u);
            int N = W * H;
            float s0 = 0.5f + (float)(rnd() % 350) / 100.0f;
            float s1 = 0.5f + (float)(rnd() % 350) / 100.0f;
            u32 tag = (u32)((sel << 20) | t);

            for (int i = 0; i < N; i++) {
                int16_t x = (int16_t)rnd();
                sv[i] = x; sc[i] = x;
            }
            memset(&srcv, 0, sizeof srcv);
            memset(&srcc, 0, sizeof srcc);
            srcv.a = W; srcv.b = H; srcv.data = sv; srcv.w = W; srcv.h = H;
            srcc.a = W; srcc.b = H; srcc.data = sc; srcc.w = W; srcc.h = H;

            memset(obj, 0, sizeof obj);
            memcpy(obj + 0, &s0, 4);
            memcpy(obj + 4, &s1, 4);
            obj[12] = (unsigned char)s;

            int rv = v(&srcv, obj);
            int rc = cr_blur_diff_norm(&srcc, obj);
            if (rv != rc) { mismatch("ret", tag, (u32)rv, (u32)rc); continue; }
            cmp_buf("dst", (unsigned char *)sv, (unsigned char *)sc,
                    (size_t)N * 2, tag);
        }
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_blur_diff_norm\n");
}


/* ---- batch 75: u8 blurred-pair difference normaliser (0x1800148c0) ----- */
static void test_blur_diff_norm_u8(void)
{
    /* FUN_1800148c0:
     *   int fn(cr_image *dst, const cr_image *src, const void *obj)
     * Three pointers -> rcx, rdx, r8 (plain MS x64 ABI, no float positions).
     * Converts the float source (scaled by 64) into an int16 scratch, blurs it
     * twice (sigma obj[0] / obj[1], selector byte obj+12, count 0xf), and
     * writes the normalised difference as u8 into dst->data.  src must be a
     * valid descriptor (a==w, b==h, offx==offy==0). */
    typedef int (WINAPI *v_bdn8_t)(cr_image *dst, const cr_image *src,
                                   const void *obj);
    v_bdn8_t v = (v_bdn8_t)fn_at(RVA(0x1800148c0));
    begin("cr_blur_diff_norm_u8");
    int bad = g_fail;

    enum { MAXN = 64 * 64 };
    static float sf[MAXN], scf[MAXN];
    static uint8_t dv[MAXN], dc[MAXN];
    static cr_image dstv, dstc, srcv, srcc;
    static unsigned char obj[16];

    for (int sel = 0; sel < 7; sel++) {
        int s = (sel < 5) ? sel : (sel == 5 ? 5 : 0xff);
        for (int t = 0; t < 400; t++) {
            int W = 24 + (int)(rnd() % 25u);          /* 24..48 */
            int H = 24 + (int)(rnd() % 25u);
            int N = W * H;
            float s0 = 0.5f + (float)(rnd() % 350) / 100.0f;
            float s1 = 0.5f + (float)(rnd() % 350) / 100.0f;
            u32 tag = (u32)((sel << 20) | t);

            for (int i = 0; i < N; i++) {
                float x = (float)((int)(rnd() % 4001) - 2000) * 0.1f;
                sf[i] = x; scf[i] = x;
            }
            memset(dv, 0xa5, sizeof dv);
            memset(dc, 0xa5, sizeof dc);

            memset(&srcv, 0, sizeof srcv);
            memset(&srcc, 0, sizeof srcc);
            srcv.a = W; srcv.b = H; srcv.data = sf; srcv.w = W; srcv.h = H;
            srcc.a = W; srcc.b = H; srcc.data = scf; srcc.w = W; srcc.h = H;

            memset(&dstv, 0, sizeof dstv);
            memset(&dstc, 0, sizeof dstc);
            dstv.data = dv; dstc.data = dc;

            memset(obj, 0, sizeof obj);
            memcpy(obj + 0, &s0, 4);
            memcpy(obj + 4, &s1, 4);
            obj[12] = (unsigned char)s;

            int rv = v(&dstv, &srcv, obj);
            int rc = cr_blur_diff_norm_u8(&dstc, &srcc, obj);
            if (rv != rc) { mismatch("ret", tag, (u32)rv, (u32)rc); continue; }
            cmp_buf("dst", dv, dc, (size_t)N, tag);
        }
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_blur_diff_norm_u8\n");
}


/* ---- batch 76: local-contrast normaliser (0x180013720) ----------------- */
static void test_blur_divnorm_stretch(void)
{
    /* FUN_180013720:
     *   int fn(cr_image *img, const void *cfg)
     * Two pointers -> rcx, rdx (plain MS x64 ABI).  Mean-subtracts the int16
     * image (unsigned load!), takes abs, blurs, divides by a floored denominator
     * and contrast-stretches back into img->data in place.  cfg+4 = sigma,
     * cfg+8 = denominator factor, cfg+0xc = selector (only 3/4 valid). */
    typedef int (WINAPI *v_bds_t)(cr_image *img, const void *cfg);
    v_bds_t v = (v_bds_t)fn_at(RVA(0x180013720));
    begin("cr_blur_divnorm_stretch");
    int bad = g_fail;

    enum { MAXN = 64 * 64 };
    static int16_t iv[MAXN], ic[MAXN];
    static cr_image imgv, imgc;
    static unsigned char cfg[16];
    static const int sels[] = { 3, 4, 0, 1, 2, 5, 0xff };

    for (int k = 0; k < (int)(sizeof sels / sizeof sels[0]); k++) {
        int s = sels[k];
        for (int t = 0; t < 300; t++) {
            int W = 48 + (int)(rnd() % 17u);          /* 48..64 */
            int H = 48 + (int)(rnd() % 17u);
            int N = W * H;
            float sigma = 0.5f + (float)(rnd() % 350) / 100.0f;
            float f8    = (float)(rnd() % 300) / 100.0f;
            u32 tag = (u32)((k << 20) | t);

            for (int i = 0; i < N; i++) {
                int16_t x = (int16_t)rnd();
                iv[i] = x; ic[i] = x;
            }
            memset(&imgv, 0, sizeof imgv);
            memset(&imgc, 0, sizeof imgc);
            imgv.a = W; imgv.b = H; imgv.data = iv; imgv.w = W; imgv.h = H;
            imgc.a = W; imgc.b = H; imgc.data = ic; imgc.w = W; imgc.h = H;

            memset(cfg, 0, sizeof cfg);
            memcpy(cfg + 4, &sigma, 4);
            memcpy(cfg + 8, &f8, 4);
            cfg[12] = (unsigned char)s;

            int rv = v(&imgv, cfg);
            int rc = cr_blur_divnorm_stretch(&imgc, cfg);
            if (rv != rc) { mismatch("ret", tag, (u32)rv, (u32)rc); continue; }
            cmp_buf("dst", (unsigned char *)iv, (unsigned char *)ic,
                    (size_t)N * 2, tag);
        }
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_blur_divnorm_stretch\n");
}


/* ---- batch 77: oriented matched filter (0x180045eb0) ------------------- */
static void test_matched_filter_45eb0(void)
{
    /* FUN_180045eb0:
     *   int fn(int16_t *out, const uint8_t *const *rows, const void *cfg)
     * Three pointers -> rcx, rdx, r8 (plain MS x64 ABI).  5x5 oriented matched
     * filter over six row pointers (rows[0..5]), max-pooled 4-wide per chunk,
     * written as int16 into out (W*H).  cfg+0xc = kernel-bank stride multiplier,
     * cfg+0x10 = W, cfg+0x14 = H, cfg+0x18 = clamp flag (1 -> non-negative),
     * cfg+0x20 = kernel bank (int16, 25/kernel), cfg+0x28 = per-row bias (int16). */
    typedef int (WINAPI *v_mf_t)(int16_t *out, const uint8_t *const *rows,
                                 const void *cfg);
    v_mf_t v = (v_mf_t)fn_at(RVA(0x180045eb0));
    begin("cr_matched_filter_45eb0");
    int bad = g_fail;

    enum { MAXW = 40, MAXH = 8, ROWBYTES = 2 * MAXW + 8, MAXK = MAXH * 4 * 25 };
    static uint8_t rowbuf[6][ROWBYTES];
    static const uint8_t *rows[6];
    static int16_t ov[MAXW * MAXH], oc[MAXW * MAXH];
    static int16_t kbank[MAXK], mbias[MAXH];
    static unsigned char cfg[0x30];

    for (int t = 0; t < 3000; t++) {
        int W = 1 + (int)(rnd() % MAXW);              /* 1..MAXW */
        int H = 1 + (int)(rnd() % MAXH);              /* 1..MAXH */
        int kmul = 1 + (int)(rnd() % 3);              /* 1..3 */
        int flag = (int)(rnd() & 1u);
        int N = W * H;
        int nk = H * kmul * 25;
        u32 tag = (u32)t;

        for (int i = 0; i < 6; i++) {
            for (int j = 0; j < ROWBYTES; j++)
                rowbuf[i][j] = (uint8_t)rnd();
            rows[i] = rowbuf[i];
        }
        for (int i = 0; i < nk; i++)
            kbank[i] = (int16_t)((int)(rnd() % 2001) - 1000);
        for (int i = 0; i < H; i++)
            mbias[i] = (int16_t)((int)(rnd() % 2001) - 1000);
        memset(ov, 0x5a, sizeof ov);
        memset(oc, 0x5a, sizeof oc);

        memset(cfg, 0, sizeof cfg);
        memcpy(cfg + 0x0c, &kmul, 4);
        memcpy(cfg + 0x10, &W, 4);
        memcpy(cfg + 0x14, &H, 4);
        memcpy(cfg + 0x18, &flag, 4);
        const int16_t *kp = kbank; memcpy(cfg + 0x20, &kp, sizeof kp);
        const int16_t *mp = mbias; memcpy(cfg + 0x28, &mp, sizeof mp);

        int rv = v(ov, rows, cfg);
        int rc = cr_matched_filter_45eb0(oc, rows, cfg);
        if (rv != rc) { mismatch("ret", tag, (u32)rv, (u32)rc); continue; }
        cmp_buf("dst", (unsigned char *)ov, (unsigned char *)oc,
                (size_t)N * 2, tag);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_matched_filter_45eb0\n");
}


/* ---- batch 78: frame quality gate (0x180035cf0) ------------------------ */
static void qg_build_store(u8 *s, const int32_t *keys, const int32_t *vals, int n)
{
    memset(s, 0, 0x100);
    *(u32 *)(s + 0) = 8;
    for (int i = 0; i < n; i++) {
        *(int32_t *)(s + 0xc + 12 * i + 0) = keys[i];
        *(int32_t *)(s + 0xc + 12 * i + 4) = 4;
        *(int32_t *)(s + 0xc + 12 * i + 8) = vals[i];
    }
    *(u32 *)(s + 4) = 0xc + 12 * n;   /* capacity */
    *(u32 *)(s + 8) = 12 * n;         /* used     */
}

static void test_quality_gate_35cf0(void)
{
    /* FUN_180035cf0:
     *   int fn(cr_image *img, float *out_q, uint8_t *out_flag, void *state,
     *          void *src, void *handle, const void *cfg)
     * rcx/rdx/r8/r9 = img/out_q/out_flag/state; src/handle/cfg are on the stack.
     * Reads four metadata keys (0xda/0xdd/0xd2/0xd6), computes a frame quality,
     * updates the running averages, optionally runs an NCC diff + Pearson
     * correlation, shifts a 19-byte history and sets *out_flag. */
    typedef int (WINAPI *v_qg_t)(cr_image *img, float *out_q, uint8_t *out_flag,
                                 void *state, void *src, void *handle,
                                 const void *cfg);
    v_qg_t v = (v_qg_t)fn_at(RVA(0x180035cf0));
    begin("cr_quality_gate_35cf0");
    int bad = g_fail;

    enum { MAXW = 13, MAXH = 11, SRCW = MAXW * 4, SRCH = MAXH * 4,
           MAXN = MAXW * MAXH, MAXSN = SRCW * SRCH, SLEN = 0x60 };

    static int16_t img_v[MAXN], img_c[MAXN];
    static int16_t prev_v[MAXN], prev_c[MAXN];
    static int16_t srcb[MAXSN];
    static u8 hist_v[0x20], hist_c[0x20];
    static u8 st_v[SLEN], st_c[SLEN];
    static u8 imgd_v[0x20], imgd_c[0x20], srcd[0x20];
    static u8 cfg[0x40], hv[0x100], hc[0x100];
    static const int32_t keys[4] = { 0xda, 0xdd, 0xd2, 0xd6 };

    for (int t = 0; t < 8000; t++) {
        int W = 2 + (int)(rnd() % (MAXW - 1));    /* 2..MAXW */
        int H = 2 + (int)(rnd() % (MAXH - 1));    /* 2..MAXH */
        int N = W * H;
        int SW = W * 4, SH = H * 4, SN = SW * SH;

        for (int i = 0; i < N; i++) {
            int16_t x = (int16_t)((int)(rnd() % 4001) - 2000);
            img_v[i] = x; img_c[i] = x;
        }
        for (int i = 0; i < SN; i++)
            srcb[i] = (int16_t)((int)(rnd() % 4001) - 2000);
        for (int i = 0; i < N; i++) {
            int16_t x = (int16_t)rnd();
            prev_v[i] = x; prev_c[i] = x;
        }
        for (int i = 0; i < 0x20; i++) {
            u8 x = (u8)rnd();
            hist_v[i] = x; hist_c[i] = x;
        }

        mk_image(imgd_v, img_v, W, W, H, 0, 0);
        mk_image(imgd_c, img_c, W, W, H, 0, 0);
        mk_image(srcd, srcb, SW, SW, SH, 0, 0);

        int count;
        switch (rnd() % 6u) {
        case 0:  count = 0; break;
        case 1:  count = 1; break;
        case 2:  count = 2; break;
        case 3:  count = 0xff; break;
        case 4:  count = 0x100 + (int)(rnd() % 32u); break;
        default: count = (int)(rnd() % 0x120u); break;
        }
        int counter = (int)(rnd() % 31u);
        if ((t & 127) == 0) counter = 0x7fffffff;
        float avg_q = (float)((int)(rnd() % 4001) - 2000) * 0.001f;
        float avg_s = (float)((int)(rnd() % 4001) - 2000) * 0.001f;

        memset(st_v, 0, sizeof st_v);
        memset(st_c, 0, sizeof st_c);
        *(u8 **)(st_v + 0x00) = hist_v;
        *(int16_t **)(st_v + 0x10) = prev_v;
        *(u8 **)(st_c + 0x00) = hist_c;
        *(int16_t **)(st_c + 0x10) = prev_c;
        for (int i = 0; i < 2; i++) {
            u8 *s = i ? st_c : st_v;
            *(int32_t *)(s + 0x40) = count;
            *(int32_t *)(s + 0x44) = counter;
            *(float *)(s + 0x48) = avg_q;
            *(float *)(s + 0x4c) = avg_s;
        }

        memset(cfg, 0, sizeof cfg);
        *(int32_t *)(cfg + 0x08) = (int)(rnd() % 400u);       /* level */
        *(float   *)(cfg + 0x0c) = (float)((int)(rnd() % 4001) - 2000) * 0.001f;
        *(int32_t *)(cfg + 0x10) = (int)(rnd() % 4u);         /* margin x */
        *(int32_t *)(cfg + 0x14) = (int)(rnd() % 4u);         /* margin y */
        *(int8_t  *)(cfg + 0x18) = (int8_t)(rnd() % 2u);      /* diff flag */
        *(float   *)(cfg + 0x1c) = (float)((int)(rnd() % 4001) - 2000) * 0.001f;
        *(float   *)(cfg + 0x20) = (float)((int)(rnd() % 4001) - 2000) * 0.001f;
        *(int8_t  *)(cfg + 0x2c) = (int8_t)(rnd() % 6u);      /* mode 0..5 */
        float scale = (float)((int)(rnd() % 4001) - 2000) * 0.001f;
        if (scale == 0.0f) scale = 1.0f;                      /* avoid 0*inf NaN */
        *(float   *)(cfg + 0x30) = scale;

        int32_t vals[4];
        vals[0] = (int)(rnd() % 500u);            /* 0xda: level */
        vals[1] = (int)(rnd() % 4000u);           /* 0xdd: t */
        vals[2] = (int)(rnd() % 4000u);           /* 0xd2: a */
        vals[3] = (int)(rnd() % 4000u);           /* 0xd6: b */
        int nk = 4;
        if ((t & 15) == 0) nk = (int)(rnd() % 5u);   /* 0..4 keys present */
        int use_handle = !((t & 255) == 0);
        qg_build_store(hv, keys, vals, nk);
        memcpy(hc, hv, sizeof hv);

        float qv = 123.0f, qc = 123.0f;
        u8 fv = 0x5a, fc = 0x5a;

        int rv = v((cr_image *)imgd_v, &qv, &fv, st_v, srcd,
                   use_handle ? hv : NULL, cfg);
        int rc = cr_quality_gate_35cf0((cr_image *)imgd_c, &qc, &fc, st_c, srcd,
                                       use_handle ? hc : NULL, cfg);

        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }
        if (fv != fc) mismatch("flag", (u32)t, fv, fc);
        if (cr_f2u(qv) != cr_f2u(qc)) mismatch("q", (u32)t, cr_f2u(qv), cr_f2u(qc));
        cmp_buf("img", (u8 *)img_v, (u8 *)img_c, (size_t)N * 2, (u32)t);
        cmp_buf("prev", (u8 *)prev_v, (u8 *)prev_c, (size_t)N * 2, (u32)t);
        cmp_buf("hist", hist_v, hist_c, 0x14, (u32)t);
        cmp_buf("st", st_v + 0x44, st_c + 0x44, 12, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_quality_gate_35cf0\n");
}


/* ---- batch 68: object constructor (0x180012fe0) ------------------------ */
static void test_obj_init_12fe0(void)
{
    typedef int (WINAPI *v_i_ppp)(void *, void *, void *);
    v_i_ppp v = (v_i_ppp)fn_at(RVA(0x180012fe0));
    v_v_p vfree = (v_v_p)fn_at(RVA(0x18000f570));
    begin("cr_obj_init_12fe0");
    int bad = g_fail;

    enum { OBJ = 0x90 };
    static u8 ov[OBJ], oc[OBJ];
    static u8 a2buf[0x20], a3buf[0x30], q[0x20], s[0x40], r[0x30];
    static u8 srcdata[16 * 16];

    for (int t = 0; t < 3000; t++) {
        int w  = 1 + (int)(rnd() % 16);
        int h  = 1 + (int)(rnd() % 16);
        int wq = w, hq = h;
        if (rnd() % 6 == 0) wq = w + 1;              /* force w mismatch */
        int a2null = (int)(rnd() % 7) == 0;
        int hasimg = (int)(rnd() % 6) != 0;
        int sflag  = (int)(rnd() % 2);
        int ax     = (int)(rnd() % 40) - 4;

        for (size_t i = 0; i < sizeof srcdata; i++) srcdata[i] = (u8)rnd();
        for (size_t i = 0; i < sizeof q; i++) q[i] = (u8)rnd();

        *(int16_t *)(a2buf + 0x00) = (int16_t)w;
        *(int16_t *)(a2buf + 0x02) = (int16_t)h;
        *(void  **)(a2buf + 0x10)  = hasimg ? (void *)srcdata : NULL;

        *(int16_t *)(q + 0xc) = (int16_t)wq;
        *(int16_t *)(q + 0xe) = (int16_t)hq;
        *(void  **)(a3buf + 0x08) = q;
        s[0x3d] = (u8)sflag;
        *(void **)(a3buf + 0x10) = s;
        *(int16_t *)(r + 0x20) = (int16_t)ax;
        *(void **)(a3buf + 0x28) = r;

        memset(ov, 0xA5, OBJ); memset(oc, 0xA5, OBJ);
        int rv = v(ov, a2null ? NULL : a2buf, a3buf);
        int rc = cr_obj_init_12fe0(oc, a2null ? NULL : a2buf, a3buf);
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }

        /* scalar ranges (pointer slots at 0x18,0x38,0x58,0x88 excluded) */
        cmp_buf("s00", ov + 0x00, oc + 0x00, 0x18, (u32)t);
        cmp_buf("s20", ov + 0x20, oc + 0x20, 0x18, (u32)t);
        cmp_buf("s40", ov + 0x40, oc + 0x40, 0x18, (u32)t);
        cmp_buf("s60", ov + 0x60, oc + 0x60, 0x28, (u32)t);

        #define PNULL(off) do { \
            if ((*(void **)(ov + (off)) != NULL) != \
                (*(void **)(oc + (off)) != NULL)) \
                mismatch("p" #off, (u32)t, 0, 0); } while (0)
        PNULL(0x18); PNULL(0x38); PNULL(0x58); PNULL(0x88);
        #undef PNULL

        if (rv == 0) {
            int iw = *(int *)(ov + 0x20), ih = *(int *)(ov + 0x24);
            int sw = *(int *)(ov + 0x40), sh = *(int *)(ov + 0x44);
            if (*(void **)(ov + 0x18) && *(void **)(oc + 0x18))
                cmp_buf("img8", *(void **)(ov + 0x18), *(void **)(oc + 0x18),
                        (size_t)(iw * ih), (u32)t);
            if (*(void **)(ov + 0x38) && *(void **)(oc + 0x38))
                cmp_buf("img16", *(void **)(ov + 0x38), *(void **)(oc + 0x38),
                        (size_t)(2 * sw * sh), (u32)t);
            if (*(void **)(ov + 0x58) && *(void **)(oc + 0x58)) {
                int stride = *(int *)(ov + 0x50);
                int bmh = *(int *)(ov + 0x54);
                cmp_buf("bm", *(void **)(ov + 0x58), *(void **)(oc + 0x58),
                        (size_t)(((stride + 31) >> 5) * bmh * 4), (u32)t);
            }
            if (*(void **)(ov + 0x88) && *(void **)(oc + 0x88))
                cmp_buf("cnt", *(void **)(ov + 0x88), *(void **)(oc + 0x88),
                        (size_t)(2 * *(int16_t *)(ov + 0x80)), (u32)t);

            vfree(ov);
            cr_free_obj_flags(oc);
        }
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_obj_init_12fe0\n");
}

/* build an image descriptor: a@+0, data@+8, w@+0x10, h@+0x14, offx@+0x18, offy@+0x1c */
static void mk_image(unsigned char *d, void *data, int stride, int w, int h, int offx, int offy)
{
    *(int   *)(d + 0x00) = stride;
    *(void **)(d + 0x08) = data;
    *(int   *)(d + 0x10) = w;
    *(int   *)(d + 0x14) = h;
    *(int   *)(d + 0x18) = offx;
    *(int   *)(d + 0x1c) = offy;
}

/* 0x180020770 — fill a u16 image from a pointer-array slot descriptor. */
static void test_image_fill_desc(void)
{
    typedef int (WINAPI *v_fill)(void **, int, uint8_t, void *);
    v_fill v = (v_fill)fn_at(RVA(0x180020770));
    begin("cr_image_fill_desc");
    int bad = g_fail;

    enum { MAXW = 24, MAXH = 24, NPIX = MAXW * MAXH };
    static uint8_t src[NPIX * 2 + 64];
    static uint8_t dv[NPIX * 2 + 64], dc[NPIX * 2 + 64];
    static void   *arrv[12], *arrc[12];
    static uint8_t ev[0x20], ec[0x20];
    static uint8_t mv[128], mc[128];
    static uint8_t iv[0x20], ic[0x20];

    for (int t = 0; t < 20000; t++) {
        int w = (int)(rnd() % MAXW);
        int h = (int)(rnd() % MAXH);
        int type;
        switch (rnd() % 5) {
        case 0:  type = 8;            break;
        case 1:  type = 0x10;         break;
        default: type = (int)(rnd() & 0x1f); break;
        }
        int idx = (int)(rnd() % 3);
        uint8_t shift = (uint8_t)rnd();
        int dw = (int)(rnd() % 3) - 1;      /* -1 .. 1 */
        int dh = (int)(rnd() % 3) - 1;

        for (size_t i = 0; i < sizeof src; i++) src[i] = (uint8_t)rnd();
        for (size_t i = 0; i < sizeof dv; i++) dv[i] = (uint8_t)rnd();
        memcpy(dc, dv, sizeof dc);

        *(int16_t *)(ev + 0x00) = (int16_t)w;
        *(int16_t *)(ev + 0x02) = (int16_t)h;
        *(uint8_t *)(ev + 0x06) = (uint8_t)type;
        *(void   **)(ev + 0x10) = src;
        memcpy(ec, ev, sizeof ec);

        uint32_t val = rnd();
        int has = (int)(rnd() & 1);
        memset(mv, 0, sizeof mv);
        *(u32 *)(mv + 0x00) = 8;
        *(u32 *)(mv + 0x04) = 0x40;
        *(u32 *)(mv + 0x08) = 0xc;
        *(u32 *)(mv + 0x0c) = has ? 0x148u : 0x149u;
        *(u32 *)(mv + 0x10) = 4;
        *(u32 *)(mv + 0x14) = val;
        memcpy(mc, mv, sizeof mc);

        int isnull = (rnd() % 6 == 0);
        for (int i = 0; i < 12; i++) { arrv[i] = NULL; arrc[i] = NULL; }
        arrv[idx]     = isnull ? NULL : ev;
        arrc[idx]     = isnull ? NULL : ec;
        arrv[idx + 7] = mv;
        arrc[idx + 7] = mc;

        mk_image(iv, dv, w, w + dw, h + dh, 0, 0);
        mk_image(ic, dc, w, w + dw, h + dh, 0, 0);

        int rv = v(arrv, idx, shift, iv);
        int rc = cr_image_fill_desc(arrc, idx, shift, (cr_image *)ic);
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }
        cmp_buf("px", dv, dc, sizeof dv, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_image_fill_desc\n");
}

/* 0x1800171d0 — build s16 image from descriptor, optionally grad score. */
static void test_grad_score_from_desc(void)
{
    typedef int (WINAPI *v_t)(uint8_t *, void **, const void *, int, int,
                              int, const void *);
    v_t v = (v_t)fn_at(RVA(0x1800171d0));
    begin("cr_grad_score_from_desc");
    int bad = g_fail;

    enum { MAXW = 24, MAXH = 24, NPIX = MAXW * MAXH };
    static uint8_t src[NPIX * 2 + 64];
    static uint8_t dv[NPIX * 2 + 64], dc[NPIX * 2 + 64];
    static uint8_t ov[8], oc[8];
    static void   *arrv[12], *arrc[12];
    static uint8_t ev[0x20], ec[0x20];
    static uint8_t a0v[0x20], a0c[0x20];
    static uint8_t mv[128], mc[128];
    static uint8_t iv[0x20], ic[0x20];
    static uint8_t cfgv[0x40], cfgc[0x40];

    for (int t = 0; t < 20000; t++) {
        int w = 2 + (int)(rnd() % (MAXW - 2));
        int h = 2 + (int)(rnd() % (MAXH - 2));
        int type;
        switch (rnd() % 5) {
        case 0:  type = 8;            break;
        case 1:  type = 0x10;         break;
        default: type = (int)(rnd() & 0x1f); break;
        }
        int idx = (int)(rnd() % 3);
        int match = (int)(rnd() & 0xff);
        int shift = (int)(rnd() & 0xf);
        int flag = (int)(rnd() % 3);
        int mmax = (w < h ? w : h) / 2;          /* keep interior non-empty */
        if (mmax < 1) mmax = 1;
        int m = (int)(rnd() % mmax);

        for (size_t i = 0; i < sizeof src; i++) src[i] = (uint8_t)rnd();
        for (size_t i = 0; i < sizeof dv; i++) dv[i] = (uint8_t)rnd();
        memcpy(dc, dv, sizeof dc);
        dv[(long long)m * w + m] = (uint8_t)match;   /* guarantee >=1 match */
        dc[(long long)m * w + m] = (uint8_t)match;
        ov[0] = (uint8_t)rnd(); oc[0] = ov[0];

        for (int i = 0; i < 12; i++) { arrv[i] = NULL; arrc[i] = NULL; }
        arrv[0] = a0v; arrc[0] = a0c;
        arrv[idx] = ev; arrc[idx] = ec;
        arrv[idx + 7] = mv; arrc[idx + 7] = mc;

        *(int16_t *)(a0v + 0x00) = (int16_t)w;
        *(int16_t *)(a0v + 0x02) = (int16_t)h;
        *(uint8_t *)(a0v + 0x06) = (uint8_t)type;
        *(void   **)(a0v + 0x10) = src;
        memcpy(a0c, a0v, sizeof a0c);

        *(int16_t *)(ev + 0x00) = (int16_t)w;
        *(int16_t *)(ev + 0x02) = (int16_t)h;
        *(uint8_t *)(ev + 0x06) = (uint8_t)type;
        *(void   **)(ev + 0x10) = src;
        memcpy(ec, ev, sizeof ec);

        uint32_t val = rnd();
        int has = (int)(rnd() & 1);
        memset(mv, 0, sizeof mv);
        *(u32 *)(mv + 0x00) = 8;
        *(u32 *)(mv + 0x04) = 0x40;
        *(u32 *)(mv + 0x08) = 0xc;
        *(u32 *)(mv + 0x0c) = has ? 0x148u : 0x149u;
        *(u32 *)(mv + 0x10) = 4;
        *(u32 *)(mv + 0x14) = val;
        memcpy(mc, mv, sizeof mc);

        memset(cfgv, 0, sizeof cfgv);
        cfgv[0x29] = (uint8_t)flag;
        *(uint16_t *)(cfgv + 0x2a) = (uint16_t)m;
        memcpy(cfgc, cfgv, sizeof cfgc);

        mk_image(iv, dv, w, w, h, 0, 0);
        mk_image(ic, dc, w, w, h, 0, 0);

        int rv = v(ov, arrv, iv, idx, match, shift, cfgv);
        int rc = cr_grad_score_from_desc(oc, arrc, (cr_image *)ic, idx,
                                        match, shift, cfgc);
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }
        if (ov[0] != oc[0]) mismatch("out", (u32)t, (u32)ov[0], (u32)oc[0]);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_grad_score_from_desc\n");
}

/* 0x18000f6f0 — masked mean-squared difference vs 0.5-sigma blur. */
static void test_masked_sharpness(void)
{
    typedef int (WINAPI *v_t)(int *, const void *, const void *);
    v_t v = (v_t)fn_at(RVA(0x18000f6f0));
    begin("cr_masked_sharpness");
    int bad = g_fail;

    enum { MAXW = 32, MAXH = 32, NP = MAXW * MAXH };
    static u8 sbuf[NP + 64], mbuf[NP + 64];
    static cr_image sv, sc;
    static void *pmv, *pmc;

    for (int t = 0; t < 20000; t++) {
        int w = 7 + (int)(rnd() % (MAXW - 7));     /* FIR ctx needs >= 7 */
        int h = 7 + (int)(rnd() % (MAXH - 7));
        for (int i = 0; i < NP; i++) sbuf[i] = (u8)rnd();
        for (int i = 0; i < NP; i++) mbuf[i] = (rnd() & 1) ? 0xff : (u8)rnd();

        (void)cr_image_set(&sv, sbuf, w, h);
        (void)cr_image_set(&sc, sbuf, w, h);
        pmv = mbuf; pmc = mbuf;

        int ov = (int)0x12345678, oc = (int)0x12345678;
        int rv = v(&ov, &sv, &pmv);
        int rc = cr_masked_sharpness(&oc, &sc, &pmc);
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }
        if (ov != oc) mismatch("out", (u32)t, (u32)ov, (u32)oc);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_masked_sharpness\n");
}

/* 0x180033f60 — float-source masked sharpness (round f32->u8 + range check). */
static void test_masked_sharpness_f32(void)
{
    typedef int (WINAPI *v_t)(int *, const void *, int, int, const void *);
    v_t v = (v_t)fn_at(RVA(0x180033f60));
    begin("cr_masked_sharpness_f32");
    int bad = g_fail;

    enum { MAXW = 32, MAXH = 32, NP = MAXW * MAXH };
    static float sbuf[NP + 64];
    static u8 mbuf[NP + 64];
    static void *pmv, *pmc;
    static const float *psv, *psc;

    for (int t = 0; t < 20000; t++) {
        int w = 7 + (int)(rnd() % (MAXW - 7));
        int h = 7 + (int)(rnd() % (MAXH - 7));
        for (int i = 0; i < NP; i++) {
            switch (rnd() % 4) {
            case 0:  sbuf[i] = (float)(rnd() % 256);             break;
            case 1:  sbuf[i] = (float)(rnd() % 1000) / 4.0f;     break;
            case 2:  sbuf[i] = 255.5f + (float)(rnd() % 10);     break;
            default: sbuf[i] = -0.5f - (float)(rnd() % 10);      break;
            }
        }
        for (int i = 0; i < NP; i++) mbuf[i] = (rnd() & 1) ? 0xff : (u8)rnd();

        psv = sbuf; psc = sbuf; pmv = mbuf; pmc = mbuf;

        int ov = (int)0x12345678, oc = (int)0x12345678;
        int rv = v(&ov, &psv, w, h, &pmv);
        int rc = cr_masked_sharpness_f32(&oc, &psc, w, h, &pmc);
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }
        if (ov != oc) mismatch("out", (u32)t, (u32)ov, (u32)oc);
    }

    /* n < 1 branch */
    for (int t = 0; t < 300; t++) {
        int w = (rnd() & 1) ? 0 : 8;
        int h = (rnd() & 1) ? 0 : 8;
        psv = sbuf; psc = sbuf; pmv = mbuf; pmc = mbuf;
        int ov = 7, oc = 7;
        int rv = v(&ov, &psv, w, h, &pmv);
        int rc = cr_masked_sharpness_f32(&oc, &psc, w, h, &pmc);
        if (rv != rc) mismatch("nret", (u32)t, (u32)rv, (u32)rc);
        if (ov != oc) mismatch("nout", (u32)t, (u32)ov, (u32)oc);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_masked_sharpness_f32\n");
}

/* 0x180023900 — masked bitmap: box-sum, threshold, FIR, bit-2 clear. */
static void test_mask_boxmax_fir_clear(void)
{
    typedef int (WINAPI *v_t)(void *, const void *, uint8_t, int, int, float);
    v_t v = (v_t)fn_at(RVA(0x180023900));
    begin("cr_mask_boxmax_fir_clear");
    int bad = g_fail;

    enum { MAXW = 28, MAXH = 28, NP = MAXW * MAXH };
    static u8 sv[NP + 64], sc[NP + 64];
    static u8 ov[NP + 64], oc[NP + 64];
    static cr_image sv_img, sc_img, ov_img, oc_img;

    for (int t = 0; t < 20000; t++) {
        int w = 4 + (int)(rnd() % (MAXW - 4));
        int h = 4 + (int)(rnd() % (MAXH - 4));
        uint8_t maskbyte = (uint8_t)(rnd() & 0xff);
        int k = 1 + 2 * (int)(rnd() % 6);          /* odd: 1,3,5,7,9,11 */
        if (k >= w) k = w - 1;
        if (k >= h) k = h - 1;
        if ((k & 1) == 0) k--;
        int niter = (int)(rnd() % 4);
        float sigma = (float)(rnd() % 1000) / 500.0f;

        for (int i = 0; i < NP; i++) { sv[i] = (u8)rnd(); sc[i] = sv[i]; }
        memset(ov, 0xAA, sizeof ov); memset(oc, 0xAA, sizeof oc);

        cr_image_set(&sv_img, sv, w, h);
        cr_image_set(&sc_img, sc, w, h);
        cr_image_set(&ov_img, ov, w, h);
        cr_image_set(&oc_img, oc, w, h);

        int rv = v(&ov_img, &sv_img, maskbyte, k, niter, sigma);
        int rc = cr_mask_boxmax_fir_clear(&oc_img, &sc_img, maskbyte, k,
                                          niter, sigma);
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }
        cmp_buf("out", ov, oc, (size_t)(w * h), (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_mask_boxmax_fir_clear\n");
}

/* 0x1800388b0 — build a masked bitmap sized to src (alloc + mask_boxmax). */
static void test_bitmap_build_masked(void)
{
    typedef int (WINAPI *v_t)(void *, const void *, const void *);
    v_t v = (v_t)fn_at(RVA(0x1800388b0));
    v_v_p vsfree = (v_v_p)fn_at(RVA(0x18003bf40));
    begin("cr_bitmap_build_masked");
    int bad = g_fail;

    enum { MAXW = 24, MAXH = 24, NPIX = MAXW * MAXH };
    static u8 sv[NPIX + 64], sc[NPIX + 64];
    static u8 srcv[0x20], srcc[0x20];
    static u8 ov[0x20], oc[0x20];
    static u8 cfgv[0x50], cfgc[0x50];

    for (int t = 0; t < 20000; t++) {
        int w = 1 + (int)(rnd() % MAXW);
        int h = 1 + (int)(rnd() % MAXH);
        for (int i = 0; i < NPIX; i++) { sv[i] = (u8)rnd(); sc[i] = sv[i]; }

        mk_image(srcv, sv, w, w, h, 0, 0);
        memcpy(srcc, srcv, sizeof srcc);

        memset(ov, 0x5A, sizeof ov); memset(oc, 0x5A, sizeof oc);
        memset(cfgv, 0, sizeof cfgv);
        *(float *)(cfgv + 0x48) = (float)(rnd() % 1000) / 500.0f;
        memcpy(cfgc, cfgv, sizeof cfgc);

        int rv = v(ov, srcv, cfgv);
        int rc = cr_bitmap_build_masked((cr_image *)oc, (const cr_image *)srcc, cfgc);
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); }
        else if (rv == 0) {
            /* descriptor fields (skip the data pointer at +8) */
            if (memcmp(ov, oc, 8) != 0 || memcmp(ov + 0x10, oc + 0x10, 0x10) != 0)
                mismatch("desc", (u32)t, 0, 0);
            void *pv = *(void **)(ov + 8), *pc = *(void **)(oc + 8);
            if ((pv != NULL) != (pc != NULL)) mismatch("ptr", (u32)t, pv != NULL, pc != NULL);
            else if (pv) cmp_buf("data", (u8 *)pv, (u8 *)pc, (size_t)(w * h), (u32)t);
        }
        if (*(void **)(ov + 8)) vsfree((void **)(ov + 8));
        if (*(void **)(oc + 8)) cr_sized_free((void **)(oc + 8));
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_bitmap_build_masked\n");
}

/* 0x18001f660 — unpack bitmap, box-sum, k*k threshold, FIR blur. */
static void test_bitmap_unpack_boxmax_fir(void)
{
    typedef int (WINAPI *v_t)(void *, const void *, int, int, float);
    v_t v = (v_t)fn_at(RVA(0x18001f660));
    begin("cr_bitmap_unpack_boxmax_fir");
    int bad = g_fail;

    enum { MAXW = 24, MAXH = 24, NPIX = MAXW * MAXH };
    static u8 bmv[512], bmc[512];
    static u8 ov[NPIX + 64], oc[NPIX + 64];
    static u8 srcv[0x20], srcc[0x20];
    static u8 outv[0x20], outc[0x20];

    for (int t = 0; t < 20000; t++) {
        int w = 8 + (int)(rnd() % (MAXW - 8));      /* >= 8: box-sum + FIR need room */
        int h = 8 + (int)(rnd() % (MAXH - 8));
        int a = ((w + 31) / 32) * 32 + 32 * (int)(rnd() % 2);
        int offx = (int)(rnd() % 4);
        int offy = (int)(rnd() % 4);
        int k = 1 + 2 * (int)(rnd() % 6);           /* odd: 1,3,5,7,9,11 */
        if (k >= w) k = w - 1;
        if (k >= h) k = h - 1;
        if ((k & 1) == 0) k--;
        if (k < 1) k = 1;
        int niter = (int)(rnd() % 4);
        float sigma = (float)(rnd() % 1000) / 500.0f;

        long long maxidx = (long long)(offy + h - 1) * a + (offx + w - 1);
        int nwords = (int)(maxidx >> 5) + 1;
        for (int i = 0; i < nwords * 4; i++) { bmv[i] = (u8)rnd(); bmc[i] = bmv[i]; }
        for (int i = 0; i < NPIX; i++) { ov[i] = 0; oc[i] = 0; }

        mk_image(srcv, bmv, a, w, h, offx, offy);
        memcpy(srcc, srcv, sizeof srcc);
        cr_image_set((cr_image *)outv, ov, w, h);
        cr_image_set((cr_image *)outc, oc, w, h);

        int rv = v(outv, srcv, k, niter, sigma);
        int rc = cr_bitmap_unpack_boxmax_fir((cr_image *)outc,
                                             (const cr_image *)srcc,
                                             k, niter, sigma);
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }
        cmp_buf("out", ov, oc, (size_t)(w * h), (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_bitmap_unpack_boxmax_fir\n");
}

/* 0x18003f060 — bitmap fill between extreme set bits (vertical then horizontal). */
static void test_bitmap_fill_extents(void)
{
    typedef int (WINAPI *v_t)(void *, const void *);
    v_t v = (v_t)fn_at(RVA(0x18003f060));
    begin("cr_bitmap_fill_extents");
    int bad = g_fail;

    enum { MAXH = 24, MAXWPR = 4, NW = MAXWPR * MAXH + 16 };
    static u8 sbuf[NW * 4], dv[NW * 4], dc[NW * 4];
    static cr_image sv, sc, ov, oc;

    for (int t = 0; t < 20000; t++) {
        int w = 32 * (1 + (int)(rnd() % MAXWPR));  /* 32,64,96,128 */
        int h = 1 + (int)(rnd() % MAXH);
        int wpr = w >> 5;
        int nwords = wpr * h;

        for (int i = 0; i < nwords * 4; i++) sbuf[i] = (u8)rnd();
        for (int i = 0; i < nwords * 4; i++) { dv[i] = 0xAA; dc[i] = 0xAA; }

        (void)cr_image_set(&sv, sbuf, w, h);
        (void)cr_image_set(&sc, sbuf, w, h);
        (void)cr_image_set(&ov, dv, w, h);
        (void)cr_image_set(&oc, dc, w, h);

        int rv = v(&ov, &sv);
        int rc = cr_bitmap_fill_extents(&oc, &sc);
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }
        cmp_buf("out", dv, dc, (size_t)(nwords * 4), (u32)t);
    }

    /* guard-failure paths: a != w or offx/offy set */
    for (int t = 0; t < 2000; t++) {
        int w = 32 * (1 + (int)(rnd() % MAXWPR));
        int h = 1 + (int)(rnd() % MAXH);
        int wpr = w >> 5;
        for (int i = 0; i < wpr * h * 4; i++) sbuf[i] = (u8)rnd();
        (void)cr_image_set(&sv, sbuf, w, h);
        (void)cr_image_set(&sc, sbuf, w, h);
        (void)cr_image_set(&ov, dv, w, h);
        (void)cr_image_set(&oc, dc, w, h);
        int mode = (int)(rnd() % 3);
        if (mode == 0) { sv.a = w + 32; sc.a = w + 32; }
        else if (mode == 1) { sv.offx = 1; sc.offx = 1; }
        else { ov.h = h + 1; oc.h = h + 1; }
        int rv = v(&ov, &sv);
        int rc = cr_bitmap_fill_extents(&oc, &sc);
        if (rv != rc) mismatch("gret", (u32)t, (u32)rv, (u32)rc);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_bitmap_fill_extents\n");
}

static void test_rect_fills(void)
{
    v_v_pb  v8  = (v_v_pb) fn_at(RVA(0x1800465a0));
    v_v_pw  v16 = (v_v_pw) fn_at(RVA(0x18001d700));
    v_v_pf  v32 = (v_v_pf)fn_at(RVA(0x18001edb0));
    const char *nm[3] = { "cr_rect_fill_u8", "cr_rect_fill_u16", "cr_rect_fill_f32" };

    for (int kind = 0; kind < 3; kind++) {
        begin(nm[kind]);
        int bad = g_fail;
        for (int t = 0; t < 8000; t++) {
            unsigned char dv[0x20], dc[0x20], pv[8192], pc[8192];
            int stride = (int)(rnd() % 40u) + 1;
            int w = (int)(rnd() % 20u), h = (int)(rnd() % 20u);
            int offx = (int)(rnd() % 8u), offy = (int)(rnd() % 8u);
            for (size_t i = 0; i < sizeof pv; i++) {
                unsigned char b = (unsigned char)rnd(); pv[i] = b; pc[i] = b;
            }
            mk_image(dv, pv, stride, w, h, offx, offy);
            mk_image(dc, pc, stride, w, h, offx, offy);
            uint32_t val = rnd();
            if (kind == 0)      { v8 (dv, (uint8_t)val);  cr_rect_fill_u8 ((cr_image *)dc, (uint8_t)val); }
            else if (kind == 1) { v16(dv, (uint16_t)val); cr_rect_fill_u16((cr_image *)dc, (uint16_t)val); }
            else {
                /* full float bit-pattern coverage (incl. denormals/NaN) */
                float f = cr_u2f(val);
                v32(dv, f);
                cr_rect_fill_f32((cr_image *)dc, f);
            }
            cmp_buf("rect", pv, pc, sizeof pv, (u32)t);
        }
        if (g_fail == bad) end(); else printf("  FAIL %s\n", nm[kind]);
    }
}

static void test_bitmap_ops(void)
{
    v_v_piiii vclr = (v_v_piiii)fn_at(RVA(0x180037fb0));
    v_v_pp    vset = (v_v_pp)fn_at(RVA(0x180023bb0));
    v_v_pp    vunp = (v_v_pp)fn_at(RVA(0x180041cc0));

    begin("cr_bitmap_clear_rect");
    int bad = g_fail;
    for (int t = 0; t < 8000; t++) {
        unsigned char dv[0x20], dc[0x20], wv[512], wc[512];
        int stride = (int)(rnd() % 64u) + 1;
        int offx = (int)(rnd() % 4u), offy = (int)(rnd() % 4u);
        int y0 = (int)(rnd() % 16u), y1 = (int)(rnd() % 16u);
        int x0 = (int)(rnd() % 32u), x1 = (int)(rnd() % 32u);
        for (size_t i = 0; i < sizeof wv; i++) {
            unsigned char b = (unsigned char)rnd(); wv[i] = b; wc[i] = b;
        }
        mk_image(dv, wv, stride, 0, 0, offx, offy);
        mk_image(dc, wc, stride, 0, 0, offx, offy);
        vclr(dv, y0, y1, x0, x1);
        cr_bitmap_clear_rect((cr_image *)dc, y0, y1, x0, x1);
        cmp_buf("clr", wv, wc, sizeof wv, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_bitmap_clear_rect\n");

    begin("cr_bitmap_set_from_image");
    bad = g_fail;
    for (int t = 0; t < 8000; t++) {
        unsigned char bv[0x20], bc[0x20], sv[0x20];
        unsigned char wv[512], wc[512], sb[256];
        int stride = (int)(rnd() % 64u) + 1;
        int offx = (int)(rnd() % 4u), offy = (int)(rnd() % 4u);
        int w = (int)(rnd() % 16u), h = (int)(rnd() % 16u);
        for (size_t i = 0; i < sizeof wv; i++) {
            unsigned char b = (unsigned char)rnd(); wv[i] = b; wc[i] = b;
        }
        for (size_t i = 0; i < sizeof sb; i++) sb[i] = (unsigned char)rnd();
        mk_image(bv, wv, stride, 0, 0, offx, offy);
        mk_image(bc, wc, stride, 0, 0, offx, offy);
        mk_image(sv, sb, 0, w, h, 0, 0);
        vset(bv, sv);
        cr_bitmap_set_from_image((cr_image *)bc, (const cr_image *)sv);
        cmp_buf("bset", wv, wc, sizeof wv, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_bitmap_set_from_image\n");

    begin("cr_bitmap_unpack");
    bad = g_fail;
    for (int t = 0; t < 8000; t++) {
        unsigned char dv[0x20], dc[0x20], sv[0x20];
        unsigned char pv[512], pc[512], wv[512];
        int stride = (int)(rnd() % 32u) + 1;
        int w = (int)(rnd() % 16u), h = (int)(rnd() % 16u);
        int soff = (int)(rnd() % 4u);
        for (size_t i = 0; i < sizeof pv; i++) {
            unsigned char b = (unsigned char)rnd(); pv[i] = b; pc[i] = b;
        }
        for (size_t i = 0; i < sizeof wv; i++) wv[i] = (unsigned char)rnd();
        mk_image(dv, pv, stride, w, h, 0, 0);
        mk_image(dc, pc, stride, w, h, 0, 0);
        mk_image(sv, wv, 32, 0, 0, soff, soff);
        vunp(dv, sv);
        cr_bitmap_unpack((cr_image *)dc, (const cr_image *)sv);
        cmp_buf("unp", pv, pc, sizeof pv, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_bitmap_unpack\n");
}

static void test_classify_mark(void)
{
    v_v_pfpp v = (v_v_pfpp)fn_at(RVA(0x180041bb0));
    begin("cr_classify_mark");
    int bad = g_fail;
    for (int t = 0; t < 20000; t++) {
        float vals[64];
        unsigned char bv[64], bc[64];
        uint16_t idx[64];
        for (int i = 0; i < 64; i++) {
            vals[i] = cr_u2f(rnd());
            unsigned char b = (unsigned char)((rnd() % 4u == 0) ? 8 : (rnd() & 0xff));
            bv[i] = bc[i] = b;
            idx[i] = (uint16_t)(rnd() % 64u);
        }
        uint16_t count = (uint16_t)(rnd() % 64u);
        unsigned char *basev = bv, *basec = bc;
        const uint16_t *ip = idx;
        v(vals, &basev, &count, &ip);
        cr_classify_mark(vals, &basec, &count, &ip);
        cmp_buf("classify", bv, bc, sizeof bv, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_classify_mark\n");
}

static void test_copy_or_relu(void)
{
    v_u64_ppii v = (v_u64_ppii)fn_at(RVA(0x180030270));
    begin("cr_copy_or_relu");
    int bad = g_fail;
    for (int t = 0; t < 20000; t++) {
        unsigned char sv[256], dv[256], dc[256];
        for (size_t i = 0; i < sizeof sv; i++) sv[i] = (unsigned char)rnd();
        memset(dv, 0x5A, sizeof dv); memset(dc, 0x5A, sizeof dc);
        int n = (int)(rnd() % 40u) - 3;
        int mode = (int)(rnd() % 4u) - 1;
        uint64_t rv = v(dv, sv, n, mode);
        uint64_t rc = cr_copy_or_relu(dc, sv, n, mode);
        if (rv != rc) mismatch("cor-ret", (u32)t, (u32)rv, (u32)rc);
        cmp_buf("cor", dv, dc, sizeof dv, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_copy_or_relu\n");
}

static void test_array_rotate(void)
{
    v_v_pli v = (v_v_pli)fn_at(RVA(0x18001d7b0));
    begin("cr_array_rotate");
    int bad = g_fail;
    for (int t = 0; t < 20000; t++) {
        uint64_t av[64], ac[64];
        for (int i = 0; i < 64; i++) { av[i] = ((uint64_t)rnd() << 32) | rnd(); ac[i] = av[i]; }
        int n = (int)(rnd() % 40u) + 3;      /* n >= 3 keeps indices in range */
        v(av, n);
        cr_array_rotate(ac, n);
        cmp_buf("rot", (unsigned char *)av, (unsigned char *)ac, sizeof av, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_array_rotate\n");
}

static void test_type_desc(void)
{
    v_u64_pc v = (v_u64_pc)fn_at(RVA(0x18003d8f0));
    begin("cr_type_desc_getter");
    int bad = g_fail;
    for (int t = 0; t < 4000; t++) {
        unsigned char pv[32], pc[32];
        memset(pv, 0xAB, sizeof pv); memset(pc, 0xAB, sizeof pc);
        char ty = (char)rnd();
        int isnull = (rnd() % 8u) == 0;
        uint64_t rv = v(isnull ? NULL : pv, ty);
        uint64_t rc = cr_type_desc_getter(isnull ? NULL : pc, ty);
        if (rv != rc) mismatch("desc-ret", (u8)ty, (u32)rv, (u32)rc);
        if (!isnull) cmp_buf("desc", pv, pc, sizeof pv, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_type_desc_getter\n");
}

/* ---- batch 5: image copies / stats / affine ---------------------------- */

/* 0x1800308d0 / 0x18000f600 / 0x18002ade0 — image copies.  The u8/u32 forms
 * bail with 0x69 on a w/h mismatch; the u16 form shifts each element left. */
static void test_image_copies(void)
{
    v_u64_pp v8  = (v_u64_pp) fn_at(RVA(0x1800308d0));
    v_u64_pp v32 = (v_u64_pp) fn_at(RVA(0x18000f600));
    v_v_ppb  v16 = (v_v_ppb)fn_at(RVA(0x18002ade0));
    const char *nm[3] = { "cr_image_copy_u8", "cr_image_copy_u32",
                          "cr_image_copy_u16_shl" };

    for (int kind = 0; kind < 3; kind++) {
        begin(nm[kind]);
        int bad = g_fail;
        int esz = (kind == 2) ? 2 : (kind == 1 ? 4 : 1);
        for (int t = 0; t < 12000; t++) {
            unsigned char dv[0x20], dc[0x20], sv[0x20], sc[0x20];
            unsigned char pv[8192], pc[8192], qv[8192], qc[8192];
            int dstride = (int)(rnd() % 48u) + 1;
            int sstride = (int)(rnd() % 48u) + 1;
            int dw = (int)(rnd() % 8u), dh = (int)(rnd() % 8u);
            int sw = dw, sh = dh;
            if (kind != 2 && (rnd() % 4u) == 0) {       /* force mismatch */
                sw = dw + (int)(rnd() % 3u) - 1;
                sh = dh + (int)(rnd() % 3u) - 1;
            }
            int dox = (int)(rnd() % 4u), doy = (int)(rnd() % 4u);
            int sox = (int)(rnd() % 4u), soy = (int)(rnd() % 4u);
            for (size_t i = 0; i < sizeof pv; i++) {
                unsigned char b = (unsigned char)rnd();
                pv[i] = b; pc[i] = b; qv[i] = b; qc[i] = b;
            }
            mk_image(dv, pv, dstride, dw, dh, dox, doy);
            mk_image(dc, pc, dstride, dw, dh, dox, doy);
            mk_image(sv, qv, sstride, sw, sh, sox, soy);
            mk_image(sc, qc, sstride, sw, sh, sox, soy);

            uint8_t shift = (uint8_t)rnd();
            uint64_t rv, rc;
            if (kind == 0)      { rv = v8 (dv, sv);            rc = cr_image_copy_u8 ((cr_image *)dc, (const cr_image *)sc); }
            else if (kind == 1) { rv = v32(dv, sv);            rc = cr_image_copy_u32((cr_image *)dc, (const cr_image *)sc); }
            else                { v16(dv, sv, shift); rv = 0;  cr_image_copy_u16_shl((cr_image *)dc, (const cr_image *)sc, shift); rc = 0; }
            if (kind != 2 && rv != rc) mismatch("cp-ret", (u32)t, rv, rc);
            cmp_buf("cp-dst", pv, pc, sizeof pv, (u32)t);
            cmp_buf("cp-src", qv, qc, sizeof qv, (u32)t); /* src must be untouched */
        }
        if (g_fail == bad) end(); else printf("  FAIL %s\n", nm[kind]);
    }
}

/* 0x180037e70 — count*sumsq - sum^2 over the samples a mask selects. */
static void test_masked_variance(void)
{
    v_f_piipp v = (v_f_piipp)fn_at(RVA(0x180037e70));
    begin("cr_masked_variance");
    int bad = g_fail;
    for (int t = 0; t < 20000; t++) {
        float data[512];
        unsigned char m[512];
        int rows = (int)(rnd() % 20u) - 2;      /* sometimes <= 0 */
        int cols = (int)(rnd() % 20u);
        if (rows > 20) rows = 20;
        for (int i = 0; i < 512; i++) {
            data[i] = cr_u2f(rnd());
            m[i] = (unsigned char)((rnd() % 3u == 0) ? 0 : (rnd() & 0xff));
        }
        const unsigned char *mp = m;
        float rv = v(data, rows, cols, &mp);
        float rc = cr_masked_variance(data, rows, cols, &mp);
        if (cr_f2u(rv) != cr_f2u(rc))
            mismatch("var", (u32)t, cr_f2u(rv), cr_f2u(rc));
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_masked_variance\n");
}

/* 0x1800469e0 — big-endian 4-byte probe of an image-like descriptor. */
static void test_read_quad(void)
{
    v_i_p v = (v_i_p)fn_at(RVA(0x1800469e0));
    begin("cr_read_quad");
    int bad = g_fail;
    for (int t = 0; t < 20000; t++) {
        unsigned char d[0x20], pix[4096];
        for (size_t i = 0; i < sizeof pix; i++) pix[i] = (unsigned char)rnd();
        int stride = (int)(rnd() % 40u) + 1;
        int A = (int)(rnd() % 30u);
        int B = (int)(rnd() % 30u);
        int isnull = (rnd() % 16u) == 0;
        memset(d, 0, sizeof d);
        *(int   *)(d + 0x00) = stride;
        *(void **)(d + 0x08) = pix;
        *(int   *)(d + 0x10) = A;
        *(int   *)(d + 0x14) = B;
        int rv = v(isnull ? NULL : d);
        int rc = cr_read_quad(isnull ? NULL : (const int *)d);
        if (rv != rc) mismatch(isnull ? "quad-null" : "quad",
                               (u32)t, (u32)rv, (u32)rc);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_read_quad\n");
}

/* 0x1800491e0 — pixel-buffer descriptor init (6 args; 5th/6th on the stack). */
static void test_buffer_pixels_setup(void)
{
    v_u64_ppuiii v = (v_u64_ppuiii)fn_at(RVA(0x1800491e0));
    begin("cr_buffer_pixels_setup");
    int bad = g_fail;
    for (int t = 0; t < 12000; t++) {
        unsigned char pv[1024], pc[1024], src[256];
        for (size_t i = 0; i < sizeof src; i++) src[i] = (unsigned char)rnd();
        uint32_t cap = (rnd() % 200u) + 8u;
        uint32_t len = rnd() % 260u;
        int a = (int)(rnd() % 40u) - 10;
        int b = (int)(rnd() % 40u) - 10;
        int c = (int)(rnd() % 40u) - 10;
        memset(pv, 0xA5, sizeof pv); memset(pc, 0xA5, sizeof pc);
        *(uint32_t *)(pv + 4) = cap;
        *(uint32_t *)(pc + 4) = cap;
        int isnull = (rnd() % 16u) == 0;

        uint64_t rv = v(isnull ? NULL : pv, src, len, a, b, c);
        uint64_t rc = cr_buffer_pixels_setup(isnull ? NULL : pc, src, len, a, b, c);
        if (rv != rc) mismatch("bps-ret", (u32)t, rv, rc);
        if (!isnull) cmp_buf("bps", pv, pc, sizeof pv, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_buffer_pixels_setup\n");
}

/* 0x180014b30 — table-driven affine transform (picks the min score). */
static void test_affine_transform(void)
{
    v_v_ppp v = (v_v_ppp)fn_at(RVA(0x180014b30));
    begin("cr_affine_transform");
    int bad = g_fail;
    for (int t = 0; t < 20000; t++) {
        float pts[27], scores[9];
        float ov[16], oc[16];
        for (int i = 0; i < 27; i++) pts[i] = cr_u2f(rnd());
        for (int i = 0; i < 9; i++)  scores[i] = cr_u2f(rnd());
        if ((rnd() % 8u) == 0) scores[rnd() % 9u] = 0.0f;  /* force ties */
        memset(ov, 0x3F, sizeof ov); memset(oc, 0x3F, sizeof oc);
        v(ov, pts, scores);
        cr_affine_transform(oc, pts, scores);
        cmp_buf("aff", (unsigned char *)ov, (unsigned char *)oc, sizeof ov, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_affine_transform\n");
}

/* ---- batch 6: 256-byte leaves ------------------------------------------ */

/* 0x1800391b0 — atan2 in degrees. */
static void test_atan2_deg(void)
{
    v_fff v = (v_fff)fn_at(RVA(0x1800391b0));
    begin("cr_atan2_deg");
    int bad = g_fail;
    static const float sp[] = {
        0.0f, -0.0f, 1.0f, -1.0f, 2.0f, -2.0f, 0.5f, -0.5f, 1e-30f, -1e-30f,
        1e30f, -1e30f, 3.4028235e38f, -3.4028235e38f, 0.7071068f, -0.7071068f,
        1e-45f, -1e-45f, 255.0f, -255.0f, 0.0001f, -0.0001f, 1e8f, -1e8f,
    };
    for (size_t i = 0; i < sizeof sp / sizeof sp[0]; i++) {
        for (size_t j = 0; j < sizeof sp / sizeof sp[0]; j++) {
            float a = sp[i], b = sp[j];
            float rv = v(a, b), rc = cr_atan2_deg(a, b);
            if (cr_f2u(rv) != cr_f2u(rc))
                mismatch("atan2-sp", cr_f2u(a), cr_f2u(rv), cr_f2u(rc));
        }
    }
    for (int t = 0; t < 20000; t++) {
        float a = cr_u2f(rnd()), b = cr_u2f(rnd());
        float rv = v(a, b), rc = cr_atan2_deg(a, b);
        if (cr_f2u(rv) != cr_f2u(rc))
            mismatch("atan2", (u32)t, cr_f2u(rv), cr_f2u(rc));
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_atan2_deg\n");
}

/* 0x18000fb20 — Q15 vertical FIR over 4 columns at a time. */
static void test_vfir4_u8(void)
{
    v_v_pppii v = (v_v_pppii)fn_at(RVA(0x18000fb20));
    begin("cr_vfir4_u8");
    int bad = g_fail;
    for (int t = 0; t < 20000; t++) {
        uint8_t iv[512], ov[256], oc[256];
        int16_t coeff[8];
        for (size_t i = 0; i < sizeof iv; i++) iv[i] = (uint8_t)rnd();
        for (int i = 0; i < 8; i++) coeff[i] = (int16_t)rnd();
        int n = (int)(rnd() % 40u) + 1;         /* sometimes <= 3 (no-op) */
        int m = (int)(rnd() % 7u);              /* 0..6 */
        memset(ov, 0x5A, sizeof ov); memset(oc, 0x5A, sizeof oc);
        v(ov, iv, coeff, n, m);
        cr_vfir4_u8(oc, iv, coeff, n, m);
        cmp_buf("vfir", ov, oc, sizeof ov, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_vfir4_u8\n");
}

/* 0x180020130 — masked min/max/count. */
static void test_masked_minmax(void)
{
    v_v_ppppp v = (v_v_ppppp)fn_at(RVA(0x180020130));
    begin("cr_masked_minmax");
    int bad = g_fail;
    for (int t = 0; t < 20000; t++) {
        unsigned char dv[0x20], dc[0x20], bv[0x20], bc[0x20];
        unsigned char px[256], bm[256];
        for (size_t i = 0; i < sizeof px; i++) px[i] = (uint8_t)rnd();
        for (size_t i = 0; i < sizeof bm; i++) bm[i] = (uint8_t)rnd();
        int w = (int)(rnd() % 12u);
        int h = (int)(rnd() % 12u);
        int stride = (int)(rnd() % 24u) + 1;
        int offx = (int)(rnd() % 4u), offy = (int)(rnd() % 4u);
        mk_image(dv, px, 0, w, h, 0, 0);
        mk_image(dc, px, 0, w, h, 0, 0);
        mk_image(bv, bm, stride, 0, 0, offx, offy);
        mk_image(bc, bm, stride, 0, 0, offx, offy);
        int mnv = -1, mxv = -1, cnv = -1, mnc = -1, mxc = -1, cnc = -1;
        v(&mnv, &mxv, &cnv, dv, bv);
        cr_masked_minmax(&mnc, &mxc, &cnc, (const cr_image *)dc, (const cr_image *)bc);
        if (mnv != mnc || mxv != mxc || cnv != cnc)
            mismatch("mm", (u32)t, (u32)mnv, (u32)mnc);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_masked_minmax\n");
}

/* 0x1800309a0 — orientation pick (forward/reverse correlation + half-swap). */
static void test_orient_pick(void)
{
    v_v_pppppii v = (v_v_pppppii)fn_at(RVA(0x1800309a0));
    begin("cr_orient_pick");
    int bad = g_fail;
    for (int t = 0; t < 20000; t++) {
        uint8_t av[512], ac[512];
        uint8_t data[128];
        int16_t coeff[128];
        for (size_t i = 0; i < sizeof av; i++) { av[i] = (uint8_t)rnd(); ac[i] = av[i]; }
        for (size_t i = 0; i < sizeof data; i++) data[i] = (uint8_t)rnd();
        for (size_t i = 0; i < sizeof coeff / sizeof coeff[0]; i++) coeff[i] = (int16_t)rnd();
        int k = (int)(rnd() % 9u);              /* k*k <= 64 */
        int half = (int)(rnd() % 400u) - 40;
        const uint8_t *dp = data;
        uint8_t fv = (uint8_t)rnd(), fc = fv;
        int ov = -1, oc = -1;
        v(av, &fv, &ov, &dp, coeff, half, k);
        cr_orient_pick(ac, &fc, &oc, &dp, coeff, half, k);
        if (ov != oc || fv != fc) mismatch("orient-ret", (u32)t, (u32)ov, (u32)oc);
        cmp_buf("orient", av, ac, sizeof av, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_orient_pick\n");
}

/* ---- batch 7: 272-byte leaves ------------------------------------------ */

/* 0x18003e9f0 — out = in * W^T (N x T matmul), with a K==Kcheck guard. */
static void test_matmul_nt(void)
{
    v_i_ppipii_p v = (v_i_ppipii_p)fn_at(RVA(0x18003e9f0));
    begin("cr_matmul_nt");
    int bad = g_fail;
    for (int t = 0; t < 20000; t++) {
        float in[64], W[64], ov[64], oc[64];
        for (int i = 0; i < 64; i++) { in[i] = cr_u2f(rnd()); W[i] = cr_u2f(rnd()); }
        int nrows = (int)(rnd() % 10u) - 1;
        int K     = (int)(rnd() % 9u);
        int ncols = (int)(rnd() % 10u) - 1;
        int Kcheck = ((rnd() % 3u) == 0) ? K + (int)(rnd() % 3u) - 1 : K;
        memset(ov, 0x3F, sizeof ov); memset(oc, 0x3F, sizeof oc);
        int rv = v(in, nrows, K, W, ncols, Kcheck, ov);
        int rc = cr_matmul_nt(in, nrows, K, W, ncols, Kcheck, oc);
        if (rv != rc) mismatch("mm-ret", (u32)t, (u32)rv, (u32)rc);
        cmp_buf("mm", (unsigned char *)ov, (unsigned char *)oc, sizeof ov, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_matmul_nt\n");
}

/* 0x18003f460 — mean + stddev of a byte buffer. */
static void test_mean_stddev(void)
{
    v_v_pppi v = (v_v_pppi)fn_at(RVA(0x18003f460));
    begin("cr_mean_stddev");
    int bad = g_fail;
    for (int t = 0; t < 20000; t++) {
        uint8_t data[64];
        for (size_t i = 0; i < sizeof data; i++) data[i] = (uint8_t)rnd();
        int n = (int)(rnd() % 66u) - 2;      /* includes <= 0 */
        float mv = 0, sv = 0, mc = 0, sc = 0;
        v(&mv, &sv, data, n);
        cr_mean_stddev(&mc, &sc, data, n);
        if (cr_f2u(mv) != cr_f2u(mc)) mismatch("mean", (u32)t, cr_f2u(mv), cr_f2u(mc));
        if (cr_f2u(sv) != cr_f2u(sc)) mismatch("std",  (u32)t, cr_f2u(sv), cr_f2u(sc));
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_mean_stddev\n");
}

/* 0x1800277e0 — min/max/count of int16 samples, optional byte mask. */
static void test_masked_minmax_s16(void)
{
    v_v_pppppb v = (v_v_pppppb)fn_at(RVA(0x1800277e0));
    begin("cr_masked_minmax_s16");
    int bad = g_fail;
    for (int t = 0; t < 20000; t++) {
        unsigned char iv[0x20], ic[0x20], mv[0x20], mc[0x20];
        int16_t d[160];
        uint8_t m[160];
        for (size_t i = 0; i < sizeof d / sizeof d[0]; i++) d[i] = (int16_t)rnd();
        for (size_t i = 0; i < sizeof m; i++) m[i] = (uint8_t)rnd();
        int w = (int)(rnd() % 12u);
        int h = (int)(rnd() % 12u);
        uint8_t am = (uint8_t)rnd();
        int usemask = (rnd() % 4u) != 0;
        mk_image(iv, d, 0, w, h, 0, 0);
        mk_image(ic, d, 0, w, h, 0, 0);
        mk_image(mv, m, 0, 0, 0, 0, 0);
        mk_image(mc, m, 0, 0, 0, 0, 0);
        int a = -1, b = -1, c = -1, p = -1, q = -1, r = -1;
        v(&a, &b, &c, iv, usemask ? mv : NULL, am);
        cr_masked_minmax_s16(&p, &q, &r, (const cr_image *)ic,
                             usemask ? (const cr_image *)mc : NULL, am);
        if (a != p || b != q || c != r)
            mismatch("mms16", (u32)t, (u32)a, (u32)p);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_masked_minmax_s16\n");
}

/* ---- batch 8: 288-byte leaves ------------------------------------------ */

/* 0x180017840 — float min/max/count of float samples, optional byte mask. */
static void test_masked_minmax_f32(void)
{
    v_v_pppppb v = (v_v_pppppb)fn_at(RVA(0x180017840));
    begin("cr_masked_minmax_f32");
    int bad = g_fail;
    for (int t = 0; t < 20000; t++) {
        unsigned char iv[0x20], ic[0x20], mv[0x20], mc[0x20];
        uint32_t d[160];
        uint8_t m[160];
        for (size_t i = 0; i < sizeof d / sizeof d[0]; i++) d[i] = (uint32_t)rnd();
        for (size_t i = 0; i < sizeof m; i++) m[i] = (uint8_t)rnd();
        int w = (int)(rnd() % 12u);
        int h = (int)(rnd() % 12u);
        uint8_t am = (uint8_t)rnd();
        int usemask = (rnd() % 4u) != 0;
        mk_image(iv, d, 0, w, h, 0, 0);
        mk_image(ic, d, 0, w, h, 0, 0);
        mk_image(mv, m, 0, 0, 0, 0, 0);
        mk_image(mc, m, 0, 0, 0, 0, 0);
        float a = 0, b = 0, p = 0, q = 0;
        int c = -1, r = -1;
        v(&a, &b, &c, iv, usemask ? mv : NULL, am);
        cr_masked_minmax_f32(&p, &q, &r, (const cr_image *)ic,
                             usemask ? (const cr_image *)mc : NULL, am);
        if (cr_f2u(a) != cr_f2u(p) || cr_f2u(b) != cr_f2u(q) || c != r)
            mismatch("mmf32", (u32)t, cr_f2u(a), cr_f2u(p));
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_masked_minmax_f32\n");
}

/* 0x1800334c0 — int16 image -> float image with power-of-two scale. */
static void test_i16_to_f32_scaled(void)
{
    v_v_ppi v = (v_v_ppi)fn_at(RVA(0x1800334c0));
    begin("cr_i16_to_f32_scaled");
    int bad = g_fail;
    for (int t = 0; t < 20000; t++) {
        unsigned char dv[0x20], dc[0x20], sv[0x20], sc[0x20];
        int16_t sb[4096];
        float pv[4096], pc[4096];
        for (size_t i = 0; i < sizeof sb / sizeof sb[0]; i++) sb[i] = (int16_t)rnd();
        for (size_t i = 0; i < sizeof pv / sizeof pv[0]; i++) {
            uint32_t u = (uint32_t)rnd();
            memcpy(&pv[i], &u, 4);
            pc[i] = pv[i];
        }
        int sa = (int)(rnd() % 40u) + 1;
        int da = (int)(rnd() % 40u) + 1;
        int w = (int)(rnd() % 20u), h = (int)(rnd() % 20u);
        int sox = (int)(rnd() % 8u), soy = (int)(rnd() % 8u);
        int dox = (int)(rnd() % 8u), doy = (int)(rnd() % 8u);
        int shift = (int)(rnd() % 70u) - 35;   /* includes 0 and both signs */
        mk_image(dv, pv, da, w, h, dox, doy);
        mk_image(dc, pc, da, w, h, dox, doy);
        mk_image(sv, sb, sa, w, h, sox, soy);
        mk_image(sc, sb, sa, w, h, sox, soy);
        v(dv, sv, shift);
        cr_i16_to_f32_scaled((cr_image *)dc, (const cr_image *)sc, shift);
        cmp_buf("i16f32", (unsigned char *)pv, (unsigned char *)pc, sizeof pv, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_i16_to_f32_scaled\n");
}

/* ---- batch 9: 304-byte leaves ------------------------------------------ */

/* 0x18001f790 — Q15 bilinear resample of a byte image along an affine path. */
static void test_bilinear_sample_u8(void)
{
    v_v_pppii v = (v_v_pppii)fn_at(RVA(0x18001f790));
    begin("cr_bilinear_sample_u8");
    int bad = g_fail;
    for (int t = 0; t < 20000; t++) {
        unsigned char iv[0x20], ic[0x20];
        uint8_t pool[8192];
        uint8_t ov[64], oc[64];
        for (size_t i = 0; i < sizeof pool; i++) pool[i] = (uint8_t)rnd();
        int stride = (int)(rnd() % 20u) + 1;
        int w = (int)(rnd() % 11u) + 2;
        int h = (int)(rnd() % 11u) + 2;
        int offx = (int)(rnd() % 5u), offy = (int)(rnd() % 5u);
        uint8_t *data = pool + 4096;      /* margin so negative coords stay in-bounds */
        int32_t s[6];
        int idx = (int)(rnd() % 5u) - 2;
        s[0] = (int32_t)(rnd() % 0x8001u) - 0x4000;                       /* xstep */
        s[1] = (int32_t)(rnd() % 3u) - 1;                                 /* xcoef */
        s[2] = (int32_t)(rnd() % ((uint32_t)(w - 2) * 0x8000u + 1u));     /* xbase */
        s[3] = (int32_t)(rnd() % 0x8001u) - 0x4000;                       /* ystep */
        s[4] = (int32_t)(rnd() % 3u) - 1;                                 /* ycoef */
        s[5] = (int32_t)(rnd() % ((uint32_t)(h - 2) * 0x8000u + 1u));     /* ybase */
        int n = (int)(rnd() % 4u) + 1;
        mk_image(iv, data, stride, w, h, offx, offy);
        mk_image(ic, data, stride, w, h, offx, offy);
        memset(ov, 0xAA, sizeof ov); memset(oc, 0xAA, sizeof oc);
        v(ov, iv, s, n, idx);
        cr_bilinear_sample_u8(oc, (const cr_image *)ic, (const cr_sampler *)s, n, idx);
        cmp_buf("bilin", ov, oc, sizeof ov, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_bilinear_sample_u8\n");
}

/* 0x18002cc00 — horizontal box blur (even window => plain copy). */
static void test_box_blur_h_f32(void)
{
    v_v_ppiii v = (v_v_ppiii)fn_at(RVA(0x18002cc00));
    static const int wins[] = { 0, 1, 2, 3, 4, 5, 6, 7, 9 };
    begin("cr_box_blur_h_f32");
    int bad = g_fail;
    for (int t = 0; t < 20000; t++) {
        float src[256], dv[256], dc[256];
        for (int i = 0; i < 256; i++) src[i] = cr_u2f(rnd());
        for (int i = 0; i < 256; i++) {
            uint32_t u = (uint32_t)rnd();
            memcpy(&dv[i], &u, 4);
            dc[i] = dv[i];
        }
        int nrows = (int)(rnd() % 9u);
        int ncols = (int)(rnd() % 9u);
        int win = wins[rnd() % (sizeof wins / sizeof wins[0])];
        float *pv = dv, *pc = dc;
        v(&pv, src, nrows, ncols, win);
        cr_box_blur_h_f32(&pc, src, nrows, ncols, win);
        cmp_buf("blur", (unsigned char *)dv, (unsigned char *)dc, sizeof dv, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_box_blur_h_f32\n");
}

/* 0x180037330 — masked sum/count of a centred box around a linear pixel index. */
static void test_masked_box_sum(void)
{
    v_v_ppppbii v = (v_v_ppppbii)fn_at(RVA(0x180037330));
    begin("cr_masked_box_sum");
    int bad = g_fail;
    for (int t = 0; t < 20000; t++) {
        unsigned char iv[0x20], ic[0x20], mv[0x20], mc[0x20];
        float d[256];
        uint8_t m[256];
        for (int i = 0; i < 256; i++) d[i] = cr_u2f(rnd());
        for (int i = 0; i < 256; i++) m[i] = (uint8_t)rnd();
        int W = (int)(rnd() % 16u) + 1;   /* > 0: the vendor does a signed /W */
        int H = (int)(rnd() % 16u);
        int win = (int)(rnd() % 10u);
        int idx = (int)(rnd() % 400u) - 50;
        uint8_t am = (uint8_t)rnd();
        mk_image(iv, d, W, W, H, 0, 0);
        mk_image(ic, d, W, W, H, 0, 0);
        mk_image(mv, m, W, W, H, 0, 0);
        mk_image(mc, m, W, W, H, 0, 0);
        int cv = -1, cc = -1;
        float sv = 0, sc = 0;
        v(&cv, &sv, iv, mv, am, win, idx);
        cr_masked_box_sum(&cc, &sc, (const cr_image *)ic, (const cr_image *)mc,
                          am, win, idx);
        if (cv != cc || cr_f2u(sv) != cr_f2u(sc))
            mismatch("boxsum", (u32)t, (u32)cv, (u32)cc);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_masked_box_sum\n");
}

/* ---- batch 10: 320-byte leaves ----------------------------------------- */

/* 0x18000f9d0 — float image -> int16 image with a power-of-two scale. */
static void test_f32_to_i16_scaled(void)
{
    v_v_ppi v = (v_v_ppi)fn_at(RVA(0x18000f9d0));
    begin("cr_f32_to_i16_scaled");
    int bad = g_fail;
    for (int t = 0; t < 20000; t++) {
        unsigned char dv[0x20], dc[0x20], sv[0x20], sc[0x20];
        float sb[4096];
        int16_t pv[4096], pc[4096];
        for (size_t i = 0; i < sizeof sb / sizeof sb[0]; i++) {
            uint32_t u = (uint32_t)rnd();
            memcpy(&sb[i], &u, 4);
        }
        for (size_t i = 0; i < sizeof pv / sizeof pv[0]; i++) {
            uint32_t u = (uint32_t)rnd();
            pv[i] = (int16_t)u;
            pc[i] = pv[i];
        }
        int sa = (int)(rnd() % 40u) + 1;
        int da = (int)(rnd() % 40u) + 1;
        int w = (int)(rnd() % 20u), h = (int)(rnd() % 20u);
        int sox = (int)(rnd() % 8u), soy = (int)(rnd() % 8u);
        int dox = (int)(rnd() % 8u), doy = (int)(rnd() % 8u);
        int shift = (int)(rnd() % 70u) - 35;
        mk_image(dv, pv, da, w, h, dox, doy);
        mk_image(dc, pc, da, w, h, dox, doy);
        mk_image(sv, sb, sa, w, h, sox, soy);
        mk_image(sc, sb, sa, w, h, sox, soy);
        v(dv, sv, shift);
        cr_f32_to_i16_scaled((cr_image *)dc, (const cr_image *)sc, shift);
        cmp_buf("f2i16", (unsigned char *)pv, (unsigned char *)pc, sizeof pv, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_f32_to_i16_scaled\n");
}

/* 0x180019490 — per-32-byte-block "intermediate byte" bitmap. */
static void test_block_extreme_bitmap(void)
{
    v_v_pp v = (v_v_pp)fn_at(RVA(0x180019490));
    begin("cr_block_extreme_bitmap");
    int bad = g_fail;
    for (int t = 0; t < 20000; t++) {
        unsigned char ov[0x20], oc[0x20], iv[0x20], ic[0x20];
        uint8_t inbuf[8192];
        uint32_t pv[512], pc[512];
        for (size_t i = 0; i < sizeof inbuf; i++) inbuf[i] = (uint8_t)rnd();
        for (size_t i = 0; i < sizeof pv / sizeof pv[0]; i++) {
            uint32_t u = (uint32_t)rnd();
            pv[i] = u;
            pc[i] = u;
        }
        int w = (int)(rnd() % 70u) + 1;
        int h = (int)(rnd() % 8u) + 1;
        int a = (w + 31) & ~31;            /* output row stride in bits */
        uint8_t *indata = inbuf + 2048;    /* margin for the downward reads */
        mk_image(ov, pv, a, w, h, 0, 0);
        mk_image(oc, pc, a, w, h, 0, 0);
        mk_image(iv, indata, w, w, h, 0, 0);
        mk_image(ic, indata, w, w, h, 0, 0);
        v(ov, iv);
        cr_block_extreme_bitmap((cr_image *)oc, (const cr_image *)ic);
        cmp_buf("beb", (unsigned char *)pv, (unsigned char *)pc, sizeof pv, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_block_extreme_bitmap\n");
}

/* 0x180034190 — total popcount of a bitmap with `w` significant bits per row. */
static void test_bitmap_popcount(void)
{
    v_i_p v = (v_i_p)fn_at(RVA(0x180034190));
    begin("cr_bitmap_popcount");
    int bad = g_fail;
    for (int t = 0; t < 20000; t++) {
        unsigned char iv[0x20], ic[0x20];
        uint32_t d[512];
        for (size_t i = 0; i < sizeof d / sizeof d[0]; i++) d[i] = (uint32_t)rnd();
        int a = (int)(rnd() % 20u) * 32 + 32;   /* multiple of 32, >= 32 */
        int w = (int)(rnd() % (unsigned)(a + 1));
        int h = (int)(rnd() % 8u);
        mk_image(iv, d, a, w, h, 0, 0);
        mk_image(ic, d, a, w, h, 0, 0);
        int rv = v(iv);
        int rc = cr_bitmap_popcount((const cr_image *)ic);
        if (rv != rc) mismatch("popcnt", (u32)t, (u32)rv, (u32)rc);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_bitmap_popcount\n");
}

/* ---- batch 17: bitmap morphology --------------------------------------- */

/* 0x180024cb0 / 0x1800220e0 — bitmap dilation / erosion.  Both take a dst
 * image (word stride + height) and a src image (input words) plus a pass count;
 * from the 2nd pass the dst feeds itself.  We exercise 1..4 words/row, 1..6
 * rows and 1..3 passes so both the multi-word carry paths and the self-feed
 * path are covered. */
static void test_bitmap_morph(void)
{
    struct {
        const char *name; u32 rva;
        void (*clean)(cr_image *, const cr_image *, int);
    } fns[] = {
        { "cr_bitmap_dilate", RVA(0x180024cb0), cr_bitmap_dilate },
        { "cr_bitmap_erode",  RVA(0x1800220e0), cr_bitmap_erode  },
    };

    for (size_t k = 0; k < sizeof fns / sizeof fns[0]; k++) {
        begin(fns[k].name);
        int bad = g_fail;
        v_v_ppim v = (v_v_ppim)fn_at(fns[k].rva);
        for (int t = 0; t < 20000; t++) {
            unsigned char dv[0x20], dc[0x20], sv[0x20], sc[0x20];
            uint32_t pv[512], pc[512], sq[512];
            int words = 1 + (int)(rnd() % 4u);       /* 1..4 words per row */
            int bits  = words * 32;
            int h     = 1 + (int)(rnd() % 6u);       /* 1..6 rows */
            int count = 1 + (int)(rnd() % 3u);       /* 1..3 passes */
            for (int i = 0; i < 512; i++) {
                uint32_t u = (uint32_t)rnd();
                pv[i] = u; pc[i] = u; sq[i] = (uint32_t)rnd();
            }
            mk_image(dv, pv, bits, bits, h, 0, 0);
            mk_image(dc, pc, bits, bits, h, 0, 0);
            mk_image(sv, sq, bits, bits, h, 0, 0);
            mk_image(sc, sq, bits, bits, h, 0, 0);
            v(dv, sv, count);
            fns[k].clean((cr_image *)dc, (const cr_image *)sc, count);
            cmp_buf("morph", (unsigned char *)pv, (unsigned char *)pc,
                    sizeof pv, (u32)t);
        }
        if (g_fail == bad) end(); else printf("  FAIL %s\n", fns[k].name);
    }
}

/* ---- batch 18: affine resample + 4-phase FIR --------------------------- */

/* 0x18002ca30 — Q15 bilinear resample of a byte image over an affine grid.
 * Source is 32-byte-stride; the origin is kept near x=20,y=20 (in Q15 pixels)
 * and the steps are small so all four taps stay inside the buffer. */
static void test_affine_sample_u8(void)
{
    typedef void (WINAPI *fn_t)(void *, const void *, const void *);
    fn_t v = (fn_t)fn_at(RVA(0x18002ca30));
    begin("cr_affine_sample_u8");
    int bad = g_fail;
    for (int t = 0; t < 20000; t++) {
        unsigned char dv[0x20], dc[0x20], sv[0x20], sc[0x20];
        uint8_t src[2048], ov[512], oc[512];
        int32_t s[6];
        for (size_t i = 0; i < sizeof src; i++) src[i] = (uint8_t)rnd();
        int w = 1 + (int)(rnd() % 8u);
        int h = 1 + (int)(rnd() % 8u);
        s[0] = (int32_t)((int)(rnd() % 0x4000u) - 0x2000);            /* x_col */
        s[1] = (int32_t)((int)(rnd() % 0x4000u) - 0x2000);            /* x_row */
        s[2] = (int32_t)(20u * 0x8000u + (rnd() % 0x8000u));          /* x_org */
        s[3] = (int32_t)((int)(rnd() % 0x4000u) - 0x2000);            /* y_col */
        s[4] = (int32_t)((int)(rnd() % 0x4000u) - 0x2000);            /* y_row */
        s[5] = (int32_t)(20u * 0x8000u + (rnd() % 0x8000u));          /* y_org */
        memset(ov, 0xAA, sizeof ov); memset(oc, 0xAA, sizeof oc);
        mk_image(dv, ov, 16, w, h, 0, 0);
        mk_image(dc, oc, 16, w, h, 0, 0);
        mk_image(sv, src, 32, 0, 0, 0, 0);
        mk_image(sc, src, 32, 0, 0, 0, 0);
        v(dv, sv, s);
        cr_affine_sample_u8((cr_image *)dc, (const cr_image *)sc,
                            (const cr_affine_map *)s);
        cmp_buf("affs", ov, oc, sizeof ov, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_affine_sample_u8\n");
}

/* 0x180032d60 — bounded (clamped) Q15 bilinear affine resample of a byte
 * image.  Same grid as cr_affine_sample_u8 but the source fetch is pinned to
 * [0,w-1]x[0,h-1]; the unclamped fast path is taken when the transformed
 * destination bounding box stays strictly inside the source. */
static void test_affine_sample_u8_clamped(void)
{
    typedef void (WINAPI *fn_t)(void *, const void *, const void *);
    fn_t v = (fn_t)fn_at(RVA(0x180032d60));
    begin("cr_affine_sample_u8_clamped");
    int bad = g_fail;
    static uint8_t src[4096], ov[4096], oc[4096];
    static cr_image sv, sc, dv, dc;
    for (int t = 0; t < 20000; t++) {
        int sw = 1 + (int)(rnd() % 24u);
        int sh = 1 + (int)(rnd() % 24u);
        int w  = (int)(rnd() % 16u);
        int h  = (int)(rnd() % 16u);
        int32_t m[6];
        int mode = (int)(rnd() % 4);
        if (mode == 0) {                 /* constant map -> often inside */
            m[0] = 0; m[1] = 0; m[3] = 0; m[4] = 0;
            m[2] = (int32_t)((rnd() % (unsigned)sw) * 0x8000u)
                 + (int32_t)(rnd() & 0x7fffu);
            m[5] = (int32_t)((rnd() % (unsigned)sh) * 0x8000u)
                 + (int32_t)(rnd() & 0x7fffu);
        } else {                         /* wide transform, both paths */
            m[0] = (int32_t)((int)(rnd() % 0x10000u) - 0x8000);
            m[1] = (int32_t)((int)(rnd() % 0x10000u) - 0x8000);
            m[2] = (int32_t)((int)((rnd() % ((unsigned)sw + 4u)) * 0x8000u)
                             - 2 * 0x8000);
            m[3] = (int32_t)((int)(rnd() % 0x10000u) - 0x8000);
            m[4] = (int32_t)((int)(rnd() % 0x10000u) - 0x8000);
            m[5] = (int32_t)((int)((rnd() % ((unsigned)sh + 4u)) * 0x8000u)
                             - 2 * 0x8000);
        }
        for (size_t i = 0; i < sizeof src; i++) src[i] = (uint8_t)rnd();
        memset(ov, 0xAA, sizeof ov); memset(oc, 0xAA, sizeof oc);
        cr_image_set(&sv, src, sw, sh);
        cr_image_set(&sc, src, sw, sh);
        cr_image_set(&dv, ov, w, h);
        cr_image_set(&dc, oc, w, h);
        v(&dv, &sv, m);
        cr_affine_sample_u8_clamped(&dc, &sc, (const cr_affine_map *)m);
        cmp_buf("affc", ov, oc, sizeof ov, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_affine_sample_u8_clamped\n");
}

/* 0x18001c700 — rotate/translate-warp a src image into an N x N u8 buffer. */
static void test_warp_rotate_u8(void)
{
    typedef int (WINAPI *fn_t)(void *, const void *, int, int, int, const int *);
    fn_t v = (fn_t)fn_at(RVA(0x18001c700));
    begin("cr_warp_rotate_u8");
    int bad = g_fail;

    enum { MAXB = 31 * 31 };
    static uint8_t src[4096];
    static uint8_t ov[MAXB + 64], oc[MAXB + 64];
    static cr_image sv, sc;
    static int cfg[2];

    for (int t = 0; t < 20000; t++) {
        int sw = 1 + (int)(rnd() % 24u);
        int sh = 1 + (int)(rnd() % 24u);
        int M = (int)(rnd() % 64u);
        int N;
        do { N = (int)(rnd() % 33u); } while (N == 1);   /* N==1 -> IDIV #DE */
        int ox = (int)(rnd() % 300u);
        int oy = (int)(rnd() % 300u);
        int phase = (int)(rnd() % 512u);
        cfg[0] = M; cfg[1] = N;

        for (size_t i = 0; i < sizeof src; i++) src[i] = (uint8_t)rnd();
        memset(ov, 0xAA, sizeof ov); memset(oc, 0xAA, sizeof oc);
        cr_image_set(&sv, src, sw, sh);
        cr_image_set(&sc, src, sw, sh);

        int rv = v(ov, &sv, ox, oy, phase, cfg);
        int rc = cr_warp_rotate_u8(oc, &sc, ox, oy, phase, cfg);
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }
        cmp_buf("rot", ov, oc, sizeof ov, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_warp_rotate_u8\n");
}

/* 0x18000ee70 — 4-phase FIR over interleaved bytes.  Input is a stream of
 * 4-byte groups; each output byte is a shifted dot product with the int16
 * coefficient vector. */
static void test_polyphase_fir4(void)
{
    v_v_ppp_fir v = (v_v_ppp_fir)fn_at(RVA(0x18000ee70));
    begin("cr_polyphase_fir4");
    int bad = g_fail;
    for (int t = 0; t < 20000; t++) {
        uint8_t inb[128], ov[128], oc[128];
        int16_t coef[16];
        for (size_t i = 0; i < sizeof inb; i++) inb[i] = (uint8_t)rnd();
        for (size_t i = 0; i < 16; i++) coef[i] = (int16_t)rnd();
        int npix   = (int)(rnd() % 8u);       /* 0..7 groups (incl. the no-op) */
        int nbytes = npix * 4;
        int ncoef  = 2 + (int)(rnd() % 9u);   /* 2..10 (even and odd) */
        memset(ov, 0x5A, sizeof ov); memset(oc, 0x5A, sizeof oc);
        v(ov, inb, coef, nbytes, ncoef);
        cr_polyphase_fir4(oc, inb, coef, nbytes, ncoef);
        cmp_buf("fir4", ov, oc, sizeof ov, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_polyphase_fir4\n");
}

/* ---- batch 19: bilinear splat ------------------------------------------ */

/* 0x180044b10 — bilinear splat of 16 weighted points into two float buffers
 * (17-float row stride).  x0/y0 are both the start and the per-step delta; the
 * buffers are offset by 512 floats so negative indices stay in-bounds. */
static void test_splat_bilinear(void)
{
    typedef void (WINAPI *fn_t)(const float *, float *, float *, const float *,
                                float, float, float);
    fn_t v = (fn_t)fn_at(RVA(0x180044b10));
    begin("cr_splat_bilinear");
    int bad = g_fail;
    for (int t = 0; t < 20000; t++) {
        float w[16], alpha[16];
        float av[1024], ac[1024], bv[1024], bc[1024];
        for (int i = 0; i < 16; i++) {
            w[i]     = (float)((int)(rnd() % 100000u) - 50000) / 1000.0f;
            alpha[i] = (float)((int)(rnd() % 100000u) - 50000) / 1000.0f;
        }
        for (int i = 0; i < 1024; i++) {
            float f = (float)((int)(rnd() % 2001u) - 1000) / 100.0f;
            av[i] = f; ac[i] = f; bv[i] = f; bc[i] = f;
        }
        float x0    = (float)((int)(rnd() % 2001u) - 1000) / 1000.0f;  /* [-1,1] */
        float y0    = (float)((int)(rnd() % 2001u) - 1000) / 1000.0f;
        float scale = (float)((int)(rnd() % 2001u) - 1000) / 100.0f;
        v(w, av + 512, bv + 512, alpha, x0, y0, scale);
        cr_splat_bilinear(w, ac + 512, bc + 512, alpha, x0, y0, scale);
        cmp_buf("splatA", (unsigned char *)av, (unsigned char *)ac, sizeof av, (u32)t);
        cmp_buf("splatB", (unsigned char *)bv, (unsigned char *)bc, sizeof bv, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_splat_bilinear\n");
}

/* ---- batch 20: bitmap border set --------------------------------------- */

/* 0x180017ac0 — fill a border frame of a packed bitmap: whole top/bottom rows
 * and the left/right bit columns.  Descriptor must have a==w, b==0, offx==0 and
 * w a multiple of 32; occasionally we corrupt b to exercise the 0x69 path. */
static void test_bitmap_border_set(void)
{
    typedef int (WINAPI *fn_t)(void *, int, int, int, int, int);
    fn_t v = (fn_t)fn_at(RVA(0x180017ac0));
    begin("cr_bitmap_border_set");
    int bad = g_fail;
    for (int t = 0; t < 20000; t++) {
        unsigned char dv[0x20], dc[0x20];
        uint32_t bv[128], bc[128];
        int words = 1 + (int)(rnd() % 4u);   /* 1..4 words */
        int w = words * 32;
        int h = 1 + (int)(rnd() % 6u);
        int left   = (int)(rnd() % (unsigned)(w + 1));
        int top    = (int)(rnd() % (unsigned)(h + 1));
        int right  = (int)(rnd() % (unsigned)(w + 1));
        int bottom = (int)(rnd() % (unsigned)(h + 1));
        int value  = (int)(rnd() & 1u);
        for (int i = 0; i < 128; i++) {
            uint32_t u = (uint32_t)rnd(); bv[i] = u; bc[i] = u;
        }
        memset(dv, 0, sizeof dv); memset(dc, 0, sizeof dc);
        mk_image(dv, bv, w, w, h, 0, 0);
        mk_image(dc, bc, w, w, h, 0, 0);
        *(int *)(dv + 4) = h;   /* duplicate dimension: guard needs b == h */
        *(int *)(dc + 4) = h;
        if (t % 16 == 0) { *(int *)(dv + 4) = h + 1; *(int *)(dc + 4) = h + 1; }
        int rv = v(dv, left, top, right, bottom, value);
        int rc = cr_bitmap_border_set((cr_image *)dc, left, top, right,
                                      bottom, value);
        if (rv != rc) mismatch("bborder_ret", (u32)t, (u32)rv, (u32)rc);
        cmp_buf("bborder", (unsigned char *)bv, (unsigned char *)bc, sizeof bv, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_bitmap_border_set\n");
}

/* ---- batch 21: 8-neighbour 3x3 Laplacian ------------------------------- */

/* 0x1800169b0 — Laplacian of one row from three input rows, 4-wide vectorised
 * in two passes.  The three rows are separate contiguous int16 arrays. */
static void test_laplacian_3x3(void)
{
    typedef void (WINAPI *fn_t)(void *, const void *, const void *,
                                const void *, int);
    fn_t v = (fn_t)fn_at(RVA(0x1800169b0));
    begin("cr_laplacian_3x3");
    int bad = g_fail;
    for (int t = 0; t < 20000; t++) {
        int16_t A[128], C[128], B[128], ov[128], oc[128];
        int w = 4 + (int)(rnd() % 61u);   /* 4..64 */
        for (int i = 0; i < 128; i++) {
            A[i] = (int16_t)rnd(); C[i] = (int16_t)rnd(); B[i] = (int16_t)rnd();
        }
        memset(ov, 0x5A, sizeof ov); memset(oc, 0x5A, sizeof oc);
        v(ov, A, C, B, w);
        cr_laplacian_3x3(oc, A, C, B, w);
        cmp_buf("lap3", (unsigned char *)ov, (unsigned char *)oc, sizeof ov, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_laplacian_3x3\n");
}

/* ---- batch 22: 7-tap edge-clamped int16 FIR ---------------------------- */

/* 0x180020d80 / 0x18001c280 — 7-tap edge-clamped int16 FIR, run across rows
 * (`rowwise`) or down columns.  Descriptor must be canonical (a==w, b==h,
 * offx==offy==0) for both images and share (a,b); occasionally we corrupt one
 * field to exercise the 0x69 guard. */
static void test_fir7_common(const char *name, u32 rva, int rowwise,
                             int (*clean)(cr_image *, const cr_image *,
                                          const int16_t *))
{
    typedef int (WINAPI *fn_t)(void *, const void *, const void *);
    fn_t v = (fn_t)fn_at(rva);
    begin(name);
    int bad = g_fail;
    for (int t = 0; t < 20000; t++) {
        unsigned char dv[0x20], dc[0x20], sv[0x20], sc[0x20];
        int16_t sbv[512], sbc[512], dbv[512], dbc[512], coef[7];
        int w = 1 + (int)(rnd() % 40u);       /* 1..40 (incl. w<5) */
        int h = 1 + (int)(rnd() % 6u);        /* 1..6 (incl. 0-height guard) */
        for (int i = 0; i < 512; i++) {
            int16_t x = (int16_t)rnd();
            sbv[i] = x; sbc[i] = x;
            int16_t y = (int16_t)rnd();
            dbv[i] = y; dbc[i] = y;
        }
        for (int k = 0; k < 7; k++) coef[k] = (int16_t)rnd();
        memset(dv, 0, sizeof dv); memset(dc, 0, sizeof dc);
        memset(sv, 0, sizeof sv); memset(sc, 0, sizeof sc);
        mk_image(dv, dbv, w, w, h, 0, 0);
        mk_image(dc, dbc, w, w, h, 0, 0);
        mk_image(sv, sbv, w, w, h, 0, 0);
        mk_image(sc, sbc, w, w, h, 0, 0);
        *(int *)(dv + 4) = h; *(int *)(dc + 4) = h;   /* b == h */
        *(int *)(sv + 4) = h; *(int *)(sc + 4) = h;
        /* corrupt one guard field on ~1/8 of runs */
        switch (t & 7) {
        case 1: *(int *)(sv + 4) = h + 1; *(int *)(sc + 4) = h + 1; break;
        case 2: *(int *)(dv + 0x18) = 1;  *(int *)(dc + 0x18) = 1;  break;
        case 3: *(int *)(sc + 0x00) = w + 1; *(int *)(sv + 0x00) = w + 1; break;
        default: break;
        }
        int rv = v(dv, sv, coef);
        int rc = clean((cr_image *)dc, (const cr_image *)sc, coef);
        if (rv != rc) mismatch("fir7_ret", (u32)t, (u32)rv, (u32)rc);
        cmp_buf("fir7", (unsigned char *)dbv, (unsigned char *)dbc,
                sizeof dbv, (u32)t);
        (void)rowwise;
    }
    if (g_fail == bad) end(); else printf("  FAIL %s\n", name);
}

static void test_fir7_s16(void)
{
    test_fir7_common("cr_fir7_s16", RVA(0x180020d80), 1, cr_fir7_s16);
}

static void test_fir7_s16_col(void)
{
    test_fir7_common("cr_fir7_s16_col", RVA(0x18001c280), 0, cr_fir7_s16_col);
}

/* ---- batch 23: in-place row permutation -------------------------------- */

/* 0x180024200 — rearrange `n` rows of `stride` bytes so that destination row
 * j takes source row perm[j].  The perm array is 8-byte entries (first int
 * used).  A random permutation of 0..n-1 is used, so both data and the perm
 * array (which the vendor temporarily flags) must match afterwards. */
static void test_permute_rows(void)
{
    typedef int (WINAPI *fn_t)(void *, void *, int, int);
    fn_t v = (fn_t)fn_at(RVA(0x180024200));
    begin("cr_permute_rows");
    int bad = g_fail;
    for (int t = 0; t < 20000; t++) {
        uint8_t dv[1024], dc[1024];
        int32_t pv[32], pc[32];
        int idx[16];
        int n = (int)(rnd() % 13u);            /* 0..12 rows */
        int stride = (int)(rnd() % 11u) - 2;   /* -2..8 (incl. the <=0 path) */
        if (t % 64 == 0) stride = 0x41 + (int)(rnd() % 4u);   /* guard failure */
        for (size_t i = 0; i < sizeof dv; i++) {
            uint8_t x = (uint8_t)rnd(); dv[i] = x; dc[i] = x;
        }
        for (int i = 0; i < n; i++) idx[i] = i;
        for (int i = n - 1; i > 0; i--) {
            int j = (int)(rnd() % (unsigned)(i + 1));
            int s = idx[i]; idx[i] = idx[j]; idx[j] = s;
        }
        for (int i = 0; i < 32; i++) pv[i] = pc[i] = 0;
        for (int i = 0; i < n; i++) { pv[i * 2] = idx[i]; pc[i * 2] = idx[i]; }
        int rv = v(dv, pv, n, stride);
        int rc = cr_permute_rows(dc, pc, n, stride);
        if (rv != rc) mismatch("perm_ret", (u32)t, (u32)rv, (u32)rc);
        cmp_buf("perm_data", dv, dc, sizeof dv, (u32)t);
        cmp_buf("perm_idx", (unsigned char *)pv, (unsigned char *)pc,
                sizeof pv, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_permute_rows\n");
}

/* ---- batch 24: bit-shifted bitmap blit --------------------------------- */

/* 0x18000fd90 — blit a source bitmap into a destination bitmap at bit column
 * `bitoff` and row `rowoff`, shifting source bits left by (bitoff & 31).  Both
 * descriptors need offx==offy==0 and src->a <= dst->a (else 0x69). */
static void test_bitmap_copy_shift(void)
{
    typedef int (WINAPI *fn_t)(void *, const void *, uint32_t, int);
    fn_t v = (fn_t)fn_at(RVA(0x18000fd90));
    begin("cr_bitmap_copy_shift");
    int bad = g_fail;
    for (int t = 0; t < 20000; t++) {
        unsigned char dv[0x20], dc[0x20], sv[0x20], sc[0x20];
        uint32_t dbv[512], dbc[512], sbv[256], sbc[256];
        int sw = 1 + (int)(rnd() % 4u);          /* src words 1..4 */
        int dw = sw + (int)(rnd() % 4u);         /* dst words >= src */
        int h  = 1 + (int)(rnd() % 4u);
        uint32_t bitoff = (uint32_t)(rnd() % 97u);   /* 0..96 (word + bit) */
        int rowoff = (int)(rnd() % 3u);
        for (int i = 0; i < 512; i++) {
            uint32_t u = (uint32_t)rnd(); dbv[i] = u; dbc[i] = u;
        }
        for (int i = 0; i < 256; i++) {
            uint32_t u = (uint32_t)rnd(); sbv[i] = u; sbc[i] = u;
        }
        memset(dv, 0, sizeof dv); memset(dc, 0, sizeof dc);
        memset(sv, 0, sizeof sv); memset(sc, 0, sizeof sc);
        mk_image(dv, dbv, dw * 32, dw * 32, h, 0, 0);
        mk_image(dc, dbc, dw * 32, dw * 32, h, 0, 0);
        mk_image(sv, sbv, sw * 32, sw * 32, h, 0, 0);
        mk_image(sc, sbc, sw * 32, sw * 32, h, 0, 0);
        /* exercise the guard on ~1/8 of runs */
        switch (t & 7) {
        case 1: *(int *)(sv + 0x18) = 1; *(int *)(sc + 0x18) = 1; break;
        case 2: *(int *)(dv + 0x1c) = 1; *(int *)(dc + 0x1c) = 1; break;
        case 3: *(int *)(dv + 0x00) = 0; *(int *)(dc + 0x00) = 0; break; /* dst->a < src->a */
        default: break;
        }
        int rv = v(dv, sv, bitoff, rowoff);
        int rc = cr_bitmap_copy_shift((cr_image *)dc, (const cr_image *)sc,
                                      bitoff, rowoff);
        if (rv != rc) mismatch("bshift_ret", (u32)t, (u32)rv, (u32)rc);
        cmp_buf("bshift_dst", (unsigned char *)dbv, (unsigned char *)dbc,
                sizeof dbv, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_bitmap_copy_shift\n");
}

/* ---- batch 25: right-shifted bitmap extract ---------------------------- */

/* 0x18003e590 — extract a `dst->a`-bit-wide, `dst->h`-row window from `src` at
 * bit column src->offx / row src->offy, shifting source bits right by
 * (src->offx & 31) and masking the last destination word.  Needs dst offx==offy
 * ==0 and src->a >= dst->a (else 0x69). */
static void test_bitmap_extract_shift(void)
{
    typedef int (WINAPI *fn_t)(void *, const void *);
    fn_t v = (fn_t)fn_at(RVA(0x18003e590));
    begin("cr_bitmap_extract_shift");
    int bad = g_fail;
    for (int t = 0; t < 20000; t++) {
        unsigned char dv[0x20], dc[0x20], sv[0x20], sc[0x20];
        uint32_t dbv[256], dbc[256], sbv[1024], sbc[1024];
        int dw = 1 + (int)(rnd() % 4u);          /* dst words 1..4 */
        int sw = dw + (int)(rnd() % 4u);         /* src words >= dst */
        int h  = 1 + (int)(rnd() % 4u);
        int offx = (int)(rnd() % 97u);           /* 0..96 (word + bit) */
        int offy = (int)(rnd() % 3u);
        int dwbits = dw * 32;
        int w = dwbits - (int)(rnd() % 32u);     /* valid width <= stride */
        for (int i = 0; i < 256; i++) {
            uint32_t u = (uint32_t)rnd(); dbv[i] = u; dbc[i] = u;
        }
        for (int i = 0; i < 1024; i++) {
            uint32_t u = (uint32_t)rnd(); sbv[i] = u; sbc[i] = u;
        }
        memset(dv, 0, sizeof dv); memset(dc, 0, sizeof dc);
        memset(sv, 0, sizeof sv); memset(sc, 0, sizeof sc);
        mk_image(dv, dbv, dwbits, dwbits, h, 0, 0);
        mk_image(dc, dbc, dwbits, dwbits, h, 0, 0);
        *(int *)(dv + 0x10) = w; *(int *)(dc + 0x10) = w;
        mk_image(sv, sbv, sw * 32, sw * 32, h, offx, offy);
        mk_image(sc, sbc, sw * 32, sw * 32, h, offx, offy);
        /* exercise the guard on ~1/8 of runs */
        switch (t & 7) {
        case 1: *(int *)(dv + 0x18) = 1; *(int *)(dc + 0x18) = 1; break;
        case 2: *(int *)(dv + 0x1c) = 1; *(int *)(dc + 0x1c) = 1; break;
        case 3: *(int *)(sv + 0x00) = dwbits - 32;   /* src->a < dst->a */
                *(int *)(sc + 0x00) = dwbits - 32; break;
        default: break;
        }
        int rv = v(dv, sv);
        int rc = cr_bitmap_extract_shift((cr_image *)dc, (const cr_image *)sc);
        if (rv != rc) mismatch("bext_ret", (u32)t, (u32)rv, (u32)rc);
        cmp_buf("bext_dst", (unsigned char *)dbv, (unsigned char *)dbc,
                sizeof dbv, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_bitmap_extract_shift\n");
}

/* ---- batch 27: masked per-column mean correction ----------------------- */

/* 0x18000d8e0 — cfg[9] is a mode byte (0 -> 0, 2 -> run, else 0x69); needs
 * r1 <= img->w and img->h > 29.  Global mean over bitmap rows r0..r1-1, local
 * mean per column, then clamp(p + global - local) written down each column. */
static void test_bitmap_mean_correct(void)
{
    typedef int (WINAPI *fn_t)(void *, const void *, const void *);
    fn_t v = (fn_t)fn_at(RVA(0x18000d8e0));
    begin("cr_bitmap_mean_correct");
    int bad = g_fail;
    for (int t = 0; t < 20000; t++) {
        unsigned char iv[0x20], ic[0x20], bv[0x20], bc[0x20], cfg[0x20];
        uint8_t ib[4096], ibc[4096];
        uint32_t bw[1024], bwc[1024];
        int w = 30 + (int)(rnd() % 11u);      /* 30..40 */
        int h = 30 + (int)(rnd() % 11u);      /* 30..40 (> 29) */
        int offx = (int)(rnd() % 17u);
        int offy = (int)(rnd() % 3u);
        int a = ((offx + h + 31) / 32) * 32;  /* row stride covers the column span */
        for (int i = 0; i < 4096; i++) {
            uint8_t x = (uint8_t)rnd(); ib[i] = x; ibc[i] = x;
        }
        for (int i = 0; i < 1024; i++) {
            uint32_t u = (uint32_t)rnd(); bw[i] = u; bwc[i] = u;
        }
        memset(iv, 0, sizeof iv); memset(ic, 0, sizeof ic);
        memset(bv, 0, sizeof bv); memset(bc, 0, sizeof bc);
        memset(cfg, 0, sizeof cfg);
        mk_image(iv, ib, w, w, h, 0, 0);
        mk_image(ic, ibc, w, w, h, 0, 0);
        mk_image(bv, bw, a, 0, 0, offx, offy);
        mk_image(bc, bwc, a, 0, 0, offx, offy);
        int r0 = (int)(rnd() % (unsigned)w);
        int dy = 1 + (int)(rnd() % (unsigned)(w - r0));
        cfg[9] = 2;
        *(int *)(cfg + 0xc) = r0;
        *(int *)(cfg + 0x10) = dy;
        switch (t & 3) {                      /* exercise early-outs */
        case 1: cfg[9] = 0; break;
        case 2: cfg[9] = 1; break;
        case 3: *(int *)(cfg + 0x10) = w + 1; break;   /* r1 > w */
        default: break;
        }
        int rv = v(iv, bv, cfg);
        int rc = cr_bitmap_mean_correct((cr_image *)ic, (const cr_image *)bc,
                                        cfg);
        if (rv != rc) mismatch("bmc_ret", (u32)t, (u32)rv, (u32)rc);
        cmp_buf("bmc_img", ib, ibc, sizeof ib, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_bitmap_mean_correct\n");
}

/* ---- batch 28: bit-packed sign signature of a filter bank --------------- */

/* 0x180043db0 — cfg[0x10] = 16-byte-aligned matrix, cfg[4] = m, cfg[8] = b8
 * (output count n = b8/2); *inpp = input window.  Per matrix row, four 4-lane
 * dot products over the m*m window are reduced to sign bits and packed into two
 * output bytes.  Guards: NULL matrix -> 0x69, misaligned -> 1, n <= 0 -> 0. */
static void test_signpack_dot(void)
{
    typedef int (WINAPI *fn_t)(void *, const void *, const void *);
    fn_t v = (fn_t)fn_at(RVA(0x180043db0));
    begin("cr_signpack_dot");
    int bad = g_fail;
    static _Alignas(16) uint8_t mat[8192];
    for (int t = 0; t < 20000; t++) {
        unsigned char cfg[0x20];
        uint8_t in[256], ov[256], oc[256];
        void *pv = in, *pc = in;
        int m = 1 + (int)(rnd() % 4u);        /* 1..4 */
        int n = 1 + (int)(rnd() % 8u);        /* output count 1..8 */
        int b8 = n * 2;
        for (int i = 0; i < 256; i++) in[i] = (uint8_t)rnd();
        for (int i = 0; i < 8192; i++) mat[i] = (uint8_t)rnd();
        memset(ov, 0xAB, sizeof ov); memset(oc, 0xAB, sizeof oc);
        memset(cfg, 0, sizeof cfg);
        *(int *)(cfg + 4) = m;
        cfg[8] = (uint8_t)b8;
        *(void **)(cfg + 0x10) = mat;
        switch (t & 7) {                      /* exercise the guards */
        case 1: *(void **)(cfg + 0x10) = NULL; break;
        case 2: *(void **)(cfg + 0x10) = mat + 1; break;   /* misaligned */
        case 3: cfg[8] = 0; break;                          /* n == 0 */
        case 4: *(int *)(cfg + 4) = 0; break;               /* m == 0 */
        default: break;
        }
        int rv = v(ov, &pv, cfg);
        int rc = cr_signpack_dot(oc, (const void *const *)&pc, cfg);
        if (rv != rc) mismatch("spk_ret", (u32)t, (u32)rv, (u32)rc);
        cmp_buf("spk_out", ov, oc, sizeof ov, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_signpack_dot\n");
}

/* ---- batch 11: 336-byte leaf ------------------------------------------- */

/* 0x180026fb0 — integer-factor block-average downsample (byte -> int16). */
static void test_downsample_mean(void)
{
    v_i_pph v = (v_i_pph)fn_at(RVA(0x180026fb0));
    begin("cr_downsample_mean");
    int bad = g_fail;
    for (int t = 0; t < 20000; t++) {
        unsigned char ov[0x20], oc[0x20], iv[0x20], ic[0x20];
        uint8_t inb[4096];
        int16_t pv[1024], pc[1024];
        for (size_t i = 0; i < sizeof inb; i++) inb[i] = (uint8_t)rnd();
        for (size_t i = 0; i < sizeof pv / sizeof pv[0]; i++) {
            uint32_t u = (uint32_t)rnd();
            pv[i] = (int16_t)u;
            pc[i] = pv[i];
        }
        int f = (int)(rnd() % 6u);            /* 0..5 (incl. the f<=0 path) */
        int ow = (int)(rnd() % 9u);
        int oh = (int)(rnd() % 9u);
        int iw = (int)(rnd() % 40u);
        int ih = (int)(rnd() % 40u);
        mk_image(ov, pv, 0, ow, oh, 0, 0);
        mk_image(oc, pc, 0, ow, oh, 0, 0);
        mk_image(iv, inb, 0, iw, ih, 0, 0);
        mk_image(ic, inb, 0, iw, ih, 0, 0);
        int rv = v(ov, iv, (int16_t)f);
        int rc = cr_downsample_mean((cr_image *)oc, (const cr_image *)ic, (int16_t)f);
        if (rv != rc) mismatch("dsret", (u32)t, (u32)rv, (u32)rc);
        cmp_buf("ds", (unsigned char *)pv, (unsigned char *)pc, sizeof pv, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_downsample_mean\n");
}

/* 0x18000eca0 — sin/cos pair.  The float angle arrives in xmm0. */
typedef void (WINAPI *v_v_ppf_f)(void *, void *, float);

static void test_sincos_f32(void)
{
    begin("cr_sincos_f32");
    void *p = fn_at(RVA(0x18000eca0));
    int bad = g_fail;

    for (u64 i = 0; i < 0x100000000ULL; i += 0x10001ULL) {
        u32 bits = (u32)i;
        float x = cr_u2f(bits);
        float vc[2], cc[2];
        ((v_v_ppf_f)p)(vc, vc + 1, x);
        ((v_v_ppf_f)cr_sincos_f32)(cc, cc + 1, x);
        if (cr_f2u(vc[0]) != cr_f2u(cc[0]))
            mismatch("cos", bits, cr_f2u(vc[0]), cr_f2u(cc[0]));
        if (cr_f2u(vc[1]) != cr_f2u(cc[1]))
            mismatch("sin", bits, cr_f2u(vc[1]), cr_f2u(cc[1]));
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_sincos_f32\n");
}

/* 0x18001c4e0 — int16 multi-region border fill.  Args (ms_abi):
 *   rcx=img, rdx=top, r8=bottom, r9=left, [rsp]=right, [rsp+8]=fill.
 * The image uses a 64x64 buffer with offx=offy=16, w=h=32, a=64 (stride),
 * so every region (top/bottom/left/right margins) stays inside the buffer. */
static void test_image_border_fill(void)
{
    v_v_piiiiu v = (v_v_piiiiu)fn_at(RVA(0x18001c4e0));
    begin("cr_image_fill_border");
    int bad = g_fail;
    const int BUFW = 128, BUFH = 128;
    for (int t = 0; t < 20000; t++) {
        int16_t pv[BUFW * BUFH], pc[BUFW * BUFH];
        unsigned char va[0x20], ca[0x20];
        int offx = 32, offy = 32, w = 64, h = 64;
        int top    = (int)(rnd() % 17u);
        int bottom = (int)(rnd() % 17u);
        int left   = (int)(rnd() % 17u);
        int right  = (int)(rnd() % 17u);
        uint16_t fill = (uint16_t)(rnd() & 0xffffu);
        for (int i = 0; i < BUFW * BUFH; i++) { pv[i] = (int16_t)i; pc[i] = (int16_t)i; }
        memset(va, 0, sizeof va); memset(ca, 0, sizeof ca);
        *(int *)(va + 0) = BUFW;  *(int *)(ca + 0) = BUFW;   /* a = stride */
        *(int *)(va + 4) = BUFH;  *(int *)(ca + 4) = BUFH;   /* b */
        *(int *)(va + 0x10) = w;  *(int *)(ca + 0x10) = w;   /* w */
        *(int *)(va + 0x14) = h;  *(int *)(ca + 0x14) = h;   /* h */
        *(int *)(va + 0x18) = offx; *(int *)(ca + 0x18) = offx; /* offx */
        *(int *)(va + 0x1c) = offy; *(int *)(ca + 0x1c) = offy; /* offy */
        *(void **)(va + 8) = pv;  *(void **)(ca + 8) = pc;   /* data */
        v(va, top, bottom, left, right, fill);
        cr_image_fill_border((cr_image *)ca, top, bottom, left, right, fill);
        cmp_buf("border", (unsigned char *)pv, (unsigned char *)pc, sizeof pv, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_image_fill_border\n");
}

/* 0x18001fb80 — byte border extension (edge replication).  Args: img, top,
 * bottom, left, right.  Same frame geometry as the fill_border leaf. */
static void test_image_border_extend(void)
{
    v_v_piiii v = (v_v_piiii)fn_at(RVA(0x18001fb80));
    begin("cr_image_border_extend");
    int bad = g_fail;
    const int BUFW = 128, BUFH = 128;
    for (int t = 0; t < 20000; t++) {
        uint8_t pv[BUFW * BUFH], pc[BUFW * BUFH];
        unsigned char va[0x20], ca[0x20];
        int offx = 32, offy = 32, w = 64, h = 64;
        int top    = (int)(rnd() % 17u);
        int bottom = (int)(rnd() % 17u);
        int left   = (int)(rnd() % 17u);
        int right  = (int)(rnd() % 17u);
        for (int i = 0; i < BUFW * BUFH; i++) { pv[i] = (uint8_t)rnd(); pc[i] = pv[i]; }
        memset(va, 0, sizeof va); memset(ca, 0, sizeof ca);
        *(int *)(va + 0) = BUFW;  *(int *)(ca + 0) = BUFW;
        *(int *)(va + 4) = BUFH;  *(int *)(ca + 4) = BUFH;
        *(int *)(va + 0x10) = w;  *(int *)(ca + 0x10) = w;
        *(int *)(va + 0x14) = h;  *(int *)(ca + 0x14) = h;
        *(int *)(va + 0x18) = offx; *(int *)(ca + 0x18) = offx;
        *(int *)(va + 0x1c) = offy; *(int *)(ca + 0x1c) = offy;
        *(void **)(va + 8) = pv;  *(void **)(ca + 8) = pc;
        v(va, top, bottom, left, right);
        cr_image_border_extend((cr_image *)ca, top, bottom, left, right);
        cmp_buf("extend", (unsigned char *)pv, (unsigned char *)pc, sizeof pv, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_image_border_extend\n");
}

/* 0x180016df0 — int16 border extension (edge replication). */
static void test_image_border_extend_s16(void)
{
    v_v_piiii v = (v_v_piiii)fn_at(RVA(0x180016df0));
    begin("cr_image_border_extend_s16");
    int bad = g_fail;
    const int BUFW = 128, BUFH = 128;
    for (int t = 0; t < 20000; t++) {
        int16_t pv[BUFW * BUFH], pc[BUFW * BUFH];
        unsigned char va[0x20], ca[0x20];
        int offx = 32, offy = 32, w = 64, h = 64;
        int top    = (int)(rnd() % 17u);
        int bottom = (int)(rnd() % 17u);
        int left   = (int)(rnd() % 17u);
        int right  = (int)(rnd() % 17u);
        for (int i = 0; i < BUFW * BUFH; i++) { pv[i] = (int16_t)rnd(); pc[i] = pv[i]; }
        memset(va, 0, sizeof va); memset(ca, 0, sizeof ca);
        *(int *)(va + 0) = BUFW;  *(int *)(ca + 0) = BUFW;
        *(int *)(va + 4) = BUFH;  *(int *)(ca + 4) = BUFH;
        *(int *)(va + 0x10) = w;  *(int *)(ca + 0x10) = w;
        *(int *)(va + 0x14) = h;  *(int *)(ca + 0x14) = h;
        *(int *)(va + 0x18) = offx; *(int *)(ca + 0x18) = offx;
        *(int *)(va + 0x1c) = offy; *(int *)(ca + 0x1c) = offy;
        *(void **)(va + 8) = pv;  *(void **)(ca + 8) = pc;
        v(va, top, bottom, left, right);
        cr_image_border_extend_s16((cr_image *)ca, top, bottom, left, right);
        cmp_buf("extend16", (unsigned char *)pv, (unsigned char *)pc, sizeof pv, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_image_border_extend_s16\n");
}

/* 0x1800356e0 — saturation / usable-pixel score of a byte image. */
static void test_saturation_score(void)
{
    v_v_pi v = (v_v_pi)fn_at(RVA(0x1800356e0));
    begin("cr_saturation_score");
    int bad = g_fail;
    uint8_t buf[64 * 64];
    for (int t = 0; t < 20000; t++) {
        unsigned char va[0x20], ca[0x20];
        int w = 1 + (int)(rnd() % 64u);
        int h = 1 + (int)(rnd() % 64u);
        int n = w * h;
        for (int i = 0; i < n; i++) {
            uint32_t r = rnd();
            /* bias toward 0/255 to exercise the saturation counter */
            buf[i] = (uint8_t)((r % 3u == 0) ? ((r & 1u) ? 255 : 0) : (r & 0xffu));
        }
        memset(va, 0, sizeof va); memset(ca, 0, sizeof ca);
        *(int16_t *)(va + 0) = (int16_t)w; *(int16_t *)(ca + 0) = (int16_t)w;
        *(int16_t *)(va + 2) = (int16_t)h; *(int16_t *)(ca + 2) = (int16_t)h;
        *(void **)(va + 0x10) = buf; *(void **)(ca + 0x10) = buf;
        int ov = 0xdeadbeef, oc = 0xdeadbeef;
        v(&ov, va);
        cr_saturation_score(&oc, (const cr_pixbuf *)ca);
        if (ov != oc) mismatch("score", (u32)t, (u32)ov, (u32)oc);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_saturation_score\n");
}

/* 0x180002fe0 / 0x180002fb0 / 0x18003bf40 — allocator wrappers.  Only the
 * observable contract is compared (status codes, null-ing); the raw pointer
 * values necessarily differ between the two allocators. */
static void test_alloc_wrappers(void)
{
    v_i_ppz vmalloc = (v_i_ppz)fn_at(RVA(0x180002fe0));
    v_v_p   vfree   = (v_v_p)fn_at(RVA(0x180002fb0));
    v_v_p   vsfree  = (v_v_p)fn_at(RVA(0x18003bf40));

    begin("cr_malloc");
    int bad = g_fail;
    for (int t = 0; t < 4000; t++) {
        size_t sz = (rnd() % 5u == 0) ? 0 : (size_t)(rnd() % 4096u);
        void *pv = (void *)0xdead, *pc = (void *)0xdead;
        int rv = vmalloc(&pv, sz);
        int rc = cr_malloc(&pc, sz);
        if (rv != rc) mismatch("malloc-status", sz, rv, rc);
        if ((pv == NULL) != (pc == NULL))
            mismatch("malloc-null", sz, pv ? 1 : 0, pc ? 1 : 0);
        vfree(&pv); cr_free(&pc);
        if (pv != NULL || pc != NULL)
            mismatch("free-null", sz, (u64)pv, (u64)pc);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_malloc\n");

    begin("cr_free");
    bad = g_fail;
    for (int t = 0; t < 4000; t++) {
        size_t sz = (size_t)(1 + rnd() % 4096u);
        void *pv = NULL, *pc = NULL;
        vmalloc(&pv, sz); cr_malloc(&pc, sz);
        vfree(&pv); cr_free(&pc);
        if (pv != NULL || pc != NULL)
            mismatch("free2-null", sz, (u64)pv, (u64)pc);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_free\n");

    begin("cr_sized_free");
    bad = g_fail;
    for (int t = 0; t < 4000; t++) {
        size_t S = (size_t)(2 + rnd() % 128u);
        int    sz = 1 + (int)(rnd() % (uint32_t)S);
        void *vb = NULL, *cb = NULL;
        vmalloc(&vb, S); cr_malloc(&cb, S);
        memset(vb, 0, S); memset(cb, 0, S);
        ((uint8_t *)vb)[sz - 1] = (uint8_t)sz;
        ((uint8_t *)cb)[sz - 1] = (uint8_t)sz;
        void *vp = (uint8_t *)vb + sz;
        void *cp = (uint8_t *)cb + sz;
        vsfree(&vp); cr_sized_free(&cp);
        if (vp != NULL || cp != NULL)
            mismatch("sfree-null", sz, (u64)vp, (u64)cp);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_sized_free\n");
}


/* Build a random image descriptor + pixel buffer, run one function on the
 * vendor copy and the clean-room copy, and compare the whole descriptor and
 * the pixel buffer. */
static void test_image_leaves(void)
{
    v_v_p   vfill2 = (v_v_p)fn_at(RVA(0x180023a60));
    v_u_ppii vset[3];
    vset[0] = (v_u_ppii)fn_at(RVA(0x18003b250));
    vset[1] = (v_u_ppii)fn_at(RVA(0x18003fbc0));
    vset[2] = (v_u_ppii)fn_at(RVA(0x180036460));
    v_u_ppii vsetp = (v_u_ppii)fn_at(RVA(0x180034490));
    v_v_ppiiii vsub[2];
    vsub[0] = (v_v_ppiiii)fn_at(RVA(0x180010ef0));
    vsub[1] = (v_v_ppiiii)fn_at(RVA(0x180017a80));
    v_v_pp  vmark = (v_v_pp)fn_at(RVA(0x1800305b0));
    v_v_ppi_s vthr = (v_v_ppi_s)fn_at(RVA(0x180033ae0));
    v_v_pp  vnonpos = (v_v_pp)fn_at(RVA(0x1800182b0));

    begin("cr_image_fill_const2");
    int bad = g_fail;
    for (int t = 0; t < 4000; t++) {
        unsigned char va[0x20], ca[0x20], pv[256], pc[256];
        int w = (int)(rnd() % 15u), h = (int)(rnd() % 15u);
        memset(va, 0, sizeof va); memset(ca, 0, sizeof ca);
        memset(pv, 0xEE, sizeof pv); memset(pc, 0xEE, sizeof pc);
        *(int *)(va + 0x10) = w; *(int *)(va + 0x14) = h; *(void **)(va + 8) = pv;
        *(int *)(ca + 0x10) = w; *(int *)(ca + 0x14) = h; *(void **)(ca + 8) = pc;
        vfill2(va); cr_image_fill_const2((cr_image *)ca);
        cmp_buf("fill2", pv, pc, sizeof pv, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_image_fill_const2\n");

    for (int k = 0; k < 3; k++) {
        const char *nm = k == 0 ? "cr_image_set(0x18003b250)"
                       : k == 1 ? "cr_image_set(0x18003fbc0)"
                                : "cr_image_set(0x180036460)";
        begin(nm);
        bad = g_fail;
        for (int t = 0; t < 8000; t++) {
            unsigned char va[0x20], ca[0x20];
            memset(va, 0xAB, sizeof va); memset(ca, 0xAB, sizeof ca);
            int w = (int)(rnd() % 40u) - 8;
            int h = (int)(rnd() % 40u) - 8;
            int isnull = (rnd() % 8u) == 0;
            void *data = (void *)(uintptr_t)(0x1000 + (rnd() & 0xfff));
            uint32_t rv = vset[k](isnull ? NULL : va, data, w, h);
            uint32_t rc = cr_image_set(isnull ? NULL : (cr_image *)ca, data, w, h);
            if (rv != rc) mismatch("set-ret", (u32)t, rv, rc);
            if (!isnull) cmp_buf("set", va, ca, sizeof va, (u32)t);
        }
        if (g_fail == bad) end(); else printf("  FAIL image_set[%d]\n", k);
    }

    begin("cr_image_set_pitch");
    bad = g_fail;
    for (int t = 0; t < 8000; t++) {
        unsigned char va[0x20], ca[0x20];
        memset(va, 0xAB, sizeof va); memset(ca, 0xAB, sizeof ca);
        int w = (int)(rnd() % 300u) - 16;
        int h = (int)(rnd() % 40u) - 8;
        int isnull = (rnd() % 8u) == 0;
        void *data = (void *)(uintptr_t)(0x1000 + (rnd() & 0xfff));
        uint32_t rv = vsetp(isnull ? NULL : va, data, w, h);
        uint32_t rc = cr_image_set_pitch(isnull ? NULL : (cr_image *)ca, data, w, h);
        if (rv != rc) mismatch("pitch-ret", (u32)t, rv, rc);
        if (!isnull) cmp_buf("pitch", va, ca, sizeof va, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_image_set_pitch\n");

    for (int k = 0; k < 2; k++) {
        begin(k ? "cr_image_subview(0x180017a80)" : "cr_image_subview(0x180010ef0)");
        bad = g_fail;
        for (int t = 0; t < 8000; t++) {
            unsigned char sv[0x20], va[0x20], ca[0x20];
            for (size_t i = 0; i < sizeof sv; i++) sv[i] = (unsigned char)rnd();
            memset(va, 0x77, sizeof va); memset(ca, 0x77, sizeof ca);
            int dx = (int)(rnd() % 200u) - 100;
            int dy = (int)(rnd() % 200u) - 100;
            int w  = (int)(rnd() % 200u) - 100;
            int h  = (int)(rnd() % 200u) - 100;
            vsub[k](va, sv, dx, dy, w, h);
            cr_image_subview((cr_image *)ca, (const cr_image *)sv, dx, dy, w, h);
            cmp_buf("subview", va, ca, sizeof va, (u32)t);
        }
        if (g_fail == bad) end(); else printf("  FAIL image_subview[%d]\n", k);
    }

    begin("cr_image_mark_indices");
    bad = g_fail;
    for (int t = 0; t < 6000; t++) {
        unsigned char iv[0x20], va[0x20], ca[0x20], pv[256], pc[256];
        uint16_t idx[32];
        memset(iv, 0, sizeof iv);
        int count = (int)(rnd() % 32u);
        *(uint16_t *)iv = (uint16_t)count;
        for (int i = 0; i < 32; i++) idx[i] = (uint16_t)(rnd() % 250u);
        *(void **)(iv + 8) = idx;
        memset(pv, 0xCC, sizeof pv); memset(pc, 0xCC, sizeof pc);
        memset(va, 0, sizeof va); memset(ca, 0, sizeof ca);
        *(void **)(va + 8) = pv; *(void **)(ca + 8) = pc;
        vmark(va, iv);
        cr_image_mark_indices((cr_image *)ca, (const cr_index_list *)iv);
        cmp_buf("mark", pv, pc, sizeof pv, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_image_mark_indices\n");

    begin("cr_image_threshold_mark");
    bad = g_fail;
    for (int t = 0; t < 6000; t++) {
        unsigned char va[0x20], ca[0x20], sa[0x20], pv[256], pc[256];
        int16_t sv[512];          /* n = w*h can reach 14*14 = 196 samples */
        int w = (int)(rnd() % 15u), h = (int)(rnd() % 15u);
        for (int i = 0; i < 512; i++) sv[i] = (int16_t)rnd();
        int16_t thr = (int16_t)rnd();
        memset(va, 0, sizeof va); memset(ca, 0, sizeof ca); memset(sa, 0, sizeof sa);
        *(int *)(va + 0x10) = w; *(int *)(va + 0x14) = h; *(void **)(va + 8) = pv;
        *(int *)(ca + 0x10) = w; *(int *)(ca + 0x14) = h; *(void **)(ca + 8) = pc;
        *(void **)(sa + 8) = sv;
        memset(pv, 0x99, sizeof pv); memset(pc, 0x99, sizeof pc);
        vthr(va, sa, thr);
        cr_image_threshold_mark((cr_image *)ca, (const cr_image *)sa, thr);
        cmp_buf("thr", pv, pc, sizeof pv, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_image_threshold_mark\n");

    begin("cr_image_mark_nonpos");
    bad = g_fail;
    for (int t = 0; t < 6000; t++) {
        unsigned char va[0x20], ca[0x20], sa[0x20], pv[256], pc[256];
        int16_t sv[512];          /* n = w*h can reach 14*14 = 196 samples */
        int w = (int)(rnd() % 15u), h = (int)(rnd() % 15u);
        for (int i = 0; i < 512; i++) sv[i] = (int16_t)rnd();
        memset(va, 0, sizeof va); memset(ca, 0, sizeof ca); memset(sa, 0, sizeof sa);
        *(int *)(va + 0x10) = w; *(int *)(va + 0x14) = h; *(void **)(va + 8) = pv;
        *(int *)(ca + 0x10) = w; *(int *)(ca + 0x14) = h; *(void **)(ca + 8) = pc;
        *(void **)(sa + 8) = sv;
        memset(pv, 0x99, sizeof pv); memset(pc, 0x99, sizeof pc);
        vnonpos(va, sa);
        cr_image_mark_nonpos((cr_image *)ca, (const cr_image *)sa);
        cmp_buf("nonpos", pv, pc, sizeof pv, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_image_mark_nonpos\n");
}

/* ---- batch 29: u8->i16 shift widen + symmetric border extend ----------- */

/* 0x1800337e0 — widen a byte image to int16 with a signed shift. */
static void test_u8_to_u16_shifted(void)
{
    v_v_ppi v = (v_v_ppi)fn_at(RVA(0x1800337e0));
    begin("cr_u8_to_u16_shifted");
    int bad = g_fail;
    enum { W = 40, H = 24 };
    for (int t = 0; t < 20000; t++) {
        uint8_t sbuf[W * H];
        uint16_t dv[W * H], dc[W * H];
        unsigned char sv[0x20], sc[0x20], dstv[0x20], dstc[0x20];
        for (int i = 0; i < W * H; i++) sbuf[i] = (uint8_t)rnd();
        int shift = (int)(int16_t)rnd();
        memset(sv, 0, sizeof sv);   memset(sc, 0, sizeof sc);
        memset(dstv, 0, sizeof dstv); memset(dstc, 0, sizeof dstc);
        *(void **)(sv + 8) = sbuf;  *(void **)(sc + 8) = sbuf;
        *(int *)(sv + 0x10) = W;    *(int *)(sc + 0x10) = W;
        *(int *)(sv + 0x14) = H;    *(int *)(sc + 0x14) = H;
        *(void **)(dstv + 8) = dv;  *(void **)(dstc + 8) = dc;
        *(int *)(dstv + 0x10) = W;  *(int *)(dstc + 0x10) = W;
        *(int *)(dstv + 0x14) = H;  *(int *)(dstc + 0x14) = H;
        memset(dv, 0xAA, sizeof dv); memset(dc, 0xAA, sizeof dc);
        v(dstv, sv, shift);
        cr_u8_to_u16_shifted((cr_image *)dstc, (const cr_image *)sc, shift);
        cmp_buf("u8u16", (unsigned char *)dv, (unsigned char *)dc,
                sizeof dv, (u32)t);
    }
    /* ODD heights: the vendor's paired-row walk plus its tail fix-up re-write
     * the penultimate row, so the final row of `dst` is deliberately left
     * untouched.  With a pre-filled destination that skipped row is
     * deterministic, which lets us pin down the quirk bit-for-bit. */
    {
        enum { WW = 40, HH = 25 };                 /* odd height */
        for (int t = 0; t < 20000; t++) {
            uint8_t sbuf[WW * HH];
            uint16_t dv[WW * HH], dc[WW * HH];
            unsigned char sv[0x20], sc[0x20], dstv[0x20], dstc[0x20];
            for (int i = 0; i < WW * HH; i++) sbuf[i] = (uint8_t)rnd();
            int shift = (int)(int16_t)rnd();
            memset(sv, 0, sizeof sv);   memset(sc, 0, sizeof sc);
            memset(dstv, 0, sizeof dstv); memset(dstc, 0, sizeof dstc);
            *(void **)(sv + 8) = sbuf;  *(void **)(sc + 8) = sbuf;
            *(int *)(sv + 0x10) = WW;   *(int *)(sc + 0x10) = WW;
            *(int *)(sv + 0x14) = HH;   *(int *)(sc + 0x14) = HH;
            *(void **)(dstv + 8) = dv;  *(void **)(dstc + 8) = dc;
            *(int *)(dstv + 0x10) = WW; *(int *)(dstc + 0x10) = WW;
            *(int *)(dstv + 0x14) = HH; *(int *)(dstc + 0x14) = HH;
            memset(dv, 0xAA, sizeof dv); memset(dc, 0xAA, sizeof dc);
            v(dstv, sv, shift);
            cr_u8_to_u16_shifted((cr_image *)dstc, (const cr_image *)sc, shift);
            cmp_buf("u8u16odd", (unsigned char *)dv, (unsigned char *)dc,
                    sizeof dv, (u32)t);
        }
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_u8_to_u16_shifted\n");
}

/* 0x180028930 — symmetric (BORDER_REFLECT) int16 border extension. */
static void test_mirror_extend_s16(void)
{
    v_v_piiii v = (v_v_piiii)fn_at(RVA(0x180028930));
    begin("cr_mirror_extend_s16");
    int bad = g_fail;
    const int BUFW = 128, BUFH = 128;
    for (int t = 0; t < 20000; t++) {
        int16_t pv[BUFW * BUFH], pc[BUFW * BUFH];
        unsigned char va[0x20], ca[0x20];
        int offx = 32, offy = 32, w = 48, h = 40;
        int top    = (int)(rnd() % 21u);
        int bottom = (int)(rnd() % 21u);
        int left   = (int)(rnd() % 21u);
        int right  = (int)(rnd() % 21u);
        for (int i = 0; i < BUFW * BUFH; i++) { pv[i] = (int16_t)rnd(); pc[i] = pv[i]; }
        memset(va, 0, sizeof va); memset(ca, 0, sizeof ca);
        *(int *)(va + 0)  = BUFW;  *(int *)(ca + 0)  = BUFW;
        *(int *)(va + 4)  = BUFH;  *(int *)(ca + 4)  = BUFH;
        *(int *)(va + 0x10) = w;   *(int *)(ca + 0x10) = w;
        *(int *)(va + 0x14) = h;   *(int *)(ca + 0x14) = h;
        *(int *)(va + 0x18) = offx;*(int *)(ca + 0x18) = offx;
        *(int *)(va + 0x1c) = offy;*(int *)(ca + 0x1c) = offy;
        *(void **)(va + 8) = pv;   *(void **)(ca + 8) = pc;
        v(va, top, bottom, left, right);
        cr_mirror_extend_s16((cr_image *)ca, top, bottom, left, right);
        cmp_buf("mirror16", (unsigned char *)pv, (unsigned char *)pc,
                sizeof pv, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_mirror_extend_s16\n");
}

/* 0x18000d040 — box sum/count of pixels NOT in a u16 index list. */
typedef void (WINAPI *v_v_iippppiii)(int, int, const uint8_t *,
                                     const uint16_t *, const uint16_t *const *,
                                     int, int, int *, float *);

static void test_box_sum_excl(void)
{
    v_v_iippppiii v = (v_v_iippppiii)fn_at(RVA(0x18000d040));
    begin("cr_box_sum_excl");
    int bad = g_fail;
    enum { W = 37, H = 29 };
    uint8_t img[W * H];
    uint16_t list[64];
    for (int t = 0; t < 20000; t++) {
        for (int i = 0; i < W * H; i++) img[i] = (uint8_t)rnd();
        uint16_t cnt = (uint16_t)(rnd() % 40u);
        for (int i = 0; i < cnt; i++) list[i] = (uint16_t)(rnd() % (W * H + 8));
        int win = (int)(rnd() % 15u);
        int idx = (int)(rnd() % (W * H));
        const uint16_t *lp = list;
        const uint16_t *const *lpp = &lp;
        int vc = 0x7f000001, cc = 0x7f000001;
        float vs = -1.0f, cs = -1.0f;
        v(W, H, img, &cnt, lpp, win, idx, &vc, &vs);
        cr_box_sum_excl(W, H, img, &cnt, lpp, win, idx, &cc, &cs);
        if (vc != cc) mismatch("count", (u32)t, (u32)vc, (u32)cc);
        if (cr_f2u(vs) != cr_f2u(cs)) mismatch("sum", (u32)t, cr_f2u(vs), cr_f2u(cs));
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_box_sum_excl\n");
}

/* 0x180032830 — 15x15 separable box filter on an int16 image. */
static void test_boxsum15_s16(void)
{
    typedef void (WINAPI *v_v_pii)(void *, int, int);
    v_v_pii v = (v_v_pii)fn_at(RVA(0x180032830));
    begin("cr_boxsum15_s16");
    int bad = g_fail;
    enum { MAXW = 48, MAXH = 48 };
    int16_t bufv[MAXW * MAXH], bufc[MAXW * MAXH];
    for (int t = 0; t < 20000; t++) {
        int W = 15 + (int)(rnd() % (MAXW - 14));
        int H = 15 + (int)(rnd() % (MAXH - 14));
        int n = W * H;
        for (int i = 0; i < n; i++) bufv[i] = (int16_t)rnd();
        memcpy(bufc, bufv, sizeof(int16_t) * n);
        v(bufv, W, H);
        cr_boxsum15_s16(bufc, W, H);
        cmp_buf("box15", (unsigned char *)bufv, (unsigned char *)bufc,
                sizeof(int16_t) * n, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_boxsum15_s16\n");
}

/* 0x18001aaa0 — byte twin of the 15x15 separable box filter. */
static void test_boxsum15_u8(void)
{
    typedef void (WINAPI *v_v_pii)(void *, int, int);
    v_v_pii v = (v_v_pii)fn_at(RVA(0x18001aaa0));
    begin("cr_boxsum15_u8");
    int bad = g_fail;
    enum { MAXW = 48, MAXH = 48 };
    uint8_t bufv[MAXW * MAXH], bufc[MAXW * MAXH];
    for (int t = 0; t < 20000; t++) {
        int W = 15 + (int)(rnd() % (MAXW - 14));
        int H = 15 + (int)(rnd() % (MAXH - 14));
        int n = W * H;
        for (int i = 0; i < n; i++) bufv[i] = (uint8_t)rnd();
        memcpy(bufc, bufv, n);
        v(bufv, W, H);
        cr_boxsum15_u8(bufc, W, H);
        cmp_buf("box15u8", bufv, bufc, n, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_boxsum15_u8\n");
}

/* 0x18003ecc0 — widen a byte row with reflect-101 padding, then run an m-tap
 * symmetric FIR: out[i] = (Σ_{k<taps} coef[k]*scratch[i+k] + 0x100) >> 9.
 * The unrolled region reads one extra tap for even m (coef[m]); both coef
 * buffers are fully initialised so that read is well-defined and shared. */
static void test_u8_expand_convolve(void)
{
    typedef void (WINAPI *v_v_ppppii)(int16_t *, uint16_t *, const uint8_t *,
                                      const int16_t *, int, int);
    v_v_ppppii v = (v_v_ppppii)fn_at(RVA(0x18003ecc0));
    begin("cr_u8_expand_convolve");
    int bad = g_fail;
    enum { MAXN = 48, MAXM = 20, MAXS = MAXN + MAXM + 2 };
    uint8_t inv[MAXN], inc[MAXN];
    int16_t coefv[MAXM], coefc[MAXM];
    uint16_t scrv[MAXS], scrc[MAXS];
    int16_t outv[MAXN], outc[MAXN];
    for (int t = 0; t < 20000; t++) {
        int m = 1 + (int)(rnd() % 17);
        int n = m + (int)(rnd() % (MAXN - m + 1));   /* n >= m, so n > pad */
        for (int i = 0; i < n; i++) inv[i] = (uint8_t)rnd();
        for (int k = 0; k < MAXM; k++) coefv[k] = (int16_t)rnd();
        memcpy(inc, inv, n);
        memcpy(coefc, coefv, sizeof coefv);
        memset(scrv, 0x5A, sizeof scrv); memset(scrc, 0x5A, sizeof scrc);
        memset(outv, 0x5A, sizeof outv); memset(outc, 0x5A, sizeof outc);
        v(outv, scrv, inv, coefv, n, m);
        cr_u8_expand_convolve(outc, scrc, inc, coefc, n, m);
        cmp_buf("out", (unsigned char *)outv, (unsigned char *)outc,
                sizeof(int16_t) * n, (u32)t);
        cmp_buf("scratch", (unsigned char *)scrv, (unsigned char *)scrc,
                sizeof(uint16_t) * (n + 2 * (m >> 1)), (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_u8_expand_convolve\n");
}

/* 0x18002f070 — spatial top-K accumulator with per-cell bounded slot lists. */
struct grid_state {
    cr_grid_node nodes[64];
    int16_t next[16];
    float   values[16];
    uint8_t coords[32];
    float   values2[16];
    uint8_t coords2[32];
    cr_grid g;
    cr_grid_cfg cfg;
};

static void test_grid_insert(void)
{
    typedef int (WINAPI *v_i_pbbfp)(void *, uint8_t, uint8_t, float, void *);
    v_i_pbbfp vfn = (v_i_pbbfp)fn_at(RVA(0x18002f070));
    begin("cr_grid_insert");
    int bad = g_fail;
    for (int t = 0; t < 4000; t++) {
        int W = 1 + (int)(rnd() % 8);
        int H = 1 + (int)(rnd() % 8);
        int cap = 1 + (int)(rnd() % 16);
        int cap2 = (int)(rnd() % 17);
        int divx = 1 + (int)(rnd() % 512);
        int divy = 1 + (int)(rnd() % 512);
        int mode = ((int)(rnd() % 4) == 0) ? 2
                 : ((int)(rnd() % 8) == 0) ? 7 : 5;

        struct grid_state sv, sc;
        memset(&sv, 0, sizeof sv);
        sv.g.nodes = sv.nodes; sv.g.coords = sv.coords; sv.g.values = sv.values;
        sv.g.next = sv.next; sv.g.coords2 = sv.coords2; sv.g.values2 = sv.values2;
        sv.g.W = W; sv.g.H = H; sv.g.divx = divx; sv.g.divy = divy;
        sv.g.count = 0; sv.g.count2 = 0; sv.g.cap = cap;
        sv.cfg.cap2 = (int16_t)cap2; sv.cfg.mode = (uint8_t)mode;
        for (int k = 0; k < W * H; k++) {
            sv.nodes[k].key = 0; sv.nodes[k].head = -1;
            sv.nodes[k].val = (float)(1 + (int)(rnd() % 1000)) * 0.001f;  /* > 0 */
        }
        for (int k = 0; k < cap; k++) {
            sv.next[k] = -1; sv.values[k] = 0.0f;
            sv.coords[2 * k] = sv.coords[2 * k + 1] = 0;
        }
        for (int k = 0; k < cap2; k++) {
            sv.values2[k] = 0.0f;
            sv.coords2[2 * k] = sv.coords2[2 * k + 1] = 0;
        }

        sc = sv;
        sc.g.nodes = sc.nodes; sc.g.coords = sc.coords; sc.g.values = sc.values;
        sc.g.next = sc.next; sc.g.coords2 = sc.coords2; sc.g.values2 = sc.values2;

        int steps = cap + 4 + (int)(rnd() % (cap + 5));
        int failed = 0;
        for (int st = 0; st < steps && !failed; st++) {
            uint8_t x = (uint8_t)rnd();
            uint8_t y = (uint8_t)rnd();
            u32 vb = rnd();
            float v = ((int)(rnd() % 8) == 0) ? cr_u2f(vb)
                                              : (float)(int)(vb % 4001) - 2000.0f;
            int rv = vfn(&sv.g, x, y, v, &sv.cfg);
            int rc = cr_grid_insert(&sc.g, x, y, v, &sc.cfg);
            if (rv != rc) { mismatch("ret", (u64)st, (u32)rv, (u32)rc); failed = 1; break; }
            size_t nn = sizeof(cr_grid_node) * (size_t)(W * H);
            if (memcmp(sv.nodes, sc.nodes, nn)) {
                cmp_buf("nodes", (unsigned char *)sv.nodes, (unsigned char *)sc.nodes,
                        nn, (u32)st); failed = 1; break; }
            if (memcmp(sv.values, sc.values, sizeof(float) * (size_t)cap)) {
                cmp_buf("values", (unsigned char *)sv.values, (unsigned char *)sc.values,
                        sizeof(float) * (size_t)cap, (u32)st); failed = 1; break; }
            if (memcmp(sv.next, sc.next, sizeof(int16_t) * (size_t)cap)) {
                cmp_buf("next", (unsigned char *)sv.next, (unsigned char *)sc.next,
                        sizeof(int16_t) * (size_t)cap, (u32)st); failed = 1; break; }
            if (memcmp(sv.coords, sc.coords, 2 * (size_t)cap)) {
                cmp_buf("coords", sv.coords, sc.coords, 2 * (size_t)cap, (u32)st);
                failed = 1; break; }
            if (memcmp(sv.values2, sc.values2, sizeof(float) * (size_t)cap2)) {
                cmp_buf("values2", (unsigned char *)sv.values2, (unsigned char *)sc.values2,
                        sizeof(float) * (size_t)cap2, (u32)st); failed = 1; break; }
            if (memcmp(sv.coords2, sc.coords2, 2 * (size_t)cap2)) {
                cmp_buf("coords2", sv.coords2, sc.coords2, 2 * (size_t)cap2, (u32)st);
                failed = 1; break; }
            if (sv.g.count != sc.g.count || sv.g.count2 != sc.g.count2) {
                mismatch("count", (u64)st, (u32)sv.g.count, (u32)sc.g.count);
                failed = 1; break; }
        }
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_grid_insert\n");
}

/* ---- 0x18000d3b0 — Gaussian-derivative structure-tensor orientation ---- */
static void test_structure_orient_d3b0(void)
{
    typedef int (WINAPI *v_i_ppppubp)(void *, const void *, const void *,
                                      uint8_t, const void *);
    v_i_ppppubp v = (v_i_ppppubp)fn_at(RVA(0x18000d3b0));
    begin("cr_structure_orient_d3b0");
    int bad = g_fail;

    enum { MAXW = 33, MAXH = 32, MAXN = MAXW * MAXH };

    static int16_t srcd[MAXN];
    static int16_t dvd[MAXN], dcd[MAXN];                  /* dst int16 data */
    static uint8_t mvd[MAXN];                             /* mask u8 data (read-only) */
    static u8 srcv[0x20], srcc[0x20];                     /* cr_image */
    static u8 dstv[0x20], dstc[0x20];
    static u8 mskv[0x20], mskc[0x20];
    static u8 cfg[0x20];                                  /* shared (identical) */

    for (int t = 0; t < 4000; t++) {
        int w = 16 + (int)(rnd() % 18u);                  /* 16..33 */
        int h = 16 + (int)(rnd() % 17u);                  /* 16..32 */
        int N = w * h;

        for (int i = 0; i < N; i++) srcd[i] = (int16_t)rnd();
        for (int i = 0; i < N; i++) { dvd[i] = 0x5A5A; dcd[i] = 0x5A5A; }
        for (int i = 0; i < N; i++) mvd[i] = (uint8_t)rnd();

        mk_img2(srcv, srcd, w, h);  memcpy(srcc, srcv, 0x20);
        mk_img2(dstv, dvd,  w, h);  mk_img2(dstc, dcd, w, h);
        mk_img2(mskv, (int16_t *)mvd, w, h);  memcpy(mskc, mskv, 0x20);

        /* cfg: 0x04 sigma1, 0x08 sigma2, 0x0c int16 count, 0x0f uint8 flag */
        float sigma1 = (float)(rnd() % 220u) / 100.0f;    /* 0..2.19 */
        float sigma2 = (float)(rnd() % 220u) / 100.0f;
        int16_t count = (int16_t)((int)(rnd() % 6u) - 1); /* -1..4 */
        uint8_t flag  = (uint8_t)(rnd() % 4u);
        uint8_t and_mask = (uint8_t)rnd();
        memset(cfg, 0, 0x20);
        *(float  *)(cfg + 0x04) = sigma1;
        *(float  *)(cfg + 0x08) = sigma2;
        *(int16_t *)(cfg + 0x0c) = count;
        cfg[0x0f] = flag;

        int rv = v(dstv, srcv, mskv, and_mask, cfg);
        int rc = cr_structure_orient_d3b0(dstc, (const cr_image *)srcc,
                                          mskc, and_mask, cfg);
        if (rv != rc) mismatch("ret", (u32)t, (u32)rv, (u32)rc);
        cmp_buf("dst", (const unsigned char *)dvd, (const unsigned char *)dcd,
                (u32)(N * 2), (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_structure_orient_d3b0\n");
}

/* ---- 0x18003b960 — Gaussian-derivative structure-tensor orientation (twin) */
static void test_structure_orient_3b960(void)
{
    typedef int (WINAPI *v_i_ppppubp)(void *, const void *, const void *,
                                      uint8_t, const void *);
    v_i_ppppubp v = (v_i_ppppubp)fn_at(RVA(0x18003b960));
    begin("cr_structure_orient_3b960");
    int bad = g_fail;

    enum { MAXW = 33, MAXH = 32, MAXN = MAXW * MAXH };

    static int16_t srcd[MAXN];
    static int16_t dvd[MAXN], dcd[MAXN];                  /* dst int16 data */
    static uint8_t mvd[MAXN];                             /* mask u8 data (read-only) */
    static u8 srcv[0x20], srcc[0x20];                     /* cr_image */
    static u8 dstv[0x20], dstc[0x20];
    static u8 mskv[0x20], mskc[0x20];
    static u8 cfg[0x20];                                  /* shared (identical) */

    for (int t = 0; t < 4000; t++) {
        int w = 16 + (int)(rnd() % 18u);                  /* 16..33 */
        int h = 16 + (int)(rnd() % 17u);                  /* 16..32 */
        int N = w * h;

        for (int i = 0; i < N; i++) srcd[i] = (int16_t)rnd();
        for (int i = 0; i < N; i++) { dvd[i] = 0x5A5A; dcd[i] = 0x5A5A; }
        for (int i = 0; i < N; i++) mvd[i] = (uint8_t)rnd();

        mk_img2(srcv, srcd, w, h);  memcpy(srcc, srcv, 0x20);
        mk_img2(dstv, dvd,  w, h);  mk_img2(dstc, dcd, w, h);
        mk_img2(mskv, (int16_t *)mvd, w, h);  memcpy(mskc, mskv, 0x20);

        /* cfg: 0x04 sigma1, 0x08 sigma2, 0x0c int16 count, 0x0f uint8 flag */
        float sigma1 = (float)(rnd() % 220u) / 100.0f;    /* 0..2.19 */
        float sigma2 = (float)(rnd() % 220u) / 100.0f;
        int16_t count = (int16_t)((int)(rnd() % 6u) - 1); /* -1..4 */
        uint8_t flag  = (uint8_t)(rnd() % 4u);
        uint8_t and_mask = (uint8_t)rnd();
        memset(cfg, 0, 0x20);
        *(float  *)(cfg + 0x04) = sigma1;
        *(float  *)(cfg + 0x08) = sigma2;
        *(int16_t *)(cfg + 0x0c) = count;
        cfg[0x0f] = flag;

        int rv = v(dstv, srcv, mskv, and_mask, cfg);
        int rc = cr_structure_orient_3b960(dstc, (const cr_image *)srcc,
                                          mskc, and_mask, cfg);
        if (rv != rc) mismatch("ret", (u32)t, (u32)rv, (u32)rc);
        cmp_buf("dst", (const unsigned char *)dvd, (const unsigned char *)dcd,
                (u32)(N * 2), (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_structure_orient_3b960\n");
}

/* ---- 0x180014320 — mask-weighted spatial bin selection ----------------- *
 * pts: 8-byte records {int32 key; int16 x; int16 y}.  mask: {stride(+0),
 * words(+8), w(+0x10), h(+0x14), x0(+0x18), y0(+0x1c)}.  cfg: {margin(+8),
 * maxpts(+0x10), weight(+0x14), NX(+0x25), NY(+0x26)}. */
static void test_bin_select_14320(void)
{
    typedef int (WINAPI *v_t)(void *, int *, int, int, const void *, uint32_t, const void *);
    v_t v = (v_t)fn_at(RVA(0x180014320));
    begin("cr_bin_select_14320");
    int bad = g_fail;

    enum { MAXPTS = 40, MAXW = 512 };
    static uint8_t ptsv[MAXPTS * 8], ptsc[MAXPTS * 8];
    static uint8_t mcfg[0x20];
    static uint8_t cfg[0x40];
    static uint32_t mwords[MAXW];

    for (int t = 0; t < 8000; t++) {
        int margin = (int)(rnd() % 3u);
        int W = 2 * margin + 1 + (int)(rnd() % 48u);
        int H = 2 * margin + 1 + (int)(rnd() % 48u);
        int NX = 1 + (int)(rnd() % 5u);
        int NY = 1 + (int)(rnd() % 5u);
        int npts = (int)(rnd() % (MAXPTS + 1));
        int maxout = (int)(rnd() % (MAXPTS + 3));
        int maxpts = npts + (int)(rnd() % 5u);
        int stride = 32 * (1 + (int)(rnd() % 4u));        /* 32..128 */
        int x0 = (int)(rnd() % 4u);
        int y0 = (int)(rnd() % 4u);
        int weight = (int)(rnd() % 2000u);
        uint32_t seed = rnd();

        for (int i = 0; i < MAXW; i++) mwords[i] = rnd();
        for (int i = 0; i < MAXPTS; i++) {
            *(int32_t *)(ptsv + i * 8) = (int32_t)rnd();
            *(int16_t *)(ptsv + i * 8 + 4) = (int16_t)((int)(rnd() % 400u) - 100);
            *(int16_t *)(ptsv + i * 8 + 6) = (int16_t)((int)(rnd() % 400u) - 100);
        }
        memcpy(ptsc, ptsv, sizeof ptsv);

        memset(mcfg, 0, sizeof mcfg);
        *(int *)(mcfg + 0x00) = stride;
        *(void **)(mcfg + 0x08) = mwords;
        *(int *)(mcfg + 0x10) = W;
        *(int *)(mcfg + 0x14) = H;
        *(int *)(mcfg + 0x18) = x0;
        *(int *)(mcfg + 0x1c) = y0;

        memset(cfg, 0, sizeof cfg);
        *(int8_t *)(cfg + 0x08) = (int8_t)margin;
        *(int16_t *)(cfg + 0x10) = (int16_t)maxpts;
        *(int *)(cfg + 0x14) = weight;
        cfg[0x25] = (uint8_t)NX;
        cfg[0x26] = (uint8_t)NY;

        int ov = 0x12345678, oc = 0x12345678;
        int rv = v(ptsv, &ov, npts, maxout, mcfg, seed, cfg);
        int rc = cr_bin_select_14320(ptsc, &oc, npts, maxout, mcfg, seed, cfg);
        if (rv != rc) mismatch("ret", (u32)t, (u32)rv, (u32)rc);
        if (ov != oc) mismatch("count", (u32)t, (u32)ov, (u32)oc);
        cmp_buf("pts", ptsv, ptsc, (u32)sizeof ptsv, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_bin_select_14320\n");
}

/* ---- 0x18002cfd0 — structure-orientation dispatcher -------------------- *
 * cfg byte +0x10 selects the twin-image (0) / three-image (1) encoder. */
static void test_structure_orient_dispatch_2cfd0(void)
{
    typedef int (WINAPI *v_t)(void *, const void *, const void *, uint8_t,
                              const void *);
    v_t v = (v_t)fn_at(RVA(0x18002cfd0));
    begin("cr_structure_orient_dispatch_2cfd0");
    int bad = g_fail;

    enum { MAXW = 33, MAXH = 32, MAXN = MAXW * MAXH };

    static int16_t srcd[MAXN];
    static int16_t dvd[MAXN], dcd[MAXN];
    static uint8_t mvd[MAXN];
    static u8 srcv[0x20], srcc[0x20];
    static u8 dstv[0x20], dstc[0x20];
    static u8 mskv[0x20], mskc[0x20];
    static u8 cfg[0x20];

    for (int t = 0; t < 4000; t++) {
        int w = 16 + (int)(rnd() % 18u);
        int h = 16 + (int)(rnd() % 17u);
        int N = w * h;

        for (int i = 0; i < N; i++) srcd[i] = (int16_t)rnd();
        for (int i = 0; i < N; i++) { dvd[i] = 0x5A5A; dcd[i] = 0x5A5A; }
        for (int i = 0; i < N; i++) mvd[i] = (uint8_t)rnd();

        mk_img2(srcv, srcd, w, h);  memcpy(srcc, srcv, 0x20);
        mk_img2(dstv, dvd,  w, h);  mk_img2(dstc, dcd, w, h);
        mk_img2(mskv, (int16_t *)mvd, w, h);  memcpy(mskc, mskv, 0x20);

        float sigma1 = (float)(rnd() % 220u) / 100.0f;
        float sigma2 = (float)(rnd() % 220u) / 100.0f;
        int16_t count = (int16_t)((int)(rnd() % 6u) - 1);
        uint8_t flag  = (uint8_t)(rnd() % 4u);
        uint8_t and_mask = (uint8_t)rnd();
        uint8_t sel = (uint8_t)(rnd() % 3u);      /* 0, 1, 2 (2 = default) */
        memset(cfg, 0, 0x20);
        *(float  *)(cfg + 0x04) = sigma1;
        *(float  *)(cfg + 0x08) = sigma2;
        *(int16_t *)(cfg + 0x0c) = count;
        cfg[0x0f] = flag;
        cfg[0x10] = sel;

        int rv = v(dstv, srcv, mskv, and_mask, cfg);
        int rc = cr_structure_orient_dispatch_2cfd0(dstc, srcc, mskc, and_mask,
                                                    cfg);
        if (rv != rc) mismatch("ret", (u32)t, (u32)rv, (u32)rc);
        cmp_buf("dst", (const unsigned char *)dvd, (const unsigned char *)dcd,
                (u32)(N * 2), (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_structure_orient_dispatch_2cfd0\n");
}

/* ---- 0x180038020 — grid-population dispatcher -------------------------- *
 * Clears grid->count then selects the callee from cfg byte +1. */
static void test_grid_populate_dispatch_38020(void)
{
    typedef int (WINAPI *v_t)(void *, const void *, const void *, const void *);
    v_t v = (v_t)fn_at(RVA(0x180038020));
    begin("cr_grid_populate_dispatch_38020");
    int bad = g_fail;

    static uint8_t  sbuf[4096];
    static uint32_t mwords[4096];
    static u8 smv[0x20], smc[0x20];
    static u8 descv[0x20], descc[0x20];
    static uint8_t cfg[0x40];

    for (int t = 0; t < 6000; t++) {
        int sel;
        switch ((int)(rnd() % 6u)) {
        case 0:  sel = 1; break;
        case 1:  sel = 4; break;
        case 2:  sel = 5; break;
        default: sel = (int)(rnd() % 8u); break;   /* includes invalid values */
        }
        int is_blob = (sel == 4);

        int W = 1 + (int)(rnd() % 6u);
        int H = 1 + (int)(rnd() % 6u);
        int cap = 1 + (int)(rnd() % 8u);
        int cap2 = (int)(rnd() % 17u);
        int divx = 1 + (int)(rnd() % 512u);
        int divy = 1 + (int)(rnd() % 512u);
        int mode = ((int)(rnd() % 4) == 0) ? 2
                 : ((int)(rnd() % 8) == 0) ? 7 : 5;
        int border = 1 + (int)(rnd() % 3u);
        float coef  = (float)(rnd() % 100u) / 1000.0f;
        float sigma = 0.72f + (float)(rnd() % 150u) / 100.0f;
        int stride_bits = (2 + (int)(rnd() % 3u)) * 32;

        for (int i = 0; i < 4096; i++) sbuf[i] = (uint8_t)rnd();
        for (int i = 0; i < 4096; i++) mwords[i] = rnd();

        /* mask object: shared layout for the blob maskcfg and the Harris mask
         * image (stride@+0, word ptr@+8, origin@+0x18/+0x1c). */
        memset(smv, 0, 0x20);
        *(int *)(smv + 0x00) = stride_bits;
        *(void **)(smv + 0x08) = mwords;
        memcpy(smc, smv, 0x20);

        memset(cfg, 0, sizeof cfg);
        *(int8_t  *)(cfg + 0x08) = (int8_t)border;
        *(int16_t *)(cfg + 0x10) = (int16_t)cap2;
        *(float   *)(cfg + 0x18) = coef;
        *(float   *)(cfg + 0x1c) = sigma;
        *(uint8_t *)(cfg + 0x24) = (uint8_t)mode;
        cfg[0x01] = (uint8_t)sel;                 /* dispatcher selector */

        if (is_blob) {
            int m = 1 + (int)(rnd() % 4);         /* margin */
            int Wn = 1 + (int)(rnd() % 6);
            int sw = Wn + 2 * m;
            int sh = 2 * m + 1 + (int)(rnd() % 6);
            int mx = (7 - m) + (int)(rnd() % 5);
            int my = (7 - m) + (int)(rnd() % 5);
            memset(descv, 0, 0x20);
            *(int   *)(descv + 0x00) = 64;
            *(int   *)(descv + 0x04) = 40;
            *(void **)(descv + 0x08) = sbuf;
            *(int   *)(descv + 0x10) = sw;
            *(int   *)(descv + 0x14) = sh;
            *(int   *)(descv + 0x18) = mx;
            *(int   *)(descv + 0x1c) = my;
            *(int8_t *)(cfg + 0x08) = (int8_t)m;  /* blob reads margin here */
        } else {
            mk_img2(descv, (int16_t *)sbuf, W, H);
        }
        memcpy(descc, descv, 0x20);

        struct grid_state gv, gc;
        memset(&gv, 0, sizeof gv);
        gv.g.nodes = gv.nodes; gv.g.coords = gv.coords; gv.g.values = gv.values;
        gv.g.next = gv.next; gv.g.coords2 = gv.coords2; gv.g.values2 = gv.values2;
        gv.g.W = W; gv.g.H = H; gv.g.divx = divx; gv.g.divy = divy;
        gv.g.count = 0x1234; gv.g.count2 = 0x5678; gv.g.cap = cap;
        for (int k = 0; k < W * H; k++) {
            gv.nodes[k].key = 0; gv.nodes[k].head = -1;
            gv.nodes[k].val = (float)(1 + (int)(rnd() % 1000)) * 0.001f;
        }
        for (int k = 0; k < cap; k++) {
            gv.next[k] = -1; gv.values[k] = 0.0f;
            gv.coords[2 * k] = gv.coords[2 * k + 1] = 0;
        }
        for (int k = 0; k < cap2; k++) {
            gv.values2[k] = 0.0f;
            gv.coords2[2 * k] = gv.coords2[2 * k + 1] = 0;
        }
        gc = gv;
        gc.g.nodes = gc.nodes; gc.g.coords = gc.coords; gc.g.values = gc.values;
        gc.g.next = gc.next; gc.g.coords2 = gc.coords2; gc.g.values2 = gc.values2;

        int rv = v(&gv.g, descv, smv, cfg);
        int rc = cr_grid_populate_dispatch_38020(&gc.g,
                                                 (const cr_image *)descc,
                                                 (const cr_image *)smc, cfg);
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }

        size_t nn = sizeof(cr_grid_node) * (size_t)(W * H);
        cmp_buf("nodes", (const unsigned char *)gv.nodes,
                (const unsigned char *)gc.nodes, nn, (u32)t);
        cmp_buf("values", (const unsigned char *)gv.values,
                (const unsigned char *)gc.values, sizeof(float) * (size_t)cap,
                (u32)t);
        cmp_buf("next", (const unsigned char *)gv.next,
                (const unsigned char *)gc.next, sizeof(int16_t) * (size_t)cap,
                (u32)t);
        cmp_buf("coords", gv.coords, gc.coords, 2 * (size_t)cap, (u32)t);
        cmp_buf("values2", (const unsigned char *)gv.values2,
                (const unsigned char *)gc.values2, sizeof(float) * (size_t)cap2,
                (u32)t);
        cmp_buf("coords2", gv.coords2, gc.coords2, 2 * (size_t)cap2, (u32)t);
        if (gv.g.count != gc.g.count || gv.g.count2 != gc.g.count2)
            mismatch("count", (u32)t, (u32)gv.g.count, (u32)gc.g.count);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_grid_populate_dispatch_38020\n");
}

/* ---- 0x180026dc0 — feature-extraction step ----------------------------- *
 * Quarter-res quality gate, then a packed 8-bit image folded into a running
 * average; cfg int16 +0x24 is the mode/limit.  The state object is the same
 * one the quality gate and the feature qualifier operate on. */
static void test_feature_extract_step_26dc0(void)
{
    typedef int (WINAPI *v_t)(void *, const void *, void *, const void *,
                              const void *);
    v_t v = (v_t)fn_at(RVA(0x180026dc0));
    begin("cr_feature_extract_step_26dc0");
    int bad = g_fail;

    enum { W = 16, H = 16, N = W * H };

    static uint8_t  imgb_v[2 * N], imgb_c[2 * N];
    static int16_t  prevv[64], prevc[64];
    static int16_t  asv[512], asc[512];
    static int16_t  dsv[512], dsc[512];
    static int16_t  dAv[64], dAc[64], dBv[64], dBc[64];
    static int16_t  cAv[64], cAc[64], cBv[64], cBc[64];
    static uint8_t  histv[0x20], histc[0x20];
    static uint8_t  bmv[2048], bmc[2048];
    static u8 st_v[0x100], st_c[0x100];
    static u8 imgv[0x20], imgc[0x20], pkv[0x20], pkc[0x20];
    static u8 storev[0x100], storec[0x100];
    static u8 cfg[0x40];

    static const int32_t keys[4] = { 0xda, 0xdd, 0xd2, 0xd6 };
    static const int32_t vals[4] = { 10, 1024, 1024, 1024 };

    for (int t = 0; t < 6000; t++) {
        int valid = (int)(rnd() % 4u) != 0;       /* occasionally invalid */
        int16_t mode;
        if (valid)
            mode = (int16_t)(1 + (int)(rnd() % 0x7ffu));
        else
            mode = (int16_t)((int)(rnd() % 3u) == 0 ? 0
                           : (int)(rnd() % 3u) == 0 ? 0x800 : -1);
        int use_handle = (int)(rnd() % 8u) != 0;
        int count = (int)(rnd() & 1u);
        int sflag = (int)(rnd() % 3u) - 1;        /* -1, 0, 1 */

        for (int i = 0; i < 2 * N; i++) {
            uint8_t b = (uint8_t)(rnd() % 200u);
            imgb_v[i] = b; imgb_c[i] = b;
        }
        for (int i = 0; i < 64; i++) {
            int16_t p = (int16_t)(rnd() % 200u);
            prevv[i] = p; prevc[i] = p;
        }
        for (int i = 0; i < 512; i++) {
            int16_t a = (int16_t)((int)(rnd() % 4001) - 2000);
            asv[i] = a; asc[i] = a;
            int16_t d = (int16_t)((int)(rnd() % 4001) - 2000);
            dsv[i] = d; dsc[i] = d;
        }
        for (int i = 0; i < 64; i++) {
            int16_t a = (int16_t)rnd();
            dAv[i] = a; dAc[i] = a; dBv[i] = a; dBc[i] = a;
            int16_t c = (int16_t)(rnd() % 40u);
            cAv[i] = c; cAc[i] = c; cBv[i] = c; cBc[i] = c;
        }
        for (int i = 0; i < 0x20; i++) {
            uint8_t h = (uint8_t)rnd();
            histv[i] = h; histc[i] = h;
        }
        for (int i = 0; i < 2048; i++) {
            uint8_t b = (uint8_t)rnd();
            bmv[i] = b; bmc[i] = b;
        }

        memset(st_v, 0, sizeof st_v);
        memset(st_c, 0, sizeof st_c);
        *(void **)(st_v + 0x00) = histv;  *(void **)(st_c + 0x00) = histc;
        *(void **)(st_v + 0x10) = prevv;  *(void **)(st_c + 0x10) = prevc;
        *(void **)(st_v + 0x18) = asv;    *(void **)(st_c + 0x18) = asc;
        *(void **)(st_v + 0x20) = dAv;    *(void **)(st_c + 0x20) = dAc;
        *(void **)(st_v + 0x28) = dBv;    *(void **)(st_c + 0x28) = dBc;
        *(void **)(st_v + 0x30) = cAv;    *(void **)(st_c + 0x30) = cAc;
        *(void **)(st_v + 0x38) = cBv;    *(void **)(st_c + 0x38) = cBc;
        *(void **)(st_v + 0x58) = dsv;    *(void **)(st_c + 0x58) = dsc;
        *(int32_t *)(st_v + 0x40) = count; *(int32_t *)(st_c + 0x40) = count;
        *(int32_t *)(st_v + 0x44) = 0;    *(int32_t *)(st_c + 0x44) = 0;
        *(float   *)(st_v + 0x48) = 0.0f; *(float   *)(st_c + 0x48) = 0.0f;
        *(float   *)(st_v + 0x4c) = 0.0f; *(float   *)(st_c + 0x4c) = 0.0f;
        *(int32_t *)(st_v + 0x60) = 16;   *(int32_t *)(st_c + 0x60) = 16;
        *(int32_t *)(st_v + 0x64) = 16;   *(int32_t *)(st_c + 0x64) = 16;
        st_v[0x08] = (uint8_t)sflag;      st_c[0x08] = (uint8_t)sflag;

        mk_img2(imgv, (int16_t *)imgb_v, W, H);
        mk_img2(imgc, (int16_t *)imgb_c, W, H);

        memset(pkv, 0, 0x20);
        memset(pkc, 0, 0x20);
        *(int   *)(pkv + 0x00) = 64;      *(int   *)(pkc + 0x00) = 64;
        *(void **)(pkv + 0x08) = bmv;     *(void **)(pkc + 0x08) = bmc;
        *(int   *)(pkv + 0x10) = W;       *(int   *)(pkc + 0x10) = W;
        *(int   *)(pkv + 0x14) = H;       *(int   *)(pkc + 0x14) = H;

        qg_build_store(storev, keys, vals, 4);
        memcpy(storec, storev, sizeof storec);

        memset(cfg, 0, sizeof cfg);
        *(int32_t *)(cfg + 0x08) = 0;             /* level < 200 */
        *(float   *)(cfg + 0x0c) = 100.0f;        /* diff ratio -> pass */
        *(int32_t *)(cfg + 0x10) = 0;             /* margin y */
        *(int32_t *)(cfg + 0x14) = 0;             /* margin x */
        *(int8_t  *)(cfg + 0x18) = 0;             /* skip NCC */
        *(float   *)(cfg + 0x1c) = 1.0f;          /* ratio */
        *(float   *)(cfg + 0x20) = -1.0e9f;       /* avg_s threshold (low) */
        *(int16_t *)(cfg + 0x24) = mode;          /* mode / limit */
        *(float   *)(cfg + 0x28) = 100.0f;        /* feature-qualify corr thr */
        *(int8_t  *)(cfg + 0x2c) = 0;             /* quality-gate level mode */
        *(float   *)(cfg + 0x30) = 1.0f;          /* scale */

        int rv = v(st_v, imgv, use_handle ? storev : NULL, pkv, cfg);
        int rc = cr_feature_extract_step_26dc0(st_c, (const cr_image *)imgc,
                                               use_handle ? storec : NULL,
                                               (const cr_image *)pkc, cfg);
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }

        if (st_v[0x08] != st_c[0x08])
            mismatch("st08", (u32)t, st_v[0x08], st_c[0x08]);
        if (*(int32_t *)(st_v + 0x40) != *(int32_t *)(st_c + 0x40))
            mismatch("st40", (u32)t, (u32)*(int32_t *)(st_v + 0x40),
                     (u32)*(int32_t *)(st_c + 0x40));
        if (*(int32_t *)(st_v + 0x44) != *(int32_t *)(st_c + 0x44))
            mismatch("st44", (u32)t, (u32)*(int32_t *)(st_v + 0x44),
                     (u32)*(int32_t *)(st_c + 0x44));
        if (cr_f2u(*(float *)(st_v + 0x48)) != cr_f2u(*(float *)(st_c + 0x48)))
            mismatch("st48", (u32)t, cr_f2u(*(float *)(st_v + 0x48)),
                     cr_f2u(*(float *)(st_c + 0x48)));
        if (cr_f2u(*(float *)(st_v + 0x4c)) != cr_f2u(*(float *)(st_c + 0x4c)))
            mismatch("st4c", (u32)t, cr_f2u(*(float *)(st_v + 0x4c)),
                     cr_f2u(*(float *)(st_c + 0x4c)));

        cmp_buf("hist", histv, histc, 0x20, (u32)t);
        cmp_buf("prev", (const unsigned char *)prevv,
                (const unsigned char *)prevc, sizeof prevv, (u32)t);
        cmp_buf("as", (const unsigned char *)asv, (const unsigned char *)asc,
                sizeof asv, (u32)t);
        cmp_buf("ds", (const unsigned char *)dsv, (const unsigned char *)dsc,
                sizeof dsv, (u32)t);
        cmp_buf("dA", (const unsigned char *)dAv, (const unsigned char *)dAc,
                sizeof dAv, (u32)t);
        cmp_buf("dB", (const unsigned char *)dBv, (const unsigned char *)dBc,
                sizeof dBv, (u32)t);
        cmp_buf("cA", (const unsigned char *)cAv, (const unsigned char *)cAc,
                sizeof cAv, (u32)t);
        cmp_buf("cB", (const unsigned char *)cBv, (const unsigned char *)cBc,
                sizeof cBv, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_feature_extract_step_26dc0\n");
}

/* ---- 0x18002db20 — float-source feature-extraction step ---------------- *
 * Same state/quality-gate plumbing as 0x180026dc0, but the source image holds
 * float pixels that are rounded/clamped into the working u8 image, and the
 * packed image is expanded with the masked (0xf) box-max FIR. */
static void test_feature_extract_step_2db20(void)
{
    typedef int (WINAPI *v_t)(void *, const void *, void *, const void *,
                              const void *);
    v_t v = (v_t)fn_at(RVA(0x18002db20));
    begin("cr_feature_extract_step_2db20");
    int bad = g_fail;

    enum { W = 16, H = 16, N = W * H };

    static float    fsrc_v[N], fsrc_c[N];
    static int16_t  prevv[64], prevc[64];
    static int16_t  asv[512], asc[512];
    static int16_t  dsv[512], dsc[512];
    static int16_t  dAv[64], dAc[64], dBv[64], dBc[64];
    static int16_t  cAv[64], cAc[64], cBv[64], cBc[64];
    static uint8_t  histv[0x20], histc[0x20];
    static uint8_t  bmv[2048], bmc[2048];
    static u8 st_v[0x100], st_c[0x100];
    static u8 fimgv[0x20], fimgc[0x20], pkv[0x20], pkc[0x20];
    static u8 storev[0x100], storec[0x100];
    static u8 cfg[0x40];

    static const int32_t keys[4] = { 0xda, 0xdd, 0xd2, 0xd6 };
    static const int32_t vals[4] = { 10, 1024, 1024, 1024 };

    for (int t = 0; t < 6000; t++) {
        int valid = (int)(rnd() % 4u) != 0;
        int16_t mode;
        if (valid)
            mode = (int16_t)(1 + (int)(rnd() % 0x7ffu));
        else
            mode = (int16_t)((int)(rnd() % 3u) == 0 ? 0
                           : (int)(rnd() % 3u) == 0 ? 0x800 : -1);
        int use_handle = (int)(rnd() % 8u) != 0;
        int count = (int)(rnd() & 1u);
        int sflag = (int)(rnd() % 3u) - 1;

        for (int i = 0; i < N; i++) {
            int kind = (int)(rnd() % 4u);
            float f;
            if (kind == 0)      f = (float)(rnd() % 300u);
            else if (kind == 1) f = (float)((int)(rnd() % 600u) - 300);
            else if (kind == 2) f = (float)(int)(rnd() % 256u) + 0.5f;
            else                f = (float)(int)(rnd() % 256u);
            fsrc_v[i] = f; fsrc_c[i] = f;
        }
        for (int i = 0; i < 64; i++) {
            int16_t p = (int16_t)(rnd() % 200u);
            prevv[i] = p; prevc[i] = p;
        }
        for (int i = 0; i < 512; i++) {
            int16_t a = (int16_t)((int)(rnd() % 4001) - 2000);
            asv[i] = a; asc[i] = a;
            int16_t d = (int16_t)((int)(rnd() % 4001) - 2000);
            dsv[i] = d; dsc[i] = d;
        }
        for (int i = 0; i < 64; i++) {
            int16_t a = (int16_t)rnd();
            dAv[i] = a; dAc[i] = a; dBv[i] = a; dBc[i] = a;
            int16_t c = (int16_t)(rnd() % 40u);
            cAv[i] = c; cAc[i] = c; cBv[i] = c; cBc[i] = c;
        }
        for (int i = 0; i < 0x20; i++) {
            uint8_t h = (uint8_t)rnd();
            histv[i] = h; histc[i] = h;
        }
        for (int i = 0; i < 2048; i++) {
            uint8_t b = (uint8_t)rnd();
            bmv[i] = b; bmc[i] = b;
        }

        memset(st_v, 0, sizeof st_v);
        memset(st_c, 0, sizeof st_c);
        *(void **)(st_v + 0x00) = histv;  *(void **)(st_c + 0x00) = histc;
        *(void **)(st_v + 0x10) = prevv;  *(void **)(st_c + 0x10) = prevc;
        *(void **)(st_v + 0x18) = asv;    *(void **)(st_c + 0x18) = asc;
        *(void **)(st_v + 0x20) = dAv;    *(void **)(st_c + 0x20) = dAc;
        *(void **)(st_v + 0x28) = dBv;    *(void **)(st_c + 0x28) = dBc;
        *(void **)(st_v + 0x30) = cAv;    *(void **)(st_c + 0x30) = cAc;
        *(void **)(st_v + 0x38) = cBv;    *(void **)(st_c + 0x38) = cBc;
        *(void **)(st_v + 0x58) = dsv;    *(void **)(st_c + 0x58) = dsc;
        *(int32_t *)(st_v + 0x40) = count; *(int32_t *)(st_c + 0x40) = count;
        *(int32_t *)(st_v + 0x44) = 0;    *(int32_t *)(st_c + 0x44) = 0;
        *(float   *)(st_v + 0x48) = 0.0f; *(float   *)(st_c + 0x48) = 0.0f;
        *(float   *)(st_v + 0x4c) = 0.0f; *(float   *)(st_c + 0x4c) = 0.0f;
        *(int32_t *)(st_v + 0x60) = 16;   *(int32_t *)(st_c + 0x60) = 16;
        *(int32_t *)(st_v + 0x64) = 16;   *(int32_t *)(st_c + 0x64) = 16;
        st_v[0x08] = (uint8_t)sflag;      st_c[0x08] = (uint8_t)sflag;

        mk_img2(fimgv, (int16_t *)fsrc_v, W, H);
        mk_img2(fimgc, (int16_t *)fsrc_c, W, H);

        memset(pkv, 0, 0x20);
        memset(pkc, 0, 0x20);
        *(int   *)(pkv + 0x00) = 64;      *(int   *)(pkc + 0x00) = 64;
        *(void **)(pkv + 0x08) = bmv;     *(void **)(pkc + 0x08) = bmc;
        *(int   *)(pkv + 0x10) = W;       *(int   *)(pkc + 0x10) = W;
        *(int   *)(pkv + 0x14) = H;       *(int   *)(pkc + 0x14) = H;

        qg_build_store(storev, keys, vals, 4);
        memcpy(storec, storev, sizeof storec);

        memset(cfg, 0, sizeof cfg);
        *(int32_t *)(cfg + 0x08) = 0;
        *(float   *)(cfg + 0x0c) = 100.0f;
        *(int32_t *)(cfg + 0x10) = 0;
        *(int32_t *)(cfg + 0x14) = 0;
        *(int8_t  *)(cfg + 0x18) = 0;
        *(float   *)(cfg + 0x1c) = 1.0f;
        *(float   *)(cfg + 0x20) = -1.0e9f;
        *(int16_t *)(cfg + 0x24) = mode;
        *(float   *)(cfg + 0x28) = 100.0f;
        *(int8_t  *)(cfg + 0x2c) = 0;
        *(float   *)(cfg + 0x30) = 1.0f;

        int rv = v(st_v, fimgv, use_handle ? storev : NULL, pkv, cfg);
        int rc = cr_feature_extract_step_2db20(st_c, (const cr_image *)fimgc,
                                               use_handle ? storec : NULL,
                                               (const cr_image *)pkc, cfg);
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }

        if (st_v[0x08] != st_c[0x08])
            mismatch("st08", (u32)t, st_v[0x08], st_c[0x08]);
        if (*(int32_t *)(st_v + 0x40) != *(int32_t *)(st_c + 0x40))
            mismatch("st40", (u32)t, (u32)*(int32_t *)(st_v + 0x40),
                     (u32)*(int32_t *)(st_c + 0x40));
        if (*(int32_t *)(st_v + 0x44) != *(int32_t *)(st_c + 0x44))
            mismatch("st44", (u32)t, (u32)*(int32_t *)(st_v + 0x44),
                     (u32)*(int32_t *)(st_c + 0x44));
        if (cr_f2u(*(float *)(st_v + 0x48)) != cr_f2u(*(float *)(st_c + 0x48)))
            mismatch("st48", (u32)t, cr_f2u(*(float *)(st_v + 0x48)),
                     cr_f2u(*(float *)(st_c + 0x48)));
        if (cr_f2u(*(float *)(st_v + 0x4c)) != cr_f2u(*(float *)(st_c + 0x4c)))
            mismatch("st4c", (u32)t, cr_f2u(*(float *)(st_v + 0x4c)),
                     cr_f2u(*(float *)(st_c + 0x4c)));

        cmp_buf("hist", histv, histc, 0x20, (u32)t);
        cmp_buf("prev", (const unsigned char *)prevv,
                (const unsigned char *)prevc, sizeof prevv, (u32)t);
        cmp_buf("as", (const unsigned char *)asv, (const unsigned char *)asc,
                sizeof asv, (u32)t);
        cmp_buf("ds", (const unsigned char *)dsv, (const unsigned char *)dsc,
                sizeof dsv, (u32)t);
        cmp_buf("dA", (const unsigned char *)dAv, (const unsigned char *)dAc,
                sizeof dAv, (u32)t);
        cmp_buf("dB", (const unsigned char *)dBv, (const unsigned char *)dBc,
                sizeof dBv, (u32)t);
        cmp_buf("cA", (const unsigned char *)cAv, (const unsigned char *)cAc,
                sizeof cAv, (u32)t);
        cmp_buf("cB", (const unsigned char *)cBv, (const unsigned char *)cBc,
                sizeof cBv, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_feature_extract_step_2db20\n");
}

/* ---- 0x18003de60 — directional 5x5 matched-filter bank ---------------- *
 * int fn(int16_t *out, const int16_t *const *rows, const void *cfg):
 *   cfg +0x08 stride, +0x0c ncoef, +0x10 w, +0x14 h, +0x18 normalise,
 *       +0x20 coefA (h*ncoef*25 shorts), +0x28 coefB (h shorts).
 * rows is an array of >=6 int16 row pointers; out receives w*h int16. */
static void test_dirbank_3de60(void)
{
    typedef int (WINAPI *v_t)(void *, const void *, const void *);
    v_t v = (v_t)fn_at(RVA(0x18003de60));
    begin("cr_dirbank_3de60");
    int bad = g_fail;

    enum { ROWN = 256, MAXH = 6, MAXNC = 4, MAXW = 16, MAXOUT = 256 };

    static int16_t rowv[6][ROWN], rowc[6][ROWN];
    static int16_t cAv[MAXH * MAXNC * 25], cAc[MAXH * MAXNC * 25];
    static int16_t cBv[MAXH], cBc[MAXH];
    static int16_t outv[MAXOUT], outc[MAXOUT];
    static u8 cfgv[0x40], cfgc[0x40];

    for (int t = 0; t < 6000; t++) {
        int w  = (int)(rnd() % (MAXW + 1));       /* 0..16 */
        int h  = (int)(rnd() % (MAXH + 1));       /* 0..6  */
        int nc = (int)(rnd() % (MAXNC + 1));      /* 0..4  */
        int stride = 1 + (int)(rnd() % 8);        /* 1..8  */
        int norm = (int)(rnd() & 1u);

        for (int i = 0; i < 6 * ROWN; i++) {
            int16_t s = (int16_t)((int)(rnd() % 20001) - 10000);
            rowv[i / ROWN][i % ROWN] = s; rowc[i / ROWN][i % ROWN] = s;
        }
        int cA_n = h * nc * 25;
        for (int i = 0; i < cA_n; i++) {
            int16_t s = (int16_t)((int)(rnd() % 20001) - 10000);
            cAv[i] = s; cAc[i] = s;
        }
        for (int i = 0; i < h; i++) {
            int16_t s = (int16_t)((int)(rnd() % 2001) - 1000);
            cBv[i] = s; cBc[i] = s;
        }
        for (int i = 0; i < MAXOUT; i++) { outv[i] = 0x7fff; outc[i] = 0x7fff; }

        const int16_t *rowsp_v[6], *rowsp_c[6];
        for (int i = 0; i < 6; i++) { rowsp_v[i] = rowv[i]; rowsp_c[i] = rowc[i]; }

        memset(cfgv, 0, sizeof cfgv);
        *(int32_t *)(cfgv + 0x08) = stride;
        *(int32_t *)(cfgv + 0x0c) = nc;
        *(int32_t *)(cfgv + 0x10) = w;
        *(int32_t *)(cfgv + 0x14) = h;
        *(int32_t *)(cfgv + 0x18) = norm;
        *(void   **)(cfgv + 0x20) = cAv;
        *(void   **)(cfgv + 0x28) = cBv;
        memcpy(cfgc, cfgv, sizeof cfgv);
        *(void **)(cfgc + 0x20) = cAc;
        *(void **)(cfgc + 0x28) = cBc;

        int rv = v(outv, rowsp_v, cfgv);
        int rc = cr_dirbank_3de60(outc, rowsp_c, cfgc);

        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }
        cmp_buf("out", (const unsigned char *)outv,
                (const unsigned char *)outc, sizeof outv, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_dirbank_3de60\n");
}

/* ---- 0x1800364c0 — three-level matched-filter pyramid ------------------ *
 * int fn(int16_t *out, const void *obj, const cr_image *img,
 *        const cr_sampler *s):
 *   obj+0x08 -> three 0x30-byte level descriptors (plane counts 5/3/5, W/H,
 *   flags, kernel/bias pointers).  `out` is partitioned into per-level row
 *   pointer arrays; rows are bilinearly resampled from `img` along `s`, run
 *   through cr_matched_filter_45eb0 / cr_block_conv_231a0 / cr_dirbank_3de60,
 *   and interleaved back into the front of `out`.  All buffers caller-owned. */
static void test_pyramid_364c0(void)
{
    typedef int (WINAPI *v_t)(void *, const void *, const void *, const void *);
    v_t v = (v_t)fn_at(RVA(0x1800364c0));
    begin("cr_pyramid_364c0");
    int bad = g_fail;

    enum { OUTN = 8192, KN = 4096 };
    static int16_t outv[OUTN], outc[OUTN];
    static uint8_t pool[8192];
    static uint8_t desc[0x98];
    static uint8_t objv[0x10], objc[0x10];
    static uint8_t iv[0x20], ic[0x20];
    static int32_t samp[6];
    static int16_t k0[KN], m0[KN], k1[KN], m1[KN], cA2[KN], cB2[KN];

    for (int i = 0; i < KN; i++) {
        k0[i]  = (int16_t)((int)(rnd() % 2001) - 1000);
        m0[i]  = (int16_t)((int)(rnd() % 2001) - 1000);
        k1[i]  = (int16_t)((int)(rnd() % 2001) - 1000);
        m1[i]  = (int16_t)((int)(rnd() % 2001) - 1000);
        cA2[i] = (int16_t)((int)(rnd() % 2001) - 1000);
        cB2[i] = (int16_t)((int)(rnd() % 2001) - 1000);
    }

    for (int t = 0; t < 3000; t++) {
        int f08 = 32, f0c = 1;                 /* level0 -> stride0 = 16 shorts */
        int W0  = (int)(rnd() % 2u) ? 4 : 8;   /* W0*H0 == 16 */
        int H0  = (W0 == 8) ? 2 : 4;
        int stride1 = 16, K1 = 1 + (int)(rnd() % 2u);
        int W1  = 4, H1 = (int)(rnd() % 2u) ? 4 : 2;
        int stride2 = 16, NC2 = 1 + (int)(rnd() % 2u);
        int W2  = 4, H2 = (int)(rnd() % 2u) ? 4 : 2;
        int nblocks = 1 + (int)(rnd() % 3u);
        int flag0 = (int)(rnd() & 1u);
        int flag1 = (int)(rnd() & 1u);
        int flag2 = (int)(rnd() & 1u);

        for (int i = 0; i < 8192; i++) pool[i] = (uint8_t)rnd();
        for (int i = 0; i < OUTN; i++) { outv[i] = 0x7fff; outc[i] = 0x7fff; }

        /* sampler: keep sample positions inside the byte image (idx <= ~28) */
        samp[0] = (int32_t)(rnd() % 0x1001u);   /* xstep */
        samp[1] = (int32_t)(rnd() % 0x8001u);   /* xcoef */
        samp[2] = (int32_t)(rnd() % 0x8001u);   /* xbase */
        samp[3] = (int32_t)(rnd() % 0x1001u);   /* ystep */
        samp[4] = (int32_t)(rnd() % 0x8001u);   /* ycoef */
        samp[5] = (int32_t)(rnd() % 0x8001u);   /* ybase */

        mk_image(iv, pool + 4096, 64, 64, 64, 0, 0);
        mk_image(ic, pool + 4096, 64, 64, 64, 0, 0);

        memset(desc, 0, sizeof desc);
        int32_t *D = (int32_t *)desc;
        D[0x00] = 5;                            /* L0[0] plane count */
        D[0x02] = f08; D[0x03] = f0c;
        D[0x04] = W0;  D[0x05] = H0; D[0x06] = flag0;
        *(void **)(desc + 0x20) = k0;
        *(void **)(desc + 0x28) = m0;

        D[0x0c] = 3;                            /* L1[0] */
        D[0x0e] = stride1; D[0x0f] = K1;
        D[0x10] = W1; D[0x11] = H1; D[0x12] = flag1;
        *(void **)(desc + 0x50) = k1;
        *(void **)(desc + 0x58) = m1;

        D[0x18] = 5;                            /* L2[0] */
        D[0x19] = 2 * nblocks + 4;
        D[0x1a] = stride2; D[0x1b] = NC2;
        D[0x1c] = W2; D[0x1d] = H2; D[0x1e] = flag2;
        *(void **)(desc + 0x80) = cA2;
        *(void **)(desc + 0x88) = cB2;

        memset(objv, 0, sizeof objv);
        memset(objc, 0, sizeof objc);
        *(void **)(objv + 8) = desc;
        *(void **)(objc + 8) = desc;

        int rv = v(outv, objv, iv, samp);
        int rc = cr_pyramid_364c0(outc, objc, (const cr_image *)ic,
                                  (const cr_sampler *)samp);

        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }
        cmp_buf("out", (const unsigned char *)outv,
                (const unsigned char *)outc, sizeof outv, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_pyramid_364c0\n");
}

/* ---- 0x180025960 — fixed-pattern (ridge template) removal ---------------- */
static void test_template_remove_25960(void)
{
    typedef int (WINAPI *v_t)(void *, const void *, int);
    v_t v = (v_t)fn_at(RVA(0x180025960));
    begin("cr_template_remove_25960");
    int bad = g_fail;

    enum { MAXN = 176 * 64 };
    static float srcv[MAXN], srcc[MAXN];
    static uint8_t mskv[MAXN], mskc[MAXN];
    static uint8_t iv[0x20], ic[0x20], mv[0x20], mc[0x20];

    /* NULL image */
    {
        mk_image(mv, mskv, 64, 64, 80, 0, 0);
        mk_image(mc, mskc, 64, 64, 80, 0, 0);
        int rv = v(NULL, mv, 1);
        int rc = cr_template_remove_25960(NULL, (const cr_image *)mc, 1);
        if (rv != rc) mismatch("null", 0, (u32)rv, (u32)rc);
    }

    for (int t = 0; t < 400; t++) {
        int sel = (int)(rnd() % 6u) - 1;              /* -1 .. 4 */
        int h = 80, w = 64;
        int pick = (int)(rnd() % 10u);
        if (pick < 5) {                               /* matching sel */
            if (sel == 2) h = 176;
            else if (sel == 1) h = 80;
            else h = (int)(rnd() % 2u) ? 80 : 176;    /* sel invalid -> early */
        } else if (pick < 7) {                        /* dim/sel mismatch */
            h = (sel == 1) ? 176 : 80;
        } else if (pick < 9) {                        /* wrong width */
            w = (int)(rnd() % 2u) ? 62 : 66;
        } else {                                      /* odd h and odd w */
            h = (int)(rnd() % 2u) ? 79 : 81;
            w = (int)(rnd() % 2u) ? 63 : 65;
        }

        int n = h * 64;
        if (n > MAXN) n = MAXN;
        for (int i = 0; i < n; i++) {
            float f;
            switch (rnd() % 5u) {
            case 0:  f = 255.0f; break;
            case 1:  f = (float)(int)(rnd() % 256u); break;
            case 2:  f = (float)(int)(rnd() % 2001u) / 8.0f; break;
            case 3:  f = 300.0f; break;
            default: f = (float)(int)(rnd() % 256u); break;
            }
            srcv[i] = f;
            srcc[i] = f;
        }
        for (int i = 0; i < n; i++) {
            uint8_t b = (rnd() % 3u) ? 0xff : (uint8_t)rnd();
            mskv[i] = b;
            mskc[i] = b;
        }

        mk_image(iv, srcv, 64, w, h, 0, 0);
        mk_image(ic, srcc, 64, w, h, 0, 0);
        mk_image(mv, mskv, 64, w, h, 0, 0);
        mk_image(mc, mskc, 64, w, h, 0, 0);

        int rv = v(iv, mv, sel);
        int rc = cr_template_remove_25960((cr_image *)ic,
                                          (const cr_image *)mc, sel);
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }
        cmp_buf("src", (const unsigned char *)srcv,
                (const unsigned char *)srcc, (size_t)n * 4, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_template_remove_25960\n");
}

/* ---- 0x180037460 — grid-bucketed point picker --------------------------- */
static void test_grid_pick_37460(void)
{
    typedef int (WINAPI *v_t)(void *, int *, int, int, const void *, unsigned, const void *);
    v_t v = (v_t)fn_at(RVA(0x180037460));
    begin("cr_grid_pick_37460");
    int bad = g_fail;

    enum { NPTS = 64, MAXW = 4096 };
    static uint8_t pv[NPTS * 8], pc[NPTS * 8];
    static uint32_t bmp[MAXW];
    static uint8_t iv[0x20], ic[0x20];
    static uint8_t cfg[0x40];

    for (int t = 0; t < 3000; t++) {
        int imgw = 8 + (int)(rnd() % 40u);
        int imgh = 8 + (int)(rnd() % 40u);
        int gw = 1 + (int)(rnd() % 4u);
        int gh = 1 + (int)(rnd() % 4u);
        int border = (int)(rnd() % 4u);
        int npts = 1 + (int)(rnd() % (NPTS - 1));
        int nslot = npts + (int)(rnd() % 3u);
        /* Phase 3 spins forever unless the per-cell quotas can satisfy `want`,
         * so the random sweep only exercises phases 1-2 (want = 0). */
        int want = 0;
        int stride = imgw + 32 + (int)(rnd() % 2u) * 32;
        int offx = (int)(rnd() % 8u);
        int offy = (int)(rnd() % 4u);
        unsigned seed = (unsigned)rnd();

        int words = (stride * (imgh + offy) + 32 + 64) / 32;
        if (words > MAXW) words = MAXW;
        for (int i = 0; i < words; i++) bmp[i] = (uint32_t)rnd();

        for (int i = 0; i < NPTS; i++) {
            int32_t val = (int32_t)rnd();
            int16_t ax = (int16_t)((int)(rnd() % (unsigned)(imgw + 16)) - 8);
            int16_t ay = (int16_t)((int)(rnd() % (unsigned)(imgh + 16)) - 8);
            memcpy(pv + i * 8, &val, 4);
            memcpy(pv + i * 8 + 4, &ax, 2);
            memcpy(pv + i * 8 + 6, &ay, 2);
        }
        memcpy(pc, pv, sizeof pv);

        memset(cfg, 0, sizeof cfg);
        cfg[0x08] = (uint8_t)border;
        *(int16_t *)(cfg + 0x10) = (int16_t)nslot;
        cfg[0x25] = (uint8_t)gw;
        cfg[0x26] = (uint8_t)gh;

        mk_image(iv, bmp, stride, imgw, imgh, offx, offy);
        mk_image(ic, bmp, stride, imgw, imgh, offx, offy);

        int nv = -12345, nc = -12345;
        int rv = v(pv, &nv, npts, want, iv, seed, cfg);
        int rc = cr_grid_pick_37460(pc, &nc, npts, want,
                                    (const cr_image *)ic, seed, cfg);
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }
        if (nv != nc) { mismatch("n", (u32)t, (u32)nv, (u32)nc); continue; }
        cmp_buf("pts", pv, pc, (size_t)npts * 8, (u32)t);
    }

    /* Phase-3 emission.  Every cell is populated so the quotas are reachable;
     * an all-ones bitmap gives each cell a quota of want/N, and an all-zero
     * bitmap makes every cell "empty" (the N == empty path). */
    for (int t = 0; t < 400; t++) {
        int imgw = 12 + (int)(rnd() % 28u);
        int imgh = 12 + (int)(rnd() % 28u);
        int gw = 1 + (int)(rnd() % 3u);
        int gh = 1 + (int)(rnd() % 3u);
        int N = gw * gh;
        int npts = N * 4;
        int zero = (t & 1);
        int want = zero ? 1 + (int)(rnd() % (unsigned)npts) : N;
        int stride = imgw + 32;
        unsigned seed = (unsigned)rnd();

        memset(bmp, zero ? 0x00 : 0xff, sizeof bmp);
        memset(pv, 0, sizeof pv);
        for (int i = 0; i < npts; i++) {
            int cell = i % N, gx = cell % gw, gy = cell / gw;
            int32_t val = (int32_t)rnd();
            int16_t ax = (int16_t)((2 * gx + 1) * imgw / (2 * gw));
            int16_t ay = (int16_t)((2 * gy + 1) * imgh / (2 * gh));
            memcpy(pv + i * 8, &val, 4);
            memcpy(pv + i * 8 + 4, &ax, 2);
            memcpy(pv + i * 8 + 6, &ay, 2);
        }
        memcpy(pc, pv, sizeof pv);

        memset(cfg, 0, sizeof cfg);
        cfg[0x08] = 0;
        *(int16_t *)(cfg + 0x10) = (int16_t)(npts + 1);
        cfg[0x25] = (uint8_t)gw;
        cfg[0x26] = (uint8_t)gh;

        mk_image(iv, bmp, stride, imgw, imgh, 0, 0);
        mk_image(ic, bmp, stride, imgw, imgh, 0, 0);

        int nv = -12345, nc = -12345;
        int rv = v(pv, &nv, npts, want, iv, seed, cfg);
        int rc = cr_grid_pick_37460(pc, &nc, npts, want,
                                    (const cr_image *)ic, seed, cfg);
        if (rv != rc) { mismatch("ret3", (u32)t, (u32)rv, (u32)rc); continue; }
        if (nv != nc) { mismatch("n3", (u32)t, (u32)nv, (u32)nc); continue; }
        cmp_buf("pts3", pv, pc, (size_t)npts * 8, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_grid_pick_37460\n");
}

/* 0x180025050 — mask-driven inpaint / classify pipeline. */
static void test_mask_pipeline_25050(void)
{
    typedef int (WINAPI *v_t)(void *, const void *, const void *, void *);
    v_t v = (v_t)fn_at(RVA(0x180025050));
    begin("cr_mask_pipeline_25050");
    int bad = g_fail;

    enum { MW = 24, MH = 24 };
    static float fv[MW * MH], fc[MW * MH];
    static uint8_t mv[MW * MH], mc[MW * MH];
    static uint8_t iv[0x20], ic[0x20], kv[0x20], kc[0x20];
    static uint8_t cfg[0x20];
    static uint16_t idx[64];
    static uint8_t lst[16];

    /* mode 7: row/column gap interpolation over the float image. */
    for (int t = 0; t < 3000; t++) {
        int W = 1 + (int)(rnd() % MW);
        int H = 1 + (int)(rnd() % MH);
        int thr = (int)(rnd() % 9u) - 2;
        int mr  = (int)(rnd() % 7u) - 1;
        int mcx = (int)(rnd() % 7u) - 1;
        for (int i = 0; i < W * H; i++) {
            unsigned k = (unsigned)(rnd() % 6u);
            float f;
            if (k == 0)      f = 0.0f;
            else if (k == 1) f = (float)(rnd() % 1000u) / 100.0f;
            else if (k == 2) f = -(float)(rnd() % 1000u) / 100.0f;
            else { uint32_t u = (uint32_t)rnd(); memcpy(&f, &u, 4); }
            fv[i] = fc[i] = f;
        }
        memset(cfg, 0, sizeof cfg);
        cfg[0] = 7;
        memcpy(cfg + 4, &thr, 4);
        cfg[0xc] = (uint8_t)(int8_t)mr;
        cfg[0xd] = (uint8_t)(int8_t)mcx;

        mk_image(iv, fv, W, W, H, 0, 0);
        mk_image(ic, fc, W, W, H, 0, 0);
        mk_image(kv, mv, W, W, H, 0, 0);
        mk_image(kc, mc, W, W, H, 0, 0);

        int rv = v(iv, lst, cfg, kv);
        int rc = cr_mask_pipeline_25050((cr_image *)ic, lst, cfg,
                                        (cr_image *)kc);
        if (rv != rc) { mismatch("m7-ret", (u32)t, (u32)rv, (u32)rc); continue; }
        cmp_buf("m7", (const unsigned char *)fv, (const unsigned char *)fc,
                (size_t)W * H * 4, (u32)t);
    }

    /* modes 0..6: point-list inpaint / classify. */
    for (int t = 0; t < 4000; t++) {
        int W = 1 + (int)(rnd() % MW);
        int H = 1 + (int)(rnd() % MH);
        int npix = W * H;
        int n = (int)(rnd() % 33u);
        int mode = (int)(rnd() % 7u);
        int lim = (int)(rnd() % 13u);
        int flag = (int)(rnd() % 2u);
        for (int i = 0; i < n; i++)
            idx[i] = (uint16_t)(rnd() % (unsigned)npix);
        for (int i = 0; i < npix; i++) {
            unsigned k = (unsigned)(rnd() % 8u);
            uint8_t b;
            if (k == 0)      b = 0x04;
            else if (k == 1) b = 0x20;
            else if (k == 2) b = 0xff;
            else if (k == 3) b = 0x00;
            else             b = (uint8_t)rnd();
            mv[i] = mc[i] = b;
            float f = (float)((int)(rnd() % 2000u) - 1000) / 8.0f;
            fv[i] = fc[i] = f;
        }
        memset(cfg, 0, sizeof cfg);
        cfg[0] = (uint8_t)mode;
        cfg[1] = (uint8_t)flag;
        *(uint16_t *)(cfg + 2) = (uint16_t)lim;
        memset(lst, 0, sizeof lst);
        uint16_t nn = (uint16_t)n;
        memcpy(lst, &nn, 2);
        const uint16_t *ip = idx;
        memcpy(lst + 8, &ip, 8);

        mk_image(iv, fv, W, W, H, 0, 0);
        mk_image(ic, fc, W, W, H, 0, 0);
        mk_image(kv, mv, W, W, H, 0, 0);
        mk_image(kc, mc, W, W, H, 0, 0);

        int rv = v(iv, lst, cfg, kv);
        int rc = cr_mask_pipeline_25050((cr_image *)ic, lst, cfg,
                                        (cr_image *)kc);
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }
        cmp_buf("img", (const unsigned char *)fv, (const unsigned char *)fc,
                (size_t)npix * 4, (u32)t);
        cmp_buf("mask", mv, mc, (size_t)npix, (u32)t);
    }

    /* NULL list: modes 0..6 must return 0 without touching anything; mode 7
     * ignores the list entirely. */
    for (int t = 0; t < 8; t++) {
        int W = 4, H = 4;
        for (int i = 0; i < W * H; i++) { fv[i] = fc[i] = (float)i; mv[i] = mc[i] = 0x04; }
        memset(cfg, 0, sizeof cfg);
        cfg[0] = (uint8_t)t;
        mk_image(iv, fv, W, W, H, 0, 0);
        mk_image(ic, fc, W, W, H, 0, 0);
        mk_image(kv, mv, W, W, H, 0, 0);
        mk_image(kc, mc, W, W, H, 0, 0);
        int rv = v(iv, NULL, cfg, kv);
        int rc = cr_mask_pipeline_25050((cr_image *)ic, NULL, cfg,
                                        (cr_image *)kc);
        if (rv != rc) { mismatch("null-ret", (u32)t, (u32)rv, (u32)rc); continue; }
        cmp_buf("null", (const unsigned char *)fv, (const unsigned char *)fc,
                (size_t)W * H * 4, (u32)t);
        cmp_buf("nullm", mv, mc, (size_t)W * H, (u32)t);
    }

    if (g_fail == bad) end(); else printf("  FAIL cr_mask_pipeline_25050\n");
}

/* 0x18002bd60 — i16 image row/column normalisation. */
static void test_norm_2bd60(void)
{
    typedef int (WINAPI *v_t)(void *, const void *, const void *);
    v_t v = (v_t)fn_at(RVA(0x18002bd60));
    begin("cr_norm_2bd60");
    int bad = g_fail;

    enum { NW = 40, NH = 48 };
    static int16_t dv[NW * NH], dc[NW * NH];
    static uint8_t mv[(NW + 8) * NH], mc[(NW + 8) * NH];
    static uint8_t iv[0x20], ic[0x20], kv[0x20], kc[0x20];
    static uint8_t cfg[0x20];
    static const int lens[3] = { 35, 36, 32 };

    for (int t = 0; t < 8000; t++) {
        int W = 1 + (int)(rnd() % NW);
        int H = 1 + (int)(rnd() % NH);
        int mode = (int)(rnd() % 6u);
        int pass = (int)(rnd() % 3u);
        int tabsel = (int)(rnd() % 8u);
        int x0, xw, row0, nrows;

        if ((t % 4) == 0) H = 31 + (int)(rnd() % (unsigned)(NH - 30));
        if (mode == 3 && (t & 1)) {
            int k = (int)(rnd() % 3u);
            W = lens[k];
            tabsel = (k == 0) ? 0 : (k == 1) ? 1 : 2 + (int)(rnd() % 4u);
        }
        x0 = (int)(rnd() % (unsigned)(W + 1));
        xw = (int)(rnd() % (unsigned)(W + 1));
        nrows = (int)(rnd() % (unsigned)H) + 1;
        row0 = (int)(rnd() % (unsigned)(H - nrows + 1));
        if ((t % 37) == 0) { nrows = -1; row0 = 0; }

        for (int i = 0; i < W * H; i++) {
            unsigned k = (unsigned)(rnd() % 8u);
            int16_t x;
            if (k == 0)      x = 0;
            else if (k == 1) x = 16320;
            else if (k == 2) x = 16319;
            else if (k == 3) x = -32768;
            else if (k == 4) x = 32767;
            else             x = (int16_t)rnd();
            dv[i] = dc[i] = x;
        }
        for (int i = 0; i < (W + 8) * H; i++) {
            uint8_t b = (uint8_t)((rnd() % 3u == 0) ? (rnd() & 0xffu)
                                                    : ((rnd() & 1u) ? 0x0e : 0x00));
            mv[i] = mc[i] = b;
        }

        memset(cfg, 0, sizeof cfg);
        cfg[9] = (uint8_t)mode;
        cfg[10] = (uint8_t)pass;
        cfg[0xb] = (uint8_t)tabsel;
        *(int32_t *)(cfg + 0xc) = x0;
        *(int32_t *)(cfg + 0x10) = xw;
        *(int32_t *)(cfg + 0x14) = row0;
        *(int32_t *)(cfg + 0x18) = nrows;

        mk_image(iv, dv, W, W, H, 0, 0);
        mk_image(ic, dc, W, W, H, 0, 0);
        mk_image(kv, mv, W + 8, W, H, 0, 0);
        mk_image(kc, mc, W + 8, W, H, 0, 0);

        int rv = v(iv, kv, cfg);
        int rc = cr_norm_2bd60((cr_image *)ic, (const cr_image *)kc, cfg);
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }
        cmp_buf("img", (const unsigned char *)dv, (const unsigned char *)dc,
                (size_t)W * H * 2, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_norm_2bd60\n");
}

/* 0x180016b90 — point-selection dispatcher on cfg[0x24]. */
static void test_pick_dispatch_16b90(void)
{
    typedef int (WINAPI *v_t)(void *, int *, int, int, const void *, unsigned,
                              const void *);
    v_t v = (v_t)fn_at(RVA(0x180016b90));
    begin("cr_pick_dispatch_16b90");
    int bad = g_fail;

    enum { MAXPTS = 40, MAXW = 512 };
    static uint8_t ptsv[MAXPTS * 8], ptsc[MAXPTS * 8];
    static uint8_t mcfg[0x20];
    static uint8_t cfg[0x40];
    static uint32_t mwords[MAXW];
    static int dims[6];
    static uint8_t iv[0x20], ic[0x20];

    for (int t = 0; t < 3200; t++) {
        int branch = (int)(rnd() % 4u);
        int margin = (int)(rnd() % 3u);
        int W = 2 * margin + 1 + (int)(rnd() % 48u);
        int H = 2 * margin + 1 + (int)(rnd() % 48u);
        int NX = 1 + (int)(rnd() % 5u);
        int NY = 1 + (int)(rnd() % 5u);
        int npts = (int)(rnd() % (MAXPTS + 1));
        int maxout = (int)(rnd() % (MAXPTS + 3));
        int maxpts = npts + (int)(rnd() % 5u);
        int stride = 32 * (1 + (int)(rnd() % 4u));
        int x0 = (int)(rnd() % 4u);
        int y0 = (int)(rnd() % 4u);
        int weight = (int)(rnd() % 2000u);
        uint32_t seed = rnd();

        for (int i = 0; i < MAXW; i++) mwords[i] = rnd();
        for (int i = 0; i < MAXPTS; i++) {
            *(int32_t *)(ptsv + i * 8) = (int32_t)rnd();
            *(int16_t *)(ptsv + i * 8 + 4) = (int16_t)((int)(rnd() % 400u) - 100);
            *(int16_t *)(ptsv + i * 8 + 6) = (int16_t)((int)(rnd() % 400u) - 100);
        }
        memcpy(ptsc, ptsv, sizeof ptsv);

        memset(mcfg, 0, sizeof mcfg);
        *(int *)(mcfg + 0x00) = stride;
        *(void **)(mcfg + 0x08) = mwords;
        *(int *)(mcfg + 0x10) = W;
        *(int *)(mcfg + 0x14) = H;
        *(int *)(mcfg + 0x18) = x0;
        *(int *)(mcfg + 0x1c) = y0;

        memset(dims, 0, sizeof dims);
        dims[4] = W;
        dims[5] = H;

        memset(cfg, 0, sizeof cfg);
        cfg[0x24] = (uint8_t)branch;
        *(int8_t *)(cfg + 0x08) = (int8_t)margin;
        *(int16_t *)(cfg + 0x10) = (int16_t)maxpts;
        *(int *)(cfg + 0x14) = weight;
        cfg[0x25] = (uint8_t)NX;
        cfg[0x26] = (uint8_t)NY;

        /* Both pickers spin forever unless `want` is reachable, so keep the
         * grid picker at 0 (phases 1-2 only) and cap the keypoint picker at
         * npts.  bin_select tolerates maxout > npts. */
        int want = maxout;
        if (branch == 1) want = 0;
        if (branch == 0) want = npts ? 1 + (int)(rnd() % (unsigned)npts) : 0;
        mk_image(iv, mwords, stride, W, H, x0, y0);
        mk_image(ic, mwords, stride, W, H, x0, y0);
        const void *srcv = (branch == 0) ? (const void *)dims : (const void *)iv;
        const void *srcc = (branch == 0) ? (const void *)dims : (const void *)ic;

        int ov = 0x12345678, oc = 0x12345678;
        int rv = v(ptsv, &ov, npts, want, srcv, seed, cfg);
        int rc = cr_pick_dispatch_16b90(ptsc, &oc, npts, want, srcc, seed, cfg);
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }
        if (ov != oc) mismatch("cnt", (u32)t, (u32)ov, (u32)oc);
        cmp_buf("pts", ptsv, ptsc, sizeof ptsv, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_pick_dispatch_16b90\n");
}

/* 0x1800317a0 — mask-aware gap inpainting (modes 5 and 7). */
static void test_mask_inpaint_317a0(void)
{
    typedef int (WINAPI *v_t)(void *, void *, const void *, const void *);
    v_t v = (v_t)fn_at(RVA(0x1800317a0));
    begin("cr_mask_inpaint_317a0");
    int bad = g_fail;

    enum { IW = 40, IH = 40, MAXIDX = 96 };
    static uint8_t bv[IW * IH], bc[IW * IH];
    static uint8_t iv[0x20], ic[0x20];
    static uint8_t cfg[0x20];
    static uint16_t idx[MAXIDX];
    static uint8_t lst[16];

    /* mode 7: row/column gap interpolation on a u8 image. */
    for (int t = 0; t < 4000; t++) {
        int W = 1 + (int)(rnd() % IW);
        int H = 1 + (int)(rnd() % IH);
        static const int thrs[] = { -4, -1, 0, 1, 2, 3, 5, 8, 13, 32, 64,
                                    128, 255, 1024, 65025 };
        int thr = thrs[rnd() % (sizeof thrs / sizeof thrs[0])];
        int ca = (int)(rnd() % 11u) - 2;   /* -2..8 */
        int cb = (int)(rnd() % 11u) - 2;

        for (int i = 0; i < W * H; i++) {
            unsigned k = (unsigned)(rnd() % 8u);
            uint8_t b;
            if (k == 0)      b = 0;
            else if (k == 1) b = 0xff;
            else if (k == 2) b = (uint8_t)(rnd() % 4u);
            else if (k == 3) b = (uint8_t)(200 + rnd() % 56u);
            else if (k == 4) b = (uint8_t)((i & 1) ? 0 : 0xff);
            else             b = (uint8_t)rnd();
            bv[i] = bc[i] = b;
        }

        memset(cfg, 0, sizeof cfg);
        cfg[0] = 7;
        memcpy(cfg + 4, &thr, 4);
        cfg[0xc] = (uint8_t)(int8_t)ca;
        cfg[0xd] = (uint8_t)(int8_t)cb;

        mk_image(iv, bv, W, W, H, 0, 0);
        mk_image(ic, bc, W, W, H, 0, 0);

        uint8_t fv = 0x5a, fc = 0x5a;
        int rv = v(&fv, iv, NULL, cfg);
        int rc = cr_mask_inpaint_317a0(&fc, (cr_image *)ic, NULL, cfg);
        if (rv != rc) { mismatch("m7-ret", (u32)t, (u32)rv, (u32)rc); continue; }
        if (fv != fc) mismatch("m7-flag", (u32)t, fv, fc);
        cmp_buf("m7", bv, bc, (size_t)W * H, (u32)t);
    }

    /* mode 5: point-list mean inpaint with the flag array. */
    for (int t = 0; t < 3000; t++) {
        int W = 1 + (int)(rnd() % IW);
        int H = 1 + (int)(rnd() % IH);
        int npix = W * H;
        int n = (int)(rnd() % (MAXIDX + 1));
        int lim = (int)(rnd() % 110u);
        int gate = (int)(rnd() % 2u);

        for (int i = 0; i < n; i++)
            idx[i] = (uint16_t)(rnd() % (unsigned)npix);
        for (int i = 0; i < npix; i++) {
            unsigned k = (unsigned)(rnd() % 6u);
            uint8_t b;
            if (k == 0)      b = 0;
            else if (k == 1) b = 0xff;
            else if (k == 2) b = 0x04;
            else if (k == 3) b = (uint8_t)(rnd() % 8u);
            else             b = (uint8_t)rnd();
            bv[i] = bc[i] = b;
        }

        memset(cfg, 0, sizeof cfg);
        cfg[0] = 5;
        cfg[1] = (uint8_t)gate;
        *(uint16_t *)(cfg + 2) = (uint16_t)lim;
        memset(lst, 0, sizeof lst);
        uint16_t nn = (uint16_t)n;
        memcpy(lst, &nn, 2);
        const uint16_t *ip = idx;
        memcpy(lst + 8, &ip, 8);

        mk_image(iv, bv, W, W, H, 0, 0);
        mk_image(ic, bc, W, W, H, 0, 0);
        *(int *)(iv + 4) = H;          /* mode 5 reads +0x00/+0x04 */
        *(int *)(ic + 4) = H;

        uint8_t fv = 0x5a, fc = 0x5a;
        int rv = v(&fv, iv, lst, cfg);
        int rc = cr_mask_inpaint_317a0(&fc, (cr_image *)ic,
                                       (const cr_index_list *)lst, cfg);
        if (rv != rc) { mismatch("m5-ret", (u32)t, (u32)rv, (u32)rc); continue; }
        if (fv != fc) mismatch("m5-flag", (u32)t, fv, fc);
        cmp_buf("m5", bv, bc, (size_t)npix, (u32)t);
    }

    /* NULL list and unknown modes. */
    for (int t = 0; t < 8; t++) {
        int W = 6, H = 5;
        static const uint8_t modes[] = { 5, 6, 7, 0, 1, 4, 8, 0xff };
        for (int i = 0; i < W * H; i++) bv[i] = bc[i] = (uint8_t)(i * 7);
        memset(cfg, 0, sizeof cfg);
        cfg[0] = modes[t];
        mk_image(iv, bv, W, W, H, 0, 0);
        mk_image(ic, bc, W, W, H, 0, 0);
        *(int *)(iv + 4) = H;
        *(int *)(ic + 4) = H;
        uint8_t fv = 0x5a, fc = 0x5a;
        int rv = v(&fv, iv, NULL, cfg);
        int rc = cr_mask_inpaint_317a0(&fc, (cr_image *)ic, NULL, cfg);
        if (rv != rc) { mismatch("nul-ret", (u32)t, (u32)rv, (u32)rc); continue; }
        if (fv != fc) mismatch("nul-flag", (u32)t, fv, fc);
        cmp_buf("nul", bv, bc, (size_t)W * H, (u32)t);
    }

    if (g_fail == bad) end(); else printf("  FAIL cr_mask_inpaint_317a0\n");
}

/* 0x18002f2e0 — sort + dispatch + copy-back wrapper for point selection. */
static void test_pick_points_2f2e0(void)
{
    typedef int (WINAPI *v_t)(void *, void *, int *, const void *, const void *,
                              int, int, const void *, unsigned, const void *);
    v_t v = (v_t)fn_at(RVA(0x18002f2e0));
    begin("cr_pick_points_2f2e0");
    int bad = g_fail;

    enum { MAXP = 48, MAXW = 512 };
    static uint8_t xyv[2 * MAXP], xyc[2 * MAXP];
    static float vlv[MAXP], vlc[MAXP];
    static uint8_t oxv[2 * MAXP], oxc[2 * MAXP];
    static float ovv[MAXP], ovc[MAXP];
    static int dims[6];
    static uint32_t mwords[MAXW];
    static uint8_t cfg[0x40], iv[0x20], ic[0x20];

    for (int t = 0; t < 3000; t++) {
        int npts = 1 + (int)(rnd() % MAXP);
        int margin = (int)(rnd() % 3u);
        int W = 2 * margin + 1 + (int)(rnd() % 48u);
        int H = 2 * margin + 1 + (int)(rnd() % 48u);
        int NX = 1 + (int)(rnd() % 5u);
        int NY = 1 + (int)(rnd() % 5u);
        int weight = (int)(rnd() % 2000u);
        int maxpts = npts + (int)(rnd() % 8u);
        int want = (int)(rnd() % (unsigned)(npts + 3));
        uint32_t seed = rnd();

        for (int i = 0; i < 2 * npts; i++) {
            uint8_t b;
            unsigned k = (unsigned)(rnd() % 4u);
            if (k == 0)      b = (uint8_t)i;
            else if (k == 1) b = 0;
            else             b = (uint8_t)rnd();
            xyv[i] = xyc[i] = b;
        }
        for (int i = 0; i < npts; i++) {
            unsigned k = (unsigned)(rnd() % 8u);
            float f;
            if (k == 0)      f = 0.0f;
            else if (k == 1) f = -0.0f;
            else if (k == 2) f = (float)(int)(rnd() % 5u);      /* ties */
            else if (k == 3) { uint32_t u = 0x7fc00000u; memcpy(&f, &u, 4); } /* NaN */
            else if (k == 4) { uint32_t u = 0x7f800000u; memcpy(&f, &u, 4); } /* +inf */
            else if (k == 5) { uint32_t u = 0xff800000u; memcpy(&f, &u, 4); } /* -inf */
            else { uint32_t u = (uint32_t)rnd(); memcpy(&f, &u, 4); }
            vlv[i] = vlc[i] = f;
        }
        for (int i = 0; i < 2 * MAXP; i++) oxv[i] = oxc[i] = 0xa5;
        for (int i = 0; i < MAXP; i++) {
            uint32_t u = 0xdeadbeefu; memcpy(&ovv[i], &u, 4); memcpy(&ovc[i], &u, 4);
        }
        for (int i = 0; i < MAXW; i++) mwords[i] = rnd();

        memset(dims, 0, sizeof dims);
        dims[4] = W;
        dims[5] = H;

        memset(cfg, 0, sizeof cfg);
        cfg[0x24] = 0;                      /* cr_keypoint_grid_sample */
        *(int8_t *)(cfg + 0x08) = (int8_t)margin;
        *(int16_t *)(cfg + 0x10) = (int16_t)maxpts;
        *(int *)(cfg + 0x14) = weight;
        cfg[0x25] = (uint8_t)NX;
        cfg[0x26] = (uint8_t)NY;
        mk_image(iv, mwords, 32, W, H, 0, 0);
        mk_image(ic, mwords, 32, W, H, 0, 0);

        int nv = 0x12345678, nc = 0x12345678;
        int rv = v(oxv, ovv, &nv, xyv, vlv, npts, want, dims, seed, cfg);
        int rc = cr_pick_points_2f2e0(oxc, ovc, &nc, xyc, vlc, npts, want,
                                      dims, seed, cfg);
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }
        if (nv != nc) mismatch("cnt", (u32)t, (u32)nv, (u32)nc);
        cmp_buf("xy", oxv, oxc, sizeof oxv, (u32)t);
        cmp_buf("val", (const unsigned char *)ovv,
                (const unsigned char *)ovc, sizeof ovv, (u32)t);
    }

    /* npts == 0: returns 0 and leaves the outputs alone. */
    for (int t = 0; t < 4; t++) {
        memset(cfg, 0, sizeof cfg);
        cfg[0x24] = (uint8_t)t;
        *(int16_t *)(cfg + 0x10) = 8;
        for (int i = 0; i < 2 * MAXP; i++) oxv[i] = oxc[i] = 0xa5;
        for (int i = 0; i < MAXP; i++) {
            uint32_t u = 0xdeadbeefu; memcpy(&ovv[i], &u, 4); memcpy(&ovc[i], &u, 4);
        }
        int nv = 0x12345678, nc = 0x12345678;
        int rv = v(oxv, ovv, &nv, xyv, vlv, 0, 3, dims, 1u, cfg);
        int rc = cr_pick_points_2f2e0(oxc, ovc, &nc, xyc, vlc, 0, 3,
                                      dims, 1u, cfg);
        if (rv != rc) { mismatch("z-ret", (u32)t, (u32)rv, (u32)rc); continue; }
        if (nv != nc) mismatch("z-cnt", (u32)t, (u32)nv, (u32)nc);
        cmp_buf("z-xy", oxv, oxc, sizeof oxv, (u32)t);
    }

    if (g_fail == bad) end(); else printf("  FAIL cr_pick_points_2f2e0\n");
}

/* 0x18000e850 — per-keypoint descriptor packer (guard / empty paths). */
static void test_feat_pack_0e850(void)
{
    typedef int (WINAPI *v_t)(void *, void *, const void *);
    v_t v = (v_t)fn_at(RVA(0x18000e850));
    begin("cr_feat_pack_0e850");
    int bad = g_fail;

    static uint8_t iv[0x20], ic[0x20];
    static uint8_t sv[64 * 64], sc[64 * 64];
    static uint8_t ov[0x40], oc[0x40];
    static uint8_t cfg[0x20];

    for (int t = 0; t < 4000; t++) {
        int sel_a = (int)(rnd() % 15u);     /* cfg[0xb], signed byte */
        int sel_b = (int)(rnd() % 9u);      /* cfg[0xe] */
        int flag  = (int)(rnd() % 2u);      /* cfg[0xc] */
        int sel_c = (int)(rnd() % 9u);      /* cfg[0xd] */
        /* A positive count would call cr_signpack_dot, which returns 0x69 in
         * the clean-room because the descriptor's table pointer is NULL (the
         * vendor's points into .rdata).  A negative count turns into a
         * multi-gigabyte request that the zeroing allocator OOMs on.  Only
         * the empty-list success path is comparable. */
        int cnt   = 0;

        for (int i = 0; i < 64 * 64; i++)
            sv[i] = sc[i] = (uint8_t)rnd();

        memset(ov, 0, sizeof ov);
        memset(oc, 0, sizeof oc);
        *(int32_t *)(ov + 0x20) = cnt;
        *(int32_t *)(oc + 0x20) = cnt;

        memset(cfg, 0, sizeof cfg);
        cfg[0xb] = (uint8_t)sel_a;
        cfg[0xc] = (uint8_t)flag;
        cfg[0xd] = (uint8_t)sel_c;
        cfg[0xe] = (uint8_t)sel_b;

        mk_image(iv, sv, 32, 32, 32, 0, 0);
        mk_image(ic, sc, 32, 32, 32, 0, 0);

        int rv = v(iv, ov, cfg);
        int rc = cr_feat_pack_0e850((cr_image *)ic, (cr_feat_obj *)oc, cfg);
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }
        /* the bin-table pointer itself is a heap address: compare only that
         * both sides produced one (the vendor's is a different allocation). */
        cmp_buf("obj", ov, oc, 0x38, (u32)t);
        int pv = *(void **)(ov + 0x38) != NULL;
        int pc = *(void **)(oc + 0x38) != NULL;
        if (pv != pc) mismatch("bins", (u32)t, (u32)pv, (u32)pc);
        cmp_buf("src", sv, sc, sizeof sv, (u32)t);
    }

    /* the full selector cross-product (guard paths only). */
    for (int a = 0; a < 16; a++) {
        for (int b = 0; b < 8; b++) {
            memset(ov, 0, sizeof ov);
            memset(oc, 0, sizeof oc);
            memset(cfg, 0, sizeof cfg);
            cfg[0xb] = (uint8_t)a;
            cfg[0xe] = (uint8_t)b;
            cfg[0xc] = 1;
            int rv = v(iv, ov, cfg);
            int rc = cr_feat_pack_0e850((cr_image *)ic, (cr_feat_obj *)oc, cfg);
            if (rv != rc) { mismatch("x-ret", (u32)(a * 8 + b), (u32)rv, (u32)rc); continue; }
            cmp_buf("x-obj", ov, oc, 0x38, (u32)(a * 8 + b));
            int pv = *(void **)(ov + 0x38) != NULL;
            int pc = *(void **)(oc + 0x38) != NULL;
            if (pv != pc) mismatch("x-bins", (u32)(a * 8 + b), (u32)pv, (u32)pc);
        }
    }

    if (g_fail == bad) end(); else printf("  FAIL cr_feat_pack_0e850\n");
}

/* ---- batch 87: row-streaming 5x5 max-pool stage runner ------------------ */
/* 0x180021000.  The buffer is allocated through the vendor/clean-room sized
 * allocators because the function releases the caller's buffer on every
 * failure path; on success it stays alive and the payload is compared. */
static void test_maxpool_stream_21000(void)
{
    typedef int (WINAPI *v_i_puipz)(void *, const int *, const void *, const void *);
    v_i_puipz v = (v_i_puipz)fn_at(RVA(0x180021000));
    v_i_ppz vmalloc = (v_i_ppz)fn_at(RVA(0x180002fe0));
    v_v_p vsfree = (v_v_p)fn_at(RVA(0x18003bf40));

    begin("cr_maxpool_stream_21000");
    int bad = g_fail;

    static int16_t kern[96];
    static int16_t bias[4];
    static uint8_t pool[8192];

    for (int t = 0; t < 6000; t++) {
        int W = 1 + (int)(rnd() % 40u);
        int H = 1 + (int)(rnd() % 40u);
        int nk = (int)(rnd() % 4u);
        int ow = (W - 4) >> 1, oh = (H - 4) >> 1;
        size_t nout = (ow > 0 && oh > 0) ? (size_t)ow * (size_t)oh * (size_t)nk : 0;
        size_t need = (size_t)6 * W + 2 * nout + 2;

        int desc[24];
        memset(desc, 0, sizeof desc);
        desc[0] = 5; desc[1] = H; desc[2] = W; desc[3] = 1; desc[5] = nk;
        desc[6] = (int)(rnd() & 1u);
        *(void **)(desc + 8) = kern;
        *(void **)(desc + 10) = bias;
        for (int i = 0; i < nk * 25; i++) kern[i] = (int16_t)rnd();
        for (int i = 0; i < nk; i++) bias[i] = (int16_t)rnd();

        int chain[4];
        chain[0] = 1;
        chain[1] = 0;
        *(int **)(chain + 2) = desc;

        /* Mode: 0 = success path, 1 = guard failure, 2 = chain failure. */
        int mode = (t % 6 == 5) ? 1 : ((t % 11 == 7) ? 2 : 0);
        if (mode == 1) {
            if (rnd() & 1) desc[3] = (int)(rnd() % 4u) + 2;
            else           desc[0] = (int)(rnd() % 5u) + (rnd() & 1 ? 6 : 0);
        } else if (mode == 2) {
            chain[0] = 2;
            desc[12] = 7;                    /* unknown stage tag */
        }

        int32_t smp[6] = { 0x8000, 0, 0, 0, 0x8000, 0 };
        for (size_t i = 0; i < sizeof pool; i++) pool[i] = (uint8_t)rnd();
        uint8_t *data = pool + 4096;
        unsigned char iv[0x20], ic[0x20];
        mk_image(iv, data, W, W, H, 0, 0);
        mk_image(ic, data, W, W, H, 0, 0);

        /* The tail copy reads n shorts from buf+6W where n is computed with
         * signed division; for degenerate W/H (<= 2) n stays positive even
         * though ow/oh are negative, so the read runs past the payload.  Give
         * the block a zeroed margin so both sides see the same bytes. */
        int sz = 1 + (int)(rnd() % 8u);
        uint8_t *bv = v_sized_alloc(vmalloc, need + (size_t)sz + 32, sz);
        uint8_t *bc = c_sized_alloc(need + (size_t)sz + 32, sz);

        int rv = v(bv, chain, iv, smp);
        int rc = cr_maxpool_stream_21000(bc, chain, (const cr_image *)ic,
                                         (const cr_sampler *)smp);
        if ((u32)rv != (u32)rc)
            mismatch("ret", (u32)t, (u32)rv, (u32)rc);
        if (rv == 0) {
            cmp_buf("out", bv, bc, (u32)need, (u32)t);
            vsfree(&bv);
            cr_sized_free((void **)&bc);
        }
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_maxpool_stream_21000\n");
}

/* ---- 0x18002b680 — point-selection dispatch wrapper -------------------- */
static void test_pick_points_dispatch_2b680(void)
{
    typedef int (WINAPI *v_t)(void *, const void *, const void *);
    v_t v = (v_t)fn_at(RVA(0x18002b680));
    begin("cr_pick_points_dispatch_2b680");
    int bad = g_fail;

    enum { MAXPTS = 40, MAXW = 512 };
    static uint8_t a[0x60], ac[0x60];
    static uint8_t xyv[2 * MAXPTS], xyc[2 * MAXPTS];
    static float vlv[MAXPTS], vlc[MAXPTS];
    static uint8_t oxv[2 * MAXPTS], oxc[2 * MAXPTS];
    static float ovv[MAXPTS], ovc[MAXPTS];
    static uint8_t mcfg[0x20];
    static uint8_t cfg[0x40];
    static uint32_t mwords[MAXW];

    for (int t = 0; t < 2400; t++) {
        int guard = (t % 12 == 11);
        int margin = (int)(rnd() % 3u);
        int W = 2 * margin + 1 + (int)(rnd() % 48u);
        int H = 2 * margin + 1 + (int)(rnd() % 48u);
        int NX = 1 + (int)(rnd() % 5u);
        int NY = 1 + (int)(rnd() % 5u);
        int npts = (int)(rnd() % (MAXPTS + 1));
        int maxpts = npts + (int)(rnd() % 5u);
        int weight = (int)(rnd() % 2000u);
        int stride = 32 * (1 + (int)(rnd() % 4u));
        int x0 = (int)(rnd() % 4u), y0 = (int)(rnd() % 4u);
        uint32_t seed = rnd();

        for (int i = 0; i < MAXW; i++) mwords[i] = rnd();
        for (int i = 0; i < 2 * MAXPTS; i++) {
            uint8_t b = (rnd() % 4u == 0) ? (uint8_t)i : (uint8_t)rnd();
            xyv[i] = xyc[i] = b;
        }
        for (int i = 0; i < MAXPTS; i++) {
            uint32_t u = (uint32_t)rnd();
            memcpy(&vlv[i], &u, 4);
            memcpy(&vlc[i], &u, 4);
        }
        for (int i = 0; i < 2 * MAXPTS; i++) oxv[i] = oxc[i] = 0xa5;
        for (int i = 0; i < MAXPTS; i++) {
            uint32_t u = 0xdeadbeefu; memcpy(&ovv[i], &u, 4); memcpy(&ovc[i], &u, 4);
        }

        memset(mcfg, 0, sizeof mcfg);
        *(int *)(mcfg + 0x00) = stride;
        *(void **)(mcfg + 0x08) = mwords;
        *(int *)(mcfg + 0x10) = W;
        *(int *)(mcfg + 0x14) = H;
        *(int *)(mcfg + 0x18) = x0;
        *(int *)(mcfg + 0x1c) = y0;

        memset(cfg, 0, sizeof cfg);
        cfg[0x24] = guard ? (uint8_t)(rnd() % 3u + 3u) : 2;
        *(int8_t *)(cfg + 0x08) = (int8_t)margin;
        *(int16_t *)(cfg + 0x10) = (int16_t)maxpts;
        *(int *)(cfg + 0x14) = weight;
        cfg[0x25] = (uint8_t)NX;
        cfg[0x26] = (uint8_t)NY;

        memset(a, 0x5A, sizeof a);
        memset(ac, 0x5A, sizeof ac);
        for (int side = 0; side < 2; side++) {
            uint8_t *p = side ? ac : a;
            *(void **)(p + 0x08) = side ? oxc : oxv;
            *(void **)(p + 0x10) = side ? (void *)ovc : (void *)ovv;
            *(void **)(p + 0x20) = side ? xyc : xyv;
            *(void **)(p + 0x28) = side ? (void *)vlc : (void *)vlv;
            *(int *)(p + 0x40) = 0x12345678;
            *(int *)(p + 0x44) = npts;
            *(uint32_t *)(p + 0x4c) = seed;
        }

        int rv = v(a, mcfg, cfg);
        int rc = cr_pick_points_dispatch_2b680(ac, mcfg, cfg);
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }
        if (*(int *)(a + 0x40) != *(int *)(ac + 0x40))
            mismatch("outn", (u32)t, (u32)*(int *)(a + 0x40),
                     (u32)*(int *)(ac + 0x40));
        /* The pointer slots are per-side by construction; everything else in
         * the object must be untouched. */
        static const int off[6] = { 0x00, 0x18, 0x30, 0x3c, 0x48, 0x50 };
        static const int len[6] = { 8, 8, 12, 4, 4, 16 };
        for (int side = 0; side < 2; side++) {
            uint8_t *p = side ? ac : a;
            int okp = (*(void **)(p + 0x08) == (void *)(side ? oxc : oxv))
                   && (*(void **)(p + 0x10) == (void *)(side ? (void *)ovc : (void *)ovv))
                   && (*(void **)(p + 0x20) == (void *)(side ? xyc : xyv))
                   && (*(void **)(p + 0x28) == (void *)(side ? (void *)vlc : (void *)vlv))
                   && (*(uint32_t *)(p + 0x4c) == seed);
            for (int k = 0; k < 6; k++)
                for (int j = 0; j < len[k]; j++)
                    if (p[off[k] + j] != 0x5A) okp = 0;
            if (!okp) mismatch("obj", (u32)t, (u32)side, 0);
        }
        cmp_buf("xy", oxv, oxc, sizeof oxv, (u32)t);
        cmp_buf("val", (const unsigned char *)ovv,
                (const unsigned char *)ovc, sizeof ovv, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_pick_points_dispatch_2b680\n");
}

/* ---- 0x1800273a0 — stage driver + block projection + softmax ----------- */
static void test_stage_run_273a0(void)
{
    typedef int (WINAPI *v_t)(void *, const void *, const void *, const void *);
    v_t v = (v_t)fn_at(RVA(0x1800273a0));
    begin("cr_stage_run_273a0");
    int bad = g_fail;

    enum { MAXBLK = 4, NCOEF = 40 };
    static int16_t kern[96], bias[4];
    static int16_t bcoef[MAXBLK][NCOEF], bbias[MAXBLK][NCOEF];
    static uint8_t pool[8192];
    static uint8_t blkbuf[0x100];
    static int desc[0x28];
    static int chain[12];
    static uint8_t iv[0x20], ic[0x20];

    for (int t = 0; t < 3000; t++) {
        int pyr = (t % 3 == 2);
        int W = 6 + (int)(rnd() % 30u);
        int H = 6 + (int)(rnd() % 30u);
        int nk = 1 + (int)(rnd() % 3u);
        /* The pyramid path's buffer formula only covers one block plane
         * (2*first_block[0] bytes), so use exactly nblocks=1 with p0 equal to
         * the block plane size 16 and a 16-entry projection row. */
        int nblk = pyr ? 1 : 1 + (int)(rnd() % MAXBLK);
        uint32_t sscale = 1u << (20 + (int)(rnd() % 10u));

        for (size_t i = 0; i < sizeof pool; i++) pool[i] = (uint8_t)rnd();
        mk_image(iv, pool + 4096, 64, 64, 64, 0, 0);
        mk_image(ic, pool + 4096, 64, 64, 64, 0, 0);

        memset(desc, 0, sizeof desc);
        memset(chain, 0, sizeof chain);
        memset(blkbuf, 0, sizeof blkbuf);

        if (!pyr) {
            desc[0] = 5; desc[1] = H; desc[2] = W; desc[3] = 1;
            desc[5] = nk; desc[6] = (int)(rnd() & 1u);
            for (int i = 0; i < nk * 25; i++) kern[i] = (int16_t)rnd();
            for (int i = 0; i < nk; i++) bias[i] = (int16_t)rnd();
            *(void **)(desc + 8) = kern;
            *(void **)(desc + 10) = bias;
            chain[0] = 1;
        } else {
            /* three-level pyramid descriptor, same shape as test_pyramid_364c0 */
            desc[0x00] = 5; desc[0x02] = 32; desc[0x03] = 1;
            desc[0x04] = 8; desc[0x05] = 2; desc[0x06] = (int)(rnd() & 1u);
            *(void **)(desc + 0x20 / 4) = kern;
            *(void **)(desc + 0x28 / 4) = bias;
            desc[0x0c] = 3; desc[0x0e] = 16; desc[0x0f] = 1;
            desc[0x10] = 4; desc[0x11] = 4; desc[0x12] = (int)(rnd() & 1u);
            *(void **)(desc + 0x50 / 4) = kern + 25;
            *(void **)(desc + 0x58 / 4) = bias + 1;
            desc[0x18] = 5; desc[0x19] = 2 * nblk + 4;
            desc[0x1a] = 16; desc[0x1b] = 1;
            desc[0x1c] = 4; desc[0x1d] = 4; desc[0x1e] = (int)(rnd() & 1u);
            *(void **)(desc + 0x80 / 4) = kern + 50;
            *(void **)(desc + 0x88 / 4) = bias + 2;
            for (int i = 0; i < 96; i++) kern[i] = (int16_t)rnd();
            for (int i = 0; i < 4; i++) bias[i] = (int16_t)rnd();
            chain[0] = 3;
        }
        *(void **)(chain + 2) = desc;

        for (int k = 0; k < nblk; k++) {
            int p0 = pyr ? 16 : 1 + (int)(rnd() % 4u);
            int p1 = (k == nblk - 1) ? 2 : 1 + (int)(rnd() % 3u);
            uint8_t *bp = blkbuf + k * 0x20;
            *(int *)(bp + 0x00) = p0;
            *(int *)(bp + 0x04) = p1;
            *(int *)(bp + 0x08) = (int)(rnd() & 1u);
            *(void **)(bp + 0x10) = bcoef[k];
            *(void **)(bp + 0x18) = bbias[k];
            for (int i = 0; i < NCOEF; i++) {
                bcoef[k][i] = (int16_t)rnd();
                bbias[k][i] = (int16_t)rnd();
            }
        }
        chain[4] = nblk;
        chain[8] = (int)sscale;
        chain[9] = 1024;                    /* buffer floor, 2048 bytes */
        *(void **)(chain + 6) = blkbuf;

        int32_t smp[6];
        smp[0] = (int32_t)(rnd() % 0x4001u);
        smp[1] = 0;
        smp[2] = 0;
        smp[3] = 0;
        smp[4] = 0x8000;
        smp[5] = 0;

        float ov = 1234.5f, oc = 1234.5f;
        int rv = v(&ov, chain, iv, smp);
        int rc = cr_stage_run_273a0(&oc, chain, (const cr_image *)ic,
                                    (const cr_sampler *)smp);
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }
        cmp_buf("out", (const unsigned char *)&ov,
                (const unsigned char *)&oc, 4, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_stage_run_273a0\n");
}

/* ---- 0x18001bbf0 — scale-space blob detector --------------------------- *
 * float +0x1c = sigma, plus the cr_grid_cfg fields read by cr_grid_insert.
 * maskcfg: [0] = bit-row stride, [2..3] = word pointer, [6]/[7] = x/y origin. */
static void test_blob_detect_1bbf0(void)
{
    typedef int (WINAPI *v_i_pppp)(void *, const void *, const void *, const void *);
    v_i_pppp v = (v_i_pppp)fn_at(RVA(0x18001bbf0));
    begin("cr_blob_detect_1bbf0");
    int bad = g_fail;

    enum { STRIDE = 64, ROWS = 40, SRCN = STRIDE * ROWS, MWORDS = 128 };

    static uint8_t srcb[SRCN];
    static uint8_t desc_v[0x20], desc_c[0x20];
    static uint8_t mcfg_v[0x20], mcfg_c[0x20];
    static uint8_t cfg[0x40];
    static uint32_t mwords[MWORDS];

    for (int t = 0; t < 6000; t++) {
        int mode = 1 + (int)(rnd() % 4);                 /* margin 1..4 */
        int Wn   = 1 + (int)(rnd() % 6);                 /* 1..6 */
        int sw   = Wn + 2 * mode;                        /* scaled width */
        int sh   = 2 * mode + 1 + (int)(rnd() % 6);      /* scaled height */
        int mx   = (7 - mode) + (int)(rnd() % 5);
        int my   = (7 - mode) + (int)(rnd() % 5);
        int mstride = 1 + (int)(rnd() % 64);
        int gmode = ((int)(rnd() % 4) == 0) ? 2
                  : ((int)(rnd() % 8) == 0) ? 7 : 5;
        int cap  = 1 + (int)(rnd() % 16);
        int cap2 = (int)(rnd() % 17);
        int divx = 1 + (int)(rnd() % 8);
        int divy = 1 + (int)(rnd() % 8);
        int W = 1 + (int)(rnd() % 8);
        int H = 1 + (int)(rnd() % 8);

        for (int i = 0; i < SRCN; i++) srcb[i] = (uint8_t)rnd();
        for (int i = 0; i < MWORDS; i++) mwords[i] = rnd();

        memset(desc_v, 0, sizeof desc_v);
        *(int *)(desc_v + 0x00) = STRIDE;
        *(int *)(desc_v + 0x04) = ROWS;
        *(void **)(desc_v + 0x08) = srcb;
        *(int *)(desc_v + 0x10) = sw;
        *(int *)(desc_v + 0x14) = sh;
        *(int *)(desc_v + 0x18) = mx;
        *(int *)(desc_v + 0x1c) = my;
        memcpy(desc_c, desc_v, sizeof desc_v);

        memset(mcfg_v, 0, sizeof mcfg_v);
        *(int *)(mcfg_v + 0x00) = mstride;
        *(void **)(mcfg_v + 0x08) = mwords;
        *(int *)(mcfg_v + 0x18) = 0;
        *(int *)(mcfg_v + 0x1c) = 0;
        memcpy(mcfg_c, mcfg_v, sizeof mcfg_v);

        memset(cfg, 0, sizeof cfg);
        *(int8_t *)(cfg + 0x08) = (int8_t)mode;
        *(int16_t *)(cfg + 0x10) = (int16_t)cap2;
        *(float *)(cfg + 0x1c) = (float)(1 + (int)(rnd() % 400u)) * 0.25f;
        *(uint8_t *)(cfg + 0x24) = (uint8_t)gmode;

        struct grid_state sv, sc;
        memset(&sv, 0, sizeof sv);
        sv.g.nodes = sv.nodes; sv.g.coords = sv.coords; sv.g.values = sv.values;
        sv.g.next = sv.next; sv.g.coords2 = sv.coords2; sv.g.values2 = sv.values2;
        sv.g.W = W; sv.g.H = H; sv.g.divx = divx; sv.g.divy = divy;
        sv.g.count = 0; sv.g.count2 = 0; sv.g.cap = cap;
        sv.cfg.cap2 = (int16_t)cap2; sv.cfg.mode = (uint8_t)gmode;
        for (int k = 0; k < W * H; k++) {
            sv.nodes[k].key = 0; sv.nodes[k].head = -1;
            sv.nodes[k].val = (float)(1 + (int)(rnd() % 1000)) * 0.001f;
        }
        for (int k = 0; k < cap; k++) {
            sv.next[k] = -1; sv.values[k] = 0.0f;
            sv.coords[2 * k] = sv.coords[2 * k + 1] = 0;
        }
        for (int k = 0; k < cap2; k++) {
            sv.values2[k] = 0.0f;
            sv.coords2[2 * k] = sv.coords2[2 * k + 1] = 0;
        }
        sc = sv;
        sc.g.nodes = sc.nodes; sc.g.coords = sc.coords; sc.g.values = sc.values;
        sc.g.next = sc.next; sc.g.coords2 = sc.coords2; sc.g.values2 = sc.values2;

        int rv = v(&sv.g, desc_v, mcfg_v, cfg);
        int rc = cr_blob_detect_1bbf0(&sc.g, (const cr_image *)desc_c,
                                      (const int32_t *)mcfg_c, cfg);
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }
        cmp_buf("nodes", (unsigned char *)sv.nodes, (unsigned char *)sc.nodes,
                sizeof(cr_grid_node) * (size_t)(W * H), (u32)t);
        cmp_buf("values", (unsigned char *)sv.values, (unsigned char *)sc.values,
                sizeof(float) * (size_t)cap, (u32)t);
        cmp_buf("next", (unsigned char *)sv.next, (unsigned char *)sc.next,
                sizeof(int16_t) * (size_t)cap, (u32)t);
        cmp_buf("coords", sv.coords, sc.coords, 2 * (size_t)cap, (u32)t);
        cmp_buf("values2", (unsigned char *)sv.values2, (unsigned char *)sc.values2,
                sizeof(float) * (size_t)cap2, (u32)t);
        cmp_buf("coords2", sv.coords2, sc.coords2, 2 * (size_t)cap2, (u32)t);
        if (sv.g.count != sc.g.count || sv.g.count2 != sc.g.count2)
            mismatch("count", (u32)t, (u32)sv.g.count, (u32)sc.g.count);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_blob_detect_1bbf0\n");
}

/* 0x18003cb30 — replicate-extend the border of a packed bitmap. */
static void test_bitmap_extend_border(void)
{
    typedef void (WINAPI *fn_t)(void *, int, int, int, int);
    fn_t v = (fn_t)fn_at(RVA(0x18003cb30));
    begin("cr_bitmap_extend_border");
    int bad = g_fail;
    enum { MAXW = 32, MAXH = 32, NWORDS = 1024 };
    static uint32_t bv[NWORDS], bc[NWORDS];
    static cr_image dv, dc;
    for (int t = 0; t < 20000; t++) {
        int w = 1 + (int)(rnd() % MAXW);
        int h = 1 + (int)(rnd() % MAXH);
        int offx = (int)(rnd() % 9u);
        int offy = (int)(rnd() % 9u);
        int k = (offx + w + 31) / 32 + 1;         /* extra word of slack */
        int a = 32 * k;                           /* stride in bits */
        /* NOTE: bottom == h (or top == h) makes the vendor read row -1 / row h,
         * which is outside the bitmap buffer and therefore depends on whatever
         * precedes it in memory; keep the bands strictly inside the content so
         * the comparison is deterministic. */
        int left   = (int)(rnd() % (unsigned)w);
        int right  = (int)(rnd() % (unsigned)w);
        int top    = (int)(rnd() % (unsigned)h);
        int bottom = (int)(rnd() % (unsigned)h);
        for (int i = 0; i < NWORDS; i++) bv[i] = rnd();
        memcpy(bc, bv, sizeof bv);
        cr_image_set(&dv, bv, w, h); dv.a = a; dv.offx = offx; dv.offy = offy;
        cr_image_set(&dc, bc, w, h); dc.a = a; dc.offx = offx; dc.offy = offy;
        v(&dv, left, top, right, bottom);
        cr_bitmap_extend_border(&dc, left, top, right, bottom);
        cmp_buf("bmborder", (const unsigned char *)bv,
                (const unsigned char *)bc, sizeof bv, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_bitmap_extend_border\n");
}

/* 0x18002ddd0 — centroid of set bits in a bitmap, clamped to a window. */
static void test_bitmap_centroid(void)
{
    typedef int (WINAPI *v_i_pppiip)(const void *, int, int, int *, int *, int);
    v_i_pppiip v = (v_i_pppiip)fn_at(RVA(0x18002ddd0));
    begin("cr_bitmap_centroid");
    int bad = g_fail;
    enum { MAXW = 64, MAXH = 24, MAXWORDS = 8 };
    uint32_t bits[MAXH * MAXWORDS];
    for (int t = 0; t < 20000; t++) {
        int w = 1 + (int)(rnd() % MAXW);
        int h = 1 + (int)(rnd() % MAXH);
        int stride_words = (w + 31) / 32 + (int)(rnd() % 3);
        int win_h = (int)(rnd() % (h + 4));
        int win_w = (int)(rnd() % (w + 4));
        int margin = (int)(rnd() % 8);
        for (int i = 0; i < h * stride_words; i++) bits[i] = rnd();
        cr_bitmap_desc bm;
        memset(&bm, 0, sizeof bm);
        bm.a = stride_words * 32; bm.data = bits; bm.w = w; bm.h = h;
        int vy = 0x11111111, vx = 0x22222222;
        int cy = vy, cx = vx;
        int rv = v(&bm, win_h, win_w, &vy, &vx, margin);
        int rc = cr_bitmap_centroid(&bm, win_h, win_w, &cy, &cx, margin);
        if (rv != rc) mismatch("ret", (u32)t, (u32)rv, (u32)rc);
        if (vy != cy) mismatch("y", (u32)t, (u32)vy, (u32)cy);
        if (vx != cx) mismatch("x", (u32)t, (u32)vx, (u32)cx);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_bitmap_centroid\n");
}

/* ---- batch 36: descriptor / table-pointer getters ---------------------- *
 * These write vendor data-section pointers; the cleanroom zeroes them.
 * Compare return value + scalar fields only; pointer slots are not compared. */

static void test_desc_getters(void)
{
    /* These write vendor data-section pointers; the cleanroom zeroes them.
     * Compare return value + scalar fields only; skip pointer slots. */

    begin("cr_desc_get_ptr1");
    {
        typedef uint64_t (WINAPI *v_u_pc)(void *, char);
        v_u_pc v = (v_u_pc)fn_at(RVA(0x18002aeb0));
        int bad = g_fail;
        for (int s = 0; s < 256; s++) {
            uint64_t vv, cv;
            uint64_t rv = v(&vv, (char)s);
            uint64_t rc = cr_desc_get_ptr1(&cv, (char)s);
            if (rv != rc) mismatch("ret", (u32)s, rv, rc);
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_desc_get_ptr1\n");
    }

    begin("cr_desc_get_ptr_size");
    {
        typedef uint64_t (WINAPI *v_u_ppc)(void *, uint32_t *, char);
        v_u_ppc v = (v_u_ppc)fn_at(RVA(0x180012f30));
        int bad = g_fail;
        for (int s = 0; s < 256; s++) {
            uint64_t vv; uint32_t vs;
            uint64_t cv; uint32_t cs;
            uint64_t rv = v(&vv, &vs, (char)s);
            uint64_t rc = cr_desc_get_ptr_size(&cv, &cs, (char)s);
            if (rv != rc) mismatch("ret", (u32)s, rv, rc);
            if (vs != cs) mismatch("size", (u32)s, (u64)vs, (u64)cs);
            if ((vv != 0) != (cv != 0))
                mismatch("ptrnull", (u32)s, (u64)(vv != 0), (u64)(cv != 0));
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_desc_get_ptr_size\n");
    }

    begin("cr_desc_get_ptr2");
    {
        typedef uint64_t (WINAPI *v_u_pc)(void *, char);
        v_u_pc v = (v_u_pc)fn_at(RVA(0x180020860));
        int bad = g_fail;
        for (int s = 0; s < 256; s++) {
            uint64_t vv, cv;
            uint64_t rv = v(&vv, (char)s);
            uint64_t rc = cr_desc_get_ptr2(&cv, (char)s);
            if (rv != rc) mismatch("ret", (u32)s, rv, rc);
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_desc_get_ptr2\n");
    }

    begin("cr_desc_get_tag_ptr");
    {
        typedef uint64_t (WINAPI *v_u_pc)(void *, char);
        v_u_pc v = (v_u_pc)fn_at(RVA(0x18002dab0));
        int bad = g_fail;
        for (int s = 0; s < 256; s++) {
            uint64_t vb[2], cb[2];
            uint64_t rv = v(vb, (char)s);
            uint64_t rc = cr_desc_get_tag_ptr(cb, (char)s);
            if (rv != rc) mismatch("ret", (u32)s, rv, rc);
            /* q[0] is a scalar tag; q[1] is the kernel-bank pointer, which we
             * embed, so only NULL-ness can be compared */
            if (vb[0] != cb[0]) mismatch("tag", (u32)s, vb[0], cb[0]);
            if ((vb[1] != 0) != (cb[1] != 0))
                mismatch("tagptr", (u32)s, vb[1], cb[1]);
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_desc_get_tag_ptr\n");
    }

    begin("cr_desc_get_ptr2_69");
    {
        typedef uint64_t (WINAPI *v_u_pc)(void *, char);
        v_u_pc v = (v_u_pc)fn_at(RVA(0x1800448f0));
        int bad = g_fail;
        for (int s = 0; s < 256; s++) {
            uint64_t vv, cv;
            uint64_t rv = v(&vv, (char)s);
            uint64_t rc = cr_desc_get_ptr2_69(&cv, (char)s);
            if (rv != rc) mismatch("ret", (u32)s, rv, rc);
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_desc_get_ptr2_69\n");
    }

    begin("cr_desc_get_ptr_ints");
    {
        typedef uint64_t (WINAPI *v_u_pppc)(void *, uint32_t *, uint32_t *, char);
        v_u_pppc v = (v_u_pppc)fn_at(RVA(0x180018e50));
        int bad = g_fail;
        for (int s = 0; s < 256; s++) {
            uint64_t vv; uint32_t v2, v3;
            uint64_t cv; uint32_t c2, c3;
            uint64_t rv = v(&vv, &v2, &v3, (char)s);
            uint64_t rc = cr_desc_get_ptr_ints(&cv, &c2, &c3, (char)s);
            if (rv != rc) mismatch("ret", (u32)s, rv, rc);
            if (v2 != c2) mismatch("i2", (u32)s, (u64)v2, (u64)c2);
            if (v3 != c3) mismatch("i3", (u32)s, (u64)v3, (u64)c3);
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_desc_get_ptr_ints\n");
    }

    begin("cr_desc_get_ptr_size_69");
    {
        typedef uint8_t (WINAPI *v_b_pc)(void *, uint32_t *, char);
        v_b_pc v = (v_b_pc)fn_at(RVA(0x180017960));
        int bad = g_fail;
        for (int s = 0; s < 256; s++) {
            uint64_t vv; uint32_t vs;
            uint64_t cv; uint32_t cs;
            uint8_t rv = v(&vv, &vs, (char)s);
            uint8_t rc = cr_desc_get_ptr_size_69(&cv, &cs, (char)s);
            if (rv != rc) mismatch("ret", (u32)s, (u64)rv, (u64)rc);
            if (vs != cs) mismatch("size", (u32)s, (u64)vs, (u64)cs);
            if (vv != cv) mismatch("ptr", (u32)s, vv, cv);
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_desc_get_ptr_size_69\n");
    }

    begin("cr_desc_get_tag_byte_ptr");
    {
        typedef uint64_t (WINAPI *v_u_pc)(void *, char);
        v_u_pc v = (v_u_pc)fn_at(RVA(0x180028de0));
        int bad = g_fail;
        for (int s = 0; s < 256; s++) {
            /* layout: +0 u64 (tag), +8 u8 (marker), +0x10 u64 (ptr, skip), +0x18 u64 */
            unsigned char vb[0x20], cb[0x20];
            uint64_t rv = v(vb, (char)s);
            uint64_t rc = cr_desc_get_tag_byte_ptr(cb, (char)s);
            if (rv != rc) mismatch("ret", (u32)s, rv, rc);
            if (memcmp(vb, cb, 8) != 0)
                mismatch("tag", (u32)s, *(uint64_t*)vb, *(uint64_t*)cb);
            if (vb[8] != cb[8])
                mismatch("marker", (u32)s, vb[8], cb[8]);
            if (memcmp(vb+0x18, cb+0x18, 8) != 0)
                mismatch("q3", (u32)s, *(uint64_t*)(vb+0x18), *(uint64_t*)(cb+0x18));
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_desc_get_tag_byte_ptr\n");
    }

    begin("cr_desc_get_triple");
    {
        typedef uint64_t (WINAPI *v_u_pb)(void *, uint8_t);
        v_u_pb v = (v_u_pb)fn_at(RVA(0x18002d4e0));
        int bad = g_fail;
        for (int s = 0; s < 256; s++) {
            uint64_t vb[3], cb[3];
            uint64_t rv = v(vb, (uint8_t)s);
            uint64_t rc = cr_desc_get_triple(cb, (uint8_t)s);
            if (rv != rc) mismatch("ret", (u32)s, rv, rc);
            /* q[0] is a scalar tag; q[1],q[2] are pointers (skip) */
            if (vb[0] != cb[0]) mismatch("tag", (u32)s, vb[0], cb[0]);
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_desc_get_triple\n");
    }
}

/* ---- batch 37: 9-tap triangular filter over an n x 9 float buffer ------- */
static void test_tri9_filter(void)
{
    typedef void (WINAPI *v_v_ppi)(float *, float *, int);
    v_v_ppi v = (v_v_ppi)fn_at(RVA(0x180043a50));
    begin("cr_tri9_filter");
    int bad = g_fail;
    enum { MAXN = 64 };
    float inv[9 * MAXN], outv[9 * MAXN], outc[9 * MAXN];
    for (int t = 0; t < 20000; t++) {
        int n = 9 + (int)(rnd() % (MAXN - 8));      /* n >= 9 (vendor assumes it) */
        for (int i = 0; i < 9 * n; i++) {
            uint32_t bits = rnd();
            /* keep values finite-ish but exercise signed zeros/denormals */
            if ((bits & 0x7f800000u) == 0x7f800000u) bits &= ~0x7f800000u;
            inv[i] = cr_u2f(bits);
        }
        memset(outv, 0x5A, sizeof outv);
        memset(outc, 0x5A, sizeof outc);
        v(inv, outv, n);
        cr_tri9_filter(inv, outc, n);
        cmp_buf("out", (unsigned char *)outv, (unsigned char *)outc,
                sizeof(float) * 9 * n, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_tri9_filter\n");
}

/* ---- batch 38: reflect-101-padded int16 FIR down each column ------------ */
static void test_fir_reflect(void)
{
    typedef int (WINAPI *v_i_pppiii)(int16_t *, const int16_t *,
                                     const int16_t *, int, int, int);
    v_i_pppiii v = (v_i_pppiii)fn_at(RVA(0x180030fc0));
    begin("cr_fir_reflect");
    int bad = g_fail;
    enum { MAXW = 40, MAXL = 200 };
    int16_t inv[MAXW * MAXL], coefv[MAXL], outv[MAXW * MAXL], outc[MAXW * MAXL];
    for (int t = 0; t < 20000; t++) {
        int W = 1 + (int)(rnd() % MAXW);
        int L = 1 + (int)(rnd() % MAXL);
        int p4 = (int)(rnd() % (L + 4)) - 2;      /* exercise the clamp */
        for (int i = 0; i < W * L; i++) inv[i] = (int16_t)rnd();
        for (int i = 0; i < L; i++) coefv[i] = (int16_t)rnd();
        memset(outv, 0x5A, sizeof outv);
        memset(outc, 0x5A, sizeof outc);
        int rv = v(outv, inv, coefv, p4, W, L);
        int rc = cr_fir_reflect(outc, inv, coefv, p4, W, L);
        if (rv != rc) mismatch("ret", (u32)t, (u32)rv, (u32)rc);
        cmp_buf("out", (unsigned char *)outv, (unsigned char *)outc,
                sizeof(int16_t) * W * L, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_fir_reflect\n");
}

/* ---- batch 39: row-wise twin of the reflect-101 column FIR -------------- */
static void test_fir_reflect_rows(void)
{
    typedef int (WINAPI *v_i_pppiii)(int16_t *, const int16_t *,
                                     const int16_t *, int, int, int);
    v_i_pppiii v = (v_i_pppiii)fn_at(RVA(0x180040560));
    begin("cr_fir_reflect_rows");
    int bad = g_fail;
    enum { MAXW = 200, MAXR = 40 };
    int16_t inv[MAXW * MAXR], coefv[MAXW], outv[MAXW * MAXR], outc[MAXW * MAXR];
    for (int t = 0; t < 20000; t++) {
        int W = 1 + (int)(rnd() % MAXW);          /* row length */
        int R = 1 + (int)(rnd() % MAXR);          /* row count  */
        int p4 = (int)(rnd() % (W + 4)) - 2;      /* exercise the clamp */
        for (int i = 0; i < W * R; i++) inv[i] = (int16_t)rnd();
        for (int i = 0; i < W; i++) coefv[i] = (int16_t)rnd();
        memset(outv, 0x5A, sizeof outv);
        memset(outc, 0x5A, sizeof outc);
        int rv = v(outv, inv, coefv, p4, W, R);
        int rc = cr_fir_reflect_rows(outc, inv, coefv, p4, W, R);
        if (rv != rc) mismatch("ret", (u32)t, (u32)rv, (u32)rc);
        cmp_buf("out", (unsigned char *)outv, (unsigned char *)outc,
                sizeof(int16_t) * W * R, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_fir_reflect_rows\n");
}

/* ---- batch 40: fixed 7-tap reflect-101 FIR down each row ---------------- *
 * The vendor uses a fixed K=7 kernel (unlike the twins, which clamp K to
 * n-1), so a 7-wide window needs W >= 4 to stay within one BORDER_REFLECT_101
 * period.  For W <= 3 the vendor's single-fold edge passes overlap and read
 * into the neighbouring row (an artifact of the unrolled tail, verified with
 * the `probe7` index-map probe); that domain is not a well-defined filter and
 * is excluded here.  For W >= 4 the closed-form refl101 matches exactly. */
static void test_fir7_reflect(void)
{
    typedef void (WINAPI *v_v_pppii)(int16_t *, const int16_t *,
                                     const int16_t *, int, int);
    v_v_pppii v = (v_v_pppii)fn_at(RVA(0x180033b40));
    begin("cr_fir7_reflect");
    int bad = g_fail;
    enum { MAXW = 200, MAXR = 40 };
    int16_t inv[MAXW * MAXR], coefv[7], outv[MAXW * MAXR], outc[MAXW * MAXR];
    for (int t = 0; t < 20000; t++) {
        int W = 4 + (int)(rnd() % (MAXW - 3));    /* row length, W >= 4 */
        int R = (int)(rnd() % (MAXR + 1));        /* row count, incl. 0 */
        if (t % 8 == 0) R = 0;                    /* force the no-op path */
        for (int i = 0; i < 7; i++) coefv[i] = (int16_t)rnd();
        for (int i = 0; i < W * MAXR; i++) inv[i] = (int16_t)rnd();
        memset(outv, 0x5A, sizeof outv);
        memset(outc, 0x5A, sizeof outc);
        v(outv, inv, coefv, W, R);
        cr_fir7_reflect(outc, inv, coefv, W, R);
        cmp_buf("out", (unsigned char *)outv, (unsigned char *)outc,
                sizeof(int16_t) * W * R, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_fir7_reflect\n");
}

/* ---- batch 41: in-place separable box mean (3x3 / 5x5) ------------------ */
static void test_box_mean(void)
{
    typedef int (WINAPI *v_i_pppi)(void *, void *, int);
    v_i_pppi v = (v_i_pppi)fn_at(RVA(0x18002c600));
    begin("cr_box_mean_f32");
    int bad = g_fail;
    enum { MAXW = 40, MAXH = 40, MAXP = MAXW * MAXH };
    struct desc { int a, b; float *data; int w, h; } vd, vs, cd, cs;
    static float vin[MAXP], cin[MAXP], ov[MAXP], oc[MAXP];
    for (int t = 0; t < 20000; t++) {
        int w = 1 + (int)(rnd() % MAXW);
        int h = 1 + (int)(rnd() % MAXH);
        int mode = (rnd() & 1) ? 3 : 5;
        if (t % 3 == 0) { w &= ~1; h &= ~1; }   /* force the valid domain */
        if (w < 1) w = 2;
        if (h < 1) h = 2;
        for (int i = 0; i < MAXP; i++)
            vin[i] = cin[i] = (float)(int)(rnd() % 2001) - 1000.0f;
        memset(ov, 0x5A, sizeof ov);
        memset(oc, 0x5A, sizeof oc);
        int inplace = !(t % 4 == 1);            /* mostly in-place (real use) */
        vd.a = vs.a = cd.a = cs.a = 0;
        vd.b = vs.b = cd.b = cs.b = 0;
        vd.w = vs.w = cd.w = cs.w = w;
        vd.h = vs.h = cd.h = cs.h = h;
        vs.data = vin;  cs.data = cin;
        vd.data = inplace ? vin : ov;
        cd.data = inplace ? cin : oc;
        int rv = v(&vd, &vs, mode);
        int rc = cr_box_mean_f32(&cd, &cs, mode);
        if (rv != rc) mismatch("ret", (u32)t, (u32)rv, (u32)rc);
        cmp_buf("out", (unsigned char *)vd.data, (unsigned char *)cd.data,
                sizeof(float) * w * h, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_box_mean_f32\n");
}

/* ---- batch 42: stack-based Hoare quicksort over 8-byte records ---------- */
static void test_sort_records(void)
{
    typedef int (WINAPI *v_i_piii)(void *, int, int, int);
    v_i_piii v = (v_i_piii)fn_at(RVA(0x18003bf90));
    begin("cr_sort_records");
    int bad = g_fail;
    enum { MAXN = 64 };
    struct rec { uint32_t v, k; } rv[MAXN], rc[MAXN];
    for (int t = 0; t < 20000; t++) {
        int n = (int)(rnd() % (MAXN + 1));
        int kt = (int)(rnd() % 2);
        int dir = (int)(rnd() % 2);
        for (int i = 0; i < n; i++) {
            rv[i].v = rnd();
            if (kt == 1) {
                /* finite float keys (many duplicates); NaN would make the
                 * vendor's partition non-terminating, so avoid it */
                if (t % 5 == 0) {
                    float f = (float)(int32_t)rnd() * 1e-3f;
                    memcpy(&rv[i].k, &f, 4);
                } else {
                    float f = (float)((int)(rnd() % 17) - 8);
                    memcpy(&rv[i].k, &f, 4);
                }
            } else {
                rv[i].k = (t % 5 == 0)
                              ? rnd()
                              : (uint32_t)(int32_t)((int)(rnd() % 17) - 8);
            }
            rc[i] = rv[i];
        }
        int retv = v(rv, n, kt, dir);
        int retc = cr_sort_records(rc, n, kt, dir);
        if (retv != retc) mismatch("ret", (u32)t, (u32)retv, (u32)retc);
        cmp_buf("rec", (unsigned char *)rv, (unsigned char *)rc,
                sizeof(rv[0]) * n, (u32)t);
    }
    /* invalid selectors -> 0x69 */
    for (int kt = -1; kt <= 3; kt++)
        for (int dir = -1; dir <= 3; dir++) {
            if ((kt == 0 || kt == 1) && (dir == 0 || dir == 1)) continue;
            struct rec a[2] = {{1, 1}, {2, 2}}, b[2] = {{1, 1}, {2, 2}};
            int rv = v(a, 2, kt, dir);
            int rc = cr_sort_records(b, 2, kt, dir);
            if (rv != rc) mismatch("guard-ret", (u32)(kt * 8 + dir),
                                   (u32)rv, (u32)rc);
        }
    /* n >= 0x100001 is a no-op returning 1 */
    {
        struct rec *big = malloc(sizeof(struct rec) * 0x100001u);
        if (big) {
            big[0].v = 7; big[0].k = 9;
            big[0x100000u].v = 3; big[0x100000u].k = 1;
            int rv = v(big, 0x100001, 0, 0);
            if (rv != 1) mismatch("big-ret", 0, (u32)rv, 1);
            if (big[0].v != 7 || big[0].k != 9 ||
                big[0x100000u].v != 3 || big[0x100000u].k != 1)
                mismatch("big-untouched", 0, 0, 1);
            free(big);
        }
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_sort_records\n");
}

/* ---- batch 43: short-line orientation fit ------------------------------- */
static void test_line_orient_fit(void)
{
    typedef void (WINAPI *v_v_pii_ff_ppp)(float *, int, int, float, float,
                                          const void *, float *, float *);
    v_v_pii_ff_ppp v = (v_v_pii_ff_ppp)fn_at(RVA(0x180020230));
    begin("cr_line_orient_fit");
    int bad = g_fail;
    enum { MAXW = 24, MAXH = 20, PAD = 64 };
    enum { MAXP = MAXW + 4, MAXQ = MAXH + 4 };
    struct desc { int stride, pad; const int16_t *data; int w, h, offA, offB; } vd, cd;
    static int16_t buf[PAD + MAXP * MAXQ + 64];
    static float vsamp[10], csamp[10], vm[27], cm[27], vr[9], cr[9];
    for (int t = 0; t < 20000; t++) {
        int w = 1 + (int)(rnd() % MAXW);
        int h = 1 + (int)(rnd() % MAXH);
        int stride = w + (int)(rnd() % 4);
        int offA = (int)(rnd() % 3);
        int offB = (int)(rnd() % 3);
        for (int i = 0; i < PAD + MAXP * MAXQ + 64; i++)
            buf[i] = (int16_t)(int)(rnd() % 2001) - 1000;
        const int16_t *img = buf + PAD;   /* leading pad absorbs negative idx */
        vd.stride = cd.stride = stride;
        vd.pad = cd.pad = 0;
        vd.data = cd.data = img;
        vd.w = cd.w = w;
        vd.h = cd.h = h;
        vd.offA = cd.offA = offA;
        vd.offB = cd.offB = offB;
        int px = (int)(rnd() % (w + 4)) - 2;
        int py = (int)(rnd() % (h + 4)) - 2;
        float sx = (float)((int)(rnd() % 9) - 4) * 0.25f;
        float sy = (float)((int)(rnd() % 9) - 4) * 0.25f;
        memset(vsamp, 0x5A, sizeof vsamp); memset(csamp, 0x5A, sizeof csamp);
        memset(vm, 0x5A, sizeof vm); memset(cm, 0x5A, sizeof cm);
        memset(vr, 0x5A, sizeof vr); memset(cr, 0x5A, sizeof cr);
        v(vsamp, px, py, sx, sy, &vd, vm, vr);
        cr_line_orient_fit(csamp, px, py, sx, sy, &cd, cm, cr);
        cmp_buf("samp", (unsigned char *)vsamp, (unsigned char *)csamp,
                sizeof(float) * 10, (u32)t);
        cmp_buf("m", (unsigned char *)vm, (unsigned char *)cm,
                sizeof(float) * 27, (u32)t);
        cmp_buf("res", (unsigned char *)vr, (unsigned char *)cr,
                sizeof(float) * 9, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_line_orient_fit\n");
}

/* ---- batch 44: fixed 7-tap reflect-101 FIR down each column ------------- */
static void test_vfir7_cols(void)
{
    typedef void (WINAPI *v_v_pppii)(int16_t *, const int16_t *,
                                     const int16_t *, int, int);
    v_v_pppii v = (v_v_pppii)fn_at(RVA(0x1800433b0));
    begin("cr_vfir7_cols");
    int bad = g_fail;
    enum { MAXN = 32, MAXS = 40, PAD = MAXN * (MAXS + 4) };
    static int16_t inv[PAD], coefv[7], outv[PAD], outc[PAD];
    for (int t = 0; t < 20000; t++) {
        int n = 1 + (int)(rnd() % MAXN);
        int sel = 4 + (int)(rnd() % (MAXS - 3));  /* sel >= 4: reflect-101 domain */
        for (int i = 0; i < 7; i++) coefv[i] = (int16_t)rnd();
        for (int i = 0; i < PAD; i++) inv[i] = (int16_t)rnd();
        memset(outv, 0x5A, sizeof outv);
        memset(outc, 0x5A, sizeof outc);
        v(outv, inv, coefv, n, sel);
        cr_vfir7_cols(outc, inv, coefv, n, sel);
        cmp_buf("out", (unsigned char *)outv, (unsigned char *)outc,
                sizeof(int16_t) * n * sel, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_vfir7_cols\n");
}

/* ---- batch 45: separable 11x11 int16 FIR, one output row ---------------- */
static void test_sep11_row(void)
{
    typedef void (WINAPI *v_v_pupii)(int16_t *, const uint8_t *,
                                     const int16_t *, int, int);
    v_v_pupii v = (v_v_pupii)fn_at(RVA(0x18002e6a0));
    begin("cr_sep11_row");
    int bad = g_fail;
    enum { MAXW = 40, MAXS = 8, PAD = 5 * MAXS + 16, BUF = PAD + MAXW + 64 };
    static uint8_t inbuf[BUF];
    static int16_t coefv[11], outv[128], outc[128];
    for (int t = 0; t < 20000; t++) {
        int w = (int)(rnd() % (MAXW + 1));
        int s = 1 + (int)(rnd() % MAXS);
        const uint8_t *in = inbuf + PAD;   /* pad absorbs negative indices */
        for (int i = 0; i < 11; i++) coefv[i] = (int16_t)rnd();
        for (int i = 0; i < BUF; i++) inbuf[i] = (uint8_t)rnd();
        memset(outv, 0x5A, sizeof outv);
        memset(outc, 0x5A, sizeof outc);
        v(outv, in, coefv, w, s);
        cr_sep11_row(outc, in, coefv, w, s);
        cmp_buf("out", (unsigned char *)outv, (unsigned char *)outc,
                sizeof(int16_t) * (w + 10), (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_sep11_row\n");
}

/* ---- batch 46: per-pixel kernel-bank 2D correlation --------------------- */
static void test_corr_kbank(void)
{
    typedef int (WINAPI *v_i_piiiiiiiii)(int32_t *, const int16_t *,
                                         const int16_t *, const int16_t *,
                                         long long, int, int, int, int, int);
    v_i_piiiiiiiii v = (v_i_piiiiiiiii)fn_at(RVA(0x180038ac0));
    begin("cr_corr_kbank");
    int bad = g_fail;
    enum { MAXOW = 6, MAXOH = 6, MAXK = 19, NK = 4, MAXIN = 64 * 64 };
    static const int ks[] = { 1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 2, 4, 6, 8 };
    static int32_t outv[64], outc[64];
    static int16_t in[MAXIN], kbank[NK * MAXK * MAXK], selarr[64];
    for (int t = 0; t < 20000; t++) {
        int K = ks[rnd() % (sizeof ks / sizeof ks[0])];
        int ow = 1 + (int)(rnd() % MAXOW);
        int oh = 1 + (int)(rnd() % MAXOH);
        /* The K==17 body processes output columns in groups of 4 aligned to
         * ow-4, so for ow < 4 it writes before the output buffer (vendor quirk);
         * the well-defined domain is ow >= 4. */
        if (K == 17 && ow < 4) ow = 4;
        int iw = ow - 1 + K + (int)(rnd() % 3);
        int ih = oh - 1 + K + (int)(rnd() % 3);
        if (iw > 64 || ih > 64) continue;
        for (int i = 0; i < NK * K * K; i++) kbank[i] = (int16_t)rnd();
        for (int i = 0; i < ow * oh; i++) selarr[i] = (int16_t)(rnd() % NK);
        for (int i = 0; i < iw * ih; i++) in[i] = (int16_t)rnd();
        memset(outv, 0x5A, sizeof outv);
        memset(outc, 0x5A, sizeof outc);
        int rv = v(outv, in, kbank, selarr, 0, ow, oh, iw, ih, K);
        int rc = cr_corr_kbank(outc, in, kbank, selarr, 0, ow, oh, iw, ih, K);
        if ((u32)rv != (u32)rc) mismatch("ret", (u32)t, (u32)rv, (u32)rc);
        cmp_buf("out", (unsigned char *)outv, (unsigned char *)outc,
                sizeof(int32_t) * ow * oh, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_corr_kbank\n");
}

/* ---- batch 47: object-tree lifecycle helpers + image-data accessors ------ */
/* Allocate a "sized" block (payload offset sz, 1-byte prefix = sz) the same way
 * cr_sized_free expects, once per allocator. */
static void *v_sized_alloc(v_i_ppz vmalloc, size_t S, int sz)
{
    void *b = NULL;
    vmalloc(&b, S);
    memset(b, 0, S);
    ((uint8_t *)b)[sz - 1] = (uint8_t)sz;
    return (uint8_t *)b + sz;
}
static void *c_sized_alloc(size_t S, int sz)
{
    void *b = NULL;
    cr_malloc(&b, S);
    memset(b, 0, S);
    ((uint8_t *)b)[sz - 1] = (uint8_t)sz;
    return (uint8_t *)b + sz;
}

static void test_tree_helpers(void)
{
    v_i_ppz vmalloc = (v_i_ppz)fn_at(RVA(0x180002fe0));
    v_v_p   vsfree  = (v_v_p)fn_at(RVA(0x18003bf40));
    typedef int  (WINAPI *v_meta_put_i16)(void *, u32, u32, char);
    typedef void *(WINAPI *v_p_ppu)(const void *, u32);
    typedef void (WINAPI *v_v_pp2)(const void *, void *);

    /* --- cr_meta_put_i16 (0x18004b640): tail-call to the uint16 store ------ */
    {
        v_meta_put_i16 v = (v_meta_put_i16)fn_at(RVA(0x18004b640));
        begin("cr_meta_put_i16");
        int bad = g_fail;
        for (int trial = 0; trial < 20000; trial++) {
            u8 sv[128], sc[128];
            memset(sv, 0xAA, sizeof sv); memset(sc, 0xAA, sizeof sc);
            u32 cap  = (rnd() % 120u) + 8u;
            u32 used = rnd() % (cap + 1u);
            if (used > 100u) used = 100u;
            for (u32 off = 0; off < used && off + 12 <= 100; ) {
                *(u32 *)(sv + 0xc + off) = rnd() % 6u;
                *(u32 *)(sv + 0xc + off + 4) = 4;
                *(u32 *)(sv + 0xc + off + 8) = rnd();
                off += 12;
            }
            memcpy(sc, sv, sizeof sv);
            *(u32 *)(sv + 4) = cap; *(u32 *)(sv + 8) = used; *(u32 *)(sv + 0) = 8;
            *(u32 *)(sc + 4) = cap; *(u32 *)(sc + 8) = used; *(u32 *)(sc + 0) = 8;
            u32 key = rnd() % 6u, val = rnd(), ow = rnd() & 1u;
            int rv = v(sv, key, val, (char)ow);
            int rc = cr_meta_put_i16(sc, key, val, (bool)ow);
            if (rv != rc || memcmp(sv, sc, sizeof sv) != 0)
                mismatch("put16", ((u64)key << 32) | val, (u32)rv, (u32)rc);
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_meta_put_i16\n");
    }

    /* --- cr_cleanup_ptr8_a / _b (0x18000fc20, 0x180011a50) ----------------- */
    {
        static const char *nm[2] = { "cr_cleanup_ptr8_a", "cr_cleanup_ptr8_b" };
        v_v_p vfn[2] = { (v_v_p)fn_at(RVA(0x18000fc20)),
                         (v_v_p)fn_at(RVA(0x180011a50)) };
        void (*cfn[2])(void *) = { cr_cleanup_ptr8_a, cr_cleanup_ptr8_b };
        for (int k = 0; k < 2; k++) {
            begin(nm[k]);
            int bad = g_fail;
            for (int t = 0; t < 8000; t++) {
                u8 ov[0x20], oc[0x20];
                memset(ov, 0x5A, sizeof ov); memset(oc, 0x5A, sizeof oc);
                if (rnd() & 1) {
                    size_t S = 2 + rnd() % 64u;
                    int sz = 1 + (int)(rnd() % (u32)S);
                    *(void **)(ov + 8) = v_sized_alloc(vmalloc, S, sz);
                    *(void **)(oc + 8) = c_sized_alloc(S, sz);
                } else {
                    *(void **)(ov + 8) = NULL; *(void **)(oc + 8) = NULL;
                }
                vfn[k](ov); cfn[k](oc);
                if (*(void **)(ov + 8) != NULL || *(void **)(oc + 8) != NULL)
                    mismatch("ptr8-null", (u32)t,
                             (u64)*(void **)(ov + 8), (u64)*(void **)(oc + 8));
                if (memcmp(ov, oc, 8) || memcmp(ov + 16, oc + 16, sizeof ov - 16))
                    mismatch("ptr8-other", (u32)t, 0, 0);
            }
            vfn[k](NULL); cfn[k](NULL);            /* NULL object: no-op */
            if (g_fail == bad) end(); else printf("  FAIL %s\n", nm[k]);
        }
    }

    /* --- cr_cleanup_ptr8_clear (0x180024760) ------------------------------- */
    {
        v_v_p v = (v_v_p)fn_at(RVA(0x180024760));
        begin("cr_cleanup_ptr8_clear");
        int bad = g_fail;
        for (int t = 0; t < 8000; t++) {
            u8 ov[0x20], oc[0x20];
            memset(ov, 0x5A, sizeof ov); memset(oc, 0x5A, sizeof oc);
            if (rnd() & 1) {
                size_t S = 2 + rnd() % 64u;
                int sz = 1 + (int)(rnd() % (u32)S);
                *(void **)(ov + 8) = v_sized_alloc(vmalloc, S, sz);
                *(void **)(oc + 8) = c_sized_alloc(S, sz);
            } else {
                *(void **)(ov + 8) = NULL; *(void **)(oc + 8) = NULL;
            }
            v(ov); cr_cleanup_ptr8_clear(oc);
            if (*(void **)(ov + 8) != NULL || *(void **)(oc + 8) != NULL)
                mismatch("clear-null", (u32)t,
                         (u64)*(void **)(ov + 8), (u64)*(void **)(oc + 8));
            if (memcmp(ov, oc, 8) || memcmp(ov + 16, oc + 16, sizeof ov - 16))
                mismatch("clear-other", (u32)t, 0, 0);
        }
        v(NULL); cr_cleanup_ptr8_clear(NULL);
        if (g_fail == bad) end(); else printf("  FAIL cr_cleanup_ptr8_clear\n");
    }

    /* --- cr_obj_zero_free (0x18001f9f0) ------------------------------------ */
    {
        v_v_p v = (v_v_p)fn_at(RVA(0x18001f9f0));
        begin("cr_obj_zero_free");
        int bad = g_fail;
        for (int t = 0; t < 8000; t++) {
            size_t S = 32 + rnd() % 64u;          /* room for the 12-byte zero */
            int sz = 1 + (int)(rnd() % (u32)(S - 16));
            void *vp = v_sized_alloc(vmalloc, S, sz);
            void *cp = c_sized_alloc(S, sz);
            void *ov = vp, *oc = cp;
            v(&ov); cr_obj_zero_free(&oc);
            if (ov != NULL || oc != NULL)
                mismatch("zf-null", (u32)t, (u64)ov, (u64)oc);
            void *nv = NULL, *nc = NULL;
            v(&nv); cr_obj_zero_free(&nc);        /* NULL payload: no-op */
            if (nv != NULL || nc != NULL)
                mismatch("zf-null2", (u32)t, (u64)nv, (u64)nc);
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_obj_zero_free\n");
    }

    /* --- cr_free_ptr_struct (0x180017170) ---------------------------------- */
    {
        v_v_p v = (v_v_p)fn_at(RVA(0x180017170));
        static const int offs[] = { 0x00,0x08,0x10,0x18,0x20,0x28,0x30,0x70 };
        begin("cr_free_ptr_struct");
        int bad = g_fail;
        for (int t = 0; t < 4000; t++) {
            u8 ov[0x80], oc[0x80];
            memset(ov, 0x5A, sizeof ov); memset(oc, 0x5A, sizeof oc);
            for (int i = 0; i < 8; i++) {
                if (rnd() & 1) {
                    size_t S = 2 + rnd() % 64u;
                    int sz = 1 + (int)(rnd() % (u32)S);
                    *(void **)(ov + offs[i]) = v_sized_alloc(vmalloc, S, sz);
                    *(void **)(oc + offs[i]) = c_sized_alloc(S, sz);
                } else {
                    *(void **)(ov + offs[i]) = NULL;
                    *(void **)(oc + offs[i]) = NULL;
                }
            }
            v(ov); cr_free_ptr_struct(oc);
            if (memcmp(ov, oc, sizeof ov) != 0)
                mismatch("fps", (u32)t, 0, 0);
        }
        v(NULL); cr_free_ptr_struct(NULL);
        if (g_fail == bad) end(); else printf("  FAIL cr_free_ptr_struct\n");
    }

    /* --- cr_malloc_aligned16 (0x1800100c0) --------------------------------- */
    {
        v_i_ppz v = (v_i_ppz)fn_at(RVA(0x1800100c0));
        begin("cr_malloc_aligned16");
        int bad = g_fail;
        for (int t = 0; t < 8000; t++) {
            size_t sz = (rnd() % 5u == 0) ? 0 : (size_t)(rnd() % 4096u);
            void *pv = (void *)0xdead, *pc = (void *)0xdead;
            int rv = v(&pv, sz);
            int rc = cr_malloc_aligned16(&pc, sz);
            if (rv != rc) mismatch("al-status", sz, (u32)rv, (u32)rc);
            if ((pv == NULL) != (pc == NULL))
                mismatch("al-null", sz, pv != NULL, pc != NULL);
            if (rv == 0) {
                if (((uintptr_t)pv & 0xf) || ((uintptr_t)pc & 0xf))
                    mismatch("al-align", sz, (u64)pv & 0xf, (u64)pc & 0xf);
                if (*(uint8_t *)((uint8_t *)pv - 1) != *(uint8_t *)((uint8_t *)pc - 1))
                    mismatch("al-prefix", sz, *(uint8_t *)((uint8_t *)pv - 1),
                             *(uint8_t *)((uint8_t *)pc - 1));
                vsfree(&pv); cr_sized_free(&pc);
                if (pv != NULL || pc != NULL)
                    mismatch("al-freenull", sz, (u64)pv, (u64)pc);
            }
        }
        {   /* size + 0x10 wraps to 0 -> cr_malloc returns 1 -> status 2 */
            void *pv = (void *)0xdead, *pc = (void *)0xdead;
            int rv = v(&pv, (size_t)-0x10);
            int rc = cr_malloc_aligned16(&pc, (size_t)-0x10);
            if (rv != rc) mismatch("al-zero", 0, (u32)rv, (u32)rc);
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_malloc_aligned16\n");
    }

    /* --- cr_image_get_dp (0x18004a890) ------------------------------------- */
    {
        v_p_ppu v = (v_p_ppu)fn_at(RVA(0x18004a890));
        static u8 defs[0x10 + 0x16 * 8 + 8];
        static u8 bufs[0x16][0x20];
        begin("cr_image_get_dp");
        int bad = g_fail;
        for (int t = 0; t < 8000; t++) {
            memset(defs, 0x5A, sizeof defs);
            for (int i = 0; i < 0x16; i++) {
                int kind = (int)(rnd() % 4u);
                void *p = NULL;
                if (kind != 0) {
                    memset(bufs[i], 0, sizeof bufs[i]);
                    *(u32 *)bufs[i] = (kind == 1) ? 0u
                                    : (kind == 2) ? 8u : (rnd() & 0x1fu);
                    p = bufs[i];
                }
                *(void **)(defs + 0x10 + i * 8) = p;
            }
            u32 idx = rnd() % 24u;                /* includes out-of-range */
            void *rv = v(defs, idx);
            void *rc = cr_image_get_dp(defs, idx);
            if (rv != rc)                         /* same input -> same pointer */
                mismatch("dp", idx, (u64)rv, (u64)rc);
        }
        if (v(NULL, 0) != NULL || cr_image_get_dp(NULL, 0) != NULL)
            mismatch("dp-nulldefs", 0, 0, 0);
        if (g_fail == bad) end(); else printf("  FAIL cr_image_get_dp\n");
    }

    /* --- cr_image_buf_desc (0x18004ab90) ----------------------------------- */
    {
        v_v_pp2 v = (v_v_pp2)fn_at(RVA(0x18004ab90));
        static u8 ctx[0x20], pb[0x20];
        begin("cr_image_buf_desc");
        int bad = g_fail;
        for (int t = 0; t < 8000; t++) {
            u8 ov[0x20], oc[0x20];
            memset(ctx, 0x5A, sizeof ctx);
            int kind = (int)(rnd() % 4u);
            u8 *p = NULL;
            if (kind != 0) {
                memset(pb, 0, sizeof pb);
                *(u32 *)pb = (kind == 1) ? 1u : (rnd() & 0x1fu);
                *(u32 *)(pb + 4) = rnd();
                *(u32 *)(pb + 0xc) = rnd();
                p = pb;
            }
            *(void **)(ctx + 0x18) = p;
            memset(ov, 0xA5, sizeof ov); memset(oc, 0xA5, sizeof oc);
            v(ctx, ov); cr_image_buf_desc(ctx, oc);
            if (memcmp(ov, oc, sizeof ov) != 0)   /* shared pb -> +8 matches */
                mismatch("bd", (u32)t, 0, 0);
        }
        {
            u8 ov[0x20], oc[0x20];
            memset(ov, 0xA5, sizeof ov); memset(oc, 0xA5, sizeof oc);
            v(NULL, ov); cr_image_buf_desc(NULL, oc);
            if (memcmp(ov, oc, sizeof ov) != 0)
                mismatch("bd-nullctx", 0, 0, 0);
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_image_buf_desc\n");
    }
}

/* ---- batch 48: object constructors / flag-driven destructors ------------ */
static void test_tree_ctors(void)
{
    v_i_ppz vmalloc = (v_i_ppz)fn_at(RVA(0x180002fe0));
    v_v_p   vsfree  = (v_v_p)fn_at(RVA(0x18003bf40));

    /* --- cr_free_obj_28_8 (0x18000ee40) ------------------------------------ */
    {
        v_v_p v = (v_v_p)fn_at(RVA(0x18000ee40));
        begin("cr_free_obj_28_8");
        int bad = g_fail;
        for (int t = 0; t < 8000; t++) {
            u8 ov[0x58], oc[0x58];
            memset(ov, 0x5A, sizeof ov); memset(oc, 0x5A, sizeof oc);
            u8 flag = (u8)(rnd() & 1u);
            *(u8 *)(ov + 0x50) = flag; *(u8 *)(oc + 0x50) = flag;
            if (rnd() & 1) {
                size_t S = 2 + rnd() % 64u; int sz = 1 + (int)(rnd() % (u32)S);
                *(void **)(ov + 0x28) = v_sized_alloc(vmalloc, S, sz);
                *(void **)(oc + 0x28) = c_sized_alloc(S, sz);
            } else { *(void **)(ov + 0x28) = NULL; *(void **)(oc + 0x28) = NULL; }
            if (rnd() & 1) {
                size_t S = 2 + rnd() % 64u; int sz = 1 + (int)(rnd() % (u32)S);
                *(void **)(ov + 8) = v_sized_alloc(vmalloc, S, sz);
                *(void **)(oc + 8) = c_sized_alloc(S, sz);
            } else { *(void **)(ov + 8) = NULL; *(void **)(oc + 8) = NULL; }
            v(ov); cr_free_obj_28_8(oc);
            if (*(void **)(ov + 0x28) != NULL || *(void **)(oc + 0x28) != NULL)
                mismatch("28-null", (u32)t, (u64)*(void **)(ov + 0x28), (u64)*(void **)(oc + 0x28));
            if ((*(void **)(ov + 8) != NULL) != (*(void **)(oc + 8) != NULL))
                mismatch("8-null", (u32)t, *(void **)(ov + 8) != NULL, *(void **)(oc + 8) != NULL);
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_free_obj_28_8\n");
    }

    /* --- cr_meta_set_slot (0x1800303d0) ------------------------------------ */
    {
        typedef uint8_t (WINAPI *v_u8_ppiii)(const void *, u32, int, int);
        v_u8_ppiii v = (v_u8_ppiii)fn_at(RVA(0x1800303d0));
        static u8 vdefs[0x10 + 0x16 * 8], cdefs[0x10 + 0x16 * 8];
        static u8 vst[128], cst[128], vother[64], cother[64];
        begin("cr_meta_set_slot");
        int bad = g_fail;
        for (int t = 0; t < 20000; t++) {
            memset(vdefs, 0x5A, sizeof vdefs); memset(cdefs, 0x5A, sizeof cdefs);
            memset(vst, 0, sizeof vst); memset(cst, 0, sizeof cst);
            u32 cap  = (rnd() % 100u) + 8u;
            u32 used = rnd() % (cap + 1u);
            if (used > 90u) used = 90u;
            for (u32 off = 0; off + 12 <= used; off += 12) {
                *(u32 *)(vst + 0xc + off) = rnd() % 6u;
                *(u32 *)(vst + 0xc + off + 4) = 4;
                *(u32 *)(vst + 0xc + off + 8) = rnd();
            }
            memcpy(cst, vst, sizeof vst);
            /* debug-class tag: 0, 9, 11, 13 all satisfy cr_buf_is_debug_class */
            u32 ty = (rnd() & 1u) ? 0u : (9u + 2u * (rnd() % 3u));
            *(u32 *)(vst + 0) = ty; *(u32 *)(vst + 4) = cap; *(u32 *)(vst + 8) = used;
            *(u32 *)(cst + 0) = ty; *(u32 *)(cst + 4) = cap; *(u32 *)(cst + 8) = used;
            memset(vother, 0x33, sizeof vother); memset(cother, 0x33, sizeof cother);

            u32 idx = rnd() % 24u;            /* includes out-of-range */
            int kind = (int)(rnd() % 3u);     /* 0 null, 1 non-debug, 2 store */
            void *vp = NULL, *cp = NULL;
            if (kind == 1) {
                *(u32 *)vother = 1u + (rnd() % 8u);
                *(u32 *)cother = *(u32 *)vother;
                vp = vother; cp = cother;
            } else if (kind == 2) { vp = vst; cp = cst; }
            if (idx < 0x16) {
                *(void **)(vdefs + 0x10 + idx * 8) = vp;
                *(void **)(cdefs + 0x10 + idx * 8) = cp;
            }
            int key = (int)rnd(), val = (int)rnd();
            uint8_t rv = v(vdefs, idx, key, val);
            uint8_t rc = cr_meta_set_slot(cdefs, idx, key, val);
            if (rv != rc) mismatch("mss-ret", (u32)t, rv, rc);
            if (memcmp(vst, cst, sizeof vst) != 0) mismatch("mss-store", (u32)t, 0, 0);
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_meta_set_slot\n");
    }

    /* --- cr_obj_init_58 (0x180046b80) -------------------------------------- */
    {
        typedef uint64_t (WINAPI *v_u64_p)(void *);
        v_u64_p v = (v_u64_p)fn_at(RVA(0x180046b80));
        begin("cr_obj_init_58");
        int bad = g_fail;
        for (int t = 0; t < 4000; t++) {
            u8 ov[0x58], oc[0x58];
            memset(ov, 0x5A, sizeof ov); memset(oc, 0x5A, sizeof oc);
            uint64_t rv = v(ov);
            uint64_t rc = cr_obj_init_58(oc);
            if (rv != rc) mismatch("init58-ret", (u32)t, rv, rc);
            if (memcmp(ov, oc, sizeof ov) != 0) mismatch("init58", (u32)t, 0, 0);
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_obj_init_58\n");
    }

    /* --- cr_alloc_handle (0x18002ad90) ------------------------------------- */
    {
        v_v_p v = (v_v_p)fn_at(RVA(0x18002ad90));
        begin("cr_alloc_handle");
        int bad = g_fail;
        for (int t = 0; t < 4000; t++) {
            void *ov = (void *)0xdead, *oc = (void *)0xdead;
            v(&ov); cr_alloc_handle(&oc);
            if ((ov == NULL) != (oc == NULL))
                mismatch("ah-null", (u32)t, ov != NULL, oc != NULL);
            if (ov) {
                /* only compare the bytes the function writes: +0x00..+0x0c and
                 * +0x10..+0x23 (0x0d..0x0f / 0x24..0x27 stay allocator garbage) */
                if (memcmp(ov, oc, 0x0d) != 0) mismatch("ah-0", (u32)t, 0, 0);
                if (memcmp((u8 *)ov + 0x10, (u8 *)oc + 0x10, 0x14) != 0)
                    mismatch("ah-1", (u32)t, 0, 0);
                vsfree(&ov); cr_sized_free(&oc);
            }
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_alloc_handle\n");
    }

    /* --- cr_alloc_400 (0x18003fb70) ---------------------------------------- */
    {
        v_pp v = (v_pp)fn_at(RVA(0x18003fb70));
        begin("cr_alloc_400");
        int bad = g_fail;
        for (int t = 0; t < 4000; t++) {
            void *ov = (void *)0xdead, *oc = (void *)0xdead;
            int rv = v(&ov); int rc = cr_alloc_400(&oc);
            if (rv != rc) mismatch("a400-ret", (u32)t, (u32)rv, (u32)rc);
            if (rv == 0) {
                if (memcmp(ov, oc, 0x38) != 0) mismatch("a400", (u32)t, 0, 0);
                vsfree(&ov); cr_sized_free(&oc);
            }
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_alloc_400\n");
    }

    /* --- cr_image_alloc_u8 / _s16 (0x18001d820, 0x18003d790) --------------- */
    {
        typedef int (WINAPI *v_i_pii)(int *, int, int);
        static const char *nm[2] = { "cr_image_alloc_u8", "cr_image_alloc_s16" };
        v_i_pii vf[2] = { (v_i_pii)fn_at(RVA(0x18001d820)),
                          (v_i_pii)fn_at(RVA(0x18003d790)) };
        int (*cf[2])(int *, int, int) = { cr_image_alloc_u8, cr_image_alloc_s16 };
        for (int k = 0; k < 2; k++) {
            begin(nm[k]);
            int bad = g_fail;
            for (int t = 0; t < 8000; t++) {
                int va[8], ca[8];
                memset(va, 0x5A, sizeof va); memset(ca, 0x5A, sizeof ca);
                int w = (int)(rnd() % 64u), h = (int)(rnd() % 64u);
                if (rnd() % 8u == 0) w = -(int)(rnd() % 4u);
                if (rnd() % 8u == 0) h = -(int)(rnd() % 4u);
                int rv = vf[k](va, w, h);
                int rc = cf[k](ca, w, h);
                if (rv != rc)
                    mismatch("ia-ret", ((u64)(u32)w << 32) | (u32)h, (u32)rv, (u32)rc);
                if (memcmp(va, ca, 8) != 0 ||
                    memcmp((u8 *)va + 0x0c, (u8 *)ca + 0x0c, 0x14) != 0)
                    mismatch("ia-fields", (u32)t, 0, 0);
                if ((*(void **)(va + 2) != NULL) != (*(void **)(ca + 2) != NULL))
                    mismatch("ia-ptr", (u32)t, *(void **)(va + 2) != NULL,
                             *(void **)(ca + 2) != NULL);
                if (rv == 0 && *(void **)(va + 2)) {   /* valid only on success */
                    if (((uintptr_t)*(void **)(va + 2) & 0xf) ||
                        ((uintptr_t)*(void **)(ca + 2) & 0xf))
                        mismatch("ia-align", (u32)t, 0, 0);
                    vsfree((void **)(va + 2)); cr_sized_free((void **)(ca + 2));
                }
            }
            if (g_fail == bad) end(); else printf("  FAIL %s\n", nm[k]);
        }
    }

    /* --- cr_free_obj_flags (0x18000f570) ----------------------------------- */
    {
        v_v_p v = (v_v_p)fn_at(RVA(0x18000f570));
        static const int sl[4] = { 0x18, 0x58, 0x88, 0x38 };
        begin("cr_free_obj_flags");
        int bad = g_fail;
        for (int t = 0; t < 6000; t++) {
            u8 ov[0x98], oc[0x98];
            memset(ov, 0x5A, sizeof ov); memset(oc, 0x5A, sizeof oc);
            u32 fl = rnd() & 0x3ffu;
            *(u32 *)(ov + 0x74) = fl; *(u32 *)(oc + 0x74) = fl;
            for (int i = 0; i < 4; i++) {
                if (rnd() & 1) {
                    size_t S = 2 + rnd() % 64u; int sz = 1 + (int)(rnd() % (u32)S);
                    *(void **)(ov + sl[i]) = v_sized_alloc(vmalloc, S, sz);
                    *(void **)(oc + sl[i]) = c_sized_alloc(S, sz);
                } else { *(void **)(ov + sl[i]) = NULL; *(void **)(oc + sl[i]) = NULL; }
            }
            v(ov); cr_free_obj_flags(oc);
            for (int i = 0; i < 4; i++)
                if ((*(void **)(ov + sl[i]) != NULL) != (*(void **)(oc + sl[i]) != NULL))
                    mismatch("fof", (u32)i, *(void **)(ov + sl[i]) != NULL,
                             *(void **)(oc + sl[i]) != NULL);
            if (*(u32 *)(ov + 0x74) != *(u32 *)(oc + 0x74))
                mismatch("fof-flags", (u32)t, *(u32 *)(ov + 0x74), *(u32 *)(oc + 0x74));
        }
        v(NULL); cr_free_obj_flags(NULL);
        if (g_fail == bad) end(); else printf("  FAIL cr_free_obj_flags\n");
    }

    /* --- cr_bitmap_alloc (0x180029750) ------------------------------------- */
    {
        typedef int (WINAPI *v_i_ppuu)(u32 *, u32, u32);
        v_i_ppuu v = (v_i_ppuu)fn_at(RVA(0x180029750));
        begin("cr_bitmap_alloc");
        int bad = g_fail;
        for (int t = 0; t < 6000; t++) {
            u32 va[8], ca[8];
            memset(va, 0x5A, sizeof va); memset(ca, 0x5A, sizeof ca);
            int w = (int)(rnd() % 200u), h = (int)(rnd() % 40u);
            if (rnd() % 10u == 0) w = -(int)(rnd() % 4u);
            if (rnd() % 10u == 0) h = -(int)(rnd() % 4u);
            int rv = v(va, (u32)w, (u32)h);
            int rc = cr_bitmap_alloc(ca, (u32)w, (u32)h);
            if (rv != rc)
                mismatch("ba-ret", ((u64)(u32)w << 32) | (u32)h, (u32)rv, (u32)rc);
            if (va[0] != ca[0] || va[1] != ca[1] || va[3] != ca[3] ||
                va[4] != ca[4] || va[5] != ca[5] || va[6] != ca[6] || va[7] != ca[7])
                mismatch("ba-fields", (u32)t, 0, 0);
            if ((*(void **)(va + 2) != NULL) != (*(void **)(ca + 2) != NULL))
                mismatch("ba-ptr", (u32)t, 0, 0);
            if (rv == 0 && *(void **)(va + 2)) {   /* valid only on success */
                int r = (int)(((u32)w + 0x1fu) >> 5);
                size_t nb = (size_t)r * (size_t)h * 4;
                if (nb > 0 && memcmp(*(void **)(va + 2), *(void **)(ca + 2), nb) != 0)
                    mismatch("ba-zero", (u32)t, 0, 0);
                vsfree((void **)(va + 2)); cr_sized_free((void **)(ca + 2));
            }
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_bitmap_alloc\n");
    }
}

/* ---- batch 49: higher-level destructors / accessors --------------------- */
static void test_tree_higher(void)
{
    v_i_ppz vmalloc = (v_i_ppz)fn_at(RVA(0x180002fe0));
    v_v_p   vsfree  = (v_v_p)fn_at(RVA(0x18003bf40));

    /* --- cr_clz_or32 (0x180039390) ----------------------------------------- */
    {
        typedef int (WINAPI *v_i_u)(uint32_t);
        v_i_u v = (v_i_u)fn_at(RVA(0x180039390));
        begin("cr_clz_or32");
        int bad = g_fail;
        for (int t = 0; t < 20000; t++) {
            uint32_t x = (rnd() % 8u == 0) ? 0u : rnd();
            if (rnd() % 16u == 0) x = 1u << (rnd() % 32u);
            int rv = v(x), rc = cr_clz_or32(x);
            if (rv != rc) mismatch("clz32", x, (u32)rv, (u32)rc);
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_clz_or32\n");
    }

    /* --- cr_free_8slot (0x18003d430) --------------------------------------- */
    {
        v_v_p v = (v_v_p)fn_at(RVA(0x18003d430));
        static const int sl[8] = { 0x00,0x08,0x10,0x18,0x28,0x38,0x48,0x50 };
        begin("cr_free_8slot");
        int bad = g_fail;
        for (int t = 0; t < 8000; t++) {
            u8 ov[0x58], oc[0x58];
            memset(ov, 0x5A, sizeof ov); memset(oc, 0x5A, sizeof oc);
            for (int i = 0; i < 8; i++) {
                if (rnd() & 1) {
                    size_t S = 2 + rnd() % 64u; int sz = 1 + (int)(rnd() % (u32)S);
                    *(void **)(ov + sl[i]) = v_sized_alloc(vmalloc, S, sz);
                    *(void **)(oc + sl[i]) = c_sized_alloc(S, sz);
                } else { *(void **)(ov + sl[i]) = NULL; *(void **)(oc + sl[i]) = NULL; }
            }
            v(ov); cr_free_8slot(oc);
            for (int i = 0; i < 8; i++)
                if (*(void **)(ov + sl[i]) != NULL || *(void **)(oc + sl[i]) != NULL)
                    mismatch("8slot-null", (u32)i,
                             (u64)*(void **)(ov + sl[i]), (u64)*(void **)(oc + sl[i]));
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_free_8slot\n");
    }

    /* --- cr_alloc_obj_58 (0x180035740) ------------------------------------- */
    {
        typedef int (WINAPI *v_i_pp)(void *);
        v_i_pp v = (v_i_pp)fn_at(RVA(0x180035740));
        begin("cr_alloc_obj_58");
        int bad = g_fail;
        for (int t = 0; t < 4000; t++) {
            void *ov = (void *)0xdead, *oc = (void *)0xdead;
            int rv = v(&ov), rc = cr_alloc_obj_58(&oc);
            if (rv != rc) mismatch("a58-ret", (u32)t, (u32)rv, (u32)rc);
            if ((ov == NULL) != (oc == NULL))
                mismatch("a58-null", (u32)t, ov != NULL, oc != NULL);
            if (rv == 0 && ov) {
                if (memcmp(ov, oc, 0x58) != 0) mismatch("a58", (u32)t, 0, 0);
                vsfree(&ov); cr_sized_free(&oc);
            }
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_alloc_obj_58\n");
    }

    /* --- cr_meta_get_slot (0x18003a8d0) ------------------------------------ */
    {
        typedef uint8_t (WINAPI *v_u8_ppipi)(const void *, u32, int, u32 *);
        v_u8_ppipi v = (v_u8_ppipi)fn_at(RVA(0x18003a8d0));
        static u8 vdefs[0x10 + 0x16 * 8], cdefs[0x10 + 0x16 * 8];
        static u8 vst[128], cst[128], vother[64], cother[64];
        begin("cr_meta_get_slot");
        int bad = g_fail;
        for (int t = 0; t < 20000; t++) {
            memset(vdefs, 0x5A, sizeof vdefs); memset(cdefs, 0x5A, sizeof cdefs);
            memset(vst, 0, sizeof vst); memset(cst, 0, sizeof cst);
            u32 cap  = (rnd() % 100u) + 8u;
            u32 used = rnd() % (cap + 1u);
            if (used > 90u) used = 90u;
            for (u32 off = 0; off + 12 <= used; off += 12) {
                *(u32 *)(vst + 0xc + off) = rnd() % 6u;
                *(u32 *)(vst + 0xc + off + 4) = 4;
                *(u32 *)(vst + 0xc + off + 8) = rnd();
            }
            memcpy(cst, vst, sizeof vst);
            u32 ty = (rnd() & 1u) ? 0u : (9u + 2u * (rnd() % 3u));
            *(u32 *)(vst + 0) = ty; *(u32 *)(vst + 4) = cap; *(u32 *)(vst + 8) = used;
            *(u32 *)(cst + 0) = ty; *(u32 *)(cst + 4) = cap; *(u32 *)(cst + 8) = used;
            memset(vother, 0x33, sizeof vother); memset(cother, 0x33, sizeof cother);

            u32 idx = rnd() % 24u;
            int kind = (int)(rnd() % 3u);
            void *vp = NULL, *cp = NULL;
            if (kind == 1) {
                *(u32 *)vother = 1u + (rnd() % 8u);
                *(u32 *)cother = *(u32 *)vother;
                vp = vother; cp = cother;
            } else if (kind == 2) { vp = vst; cp = cst; }
            if (idx < 0x16) {
                *(void **)(vdefs + 0x10 + idx * 8) = vp;
                *(void **)(cdefs + 0x10 + idx * 8) = cp;
            }
            int key = (int)rnd();
            u32 ov = 0xdeadbeef, oc = 0xdeadbeef;
            uint8_t rv = v(vdefs, idx, key, &ov);
            uint8_t rc = cr_meta_get_slot(cdefs, idx, key, &oc);
            if (rv != rc) mismatch("msg-ret", (u32)t, rv, rc);
            if (ov != oc) mismatch("msg-out", (u32)t, ov, oc);
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_meta_get_slot\n");
    }

    /* --- cr_subview_extend_s16 / _u8 (0x1800342d0, 0x180037f10) ------------ */
    {
        typedef int (WINAPI *v_i_piiiii)(void *, int, int, int, int);
        static const char *nm[2] = { "cr_subview_extend_s16", "cr_subview_extend_u8" };
        v_i_piiiii vf[2] = { (v_i_piiiii)fn_at(RVA(0x1800342d0)),
                             (v_i_piiiii)fn_at(RVA(0x180037f10)) };
        int (*cf[2])(cr_image *, int, int, int, int) =
            { cr_subview_extend_s16, cr_subview_extend_u8 };
        const int BUFW = 128, BUFH = 128;
        for (int k = 0; k < 2; k++) {
            begin(nm[k]);
            int bad = g_fail;
            for (int t = 0; t < 20000; t++) {
                unsigned char va[0x20], ca[0x20];
                int w = 64, h = 64, offx = 32, offy = 32;
                int tp = (int)(rnd() % 40u), bt = (int)(rnd() % 40u);
                int lf = (int)(rnd() % 40u), rt = (int)(rnd() % 40u);
                memset(va, 0, sizeof va); memset(ca, 0, sizeof ca);
                *(int *)(va + 0) = BUFW;  *(int *)(ca + 0) = BUFW;
                *(int *)(va + 4) = BUFH;  *(int *)(ca + 4) = BUFH;
                *(int *)(va + 0x10) = w;  *(int *)(ca + 0x10) = w;
                *(int *)(va + 0x14) = h;  *(int *)(ca + 0x14) = h;
                *(int *)(va + 0x18) = offx; *(int *)(ca + 0x18) = offx;
                *(int *)(va + 0x1c) = offy; *(int *)(ca + 0x1c) = offy;
                if (k == 0) {
                    int16_t pv[BUFW * BUFH], pc[BUFW * BUFH];
                    for (int i = 0; i < BUFW * BUFH; i++) { pv[i] = (int16_t)rnd(); pc[i] = pv[i]; }
                    *(void **)(va + 8) = pv;  *(void **)(ca + 8) = pc;
                    int rv = vf[k](va, tp, bt, lf, rt);
                    int rc = cf[k]((cr_image *)ca, tp, bt, lf, rt);
                    if (rv != rc) mismatch("se-ret", (u32)t, (u32)rv, (u32)rc);
                    if (rv == 0)
                        cmp_buf("se16", (unsigned char *)pv, (unsigned char *)pc,
                                sizeof pv, (u32)t);
                } else {
                    uint8_t pv[BUFW * BUFH], pc[BUFW * BUFH];
                    for (int i = 0; i < BUFW * BUFH; i++) { pv[i] = (uint8_t)rnd(); pc[i] = pv[i]; }
                    *(void **)(va + 8) = pv;  *(void **)(ca + 8) = pc;
                    int rv = vf[k](va, tp, bt, lf, rt);
                    int rc = cf[k]((cr_image *)ca, tp, bt, lf, rt);
                    if (rv != rc) mismatch("se-ret", (u32)t, (u32)rv, (u32)rc);
                    if (rv == 0)
                        cmp_buf("se8", (unsigned char *)pv, (unsigned char *)pc,
                                sizeof pv, (u32)t);
                }
            }
            if (g_fail == bad) end(); else printf("  FAIL %s\n", nm[k]);
        }
    }
}

/* ---- batch 50: nested destructor chain --------------------------------- */
/* The clean-room allocator (cr_malloc) is a normal SysV function, while the
 * vendor one is an ms_abi (WINAPI) DLL function.  The builders therefore take
 * a plain SysV allocator so the same code drives both sides; v_alloc bridges
 * to the vendor function through the ms_abi-typed pointer. */
static v_i_ppz g_vmalloc;
static int v_alloc(void **o, size_t n) { return g_vmalloc(o, n); }

static void *sized_alloc_via(int (*alloc)(void **, size_t), size_t S, int sz)
{
    void *b = NULL;
    alloc(&b, S);
    memset(b, 0, S);
    ((uint8_t *)b)[sz - 1] = (uint8_t)sz;
    return (uint8_t *)b + sz;
}

/* Build an 8-slot object (>= 0x58-byte payload) with randomly populated,
 * independently sized sub-slots, using the supplied allocator. */
static void *build_8slot(int (*alloc)(void **, size_t))
{
    size_t S = 0x80; int sz = 0x18;
    void *b = NULL;
    alloc(&b, S);
    memset(b, 0, S);
    ((uint8_t *)b)[sz - 1] = (uint8_t)sz;
    void *obj = (uint8_t *)b + sz;
    static const int sl[8] = { 0x00,0x28,0x38,0x08,0x18,0x10,0x48,0x50 };
    for (int i = 0; i < 8; i++) {
        if (rnd() & 1) {
            size_t S2 = 2 + rnd() % 64u; int sz2 = 1 + (int)(rnd() % (u32)S2);
            *(void **)((uint8_t *)obj + sl[i]) = sized_alloc_via(alloc, S2, sz2);
        } else {
            *(void **)((uint8_t *)obj + sl[i]) = NULL;
        }
    }
    return obj;
}

/* Build a 0x58-byte object for cr_free_obj_28_8 / cr_obj_destroy: flag byte at
 * +0x50, sized slots at +0x28 and +8, and (optionally) an 8-slot object at
 * +0x48 for the cr_free_8slot_wrap half of cr_obj_destroy. */
static void *build_obj58(int (*alloc)(void **, size_t), int with8slot)
{
    size_t S = 0x80; int sz = 0x18;
    void *b = NULL;
    alloc(&b, S);
    memset(b, 0, S);
    ((uint8_t *)b)[sz - 1] = (uint8_t)sz;
    void *obj = (uint8_t *)b + sz;
    *(uint8_t *)((uint8_t *)obj + 0x50) = (uint8_t)(rnd() & 1u);
    if (rnd() & 1) {
        size_t S2 = 2 + rnd() % 64u; int sz2 = 1 + (int)(rnd() % (u32)S2);
        *(void **)((uint8_t *)obj + 0x28) = sized_alloc_via(alloc, S2, sz2);
    } else {
        *(void **)((uint8_t *)obj + 0x28) = NULL;
    }
    if (rnd() & 1) {
        size_t S2 = 2 + rnd() % 64u; int sz2 = 1 + (int)(rnd() % (u32)S2);
        *(void **)((uint8_t *)obj + 8) = sized_alloc_via(alloc, S2, sz2);
    } else {
        *(void **)((uint8_t *)obj + 8) = NULL;
    }
    if (with8slot && (rnd() & 1))
        *(void **)((uint8_t *)obj + 0x48) = build_8slot(alloc);
    else
        *(void **)((uint8_t *)obj + 0x48) = NULL;
    return obj;
}

/* Build the outer object for cr_wrap_destroy2: a sized block whose +8 slot
 * holds (optionally) a full 0x58 object for the inner cr_wrap_destroy. */
static void *build_outer_for_wrap2(int (*alloc)(void **, size_t))
{
    size_t S = 0x80; int sz = 0x18;
    void *b = NULL;
    alloc(&b, S);
    memset(b, 0, S);
    ((uint8_t *)b)[sz - 1] = (uint8_t)sz;
    void *outer = (uint8_t *)b + sz;
    if (rnd() & 1)
        *(void **)((uint8_t *)outer + 8) = build_obj58(alloc, 1);
    else
        *(void **)((uint8_t *)outer + 8) = NULL;
    return outer;
}

static void test_tree_nested(void)
{
    g_vmalloc = (v_i_ppz)fn_at(RVA(0x180002fe0));

    /* --- cr_free_8slot_wrap (0x18003fcd0) ---------------------------------- */
    {
        v_v_p v = (v_v_p)fn_at(RVA(0x18003fcd0));
        begin("cr_free_8slot_wrap");
        int bad = g_fail;
        for (int t = 0; t < 8000; t++) {
            int kind = (int)(rnd() % 3u);     /* 0 NULL slot, 1 NULL *slot, 2 object */
            void *vslot = NULL, *cslot = NULL;
            if (kind == 2) {
                u32 sv = rng_state;           /* same random structure both sides */
                vslot = build_8slot(v_alloc);
                rng_state = sv;
                cslot = build_8slot(cr_malloc);
            }
            void *vsp = (kind == 0) ? NULL : &vslot;
            void *csp = (kind == 0) ? NULL : &cslot;
            v(vsp); cr_free_8slot_wrap((void **)csp);
            if (kind == 0)
                continue;
            if (vslot != NULL || cslot != NULL)
                mismatch("f8w-null", (u32)t, (u64)vslot, (u64)cslot);
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_free_8slot_wrap\n");
    }

    /* --- cr_obj_destroy (0x18001c680) -------------------------------------- */
    {
        v_v_p v = (v_v_p)fn_at(RVA(0x18001c680));
        begin("cr_obj_destroy");
        int bad = g_fail;
        for (int t = 0; t < 8000; t++) {
            u32 sv = rng_state;               /* same random structure both sides */
            void *vobj = build_obj58(v_alloc, 1);
            rng_state = sv;
            void *cobj = build_obj58(cr_malloc, 1);
            /* capture the flag byte (cr_obj_destroy must not touch it) */
            u8 vf = *(u8 *)((u8 *)vobj + 0x50);
            v(vobj); cr_obj_destroy(cobj);
            if (*(void **)((u8 *)vobj + 0x28) != NULL ||
                *(void **)((u8 *)cobj + 0x28) != NULL)
                mismatch("od-28", (u32)t, 0, 0);
            if (*(void **)((u8 *)vobj + 0x48) != NULL ||
                *(void **)((u8 *)cobj + 0x48) != NULL)
                mismatch("od-48", (u32)t, 0, 0);
            /* +8 is freed only when the flag byte has bit 0 set */
            int v8 = (*(void **)((u8 *)vobj + 8) != NULL);
            int c8 = (*(void **)((u8 *)cobj + 8) != NULL);
            if ((vf & 1u) ? (v8 || c8) : (v8 != c8))
                mismatch("od-8", (u32)t, (u64)v8, (u64)c8);
            if (*(u8 *)((u8 *)vobj + 0x50) != *(u8 *)((u8 *)cobj + 0x50))
                mismatch("od-flag", (u32)t,
                         *(u8 *)((u8 *)vobj + 0x50), *(u8 *)((u8 *)cobj + 0x50));
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_obj_destroy\n");
    }

    /* --- cr_wrap_destroy (0x180044ce0) ------------------------------------- */
    {
        v_v_p v = (v_v_p)fn_at(RVA(0x180044ce0));
        begin("cr_wrap_destroy");
        int bad = g_fail;
        for (int t = 0; t < 8000; t++) {
            int kind = (int)(rnd() & 1u);     /* 0 NULL *slot, 1 full object */
            void *vslot = NULL, *cslot = NULL;
            if (kind == 1) {
                u32 sv = rng_state;           /* same random structure both sides */
                vslot = build_obj58(v_alloc, 1);
                rng_state = sv;
                cslot = build_obj58(cr_malloc, 1);
            }
            v(&vslot); cr_wrap_destroy(&cslot);
            if (vslot != NULL || cslot != NULL)
                mismatch("wd-null", (u32)t, (u64)vslot, (u64)cslot);
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_wrap_destroy\n");
    }

    /* --- cr_wrap_destroy2 (0x180043a10) ------------------------------------ */
    {
        v_v_p v = (v_v_p)fn_at(RVA(0x180043a10));
        begin("cr_wrap_destroy2");
        int bad = g_fail;
        for (int t = 0; t < 8000; t++) {
            int kind = (int)(rnd() & 1u);     /* 0 NULL *slot, 1 full object */
            void *vslot = NULL, *cslot = NULL;
            if (kind == 1) {
                u32 sv = rng_state;           /* same random structure both sides */
                vslot = build_outer_for_wrap2(v_alloc);
                rng_state = sv;
                cslot = build_outer_for_wrap2(cr_malloc);
            }
            v(&vslot); cr_wrap_destroy2(&cslot);
            if (vslot != NULL || cslot != NULL)
                mismatch("wd2-null", (u32)t, (u64)vslot, (u64)cslot);
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_wrap_destroy2\n");
    }
}

/* ---- batch 51: small ready wrappers ------------------------------------ */
static void test_tree_wrappers(void)
{
    v_i_ppz vmalloc = (v_i_ppz)fn_at(RVA(0x180002fe0));

    /* --- cr_sized_free_if (0x180038720) ------------------------------------ */
    {
        v_v_p v = (v_v_p)fn_at(RVA(0x180038720));
        begin("cr_sized_free_if");
        int bad = g_fail;
        for (int t = 0; t < 8000; t++) {
            void *vslot = NULL, *cslot = NULL;
            if (rnd() & 1) {
                size_t S = 2 + rnd() % 64u; int sz = 1 + (int)(rnd() % (u32)S);
                vslot = v_sized_alloc(vmalloc, S, sz);
                cslot = c_sized_alloc(S, sz);
            }
            v(&vslot); cr_sized_free_if(&cslot);
            if (vslot != NULL || cslot != NULL)
                mismatch("sfi-null", (u32)t, (u64)vslot, (u64)cslot);
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_sized_free_if\n");
    }

    /* --- cr_free_pair8 (0x18001f640) --------------------------------------- */
    {
        v_v_p v = (v_v_p)fn_at(RVA(0x18001f640));
        begin("cr_free_pair8");
        int bad = g_fail;
        for (int t = 0; t < 8000; t++) {
            u8 ov[0x18], oc[0x18];
            memset(ov, 0x5A, sizeof ov); memset(oc, 0x5A, sizeof oc);
            for (int i = 0; i < 2; i++) {
                if (rnd() & 1) {
                    size_t S = 2 + rnd() % 64u; int sz = 1 + (int)(rnd() % (u32)S);
                    *(void **)(ov + 8 * i) = v_sized_alloc(vmalloc, S, sz);
                    *(void **)(oc + 8 * i) = c_sized_alloc(S, sz);
                } else {
                    *(void **)(ov + 8 * i) = NULL; *(void **)(oc + 8 * i) = NULL;
                }
            }
            v(ov); cr_free_pair8(oc);
            if (*(void **)(ov + 0) != NULL || *(void **)(oc + 0) != NULL ||
                *(void **)(ov + 8) != NULL || *(void **)(oc + 8) != NULL)
                mismatch("fp8-null", (u32)t, 0, 0);
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_free_pair8\n");
    }

    /* --- cr_free_slot8 / cr_cleanup_ptr8_guard / cr_cleanup_ptr8_clear_b --- */
    {
        static const char *nm[3] = { "cr_free_slot8", "cr_cleanup_ptr8_guard",
                                     "cr_cleanup_ptr8_clear_b" };
        v_v_p vf[3] = { (v_v_p)fn_at(RVA(0x180033f40)),
                        (v_v_p)fn_at(RVA(0x1800276a0)),
                        (v_v_p)fn_at(RVA(0x18003b920)) };
        void (*cf[3])(void *) = { cr_free_slot8, cr_cleanup_ptr8_guard,
                                  cr_cleanup_ptr8_clear_b };
        for (int k = 0; k < 3; k++) {
            begin(nm[k]);
            int bad = g_fail;
            for (int t = 0; t < 8000; t++) {
                u8 ov[0x18], oc[0x18];
                memset(ov, 0x5A, sizeof ov); memset(oc, 0x5A, sizeof oc);
                if (rnd() & 1) {
                    size_t S = 2 + rnd() % 64u; int sz = 1 + (int)(rnd() % (u32)S);
                    *(void **)(ov + 8) = v_sized_alloc(vmalloc, S, sz);
                    *(void **)(oc + 8) = c_sized_alloc(S, sz);
                } else {
                    *(void **)(ov + 8) = NULL; *(void **)(oc + 8) = NULL;
                }
                vf[k](ov); cf[k](oc);
                if ((*(void **)(ov + 8) != NULL) != (*(void **)(oc + 8) != NULL))
                    mismatch("fs8-null", (u32)t, *(void **)(ov + 8) != NULL,
                             *(void **)(oc + 8) != NULL);
                if (memcmp(ov, oc, 8) || memcmp(ov + 16, oc + 16, sizeof ov - 16))
                    mismatch("fs8-other", (u32)t, 0, 0);
            }
            vf[k](NULL); cf[k](NULL);              /* NULL object: no-op */
            if (g_fail == bad) end(); else printf("  FAIL %s\n", nm[k]);
        }
    }

    /* --- cr_free_4slot (0x1800464b0) --------------------------------------- */
    {
        v_v_p v = (v_v_p)fn_at(RVA(0x1800464b0));
        static const int off[4] = { 0x18, 0x00, 0x20, 0x28 };
        begin("cr_free_4slot");
        int bad = g_fail;
        for (int t = 0; t < 8000; t++) {
            u8 ov[0x38], oc[0x38];
            memset(ov, 0x5A, sizeof ov); memset(oc, 0x5A, sizeof oc);
            for (int i = 0; i < 4; i++) {
                if (rnd() & 1) {
                    size_t S = 2 + rnd() % 64u; int sz = 1 + (int)(rnd() % (u32)S);
                    *(void **)(ov + off[i]) = v_sized_alloc(vmalloc, S, sz);
                    *(void **)(oc + off[i]) = c_sized_alloc(S, sz);
                } else {
                    *(void **)(ov + off[i]) = NULL; *(void **)(oc + off[i]) = NULL;
                }
            }
            v(ov); cr_free_4slot(oc);
            for (int i = 0; i < 4; i++)
                if (*(void **)(ov + off[i]) != NULL || *(void **)(oc + off[i]) != NULL)
                    mismatch("f4s-null", (u32)i, 0, 0);
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_free_4slot\n");
    }

    /* --- cr_hi_bit_index (0x1800384c0) ------------------------------------- */
    {
        typedef int (WINAPI *v_i_u)(uint32_t);
        v_i_u v = (v_i_u)fn_at(RVA(0x1800384c0));
        begin("cr_hi_bit_index");
        int bad = g_fail;
        for (int t = 0; t < 20000; t++) {
            uint32_t x = (rnd() % 8u == 0) ? 0u : rnd();
            if (rnd() % 16u == 0) x = 1u << (rnd() % 32u);
            int rv = v(x), rc = cr_hi_bit_index(x);
            if (rv != rc) mismatch("hbi", x, (u32)rv, (u32)rc);
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_hi_bit_index\n");
    }

    /* --- cr_image_get_meta_dp (0x18004a910) -------------------------------- */
    {
        typedef void *(WINAPI *v_p_ppu)(const void *, uint32_t);
        v_p_ppu v = (v_p_ppu)fn_at(RVA(0x18004a910));
        static u8 defs[0x10 + 0x16 * 8 + 8];
        static u8 bufs[0x16][0x20];
        begin("cr_image_get_meta_dp");
        int bad = g_fail;
        for (int t = 0; t < 8000; t++) {
            memset(defs, 0x5A, sizeof defs);
            for (int i = 0; i < 0x16; i++) {
                int kind = (int)(rnd() % 5u);
                void *p = NULL;
                if (kind != 0) {
                    memset(bufs[i], 0, sizeof bufs[i]);
                    /* tags: <8 (false), 8/10 (true), 9/11 (false), high-bit */
                    switch (kind) {
                    case 1: *(u32 *)bufs[i] = rnd() % 8u; break;
                    case 2: *(u32 *)bufs[i] = 8u + 2u * (rnd() % 8u); break;
                    case 3: *(u32 *)bufs[i] = 9u + 2u * (rnd() % 8u); break;
                    default: *(u32 *)bufs[i] = 0x80000000u + (rnd() & 0xffu); break;
                    }
                    p = bufs[i];
                }
                *(void **)(defs + 0x10 + i * 8) = p;
            }
            u32 idx = rnd() % 24u;                /* includes out-of-range */
            void *rv = v(defs, idx);
            void *rc = cr_image_get_meta_dp(defs, idx);
            if (rv != rc)                         /* same input -> same pointer */
                mismatch("mdp", idx, (u64)rv, (u64)rc);
        }
        if (v(NULL, 0) != NULL || cr_image_get_meta_dp(NULL, 0) != NULL)
            mismatch("mdp-nulldefs", 0, 0, 0);
        if (g_fail == bad) end(); else printf("  FAIL cr_image_get_meta_dp\n");
    }

    /* --- cr_free_4args (0x18000fd40) --------------------------------------- */
    {
        typedef void (WINAPI *v_v_pppp)(void *, void *, void *, void *);
        v_v_pppp v = (v_v_pppp)fn_at(RVA(0x18000fd40));
        begin("cr_free_4args");
        int bad = g_fail;
        for (int t = 0; t < 8000; t++) {
            void *va[4], *ca[4];
            for (int i = 0; i < 4; i++) {
                if (rnd() & 1) {
                    size_t S = 2 + rnd() % 64u; int sz = 1 + (int)(rnd() % (u32)S);
                    va[i] = v_sized_alloc(vmalloc, S, sz);
                    ca[i] = c_sized_alloc(S, sz);
                } else { va[i] = NULL; ca[i] = NULL; }
            }
            v(va[0], va[1], va[2], va[3]);
            cr_free_4args(ca[0], ca[1], ca[2], ca[3]);
            /* no outputs: the contract is "frees exactly these four, no crash" */
        }
        v(NULL, NULL, NULL, NULL);
        cr_free_4args(NULL, NULL, NULL, NULL);
        if (g_fail == bad) end(); else printf("  FAIL cr_free_4args\n");
    }
}

/* ---- batch 52: ready wrappers / allocators ----------------------------- */
static void test_tree_batch52(void)
{
    v_i_ppz vmalloc = (v_i_ppz)fn_at(RVA(0x180002fe0));
    v_v_p   vsfree  = (v_v_p)fn_at(RVA(0x18003bf40));

    /* --- cr_free_4slot_guard (0x180046490) --------------------------------- */
    {
        v_v_p v = (v_v_p)fn_at(RVA(0x180046490));
        begin("cr_free_4slot_guard");
        int bad = g_fail;
        for (int t = 0; t < 4000; t++) {
            static const int sl[4] = { 0x18, 0x00, 0x20, 0x28 };
            u8 ov[0x30], oc[0x30];
            memset(ov, 0x5A, sizeof ov); memset(oc, 0x5A, sizeof oc);
            for (int i = 0; i < 4; i++) {
                if (rnd() & 1) {
                    size_t S = 2 + rnd() % 64u; int sz = 1 + (int)(rnd() % (u32)S);
                    *(void **)(ov + sl[i]) = v_sized_alloc(vmalloc, S, sz);
                    *(void **)(oc + sl[i]) = c_sized_alloc(S, sz);
                } else {
                    *(void **)(ov + sl[i]) = NULL; *(void **)(oc + sl[i]) = NULL;
                }
            }
            if (t & 1) { v(ov); cr_free_4slot_guard(oc); }
            else       { v(NULL); cr_free_4slot_guard(NULL); }
            for (int i = 0; i < 4; i++)
                if ((*(void **)(ov + sl[i]) != NULL) != (*(void **)(oc + sl[i]) != NULL))
                    mismatch("f4g", (u32)i, *(void **)(ov + sl[i]) != NULL,
                             *(void **)(oc + sl[i]) != NULL);
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_free_4slot_guard\n");
    }

    /* --- cr_clear_6ptr (0x180011890) --------------------------------------- */
    {
        v_v_p v = (v_v_p)fn_at(RVA(0x180011890));
        static const int off[6] = { 0xa8, 0x08, 0x28, 0x48, 0x68, 0x88 };
        begin("cr_clear_6ptr");
        int bad = g_fail;
        for (int t = 0; t < 4000; t++) {
            u8 ov[0xb0], oc[0xb0];
            memset(ov, 0x5A, sizeof ov); memset(oc, 0x5A, sizeof oc);
            for (int i = 0; i < 6; i++) {
                if (rnd() & 1) {
                    size_t S = 2 + rnd() % 64u; int sz = 1 + (int)(rnd() % (u32)S);
                    *(void **)(ov + off[i]) = v_sized_alloc(vmalloc, S, sz);
                    *(void **)(oc + off[i]) = c_sized_alloc(S, sz);
                } else {
                    *(void **)(ov + off[i]) = NULL; *(void **)(oc + off[i]) = NULL;
                }
            }
            v(ov); cr_clear_6ptr(oc);
            for (int i = 0; i < 6; i++)
                if ((*(void **)(ov + off[i]) != NULL) != (*(void **)(oc + off[i]) != NULL))
                    mismatch("c6p", (u32)i, *(void **)(ov + off[i]) != NULL,
                             *(void **)(oc + off[i]) != NULL);
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_clear_6ptr\n");
    }

    /* --- cr_bit_alloc (0x18001f080) ---------------------------------------- */
    {
        typedef int (WINAPI *v_i_ppi)(void **, int);
        v_i_ppi v = (v_i_ppi)fn_at(RVA(0x18001f080));
        begin("cr_bit_alloc");
        int bad = g_fail;
        for (int t = 0; t < 4000; t++) {
            void *vp = (void *)0x5A5A5A5A, *cp = (void *)0x5A5A5A5A;
            int n;
            switch (rnd() % 4u) {
                case 0: n = 0; break;
                case 1: n = -(int)(rnd() % 4u); break;
                default: n = 1 + (int)(rnd() % 200u); break;
            }
            int rv = v(&vp, n);
            int rc = cr_bit_alloc(&cp, n);
            if (rv != rc) mismatch("ba-ret", (u32)n, (u32)rv, (u32)rc);
            if ((vp != NULL) != (cp != NULL))
                mismatch("ba-null", (u32)n, vp != NULL, cp != NULL);
            if (rv == 0 && vp) {
                int bytes = (n + 7) >> 3;
                /* verify zeroed */
                u8 *vb = (u8 *)vp, *cb = (u8 *)cp;
                for (int i = 0; i < bytes; i++)
                    if (vb[i] != 0 || cb[i] != 0) { mismatch("ba-zero", (u32)i, vb[i], cb[i]); break; }
                if (((uintptr_t)vp & 0xf) || ((uintptr_t)cp & 0xf))
                    mismatch("ba-align", (u32)n, 0, 0);
                vsfree(&vp);
                cr_sized_free(&cp);
            }
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_bit_alloc\n");
    }

    /* --- cr_image_alloc_f32 (0x18001e8b0) --------------------------------- */
    {
        typedef int (WINAPI *v_i_ppii)(cr_image *, int, int);
        v_i_ppii v = (v_i_ppii)fn_at(RVA(0x18001e8b0));
        begin("cr_image_alloc_f32");
        int bad = g_fail;
        for (int t = 0; t < 4000; t++) {
            cr_image va, ca;
            memset(&va, 0x5A, sizeof va); memset(&ca, 0x5A, sizeof ca);
            int w = (int)(rnd() % 32u), h = (int)(rnd() % 32u);
            if (rnd() % 8u == 0) w = -(int)(rnd() % 4u);
            if (rnd() % 8u == 0) h = -(int)(rnd() % 4u);
            int rv = v(&va, w, h);
            int rc = cr_image_alloc_f32(&ca, w, h);
            if (rv != rc) mismatch("f32-ret", (u32)t, (u32)rv, (u32)rc);
            if (va.a != ca.a || va.b != ca.b || va.w != ca.w || va.h != ca.h ||
                va.offx != ca.offx || va.offy != ca.offy)
                mismatch("f32-fields", (u32)t, 0, 0);
            if ((va.data != NULL) != (ca.data != NULL))
                mismatch("f32-ptr", (u32)t, va.data != NULL, ca.data != NULL);
            if (rv == 0 && va.data) {
                if (((uintptr_t)va.data & 0xf) || ((uintptr_t)ca.data & 0xf))
                    mismatch("f32-align", (u32)t, 0, 0);
                vsfree(&va.data);
                cr_sized_free(&ca.data);
            }
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_image_alloc_f32\n");
    }

    /* --- cr_image_alloc_quarter (0x180026d00) ------------------------------ */
    {
        typedef int (WINAPI *v_v_ppii)(cr_image *, int, int);
        v_v_ppii v = (v_v_ppii)fn_at(RVA(0x180026d00));
        begin("cr_image_alloc_quarter");
        int bad = g_fail;
        for (int t = 0; t < 4000; t++) {
            int va[16], ca[16];
            memset(va, 0x5A, 64); memset(ca, 0x5A, 64);
            int w = (int)(rnd() % 32u), h = (int)(rnd() % 32u);
            if (rnd() % 8u == 0) w = -(int)(rnd() % 4u);
            if (rnd() % 8u == 0) h = -(int)(rnd() % 4u);
            int vr = v((cr_image *)va, w, h);
            int cr = cr_image_alloc_quarter((cr_image *)ca, w, h);
            if (vr != cr)
                mismatch("q-ret", (u32)t, (u32)vr, (u32)cr);
            /* compare descriptor fields, excluding the data pointer at +8
             * (its value necessarily differs between the two allocators) */
            if (memcmp(va, ca, 8) != 0 ||
                memcmp((u8 *)va + 16, (u8 *)ca + 16, 32) != 0)
                mismatch("q-fields", (u32)t, 0, 0);
            /* desc[2] is only written (NULL or real ptr) when the sub-call
             * reaches its assignment; otherwise it stays poison. */
            int wi = (w - 4 > -1) ? w - 4 : w - 1;
            int hi = (h - 4 > -1) ? h - 4 : h - 1;
            int valid = ((wi >> 2) >= 0 && (hi >> 2) >= 0);
            void *vdp = *(void **)(va + 2), *cdp = *(void **)(ca + 2);
            if (valid) {
                if ((vdp != NULL) != (cdp != NULL))
                    mismatch("q-ptr", (u32)t, vdp != NULL, cdp != NULL);
                if (vdp) {
                    vsfree(&vdp);
                    cr_sized_free(&cdp);
                }
            }
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_image_alloc_quarter\n");
    }

    /* --- cr_copy_image_fields (0x1800357a0) -------------------------------- */
    /* b != NULL: a+0x28 / a+0x30 hold int16 descriptors {w@0, h@2, data@0x10};
     * b+0x58 / b+0x18 hold destination buffers.  The second copy only runs if
     * the first source descriptor is present.  b == NULL: pure no-op (a is
     * never dereferenced). */
    {
        typedef int (WINAPI *v_i_pp)(void *, void *);
        v_i_pp v = (v_i_pp)fn_at(RVA(0x1800357a0));
        begin("cr_copy_image_fields");
        int bad = g_fail;
        enum { SW = 8, SH = 4, NB = SW * SH * 2 };
        u8 src1data[NB], src2data[NB];
        int16_t src1desc[16], src2desc[16];
        u8 a[0x40], bv[0x60], bc[0x60];
        u8 dstv1[NB], dstc1[NB], dstv2[NB], dstc2[NB];
        for (int t = 0; t < 4000; t++) {
            for (int i = 0; i < NB; i++) { src1data[i] = (u8)rnd(); src2data[i] = (u8)rnd(); }
            memset(src1desc, 0, sizeof src1desc);
            memset(src2desc, 0, sizeof src2desc);
            src1desc[0] = SW; src1desc[1] = SH;
            src2desc[0] = SW; src2desc[1] = SH;
            *(void **)((u8 *)src1desc + 0x10) = src1data;
            *(void **)((u8 *)src2desc + 0x10) = src2data;
            memset(a, 0, sizeof a);
            memset(bv, 0, sizeof bv); memset(bc, 0, sizeof bc);
            *(void **)(a + 0x28) = src1desc;
            *(void **)(a + 0x30) = src2desc;
            /* exercise the optional second source */
            if (rnd() & 1) *(void **)(a + 0x30) = NULL;
            *(void **)(bv + 0x58) = dstv1; *(void **)(bc + 0x58) = dstc1;
            *(void **)(bv + 0x18) = dstv2; *(void **)(bc + 0x18) = dstc2;
            memset(dstv1, 0x5A, sizeof dstv1); memset(dstc1, 0x5A, sizeof dstc1);
            memset(dstv2, 0x5A, sizeof dstv2); memset(dstc2, 0x5A, sizeof dstc2);
            int rv = v(a, bv);
            int rc = cr_copy_image_fields(a, bc);
            if (rv != rc) mismatch("cif-ret", (u32)t, (u32)rv, (u32)rc);
            cmp_buf("cif1", dstv1, dstc1, sizeof dstv1, (u32)t);
            cmp_buf("cif2", dstv2, dstc2, sizeof dstv2, (u32)t);
        }
        /* b == NULL: no dereference of a, returns 0 */
        {
            u8 a2[0x40]; memset(a2, 0, sizeof a2);
            int rv = v(a2, NULL);
            int rc = cr_copy_image_fields(a2, NULL);
            if (rv != rc) mismatch("cif-null", 0, (u32)rv, (u32)rc);
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_copy_image_fields\n");
    }

    /* --- cr_sqrt_q16 (0x180038a50) ----------------------------------------- */
    {
        typedef int (WINAPI *v_i_u32)(uint32_t);
        v_i_u32 v = (v_i_u32)fn_at(RVA(0x180038a50));
        begin("cr_sqrt_q16");
        int bad = g_fail;
        for (int t = 0; t < 100000; t++) {
            uint32_t x = rnd() | (rnd() << 16);
            if (t % 16 == 0) x = 0;
            if (t % 32 == 1) x = 1;
            int rv = v(x);
            int rc = cr_sqrt_q16(x);
            if (rv != rc) mismatch("sqrt", x, (u32)rv, (u32)rc);
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_sqrt_q16\n");
    }

    /* --- cr_u8_to_u16_guarded (0x180032530) ------------------------------- */
    {
        typedef int (WINAPI *v_i_pph)(cr_image *, const cr_image *, int16_t);
        v_i_pph v = (v_i_pph)fn_at(RVA(0x180032530));
        begin("cr_u8_to_u16_guarded");
        int bad = g_fail;
        enum { W = 32, H = 16 };
        u8 src_buf[W * H];
        int16_t dst_buf[W * H], dst_buf2[W * H];
        for (int t = 0; t < 4000; t++) {
            for (int i = 0; i < W * H; i++) src_buf[i] = (u8)rnd();
            cr_image src, dstv, dstc;
            cr_image_set(&src, src_buf, W, H);
            cr_image_set(&dstv, dst_buf, W, H);
            cr_image_set(&dstc, dst_buf2, W, H);
            int16_t shift = (int16_t)(int)(rnd() % 8u);
            int mode = (int)(rnd() % 4u);
            /* mode 0: full-view both (should succeed) */
            if (mode > 0) { dstv.offx = 1; dstc.offx = 1; }  /* break the guard */
            memset(dst_buf, 0x5A, sizeof dst_buf);
            memset(dst_buf2, 0x5A, sizeof dst_buf2);
            int rv = v(&dstv, &src, shift);
            int rc = cr_u8_to_u16_guarded(&dstc, &src, shift);
            if (rv != rc) mismatch("u16g-ret", (u32)t, (u32)rv, (u32)rc);
            if (rv == 0)
                cmp_buf("u16g", (u8 *)dst_buf, (u8 *)dst_buf2, sizeof dst_buf, (u32)t);
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_u8_to_u16_guarded\n");
    }

    /* --- cr_copy_u16_shl_guarded (0x180024e60) ---------------------------- */
    {
        typedef int (WINAPI *v_i_ppb)(cr_image *, const cr_image *, uint8_t);
        v_i_ppb v = (v_i_ppb)fn_at(RVA(0x180024e60));
        begin("cr_copy_u16_shl_guarded");
        int bad = g_fail;
        enum { W = 32, H = 16 };
        int16_t src_buf[W * H], dst_buf[W * H], dst_buf2[W * H];
        for (int t = 0; t < 4000; t++) {
            for (int i = 0; i < W * H; i++) src_buf[i] = (int16_t)rnd();
            cr_image src, dstv, dstc;
            cr_image_set(&src, src_buf, W, H);
            cr_image_set(&dstv, dst_buf, W, H);
            cr_image_set(&dstc, dst_buf2, W, H);
            uint8_t shift = (uint8_t)(rnd() % 8u);
            int mode = (int)(rnd() % 4u);
            /* the guard is w/h equality; break it by perturbing dst w */
            if (mode > 0) { dstv.w = W + 1; dstc.w = W + 1; }
            memset(dst_buf, 0x5A, sizeof dst_buf);
            memset(dst_buf2, 0x5A, sizeof dst_buf2);
            int rv = v(&dstv, &src, shift);
            int rc = cr_copy_u16_shl_guarded(&dstc, &src, shift);
            if (rv != rc) mismatch("c16g-ret", (u32)t, (u32)rv, (u32)rc);
            if (rv == 0)
                cmp_buf("c16g", (u8 *)dst_buf, (u8 *)dst_buf2, sizeof dst_buf, (u32)t);
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_copy_u16_shl_guarded\n");
    }

    /* --- cr_fir_reflect_guarded (0x1800280d0) ----------------------------- */
    {
        typedef int (WINAPI *v_i_pppiii)(int16_t *, const int16_t *,
                                         const int16_t *, int, int, int);
        v_i_pppiii v = (v_i_pppiii)fn_at(RVA(0x1800280d0));
        begin("cr_fir_reflect_guarded");
        int bad = g_fail;
        enum { MAXW = 40, MAXL = 200 };
        int16_t inv[MAXW * MAXL], coefv[MAXL], outv[MAXW * MAXL], outc[MAXW * MAXL];
        for (int t = 0; t < 20000; t++) {
            int W = 1 + (int)(rnd() % MAXW);
            int L = 1 + (int)(rnd() % MAXL);
            int p4;
            /* exercise both fast and general paths */
            switch (rnd() % 4u) {
                case 0: p4 = 7; break;
                case 1: p4 = 0xf; break;
                default: p4 = (int)(rnd() % (L + 4)) - 2; break;
            }
            for (int i = 0; i < W * L; i++) inv[i] = (int16_t)rnd();
            for (int i = 0; i < L; i++) coefv[i] = (int16_t)rnd();
            memset(outv, 0x5A, sizeof outv);
            memset(outc, 0x5A, sizeof outc);
            int rv = v(outv, inv, coefv, p4, W, L);
            int rc = cr_fir_reflect_guarded(outc, inv, coefv, p4, W, L);
            if (rv != rc) mismatch("fg-ret", (u32)t, (u32)rv, (u32)rc);
            if (rv == 0)
                cmp_buf("fg", (u8 *)outv, (u8 *)outc, sizeof(int16_t) * W * L, (u32)t);
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_fir_reflect_guarded\n");
    }

    /* --- cr_fir_reflect_rows_guarded (0x18002d960) ------------------------ */
    {
        typedef int (WINAPI *v_i_pppiii)(int16_t *, const int16_t *,
                                         const int16_t *, int, int, int);
        v_i_pppiii v = (v_i_pppiii)fn_at(RVA(0x18002d960));
        begin("cr_fir_reflect_rows_guarded");
        int bad = g_fail;
        enum { MAXW = 200, MAXR = 40 };
        int16_t inv[MAXW * MAXR], coefv[MAXW], outv[MAXW * MAXR], outc[MAXW * MAXR];
        for (int t = 0; t < 20000; t++) {
            int W = 1 + (int)(rnd() % MAXW);
            int R = 1 + (int)(rnd() % MAXR);
            int p4;
            switch (rnd() % 4u) {
                case 0: p4 = 7; break;
                case 1: p4 = 0xf; break;
                default: p4 = (int)(rnd() % (W + 4)) - 2; break;
            }
            for (int i = 0; i < W * R; i++) inv[i] = (int16_t)rnd();
            for (int i = 0; i < W; i++) coefv[i] = (int16_t)rnd();
            memset(outv, 0x5A, sizeof outv);
            memset(outc, 0x5A, sizeof outc);
            int rv = v(outv, inv, coefv, p4, W, R);
            int rc = cr_fir_reflect_rows_guarded(outc, inv, coefv, p4, W, R);
            if (rv != rc) mismatch("fgr-ret", (u32)t, (u32)rv, (u32)rc);
            if (rv == 0)
                cmp_buf("fgr", (u8 *)outv, (u8 *)outc, sizeof(int16_t) * W * R, (u32)t);
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_fir_reflect_rows_guarded\n");
    }

    /* --- cr_palette_remap (0x180010e60) ----------------------------------- */
    {
        typedef int (WINAPI *v_i_ppp)(void *, cr_image *, const void *);
        v_i_ppp v = (v_i_ppp)fn_at(RVA(0x180010e60));
        begin("cr_palette_remap");
        int bad = g_fail;
        enum { NLUT = 8 * 256, MAXP = 64 };   /* LUT must cover idx = hi*mult + lo, mult<=8 */
        int16_t lut[NLUT];
        u8 src_bytes[MAXP * 2];
        int16_t dst_v[MAXP], dst_c[MAXP];
        for (int t = 0; t < 4000; t++) {
            for (int i = 0; i < NLUT; i++) lut[i] = (int16_t)rnd();
            int mult = 1 + (int)(rnd() % 8u);
            int count = 1 + (int)(rnd() % MAXP);
            /* idx = src[2i+1]*mult + src[2i]; the LUT is [256][mult] so the
             * low byte (column) must be < mult to stay in bounds for both
             * vendor and clean-room. */
            for (int i = 0; i < count * 2; i += 2) {
                src_bytes[i]     = (u8)(rnd() % (uint32_t)mult);   /* lo < mult */
                src_bytes[i + 1] = (u8)rnd();                        /* hi 0..255 */
            }
            /* Build ctx: ctx+0x48 → palette object */
            /* palette object: +0x00=src ptr, +0x18=dst ptr(alloc), +0x20=count */
            struct { void *src; void *pad[2]; int16_t *dst; int count; } palobj;
            struct { u8 pad[0x48]; void *palptr; } ctx;
            palobj.src = src_bytes;
            palobj.pad[0] = palobj.pad[1] = NULL;
            palobj.dst = NULL;
            palobj.count = count;
            ctx.palptr = &palobj;
            /* lut_desc: cr_image with data=lut, w=mult */
            cr_image lut_desc;
            memset(&lut_desc, 0, sizeof lut_desc);
            lut_desc.data = lut;
            lut_desc.w = mult;
            /* flag_obj: +0x3d must be non-zero */
            u8 flag_obj[0x40];
            memset(flag_obj, 0, sizeof flag_obj);
            flag_obj[0x3d] = 1;
            memset(dst_v, 0x5A, sizeof dst_v);
            memset(dst_c, 0x5A, sizeof dst_c);
            palobj.dst = NULL;
            int rv = v(&ctx, &lut_desc, flag_obj);
            /* vendor allocated dst_v through palobj.dst — copy then free */
            if (rv == 0 && palobj.dst)
                memcpy(dst_v, palobj.dst, count * 2);
            void *vdp = palobj.dst;
            if (vdp) vsfree(&vdp);

            palobj.dst = NULL;
            int rc = cr_palette_remap(&ctx, &lut_desc, flag_obj);
            if (rc == 0 && palobj.dst)
                memcpy(dst_c, palobj.dst, count * 2);
            void *cdp = palobj.dst;
            if (cdp) cr_sized_free(&cdp);

            if (rv != rc) mismatch("pm-ret", (u32)t, (u32)rv, (u32)rc);
            if (rv == 0)
                cmp_buf("pm", (u8 *)dst_v, (u8 *)dst_c, count * 2, (u32)t);
        }
        /* flag=0 early return */
        {
            u8 flag_obj[0x40]; memset(flag_obj, 0, sizeof flag_obj);
            u8 ctx_buf[0x50]; memset(ctx_buf, 0, sizeof ctx_buf);
            cr_image lut_desc; memset(&lut_desc, 0, sizeof lut_desc);
            int rv = v(ctx_buf, &lut_desc, flag_obj);
            int rc = cr_palette_remap(ctx_buf, &lut_desc, flag_obj);
            if (rv != rc) mismatch("pm-zero", 0, (u32)rv, (u32)rc);
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_palette_remap\n");
    }
}

/* ---- batch 53: ready wrappers (size 160-500) --------------------------- */
static void test_tree_batch53(void)
{
    /* --- cr_shuffle_indices (0x18000d310) --------------------------------- */
    {
        typedef void (WINAPI *v_v_piU)(int *, int, uint64_t);
        v_v_piU v = (v_v_piU)fn_at(RVA(0x18000d310));
        begin("cr_shuffle_indices");
        int bad = g_fail;
        enum { MAXN = 64 };
        int av[MAXN], ac[MAXN];
        for (int t = 0; t < 20000; t++) {
            int n = 1 + (int)(rnd() % MAXN);
            uint64_t seed = ((uint64_t)rnd() << 32) | rnd();
            memset(av, 0x5A, sizeof av);
            memset(ac, 0x5A, sizeof ac);
            v(av, n, seed);
            cr_shuffle_indices(ac, n, seed);
            cmp_buf("shuf", (u8 *)av, (u8 *)ac, sizeof(int) * n, (u32)t);
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_shuffle_indices\n");
    }

    /* --- cr_softmax2 (0x1800363b0) ---------------------------------------- */
    {
        typedef void (WINAPI *v_v_pfp)(float *, const void *, const int16_t *);
        v_v_pfp v = (v_v_pfp)fn_at(RVA(0x1800363b0));
        begin("cr_softmax2");
        int bad = g_fail;
        u8 ctx[0x28];
        int16_t vals[2];
        for (int t = 0; t < 20000; t++) {
            memset(ctx, 0, sizeof ctx);
            *(uint32_t *)(ctx + 0x20) = rnd();
            vals[0] = (int16_t)rnd();
            vals[1] = (int16_t)rnd();
            float ov = 0.0f, oc = 0.0f;
            v(&ov, ctx, vals);
            cr_softmax2(&oc, ctx, vals);
            cmp_buf("sm", (u8 *)&ov, (u8 *)&oc, 4, (u32)t);
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_softmax2\n");
    }

    /* --- cr_centroid_affine (0x180038930) --------------------------------- */
    {
        typedef int (WINAPI *v_i_ppfiii)(int *, const void *, float, int, int, int);
        v_i_ppfiii v = (v_i_ppfiii)fn_at(RVA(0x180038930));
        begin("cr_centroid_affine");
        int bad = g_fail;
        enum { MAXW = 64, MAXH = 24, MAXWORDS = 8 };
        uint32_t bits[MAXH * MAXWORDS];
        int ov[6], oc[6];
        for (int t = 0; t < 20000; t++) {
            int w = 1 + (int)(rnd() % MAXW);
            int h = 1 + (int)(rnd() % MAXH);
            int stride_words = (w + 31) / 32 + (int)(rnd() % 3);
            int win_w = (int)(rnd() % (w + 4));
            int win_h = (int)(rnd() % (h + 4));
            int margin = (int)(rnd() % 8);
            for (int i = 0; i < h * stride_words; i++) bits[i] = rnd();
            cr_bitmap_desc bm;
            memset(&bm, 0, sizeof bm);
            bm.a = stride_words * 32; bm.data = bits; bm.w = w; bm.h = h;
            float scale;
            switch (rnd() % 4u) {
                case 0: scale = 1.0f; break;
                case 1: scale = 1.0f + (float)(rnd() % 1000u) * 0x1p-10f; break;
                case 2: scale = 0.5f; break;
                default: scale = 2.0f + (float)(rnd() % 100u); break;
            }
            for (int i = 0; i < 6; i++) { ov[i] = 0x5A5A5A5A; oc[i] = 0x5A5A5A5A; }
            int rv = v(ov, &bm, scale, win_w, win_h, margin);
            int rc = cr_centroid_affine(oc, &bm, scale, win_w, win_h, margin);
            if (rv != rc) mismatch("ca-ret", (u32)t, (u32)rv, (u32)rc);
            if (rv == 0)
                cmp_buf("ca", (u8 *)ov, (u8 *)oc, sizeof ov, (u32)t);
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_centroid_affine\n");
    }

    /* --- cr_running_avg (0x180030ea0) ------------------------------------- */
    {
        typedef void (WINAPI *v_v_pppifp)(int16_t *, int16_t *, const int16_t *,
                                          int, float, const int16_t *);
        v_v_pppifp v = (v_v_pppifp)fn_at(RVA(0x180030ea0));
        begin("cr_running_avg");
        int bad = g_fail;
        enum { MAXN = 64 };
        int16_t cntv[MAXN], cntc[MAXN], dstv[MAXN], dstc[MAXN];
        int16_t src[MAXN], limit;
        for (int t = 0; t < 20000; t++) {
            int n = 1 + (int)(rnd() % MAXN);
            float k = (float)(int)(rnd() % 2000u) * 0x1p-10f - 1.0f;
            limit = (int16_t)(int)(rnd() % 400u);
            for (int i = 0; i < n; i++) {
                /* bias src toward the active branch (s < 250) */
                src[i] = (int16_t)((int)(rnd() % 600u) - 50);
                cntv[i] = cntc[i] = (int16_t)(1 + (int)(rnd() % 300u));
                dstv[i] = dstc[i] = (int16_t)rnd();
            }
            v(cntv, dstv, src, n, k, &limit);
            cr_running_avg(cntc, dstc, src, n, k, &limit);
            cmp_buf("ra-cnt", (u8 *)cntv, (u8 *)cntc, sizeof(int16_t) * n, (u32)t);
            cmp_buf("ra-dst", (u8 *)dstv, (u8 *)dstc, sizeof(int16_t) * n, (u32)t);
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_running_avg\n");
    }

    /* --- cr_atan2_fixed (0x180012260) ------------------------------------- *
     * The vendor normalises with `sh = clz(uVar6) - 1`; when bit 31 of the
     * signed difference uVar6 is set this makes den == 0 and the vendor IDIV
     * faults.  That only occurs for |p1|,|p2| > 2^15, so the function's real
     * domain is 16-bit inputs (where |uVar6| < 2^31 and clz >= 1). */
    {
        typedef int (WINAPI *v_i_ii)(int, int);
        v_i_ii v = (v_i_ii)fn_at(RVA(0x180012260));
        begin("cr_atan2_fixed");
        int bad = g_fail;
        static const int edge[] = { 0, 1, -1, 2, -2, 32767, -32768,
                                    12540, -12540, 30274, -30274,
                                    16384, -16384, 10000, -10000, 12345, -6789 };
        enum { NE = sizeof edge / sizeof edge[0] };
        for (int e = 0; e < NE; e++) {
            for (int f = 0; f < NE; f++) {
                int p1 = edge[e], p2 = edge[f];
                int rv = v(p1, p2);
                int rc = cr_atan2_fixed(p1, p2);
                if (rv != rc) mismatch("at-edge", (u32)(e * NE + f), (u32)rv, (u32)rc);
            }
        }
        for (int t = 0; t < 200000; t++) {
            int p1 = (int)(int16_t)rnd();
            int p2 = (int)(int16_t)rnd();
            int rv = v(p1, p2);
            int rc = cr_atan2_fixed(p1, p2);
            if (rv != rc) mismatch("at", (u32)t, (u32)rv, (u32)rc);
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_atan2_fixed\n");
    }

    /* --- cr_box_mean_edge (0x1800335e0) ----------------------------------- */
    {
        typedef void (WINAPI *v_v_ppiu)(float *, const float *, int, uint32_t);
        v_v_ppiu v = (v_v_ppiu)fn_at(RVA(0x1800335e0));
        begin("cr_box_mean_edge");
        int bad = g_fail;
        enum { MAXN = 64, MAXW = 20 };
        float inbuf[MAXN + MAXW + 8];
        float outv[MAXN + 2], outc[MAXN + 2];
        for (int t = 0; t < 20000; t++) {
            uint32_t w = rnd() % (MAXW + 1);
            int n = (int)w + (int)(rnd() % (MAXN - (int)w + 1)); /* n >= w */
            for (int i = 0; i < (int)(sizeof inbuf / sizeof inbuf[0]); i++)
                inbuf[i] = (float)(int)rnd() * 0x1p-8f;
            outv[0] = outc[0] = 0.0f;
            outv[MAXN + 1] = outc[MAXN + 1] = 0.0f;
            for (int i = 1; i <= MAXN; i++) {
                outv[i] = 0x5A5A5A5Au; outc[i] = 0x5A5A5A5Au;
            }
            v(outv + 1, inbuf, n, w);
            cr_box_mean_edge(outc + 1, inbuf, n, w);
            cmp_buf("bm", (u8 *)outv, (u8 *)outc, sizeof(float) * (MAXN + 2), (u32)t);
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_box_mean_edge\n");
    }
}

/* ---- batch 54: ready wrappers (size 192-512) --------------------------- */
static void test_tree_batch54(void)
{
    /* --- cr_atan2_image_u8 (0x18003ce10) ---------------------------------- */
    {
        typedef void (WINAPI *v_v_ppp)(void *, const void *, const void *);
        v_v_ppp v = (v_v_ppp)fn_at(RVA(0x18003ce10));
        begin("cr_atan2_image_u8");
        int bad = g_fail;
        enum { MAXW = 48, MAXH = 24 };
        int16_t abuf[MAXW * MAXH], bbuf[MAXW * MAXH];
        u8 dv[MAXW * MAXH], dc[MAXW * MAXH];
        for (int t = 0; t < 4000; t++) {
            int w = 1 + (int)(rnd() % MAXW);
            int h = 1 + (int)(rnd() % MAXH);
            for (int i = 0; i < w * h; i++) {
                abuf[i] = (int16_t)rnd();
                bbuf[i] = (int16_t)rnd();
            }
            cr_image da, db, ddv, ddc;
            cr_image_set(&da, abuf, w, h);
            cr_image_set(&db, bbuf, w, h);
            cr_image_set(&ddv, dv, w, h);
            cr_image_set(&ddc, dc, w, h);
            memset(dv, 0x5A, sizeof dv);
            memset(dc, 0x5A, sizeof dc);
            v(&ddv, &da, &db);
            cr_atan2_image_u8(&ddc, &da, &db);
            cmp_buf("at2img", dv, dc, (size_t)w * h, (u32)t);
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_atan2_image_u8\n");
    }

    /* --- cr_gain_normalize_u8 (0x180037ac0) ------------------------------- */
    {
        typedef int (WINAPI *v_i_p)(void *);
        v_i_p v = (v_i_p)fn_at(RVA(0x180037ac0));
        begin("cr_gain_normalize_u8");
        int bad = g_fail;
        enum { MAXW = 64, MAXH = 24 };
        u8 bv[MAXW * MAXH], bc[MAXW * MAXH];
        for (int t = 0; t < 4000; t++) {
            int w = ((int)(rnd() % (MAXW / 8 + 1))) * 8;   /* multiple of 8 */
            int h = (int)(rnd() % (MAXH + 1));
            if (w == 0) h = (int)(rnd() % 3);              /* exercise w==0 */
            for (int i = 0; i < w * h; i++) bv[i] = (u8)rnd();
            memcpy(bc, bv, (size_t)w * h);
            cr_image dv, dc;
            cr_image_set(&dv, bv, w, h);
            cr_image_set(&dc, bc, w, h);
            int rv = v(&dv);
            int rc = cr_gain_normalize_u8(&dc);
            if (rv != rc) mismatch("gnu8-ret", (u32)t, (u32)rv, (u32)rc);
            if (rv == 0)
                cmp_buf("gnu8", bv, bc, (size_t)w * h, (u32)t);
        }
        /* guard: w not a multiple of 8 */
        for (int t = 0; t < 200; t++) {
            int w = 1 + (int)(rnd() % 31);
            if (w % 8 == 0) continue;
            int h = 1 + (int)(rnd() % 8);
            u8 bv2[64], bc2[64];
            for (int i = 0; i < w * h && i < 64; i++) bv2[i] = bc2[i] = (u8)rnd();
            cr_image dv, dc;
            cr_image_set(&dv, bv2, w, h);
            cr_image_set(&dc, bc2, w, h);
            int rv = v(&dv);
            int rc = cr_gain_normalize_u8(&dc);
            if (rv != rc) mismatch("gnu8-guard", (u32)t, (u32)rv, (u32)rc);
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_gain_normalize_u8\n");
    }

    /* --- cr_gain_normalize_s16 (0x1800175b0) ------------------------------ */
    {
        typedef int (WINAPI *v_i_p)(void *);
        v_i_p v = (v_i_p)fn_at(RVA(0x1800175b0));
        begin("cr_gain_normalize_s16");
        int bad = g_fail;
        enum { MAXW = 64, MAXH = 24 };
        int16_t bv[MAXW * MAXH], bc[MAXW * MAXH];
        for (int t = 0; t < 4000; t++) {
            int w = ((int)(rnd() % (MAXW / 8 + 1))) * 8;
            int h = (int)(rnd() % (MAXH + 1));
            for (int i = 0; i < w * h; i++)
                bv[i] = (int16_t)(int)(rnd() % 0x3fc1u);   /* [0,0x3fc0] */
            memcpy(bc, bv, sizeof(int16_t) * (size_t)w * h);
            cr_image dv, dc;
            cr_image_set(&dv, bv, w, h);
            cr_image_set(&dc, bc, w, h);
            int rv = v(&dv);
            int rc = cr_gain_normalize_s16(&dc);
            if (rv != rc) mismatch("gns16-ret", (u32)t, (u32)rv, (u32)rc);
            if (rv == 0)
                cmp_buf("gns16", (u8 *)bv, (u8 *)bc, sizeof(int16_t) * (size_t)w * h, (u32)t);
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_gain_normalize_s16\n");
    }

    /* --- cr_affine_sample_s16_nn (0x180044040) ---------------------------- */
    {
        typedef void (WINAPI *v_v_ppph)(void *, const void *, const float *, int16_t);
        v_v_ppph v = (v_v_ppph)fn_at(RVA(0x180044040));
        begin("cr_affine_sample_s16_nn");
        int bad = g_fail;
        enum { MAXW = 40, MAXH = 24 };
        int16_t sbuf[MAXW * MAXH], dv[MAXW * MAXH], dc[MAXW * MAXH];
        for (int t = 0; t < 4000; t++) {
            int w = 1 + (int)(rnd() % MAXW);
            int h = 1 + (int)(rnd() % MAXH);
            for (int i = 0; i < w * h; i++) sbuf[i] = (int16_t)rnd();
            float m[6];
            m[0] = (float)((int)(rnd() % 9) - 4);   /* x_col  */
            m[1] = (float)((int)(rnd() % 5) - 2);   /* x_row  */
            m[2] = (float)((int)(rnd() % (2 * w + 4)) - w);
            m[3] = (float)((int)(rnd() % 9) - 4);   /* y_col  */
            m[4] = (float)((int)(rnd() % 5) - 2);   /* y_row  */
            m[5] = (float)((int)(rnd() % (2 * h + 4)) - h);
            int16_t fill = (int16_t)rnd();
            cr_image ds, ddv, ddc;
            cr_image_set(&ds, sbuf, w, h);
            cr_image_set(&ddv, dv, w, h);
            cr_image_set(&ddc, dc, w, h);
            memset(dv, 0x5A, sizeof dv);
            memset(dc, 0x5A, sizeof dc);
            v(&ddv, &ds, m, fill);
            cr_affine_sample_s16_nn(&ddc, &ds, m, fill);
            cmp_buf("affnn", (u8 *)dv, (u8 *)dc, sizeof(int16_t) * (size_t)w * h, (u32)t);
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_affine_sample_s16_nn\n");
    }

    /* --- cr_weighted_running_avg (0x180040ea0) ---------------------------- */
    {
        typedef void (WINAPI *v_v_ppppfp)(int16_t *, int16_t **, const void *,
                                          const u8 **, float, const int16_t *);
        v_v_ppppfp v = (v_v_ppppfp)fn_at(RVA(0x180040ea0));
        begin("cr_weighted_running_avg");
        int bad = g_fail;
        enum { MAXN = 256 };
        int16_t stv[MAXN], stc[MAXN], dstv[MAXN], dstc[MAXN];
        u8 src[MAXN], imgd[MAXN];
        for (int t = 0; t < 20000; t++) {
            int n = 1 + (int)(rnd() % MAXN);
            int w = 1 + (int)(rnd() % n);
            int h = (n + w - 1) / w;
            if (w * h > MAXN) h = MAXN / w;
            int cnt = w * h;
            float k = (float)(int)(rnd() % 400u) * 0x1p-7f - 1.5f;
            int16_t limit = (int16_t)(1 + (int)(rnd() % 0x4000u));
            for (int i = 0; i < cnt; i++) {
                stv[i] = stc[i] = (int16_t)(16 + (int)(rnd() % 0x4000u));
                dstv[i] = dstc[i] = (int16_t)rnd();
                src[i] = (u8)rnd();
                imgd[i] = (u8)rnd();
            }
            cr_image dimg;
            cr_image_set(&dimg, imgd, w, h);
            int16_t *pvd = dstv, *pcd = dstc;
            const u8 *psv = src, *psc = src;
            v(stv, &pvd, &dimg, &psv, k, &limit);
            cr_weighted_running_avg(stc, &pcd, &dimg, &psc, k, &limit);
            cmp_buf("wra-st", (u8 *)stv, (u8 *)stc, sizeof(int16_t) * cnt, (u32)t);
            cmp_buf("wra-ds", (u8 *)dstv, (u8 *)dstc, sizeof(int16_t) * cnt, (u32)t);
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_weighted_running_avg\n");
    }

    /* --- cr_pool_builder (0x18003b690) ------------------------------------ */
    {
        typedef int (WINAPI *v_i_ppbp)(void **, void **, uint8_t, const uint32_t *);
        typedef void (WINAPI *v_v_p)(void *);
        v_i_ppbp v = (v_i_ppbp)fn_at(RVA(0x18003b690));
        v_v_p vsfree = (v_v_p)fn_at(RVA(0x18003bf40));
        begin("cr_pool_builder");
        int bad = g_fail;
        enum { MAXN = 8, MAXSZ = 200 };
        uint32_t sizes[MAXN];
        for (int t = 0; t < 3000; t++) {
            int n = (int)(rnd() % (MAXN + 1));
            for (int i = 0; i < n; i++) sizes[i] = rnd() % MAXSZ;
            u8 hbuf[16], cbuf[16];
            void *pv[MAXN], *pc[MAXN];
            memset(hbuf, 0x5A, sizeof hbuf);
            memset(cbuf, 0x5A, sizeof cbuf);
            memset(pv, 0x5A, sizeof pv);
            memset(pc, 0x5A, sizeof pc);
            int rv = v((void **)hbuf, pv, (uint8_t)n, sizes);
            int rc = cr_pool_builder((void **)cbuf, pc, (uint8_t)n, sizes);
            if (rv != rc) mismatch("pb-ret", (u32)t, (u32)rv, (u32)rc);
            u8 *hb = *(u8 **)hbuf, *cb = *(u8 **)cbuf;
            if ((hb == NULL) != (cb == NULL)) {
                mismatch("pb-null", (u32)t, hb ? 1 : 0, cb ? 1 : 0);
                continue;
            }
            if (hbuf[8] != cbuf[8] || hbuf[9] != cbuf[9])
                mismatch("pb-hdr", (u32)t, hbuf[8] * 256u + hbuf[9],
                         cbuf[8] * 256u + cbuf[9]);
            if (!hb) continue;
            cmp_buf("pb-sizes", hb, cb, 4u * (size_t)n, (u32)t);
            for (int i = 0; i < n; i++) {
                long dv2 = (long)((u8 *)pv[i] - hb);
                long dc2 = (long)((u8 *)pc[i] - cb);
                if (dv2 != dc2) mismatch("pb-off", (u32)(t * 8 + i), (u32)dv2, (u32)dc2);
                uint32_t bs = (sizes[i] + 0x13u) & 0xfffffff0u;
                if (memcmp((u8 *)pv[i] + bs - 4, (u8 *)pc[i] + bs - 4, 4) != 0)
                    mismatch("pb-tr", (u32)(t * 8 + i), ((u8 *)pv[i])[bs - 4],
                             ((u8 *)pc[i])[bs - 4]);
            }
            void *vp = hb;
            vsfree(&vp);
            void *cp = cb;
            cr_sized_free(&cp);
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_pool_builder\n");
    }
}

/* ---- batch 55: pool users + ready wrappers ----------------------------- */
/* shared checker for the cr_pool_allocN wrappers (see cr_pool_builder test) */
static void pool_check(const char *what, int t,
                       void *hv, void *hc, void **pv, void **pc,
                       int n, const uint32_t *sizes, int rv, int rc)
{
    if (rv != rc) { mismatch("p-ret", (u32)t, (u32)rv, (u32)rc); return; }
    u8 *hb = *(u8 **)hv, *cb = *(u8 **)hc;
    if ((hb == NULL) != (cb == NULL)) {
        mismatch("p-null", (u32)t, hb ? 1 : 0, cb ? 1 : 0);
        return;
    }
    if (((u8 *)hv)[8] != ((u8 *)hc)[8] || ((u8 *)hv)[9] != ((u8 *)hc)[9])
        mismatch("p-hdr", (u32)t, ((u8 *)hv)[8] * 256u + ((u8 *)hv)[9],
                 ((u8 *)hc)[8] * 256u + ((u8 *)hc)[9]);
    if (!hb) return;
    cmp_buf(what, hb, cb, 4u * (size_t)n, (u32)t);
    for (int i = 0; i < n; i++) {
        long dv = (long)((u8 *)pv[i] - hb);
        long dc = (long)((u8 *)pc[i] - cb);
        if (dv != dc) mismatch("p-off", (u32)(t * 8 + i), (u32)dv, (u32)dc);
        uint32_t bs = (sizes[i] + 0x13u) & 0xfffffff0u;
        if (memcmp((u8 *)pv[i] + bs - 4, (u8 *)pc[i] + bs - 4, 4) != 0)
            mismatch("p-tr", (u32)(t * 8 + i), ((u8 *)pv[i])[bs - 4],
                     ((u8 *)pc[i])[bs - 4]);
    }
}

static void test_tree_batch55(void)
{
    /* --- cr_affine_sample_u8_nn (0x180014110) ----------------------------- */
    {
        typedef void (WINAPI *v_v_ppph)(void *, const void *, const float *, uint8_t);
        v_v_ppph v = (v_v_ppph)fn_at(RVA(0x180014110));
        begin("cr_affine_sample_u8_nn");
        int bad = g_fail;
        enum { MAXW = 40, MAXH = 24 };
        u8 sbuf[MAXW * MAXH], dv[MAXW * MAXH], dc[MAXW * MAXH];
        for (int t = 0; t < 4000; t++) {
            int w = 1 + (int)(rnd() % MAXW);
            int h = 1 + (int)(rnd() % MAXH);
            for (int i = 0; i < w * h; i++) sbuf[i] = (u8)rnd();
            float m[6];
            m[0] = (float)((int)(rnd() % 9) - 4);
            m[1] = (float)((int)(rnd() % 5) - 2);
            m[2] = (float)((int)(rnd() % (2 * w + 4)) - w);
            m[3] = (float)((int)(rnd() % 9) - 4);
            m[4] = (float)((int)(rnd() % 5) - 2);
            m[5] = (float)((int)(rnd() % (2 * h + 4)) - h);
            u8 fill = (u8)rnd();
            cr_image ds, ddv, ddc;
            cr_image_set(&ds, sbuf, w, h);
            cr_image_set(&ddv, dv, w, h);
            cr_image_set(&ddc, dc, w, h);
            memset(dv, 0x5A, sizeof dv);
            memset(dc, 0x5A, sizeof dc);
            v(&ddv, &ds, m, fill);
            cr_affine_sample_u8_nn(&ddc, &ds, m, fill);
            cmp_buf("affu8", dv, dc, (size_t)w * h, (u32)t);
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_affine_sample_u8_nn\n");
    }

    /* --- cr_mirror_extend_fir (0x18001a510) ------------------------------- */
    {
        typedef int (WINAPI *v_i_ppppii)(uint8_t *, uint8_t *, const uint8_t *,
                                         const int16_t *, int, int);
        v_i_ppppii v = (v_i_ppppii)fn_at(RVA(0x18001a510));
        begin("cr_mirror_extend_fir");
        int bad = g_fail;
        enum { CAP = 512, OFF = 64 };
        static const int kerns[] = { 9, 15, 3, 5, 7, 11, 13, 1 };
        u8 outv[CAP], outc[CAP], dstv[CAP], dstc[CAP], sbuf[CAP];
        int16_t coef[32];
        for (int t = 0; t < 4000; t++) {
            int n = 1 + (int)(rnd() % 120);
            int ncoef = kerns[rnd() % (sizeof kerns / sizeof kerns[0])];
            for (int i = 0; i < CAP; i++) sbuf[i] = (u8)rnd();
            for (int i = 0; i < 32; i++) coef[i] = (int16_t)rnd();
            memset(dstv, 0x5A, sizeof dstv);
            memset(dstc, 0x5A, sizeof dstc);
            memset(outv, 0x5A, sizeof outv);
            memset(outc, 0x5A, sizeof outc);
            const u8 *src = sbuf + OFF;
            int rv = v(outv, dstv, src, coef, n, ncoef);
            int rc = cr_mirror_extend_fir(outc, dstc, src, coef, n, ncoef);
            if (rv != rc) mismatch("mfir-ret", (u32)t, (u32)rv, (u32)rc);
            cmp_buf("mfir-dst", dstv, dstc, (size_t)n + ncoef, (u32)t);
            cmp_buf("mfir-out", outv, outc, (size_t)n + 32, (u32)t);
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_mirror_extend_fir\n");
    }

    /* --- cr_inpaint_masked_box (0x180041140) ------------------------------ */
    {
        typedef void (WINAPI *v_v_ppbi)(void *, void *, uint8_t, int);
        v_v_ppbi v = (v_v_ppbi)fn_at(RVA(0x180041140));
        begin("cr_inpaint_masked_box");
        int bad = g_fail;
        enum { MAXW = 24, MAXH = 16 };
        u8 mv[MAXW * MAXH], mc[MAXW * MAXH];
        float fv[MAXW * MAXH], fc[MAXW * MAXH];
        for (int t = 0; t < 4000; t++) {
            int w = 1 + (int)(rnd() % MAXW);
            int h = 1 + (int)(rnd() % MAXH);
            for (int i = 0; i < w * h; i++) {
                mv[i] = mc[i] = (u8)rnd();
                fv[i] = fc[i] = (float)((int)(rnd() % 2001) - 1000) * 0.25f;
            }
            uint8_t am = (uint8_t)rnd();
            int ap = (int)(rnd() & 1);
            cr_image dvm, dcm, dvf, dcf;
            cr_image_set(&dvm, mv, w, h);
            cr_image_set(&dcm, mc, w, h);
            cr_image_set(&dvf, fv, w, h);
            cr_image_set(&dcf, fc, w, h);
            v(&dvm, &dvf, am, ap);
            cr_inpaint_masked_box(&dcm, &dcf, am, ap);
            cmp_buf("inp-mask", mv, mc, (size_t)w * h, (u32)t);
            cmp_buf("inp-img", (u8 *)fv, (u8 *)fc, sizeof(float) * (size_t)w * h, (u32)t);
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_inpaint_masked_box\n");
    }

    /* --- cr_pool_alloc1 (0x180044230) ------------------------------------- */
    {
        typedef int (WINAPI *v_i_ppz)(void **, void **, uint32_t);
        typedef void (WINAPI *v_v_p)(void *);
        v_i_ppz v = (v_i_ppz)fn_at(RVA(0x180044230));
        v_v_p vsfree = (v_v_p)fn_at(RVA(0x18003bf40));
        begin("cr_pool_alloc1");
        int bad = g_fail;
        enum { MAXSZ = 200 };
        for (int t = 0; t < 3000; t++) {
            uint32_t sizes[1] = { rnd() % MAXSZ };
            u8 hv[16], hc[16];
            void *ov = (void *)0x5A5A, *oc = (void *)0x5A5A;
            memset(hv, 0x5A, sizeof hv);
            memset(hc, 0x5A, sizeof hc);
            int rv = v((void **)hv, &ov, sizes[0]);
            int rc = cr_pool_alloc1((void **)hc, &oc, sizes[0]);
            void *pv[1] = { ov }, *pc[1] = { oc };
            pool_check("pa1", t, hv, hc, pv, pc, 1, sizes, rv, rc);
            if (*(u8 **)hv) { void *p = *(u8 **)hv; vsfree(&p); }
            if (*(u8 **)hc) { void *p = *(u8 **)hc; cr_sized_free(&p); }
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_pool_alloc1\n");
    }

    /* --- cr_pool_alloc2 (0x180047e30) ------------------------------------- */
    {
        typedef int (WINAPI *v_i_ppzpz)(void **, void **, uint32_t, void **, uint32_t);
        typedef void (WINAPI *v_v_p)(void *);
        v_i_ppzpz v = (v_i_ppzpz)fn_at(RVA(0x180047e30));
        v_v_p vsfree = (v_v_p)fn_at(RVA(0x18003bf40));
        begin("cr_pool_alloc2");
        int bad = g_fail;
        enum { MAXSZ = 200 };
        for (int t = 0; t < 3000; t++) {
            uint32_t sizes[2] = { rnd() % MAXSZ, rnd() % MAXSZ };
            u8 hv[16], hc[16];
            void *ov0 = (void *)0x5A5A, *ov1 = (void *)0x5A5A;
            void *oc0 = (void *)0x5A5A, *oc1 = (void *)0x5A5A;
            memset(hv, 0x5A, sizeof hv);
            memset(hc, 0x5A, sizeof hc);
            int rv = v((void **)hv, &ov0, sizes[0], &ov1, sizes[1]);
            int rc = cr_pool_alloc2((void **)hc, &oc0, sizes[0], &oc1, sizes[1]);
            void *pv[2] = { ov0, ov1 }, *pc[2] = { oc0, oc1 };
            pool_check("pa2", t, hv, hc, pv, pc, 2, sizes, rv, rc);
            if (*(u8 **)hv) { void *p = *(u8 **)hv; vsfree(&p); }
            if (*(u8 **)hc) { void *p = *(u8 **)hc; cr_sized_free(&p); }
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_pool_alloc2\n");
    }

    /* --- cr_pool_alloc3 (0x180010f40) ------------------------------------- */
    {
        typedef int (WINAPI *v_i_ppzpzpz)(void **, void **, uint32_t, void **,
                                          uint32_t, void **, uint32_t);
        typedef void (WINAPI *v_v_p)(void *);
        v_i_ppzpzpz v = (v_i_ppzpzpz)fn_at(RVA(0x180010f40));
        v_v_p vsfree = (v_v_p)fn_at(RVA(0x18003bf40));
        begin("cr_pool_alloc3");
        int bad = g_fail;
        enum { MAXSZ = 200 };
        for (int t = 0; t < 3000; t++) {
            uint32_t sizes[3] = { rnd() % MAXSZ, rnd() % MAXSZ, rnd() % MAXSZ };
            u8 hv[16], hc[16];
            void *ov[3], *oc[3];
            for (int i = 0; i < 3; i++) ov[i] = oc[i] = (void *)0x5A5A;
            memset(hv, 0x5A, sizeof hv);
            memset(hc, 0x5A, sizeof hc);
            int rv = v((void **)hv, &ov[0], sizes[0], &ov[1], sizes[1], &ov[2], sizes[2]);
            int rc = cr_pool_alloc3((void **)hc, &oc[0], sizes[0], &oc[1], sizes[1],
                                    &oc[2], sizes[2]);
            pool_check("pa3", t, hv, hc, ov, oc, 3, sizes, rv, rc);
            if (*(u8 **)hv) { void *p = *(u8 **)hv; vsfree(&p); }
            if (*(u8 **)hc) { void *p = *(u8 **)hc; cr_sized_free(&p); }
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_pool_alloc3\n");
    }

    /* --- cr_pool_alloc4 (0x18001b9e0) ------------------------------------- */
    {
        typedef int (WINAPI *v_i_p8)(void **, void **, uint32_t, void **, uint32_t,
                                     void **, uint32_t, void **, uint32_t);
        typedef void (WINAPI *v_v_p)(void *);
        v_i_p8 v = (v_i_p8)fn_at(RVA(0x18001b9e0));
        v_v_p vsfree = (v_v_p)fn_at(RVA(0x18003bf40));
        begin("cr_pool_alloc4");
        int bad = g_fail;
        enum { MAXSZ = 200 };
        for (int t = 0; t < 3000; t++) {
            uint32_t sizes[4] = { rnd() % MAXSZ, rnd() % MAXSZ,
                                  rnd() % MAXSZ, rnd() % MAXSZ };
            u8 hv[16], hc[16];
            void *ov[4], *oc[4];
            for (int i = 0; i < 4; i++) ov[i] = oc[i] = (void *)0x5A5A;
            memset(hv, 0x5A, sizeof hv);
            memset(hc, 0x5A, sizeof hc);
            int rv = v((void **)hv, &ov[0], sizes[0], &ov[1], sizes[1],
                       &ov[2], sizes[2], &ov[3], sizes[3]);
            int rc = cr_pool_alloc4((void **)hc, &oc[0], sizes[0], &oc[1], sizes[1],
                                    &oc[2], sizes[2], &oc[3], sizes[3]);
            pool_check("pa4", t, hv, hc, ov, oc, 4, sizes, rv, rc);
            if (*(u8 **)hv) { void *p = *(u8 **)hv; vsfree(&p); }
            if (*(u8 **)hc) { void *p = *(u8 **)hc; cr_sized_free(&p); }
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_pool_alloc4\n");
    }

    /* --- cr_pool_alloc5 (0x18001d480) ------------------------------------- */
    {
        typedef int (WINAPI *v_i_p10)(void **, void **, uint32_t, void **, uint32_t,
                                      void **, uint32_t, void **, uint32_t,
                                      void **, uint32_t);
        typedef void (WINAPI *v_v_p)(void *);
        v_i_p10 v = (v_i_p10)fn_at(RVA(0x18001d480));
        v_v_p vsfree = (v_v_p)fn_at(RVA(0x18003bf40));
        begin("cr_pool_alloc5");
        int bad = g_fail;
        enum { MAXSZ = 200 };
        for (int t = 0; t < 3000; t++) {
            uint32_t sizes[5] = { rnd() % MAXSZ, rnd() % MAXSZ, rnd() % MAXSZ,
                                  rnd() % MAXSZ, rnd() % MAXSZ };
            u8 hv[16], hc[16];
            void *ov[5], *oc[5];
            for (int i = 0; i < 5; i++) ov[i] = oc[i] = (void *)0x5A5A;
            memset(hv, 0x5A, sizeof hv);
            memset(hc, 0x5A, sizeof hc);
            int rv = v((void **)hv, &ov[0], sizes[0], &ov[1], sizes[1], &ov[2], sizes[2],
                       &ov[3], sizes[3], &ov[4], sizes[4]);
            int rc = cr_pool_alloc5((void **)hc, &oc[0], sizes[0], &oc[1], sizes[1],
                                    &oc[2], sizes[2], &oc[3], sizes[3], &oc[4], sizes[4]);
            pool_check("pa5", t, hv, hc, ov, oc, 5, sizes, rv, rc);
            if (*(u8 **)hv) { void *p = *(u8 **)hv; vsfree(&p); }
            if (*(u8 **)hc) { void *p = *(u8 **)hc; cr_sized_free(&p); }
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_pool_alloc5\n");
    }
}

/* ---- batch 56: streaming FIR + correlation / splat --------------------- */
static void fir_rows_test(const char *tag, u32 rva, int is_i8)
{
    typedef int (WINAPI *v_i_pppi)(void *, void *, const void *, int);
    v_i_pppi v = (v_i_pppi)fn_at(rva);
    begin(tag);
    int bad = g_fail;
    enum { BUF = 16384, IMG = 4096, OUTCAP = 256,
           COEF_OFF = 0, RING_OFF = 4096, SCR_OFF = 4096 + 4096 };
    static u8 bufv[BUF], bufc[BUF];
    u8 img[IMG], outv[OUTCAP], outc[OUTCAP];

    for (int t = 0; t < 1500; t++) {
        int w    = 4 * (1 + (int)(rnd() % 12));      /* 4..48, multiple of 4 */
        int h    = 1 + (int)(rnd() % 20);
        int n    = 1 + (int)(rnd() % 8);             /* kernel taps          */
        int rows = 1 + (int)(rnd() % 24);

        for (int i = 0; i < w * h; i++)
            img[i] = (u8)rnd();

        /* identical starting state for both sides: arbitrary ring/scratch,
           but small coefficients so the 32-bit accumulators cannot overflow */
        for (int i = 0; i < BUF / 2; i++)
            ((int16_t *)bufv)[i] = (int16_t)((int)(rnd() % 2001) - 1000);
        for (int i = 0; i < 32; i++)
            ((int16_t *)bufv)[i] = (int16_t)((int)(rnd() % 33) - 16);
        memcpy(bufc, bufv, BUF);

        cr_image dimg;
        cr_image_set(&dimg, img, w, h);

        cr_fir_row_ctx cv, cc;
        memset(&cv, 0, sizeof cv);
        memset(&cc, 0, sizeof cc);
        cv.n = n; cv.row = 0; cv.base = bufv;
        cv.coef_off = COEF_OFF; cv.out_off = RING_OFF; cv.scratch_off = SCR_OFF;
        cc.n = n; cc.row = 0; cc.base = bufc;
        cc.coef_off = COEF_OFF; cc.out_off = RING_OFF; cc.scratch_off = SCR_OFF;

        for (int r = 1; r <= rows; r++) {
            memset(outv, 0x5A, sizeof outv);
            memset(outc, 0x5A, sizeof outc);
            int rv = v(outv, &cv, &dimg, r);
            int rc = is_i8 ? cr_row_fir_i8(outc, &cc, &dimg, r)
                           : cr_row_fir_i16((int16_t *)outc, &cc, &dimg, r);
            if (rv != rc) {
                mismatch("fir-ret", (u32)t, (u32)rv, (u32)rc);
                break;
            }
            if (cv.row != cc.row) {
                mismatch("fir-row", (u32)t, (u32)cv.row, (u32)cc.row);
                break;
            }
            if (is_i8)
                cmp_buf("fir8", outv, outc, (size_t)w, (u32)t);
            else
                cmp_buf("fir16", outv, outc, sizeof(int16_t) * (size_t)w, (u32)t);
        }
    }
    if (g_fail == bad) end(); else printf("  FAIL %s\n", tag);
}

static void test_tree_batch56(void)
{
    /* --- cr_corr_coeff (0x18002eba0) -------------------------------------- */
    {
        typedef void (WINAPI *v_v_pipiiii)(float *, int *, const int16_t *,
                                           const int16_t *, int, int, int,
                                           int, int);
        v_v_pipiiii v = (v_v_pipiiii)fn_at(RVA(0x18002eba0));
        begin("cr_corr_coeff");
        int bad = g_fail;
        enum { MAXW = 24, MAXH = 20 };
        int16_t A[MAXW * MAXH], B[MAXW * MAXH];
        for (int t = 0; t < 3000; t++) {
            int w = 1 + (int)(rnd() % MAXW);
            int h = 1 + (int)(rnd() % MAXH);
            for (int i = 0; i < w * h; i++) {
                A[i] = (int16_t)((int)(rnd() % 4001) - 2000);
                B[i] = (int16_t)((int)(rnd() % 4001) - 2000);
            }
            int thr = (int)(rnd() % 4001) - 2000;
            int my  = (int)(rnd() % (h + 1));
            int mx  = (int)(rnd() % (w + 1));
            float ov = 123.0f, oc = 123.0f;
            int   vv = 0x5A, vc = 0x5A;
            v(&ov, &vv, A, B, w, h, thr, my, mx);
            cr_corr_coeff(&oc, &vc, A, B, w, h, (int16_t)thr, my, mx);
            if (vv != vc)
                mismatch("corr-valid", (u32)t, (u32)vv, (u32)vc);
            cmp_buf("corr-val", (u8 *)&ov, (u8 *)&oc, sizeof(float), (u32)t);
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_corr_coeff\n");
    }

    /* --- cr_inpaint_index_list (0x18003af20) ------------------------------ */
    {
        typedef void (WINAPI *v_v_pppp)(void *, void *, const uint16_t *,
                                        const uint16_t *const *);
        v_v_pppp v = (v_v_pppp)fn_at(RVA(0x18003af20));
        begin("cr_inpaint_index_list");
        int bad = g_fail;
        enum { MAXW = 24, MAXH = 16, MAXIDX = 64 };
        u8  mv[MAXW * MAXH], mc[MAXW * MAXH];
        float fv[MAXW * MAXH], fc[MAXW * MAXH];
        uint16_t idxs[MAXIDX];
        for (int t = 0; t < 3000; t++) {
            int w = 1 + (int)(rnd() % MAXW);
            int h = 1 + (int)(rnd() % MAXH);
            for (int i = 0; i < w * h; i++) {
                mv[i] = mc[i] = (u8)rnd();
                fv[i] = fc[i] = (float)((int)(rnd() % 2001) - 1000) * 0.25f;
            }
            int cnt = (int)(rnd() % (MAXIDX + 1));
            for (int i = 0; i < cnt; i++)
                idxs[i] = (uint16_t)(rnd() % (w * h));
            uint16_t c = (uint16_t)cnt;
            const uint16_t *ip = idxs;
            cr_image dv, dc, dmv, dmc;
            cr_image_set(&dv, fv, w, h);
            cr_image_set(&dc, fc, w, h);
            cr_image_set(&dmv, mv, w, h);
            cr_image_set(&dmc, mc, w, h);
            v(&dv, &dmv, &c, &ip);
            cr_inpaint_index_list(&dc, &dmc, &c, &ip);
            cmp_buf("inpl-mask", mv, mc, (size_t)w * h, (u32)t);
            cmp_buf("inpl-img", (u8 *)fv, (u8 *)fc,
                    sizeof(float) * (size_t)w * h, (u32)t);
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_inpaint_index_list\n");
    }

    /* --- cr_splat_accum16 (0x180043120) ----------------------------------- */
    {
        typedef void (WINAPI *v_v_ppffppfi)(float *, float *, float, float,
                                            float *, float *, float, int);
        v_v_ppffppfi v = (v_v_ppffppfi)fn_at(RVA(0x180043120));
        begin("cr_splat_accum16");
        int bad = g_fail;
        enum { NBUF = 2048 };
        static float av[NBUF], ac[NBUF], bv[NBUF], bc[NBUF];
        float pts[16], alpha[16];
        for (int t = 0; t < 1500; t++) {
            for (int i = 0; i < 16; i++) {
                pts[i]   = (float)((int)(rnd() % 2001) - 1000) * 0.01f;
                alpha[i] = (float)((int)(rnd() % 2001) - 1000) * 0.01f;
            }
            int k = (int)(rnd() % 4);
            float p3, p4;
            if (rnd() & 1) {                        /* p3<0, p4>=0 -> x0,y0 >= 0 */
                p3 = -(float)(rnd() % 101) * 0.01f;
                p4 =  (float)(rnd() % 101) * 0.01f;
            } else {                                /* p3>=0, p4<=0 -> x0,y0 >= 0 */
                p3 =  (float)(rnd() % 101) * 0.01f;
                p4 = -(float)(rnd() % 101) * 0.01f;
            }
            float beta = (float)((int)(rnd() % 2001) - 1000) * 0.01f;
            for (int i = 0; i < NBUF; i++) {
                av[i] = ac[i] = (float)((int)(rnd() % 2001) - 1000) * 0.25f;
                bv[i] = bc[i] = (float)((int)(rnd() % 2001) - 1000) * 0.25f;
            }
            v(pts, alpha, p3, p4, av, bv, beta, k);
            cr_splat_accum16(pts, alpha, p3, p4, ac, bc, beta, k);
            cmp_buf("splat-A", (u8 *)av, (u8 *)ac,
                    sizeof(float) * NBUF, (u32)t);
            cmp_buf("splat-B", (u8 *)bv, (u8 *)bc,
                    sizeof(float) * NBUF, (u32)t);
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_splat_accum16\n");
    }

    /* --- cr_row_fir_i16 (0x18002af00) / cr_row_fir_i8 (0x180010440) ------- */
    fir_rows_test("cr_row_fir_i16", RVA(0x18002af00u), 0);
    fir_rows_test("cr_row_fir_i8",  RVA(0x180010440u), 1);
}

/* ---- batch 57: small destructor / constructor wrappers ------------------ */
static void test_tree_batch57(void)
{
    typedef void     (WINAPI *p57_v_p)(void *);
    typedef void     (WINAPI *p57_v_pp)(void **, void *);
    typedef int      (WINAPI *p57_i_pp)(void **);
    typedef uint32_t (WINAPI *p57_u_ppuup)(uint32_t *, uint32_t *,
                                           uint32_t, uint32_t, const void *);
    typedef void     (WINAPI *p57_v_pi_pkii)(int *, void **,
                                             const int16_t *, int, int);
    typedef uint32_t (WINAPI *p57_u_ppp)(cr_image *, cr_image *,
                                         const cr_image *);
    typedef int      (WINAPI *p57_i_pppi)(void *, void *, const void *, int);
    v_i_ppz vmalloc = (v_i_ppz)fn_at(RVA(0x180002fe0));
    v_v_p   vsfree  = (v_v_p)fn_at(RVA(0x18003bf40));

    /* --- cr_free_4slot_clear1 (0x18003f940) ------------------------------- */
    {
        p57_v_p v = (p57_v_p)fn_at(RVA(0x18003f940));
        static const int sl[4] = { 0x08, 0x28, 0x48, 0x68 };
        begin("cr_free_4slot_clear1");
        int bad = g_fail;
        for (int t = 0; t < 8000; t++) {
            u8 ov[0x80], oc[0x80];
            memset(ov, 0x5A, sizeof ov); memset(oc, 0x5A, sizeof oc);
            for (int i = 0; i < 4; i++) {
                if (rnd() & 1) {
                    size_t S = 2 + rnd() % 64u; int sz = 1 + (int)(rnd() % (u32)S);
                    *(void **)(ov + sl[i]) = v_sized_alloc(vmalloc, S, sz);
                    *(void **)(oc + sl[i]) = c_sized_alloc(S, sz);
                } else { *(void **)(ov + sl[i]) = NULL; *(void **)(oc + sl[i]) = NULL; }
            }
            v(ov); cr_free_4slot_clear1(oc);
            for (int i = 0; i < 4; i++)
                if (*(void **)(ov + sl[i]) != NULL || *(void **)(oc + sl[i]) != NULL)
                    mismatch("4sc-null", (u32)i,
                             (u64)*(void **)(ov + sl[i]), (u64)*(void **)(oc + sl[i]));
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_free_4slot_clear1\n");
    }

    /* --- cr_free_3ptr_and8 (0x1800140d0) ---------------------------------- */
    {
        p57_v_pp v = (p57_v_pp)fn_at(RVA(0x1800140d0));
        static const int asl[3] = { 0x00, 0x08, 0x28 };
        begin("cr_free_3ptr_and8");
        int bad = g_fail;
        for (int t = 0; t < 8000; t++) {
            u8 ov[0x30], oc[0x30], bv[0x10], bc[0x10];
            memset(ov, 0x5A, sizeof ov); memset(oc, 0x5A, sizeof oc);
            memset(bv, 0x5A, sizeof bv); memset(bc, 0x5A, sizeof bc);
            int use_a = (int)(rnd() & 1);
            if (use_a) {
                for (int i = 0; i < 3; i++) {
                    if (rnd() & 1) {
                        size_t S = 2 + rnd() % 64u; int sz = 1 + (int)(rnd() % (u32)S);
                        *(void **)(ov + asl[i]) = v_sized_alloc(vmalloc, S, sz);
                        *(void **)(oc + asl[i]) = c_sized_alloc(S, sz);
                    } else { *(void **)(ov + asl[i]) = NULL; *(void **)(oc + asl[i]) = NULL; }
                }
            }
            if (rnd() & 1) {
                size_t S = 2 + rnd() % 64u; int sz = 1 + (int)(rnd() % (u32)S);
                *(void **)(bv + 8) = v_sized_alloc(vmalloc, S, sz);
                *(void **)(bc + 8) = c_sized_alloc(S, sz);
            } else { *(void **)(bv + 8) = NULL; *(void **)(bc + 8) = NULL; }

            v(use_a ? (void **)ov : NULL, bv);
            cr_free_3ptr_and8(use_a ? (void **)oc : NULL, bc);

            if (*(void **)(bv + 8) != NULL || *(void **)(bc + 8) != NULL)
                mismatch("3p-b8", (u32)t, (u64)*(void **)(bv + 8), (u64)*(void **)(bc + 8));
            if (use_a)
                for (int i = 0; i < 3; i++)
                    if (*(void **)(ov + asl[i]) != NULL || *(void **)(oc + asl[i]) != NULL)
                        mismatch("3p-a", (u32)i,
                                 (u64)*(void **)(ov + asl[i]), (u64)*(void **)(oc + asl[i]));
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_free_3ptr_and8\n");
    }

    /* --- cr_free_9slot_clear6 (0x180012f70) ------------------------------- */
    {
        p57_v_p v = (p57_v_p)fn_at(RVA(0x180012f70));
        static const int sl[9] = { 0x08, 0x28, 0x48, 0x68, 0x88, 0xa8,
                                   0xc8, 0xe8, 0x108 };
        begin("cr_free_9slot_clear6");
        int bad = g_fail;
        for (int t = 0; t < 8000; t++) {
            u8 ov[0x120], oc[0x120];
            memset(ov, 0x5A, sizeof ov); memset(oc, 0x5A, sizeof oc);
            for (int i = 0; i < 9; i++) {
                if (rnd() & 1) {
                    size_t S = 2 + rnd() % 64u; int sz = 1 + (int)(rnd() % (u32)S);
                    *(void **)(ov + sl[i]) = v_sized_alloc(vmalloc, S, sz);
                    *(void **)(oc + sl[i]) = c_sized_alloc(S, sz);
                } else { *(void **)(ov + sl[i]) = NULL; *(void **)(oc + sl[i]) = NULL; }
            }
            v(ov); cr_free_9slot_clear6(oc);
            for (int i = 0; i < 9; i++)
                if (*(void **)(ov + sl[i]) != NULL || *(void **)(oc + sl[i]) != NULL)
                    mismatch("9sc-null", (u32)i,
                             (u64)*(void **)(ov + sl[i]), (u64)*(void **)(oc + sl[i]));
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_free_9slot_clear6\n");
    }

    /* --- cr_alloc_60_init (0x180038820) ----------------------------------- */
    {
        p57_i_pp v = (p57_i_pp)fn_at(RVA(0x180038820));
        begin("cr_alloc_60_init");
        int bad = g_fail;
        for (int t = 0; t < 4000; t++) {
            void *ov = (void *)0xdead, *oc = (void *)0xdead;
            int rv = v(&ov), rc = cr_alloc_60_init(&oc);
            if (rv != rc) mismatch("a60-ret", (u32)t, (u32)rv, (u32)rc);
            if ((ov == NULL) != (oc == NULL))
                mismatch("a60-null", (u32)t, ov != NULL, oc != NULL);
            if (rv == 0 && ov) {
                if (memcmp(ov, oc, 0x60) != 0) mismatch("a60", (u32)t, 0, 0);
                vsfree(&ov); cr_sized_free(&oc);
            }
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_alloc_60_init\n");
    }

    /* --- cr_round_dims_pow2 (0x180027730) --------------------------------- */
    {
        p57_u_ppuup v = (p57_u_ppuup)fn_at(RVA(0x180027730));
        begin("cr_round_dims_pow2");
        int bad = g_fail;
        for (int t = 0; t < 20000; t++) {
            u8 cfg[8];
            for (int i = 0; i < 8; i++) cfg[i] = (u8)rnd();
            uint32_t w = rnd(), h = rnd();
            uint32_t vw = 0xdeadbeef, vh = 0xdeadbeef;
            uint32_t cw = 0xdeadbeef, ch = 0xdeadbeef;
            uint32_t rv = v(&vw, &vh, w, h, cfg);
            uint32_t rc = cr_round_dims_pow2(&cw, &ch, w, h, cfg);
            if (rv != rc) mismatch("rd-ret", (u32)t, rv, rc);
            if (vw != cw) mismatch("rd-w", (u32)t, vw, cw);
            if (vh != ch) mismatch("rd-h", (u32)t, vh, ch);
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_round_dims_pow2\n");
    }

    /* --- cr_norm_corr_score (0x180046c40) --------------------------------- */
    {
        p57_v_pi_pkii v = (p57_v_pi_pkii)fn_at(RVA(0x180046c40));
        begin("cr_norm_corr_score");
        int bad = g_fail;
        for (int t = 0; t < 20000; t++) {
            int n = (int)(rnd() % 9);              /* 0..8 -> nn 0..64 */
            int mode = (int)(rnd() & 1);
            u8 data[64]; int16_t coef[64];
            for (int i = 0; i < 64; i++) {
                data[i] = (u8)rnd();
                coef[i] = (int16_t)((int)(rnd() % 2001) - 1000);
            }
            void *pv = data, *pc = data;
            int ov = 0x5A5A, oc = 0x5A5A;
            v(&ov, &pv, coef, n, mode);
            cr_norm_corr_score(&oc, &pc, coef, n, mode);
            if (ov != oc) mismatch("ncs", (u32)t, (u32)ov, (u32)oc);
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_norm_corr_score\n");
    }

    /* --- cr_sep_fir_pair (0x180026b30) ------------------------------------ */
    {
        p57_u_ppp v = (p57_u_ppp)fn_at(RVA(0x180026b30));
        begin("cr_sep_fir_pair");
        int bad = g_fail;
        enum { CAP = 0x100 * 0x100 };
        static int16_t sv[CAP], av[CAP], bv[CAP];
        static int16_t sc[CAP], ac[CAP], bc[CAP];
        for (int t = 0; t < 4000; t++) {
            int w = 4 + (int)(rnd() % 0x3d);       /* 4..0x40 */
            int h = 4 + (int)(rnd() % 0x3d);
            if ((rnd() & 7) == 0) { w = (int)(rnd() % 4); }      /* guard: w<4 */
            else if ((rnd() & 15) == 0) { h = (int)(rnd() % 4); }/* guard: h<4 */
            if (w < 0) w = 0;
            if (h < 0) h = 0;
            size_t nn = (size_t)(w > 0 ? w : 0) * (size_t)(h > 0 ? h : 0);
            if (nn > CAP) nn = CAP;
            for (size_t i = 0; i < nn; i++) sv[i] = (int16_t)rnd();
            memcpy(sc, sv, nn * sizeof(int16_t));
            memset(av, 0x5A, sizeof(int16_t) * CAP);
            memset(bv, 0x5A, sizeof(int16_t) * CAP);
            memcpy(ac, av, sizeof(int16_t) * CAP);
            memcpy(bc, bv, sizeof(int16_t) * CAP);
            cr_image svi, avi, bvi, sci, aci, bci;
            cr_image_set(&svi, sv, w, h);
            cr_image_set(&avi, av, w, h);
            cr_image_set(&bvi, bv, w, h);
            cr_image_set(&sci, sc, w, h);
            cr_image_set(&aci, ac, w, h);
            cr_image_set(&bci, bc, w, h);
            uint32_t rv = v(&avi, &bvi, &svi);
            uint32_t rc = cr_sep_fir_pair(&aci, &bci, &sci);
            if (rv != rc) mismatch("sfp-ret", (u32)t, rv, rc);
            cmp_buf("sfp-A", (u8 *)av, (u8 *)ac, sizeof(int16_t) * CAP, (u32)t);
            cmp_buf("sfp-B", (u8 *)bv, (u8 *)bc, sizeof(int16_t) * CAP, (u32)t);
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_sep_fir_pair\n");
    }

    /* --- cr_row_fir_vfir (0x18003b110) ------------------------------------ */
    {
        p57_i_pppi v = (p57_i_pppi)fn_at(RVA(0x18003b110));
        begin("cr_row_fir_vfir");
        int bad = g_fail;
        enum { BUF = 8192, IMG = 8192, OUTCAP = 512,
               COEF_OFF = 0, RING_OFF = 2048, SCR_OFF = 6144 };
        static u8 bufv[BUF], bufc[BUF];
        u8 img[IMG], outv[OUTCAP], outc[OUTCAP];
        for (int t = 0; t < 1500; t++) {
            int w    = 4 * (1 + (int)(rnd() % 12));   /* 4..48 */
            int h    = 1 + (int)(rnd() % 20);
            int n    = 1 + (int)(rnd() % 8);
            int rows = 1 + (int)(rnd() % 24);
            for (int i = 0; i < w * h; i++) img[i] = (u8)rnd();
            for (int i = 0; i < BUF; i++) bufv[i] = (u8)rnd();
            for (int i = 0; i < 32; i++)
                ((int16_t *)bufv)[i] = (int16_t)((int)(rnd() % 33) - 16);
            memcpy(bufc, bufv, BUF);
            cr_image dimg;
            cr_image_set(&dimg, img, w, h);
            cr_fir_row_ctx cv, cc;
            memset(&cv, 0, sizeof cv); memset(&cc, 0, sizeof cc);
            cv.n = n; cv.base = bufv;
            cv.coef_off = COEF_OFF; cv.out_off = RING_OFF; cv.scratch_off = SCR_OFF;
            cc.n = n; cc.base = bufc;
            cc.coef_off = COEF_OFF; cc.out_off = RING_OFF; cc.scratch_off = SCR_OFF;
            for (int r = 1; r <= rows; r++) {
                memset(outv, 0x5A, sizeof outv);
                memset(outc, 0x5A, sizeof outc);
                int rv = v(outv, &cv, &dimg, r);
                int rc = cr_row_fir_vfir(outc, &cc, &dimg, r);
                if (rv != rc) { mismatch("vfr-ret", (u32)t, (u32)rv, (u32)rc); break; }
                if (cv.row != cc.row) { mismatch("vfr-row", (u32)t, (u32)cv.row, (u32)cc.row); break; }
                cmp_buf("vfr", outv, outc, (size_t)w, (u32)t);
            }
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_row_fir_vfir\n");
    }
}

static void test_tree_batch58(void)
{
    typedef int  (WINAPI *p58_i_pf_pif)(float *, const float *, int, float);
    typedef void (WINAPI *p58_v_pfi)(int16_t *, float, int);
    typedef void (WINAPI *p58_v_pppfi)(int16_t *, int16_t *, int16_t *, float, int);
    typedef int  (WINAPI *p58_i_ppii)(const void *, int, int);

    /* --- cr_masked_median_f32 (0x18000e6f0) ------------------------------- */
    {
        p58_i_pf_pif v = (p58_i_pf_pif)fn_at(RVA(0x18000e6f0));
        begin("cr_masked_median_f32");
        int bad = g_fail;
        for (int t = 0; t < 20000; t++) {
            int   n    = (int)(rnd() % 40);
            float skip = (float)((int)(rnd() % 7) - 3);
            float src[40];
            for (int i = 0; i < n; i++) {
                if ((rnd() & 3) == 0) src[i] = skip;
                else src[i] = (float)((int)(rnd() % 2001) - 1000) * 0.25f;
            }
            float ov = 1234.5f, oc = 1234.5f;
            int rv = v(&ov, src, n, skip);
            int rc = cr_masked_median_f32(&oc, src, n, skip);
            if (rv != rc) mismatch("mm-ret", (u32)t, (u32)rv, (u32)rc);
            if (memcmp(&ov, &oc, 4) != 0) mismatch("mm", (u32)t, 0, 0);
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_masked_median_f32\n");
    }

    /* --- cr_gaussian_window_q15 (0x1800345f0) ----------------------------- */
    {
        p58_v_pfi v = (p58_v_pfi)fn_at(RVA(0x1800345f0));
        begin("cr_gaussian_window_q15");
        int bad = g_fail;
        for (int t = 0; t < 8000; t++) {
            int      n     = 1 + (int)(rnd() % 40);
            float    sigma = (float)(1 + (int)(rnd() % 20)) * 0.5f;
            int16_t  ov[40], oc[40];
            memset(ov, 0x5A, sizeof ov); memset(oc, 0x5A, sizeof oc);
            v(ov, sigma, n); cr_gaussian_window_q15(oc, sigma, n);
            cmp_buf("gw", (u8 *)ov, (u8 *)oc, (size_t)n * 2, (u32)t);
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_gaussian_window_q15\n");
    }

    /* --- cr_gaussian_deriv_windows_q15 (0x180018a10) ---------------------- */
    {
        p58_v_pppfi v = (p58_v_pppfi)fn_at(RVA(0x180018a10));
        begin("cr_gaussian_deriv_windows_q15");
        int bad = g_fail;
        for (int t = 0; t < 8000; t++) {
            int      n     = 1 + (int)(rnd() % 40);
            float    sigma = (float)(1 + (int)(rnd() % 20)) * 0.5f;
            int16_t  gv[40], dv[40], d2v[40], gc[40], dc[40], d2c[40];
            memset(gv,0x5A,sizeof gv);  memset(dv,0x5A,sizeof dv);
            memset(d2v,0x5A,sizeof d2v); memset(gc,0x5A,sizeof gc);
            memset(dc,0x5A,sizeof dc);  memset(d2c,0x5A,sizeof d2c);
            v(gv, dv, d2v, sigma, n);
            cr_gaussian_deriv_windows_q15(gc, dc, d2c, sigma, n);
            cmp_buf("gdw-g",  (u8 *)gv,  (u8 *)gc,  (size_t)n * 2, (u32)t);
            cmp_buf("gdw-d",  (u8 *)dv,  (u8 *)dc,  (size_t)n * 2, (u32)t);
            cmp_buf("gdw-d2", (u8 *)d2v, (u8 *)d2c, (size_t)n * 2, (u32)t);
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_gaussian_deriv_windows_q15\n");
    }

    /* --- cr_bilinear_angle_sample (0x18003e7a0) --------------------------- */
    {
        p58_i_ppii v = (p58_i_ppii)fn_at(RVA(0x18003e7a0));
        begin("cr_bilinear_angle_sample");
        int bad = g_fail;
        enum { AW = 32, AH = 24 };
        static int8_t fldv[AW * AH], fldc[AW * AH];
        for (int t = 0; t < 20000; t++) {
            int w  = 1 + (int)(rnd() % AW);
            int h  = 1 + (int)(rnd() % AH);
            int ox = (int)(rnd() % 64) - 32;
            int oy = (int)(rnd() % 64) - 32;
            for (int i = 0; i < w * h; i++) fldv[i] = (int8_t)rnd();
            memcpy(fldc, fldv, (size_t)w * h);
            cr_angle_field dv, dc;
            memset(&dv, 0, sizeof dv); memset(&dc, 0, sizeof dc);
            dv.img.data = fldv; dv.img.w = w; dv.img.h = h; dv.ox = ox; dv.oy = oy;
            dc.img.data = fldc; dc.img.w = w; dc.img.h = h; dc.ox = ox; dc.oy = oy;
            int px = ox + (int)(rnd() % (u32)(w * 64 + 128)) - 64;
            int py = oy + (int)(rnd() % (u32)(h * 64 + 128)) - 64;
            int rv = v(&dv, px, py);
            int rc = cr_bilinear_angle_sample(&dc, px, py);
            if (rv != rc) mismatch("bas", (u32)t, (u32)rv, (u32)rc);
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_bilinear_angle_sample\n");
    }
}

static void test_tree_batch59(void)
{
    typedef int      (WINAPI *p59_v_ppf)(cr_image *, cr_image *, float);
    typedef uint32_t (WINAPI *p59_u_ppiiiii)(cr_image *, const cr_image *,
                                             int, int, int, int);
    typedef uint32_t (WINAPI *p59_u_ppiiiiih)(cr_image *, const cr_image *,
                                              int, int, int, int, uint16_t);

    /* --- cr_gauss_blur7_pair (0x180034740) -------------------------------- */
    {
        p59_v_ppf v = (p59_v_ppf)fn_at(RVA(0x180034740));
        begin("cr_gauss_blur7_pair");
        int bad = g_fail;
        enum { CW = 32, CH = 32 };
        static int16_t av[CW * CH], bv[CW * CH], ac[CW * CH], bc[CW * CH];
        for (int t = 0; t < 4000; t++) {
            int   w     = 8 + (int)(rnd() % (CW - 8));
            int   h     = 8 + (int)(rnd() % (CH - 8));
            float sigma = (float)(1 + (int)(rnd() % 12)) * 0.5f;
            for (int i = 0; i < CW * CH; i++) {
                av[i] = (int16_t)rnd(); bv[i] = (int16_t)rnd();
            }
            memcpy(ac, av, sizeof av); memcpy(bc, bv, sizeof bv);
            cr_image ai, bi, aci, bci;
            cr_image_set(&ai, av, w, h);  cr_image_set(&bi, bv, w, h);
            cr_image_set(&aci, ac, w, h); cr_image_set(&bci, bc, w, h);
            int rv = v(&ai, &bi, sigma);
            int rc = cr_gauss_blur7_pair(&aci, &bci, sigma);
            if (rv != rc) { mismatch("gb7-ret", (u32)t, (u32)rv, (u32)rc); continue; }
            cmp_buf("gb7-a", (u8 *)av, (u8 *)ac, sizeof av, (u32)t);
            cmp_buf("gb7-b", (u8 *)bv, (u8 *)bc, sizeof bv, (u32)t);
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_gauss_blur7_pair\n");
    }

    /* --- cr_blit_mirror_s16 / cr_blit_extend_s16 (6-arg) ------------------ */
    {
        enum { DW = 48, DH = 48, SW = 8, SH = 8 };
        static int16_t dv[DW * DH], dc[DW * DH], sv[SW * SH];

        struct { const char *tag; int rva;
                 uint32_t (*clean)(cr_image *, const cr_image *,
                                   int, int, int, int); } cases[2] = {
            { "cr_blit_mirror_s16", 0x180024fa0, cr_blit_mirror_s16 },
            { "cr_blit_extend_s16", 0x180046a80, cr_blit_extend_s16 },
        };
        for (int c = 0; c < 2; c++) {
            p59_u_ppiiiii v = (p59_u_ppiiiii)fn_at(RVA(cases[c].rva));
            begin(cases[c].tag);
            int bad = g_fail;
            for (int t = 0; t < 4000; t++) {
                for (int i = 0; i < DW * DH; i++) dv[i] = (int16_t)rnd();
                memcpy(dc, dv, sizeof dc);
                for (int i = 0; i < SW * SH; i++) sv[i] = (int16_t)rnd();
                int top = (int)(rnd() % 7), bottom = (int)(rnd() % 7);
                int left = (int)(rnd() % 7), right = (int)(rnd() % 7);
                cr_image dvimg, dcimg, simg;
                cr_image_set(&dvimg, dv, DW, DH);
                cr_image_set(&dcimg, dc, DW, DH);
                cr_image_set(&simg, sv, SW, SH);
                uint32_t rv = v(&dvimg, &simg, top, bottom, left, right);
                uint32_t rc = cases[c].clean(&dcimg, &simg,
                                             top, bottom, left, right);
                if (rv != rc) mismatch("blit-ret", (u32)t, rv, rc);
                cmp_buf("blit", (u8 *)dv, (u8 *)dc, sizeof dv, (u32)t);
            }
            if (g_fail == bad) end(); else printf("  FAIL %s\n", cases[c].tag);
        }
    }

    /* --- cr_blit_fillborder_s16 (0x18003cf00, 7-arg) ---------------------- */
    {
        enum { DW = 48, DH = 48, SW = 8, SH = 8 };
        static int16_t dv[DW * DH], dc[DW * DH], sv[SW * SH];
        p59_u_ppiiiiih v = (p59_u_ppiiiiih)fn_at(RVA(0x18003cf00));
        begin("cr_blit_fillborder_s16");
        int bad = g_fail;
        for (int t = 0; t < 4000; t++) {
            for (int i = 0; i < DW * DH; i++) dv[i] = (int16_t)rnd();
            memcpy(dc, dv, sizeof dc);
            for (int i = 0; i < SW * SH; i++) sv[i] = (int16_t)rnd();
            int top = (int)(rnd() % 7), bottom = (int)(rnd() % 7);
            int left = (int)(rnd() % 7), right = (int)(rnd() % 7);
            uint16_t fill = (uint16_t)rnd();
            cr_image dvimg, dcimg, simg;
            cr_image_set(&dvimg, dv, DW, DH);
            cr_image_set(&dcimg, dc, DW, DH);
            cr_image_set(&simg, sv, SW, SH);
            uint32_t rv = v(&dvimg, &simg, top, bottom, left, right, fill);
            uint32_t rc = cr_blit_fillborder_s16(&dcimg, &simg,
                                                 top, bottom, left, right, fill);
            if (rv != rc) mismatch("bfb-ret", (u32)t, rv, rc);
            cmp_buf("bfb", (u8 *)dv, (u8 *)dc, sizeof dv, (u32)t);
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_blit_fillborder_s16\n");
    }
}

/* ---- batch 60: Gaussian-derivative blur pair + box-median filter -------- */
static void test_tree_batch60(void)
{
    /* cr_gauss_deriv_blur_pair: separate vendor/clean output+source buffers. */
    {
        enum { W = 64, H = 48, CAP = W * H };
        static int16_t sv[CAP], sc[CAP], o1v[CAP], o1c[CAP], o2v[CAP], o2c[CAP];
        cr_image svi, sci, o1vi, o1ci, o2vi, o2ci;
        typedef uint32_t (WINAPI *p60_pair)(cr_image *, cr_image *, const cr_image *, float);
        p60_pair vfn = (p60_pair)fn_at(RVA(0x18002b930));

        begin("cr_gauss_deriv_blur_pair");
        int bad = g_fail;
        for (int t = 0; t < 2000; t++) {
            for (int i = 0; i < CAP; i++) sv[i] = (int16_t)rnd();
            memcpy(sc, sv, sizeof sv);
            memset(o1v, 0x5A, sizeof o1v); memset(o1c, 0x5A, sizeof o1c);
            memset(o2v, 0x5A, sizeof o2v); memset(o2c, 0x5A, sizeof o2c);
            cr_image_set(&svi, sv, W, H); cr_image_set(&sci, sc, W, H);
            cr_image_set(&o1vi, o1v, W, H); cr_image_set(&o1ci, o1c, W, H);
            cr_image_set(&o2vi, o2v, W, H); cr_image_set(&o2ci, o2c, W, H);
            float sigma = (float)(rnd() % 1000) * 0.01f + 0.3f;
            uint32_t rv = vfn(&o1vi, &o2vi, &svi, sigma);
            uint32_t rc = cr_gauss_deriv_blur_pair(&o1ci, &o2ci, &sci, sigma);
            if (rv != rc) mismatch("ret", (u32)t, rv, rc);
            if (rv == 0) {
                cmp_buf("o1", (u8 *)o1v, (u8 *)o1c, sizeof o1v, (u32)t);
                cmp_buf("o2", (u8 *)o2v, (u8 *)o2c, sizeof o2v, (u32)t);
            }
        }
        if (g_fail == bad) end(); else printf("  FAIL cr_gauss_deriv_blur_pair\n");
    }

    /* cr_box_median_u8: 8-bit box median, several window sizes. */
    {
        enum { W = 40, H = 30, CAP = W * H };
        static uint8_t sv[CAP], sc[CAP], ov[CAP], oc[CAP];
        cr_image svi, sci, ovi, oci;
        typedef uint32_t (WINAPI *p60_med)(cr_image *, const cr_image *, uint16_t);
        p60_med vfn = (p60_med)fn_at(RVA(0x1800256e0));

        for (int n = 1; n <= 9; n += 2) {
            char nm[48]; snprintf(nm, sizeof nm, "cr_box_median_u8(n=%d)", n);
            begin(nm);
            int bad = g_fail;
            for (int t = 0; t < 500; t++) {
                for (int i = 0; i < CAP; i++) sv[i] = (uint8_t)rnd();
                memcpy(sc, sv, sizeof sv);
                memset(ov, 0x5A, sizeof ov); memset(oc, 0x5A, sizeof oc);
                cr_image_set(&svi, sv, W, H); cr_image_set(&sci, sc, W, H);
                cr_image_set(&ovi, ov, W, H); cr_image_set(&oci, oc, W, H);
                uint32_t rv = vfn(&ovi, &svi, (uint16_t)n);
                uint32_t rc = cr_box_median_u8(&oci, &sci, (uint16_t)n);
                if (rv != rc) mismatch("ret", (u32)t, rv, rc);
                if (rv == 0)
                    cmp_buf("out", ov, oc, sizeof ov, (u32)t);
            }
            if (g_fail == bad) end(); else printf("  FAIL %s\n", nm);
        }
    }
}


/* ---- 0x18002e060: multi-scale score-map builder -------------------------- */
static void test_mscale_score_2e060(void)
{
    typedef int (WINAPI *v_t)(uint16_t *, void *, const void *, const void *,
                              const void *);
    v_t v = (v_t)fn_at(RVA(0x18002e060));
    begin("cr_mscale_score_2e060");
    int bad = g_fail;

    enum { MW = 48, MH = 48, SLACK = 16 };
    static int16_t srv[(MH + SLACK) * (MW + SLACK)];
    static int16_t src[(MH + SLACK) * (MW + SLACK)];
    static float   sov[(MH + 8) * (MW + 8)];
    static float   soc[(MH + 8) * (MW + 8)];
    static uint32_t bmv[4096], bmc[4096];
    static uint8_t iv[0x20], ic[0x20], ov[0x20], oc[0x20];
    static uint8_t kv[0x20], kc[0x20], dv[0x20], dc[0x20];

    for (int t = 0; t < 3000; t++) {
        int W = 16 + (int)(rnd() % 25u);
        int H = 16 + (int)(rnd() % 25u);
        int scale = 1 + (int)(rnd() % 5u);
        if ((t % 19) == 0)
            scale = W + (int)(rnd() % 3u);           /* guard path */
        int w2 = (W + scale - 1) / scale + (int)(rnd() % 2u);
        int h2 = (H + scale - 1) / scale + (int)(rnd() % 2u);
        int offc = 8 + (int)(rnd() % 8u);
        int offr = 8 + (int)(rnd() % 8u);
        int stride = W + 16;

        for (int i = 0; i < (MH + SLACK) * (MW + SLACK); i++) {
            int16_t x = (int16_t)((int)(rnd() % 4001) - 2000);
            srv[i] = x; src[i] = x;
        }
        for (int i = 0; i < 4096; i++) {
            uint32_t x = (rnd() & 1u) ? (uint32_t)rnd()
                                      : ((uint32_t)rnd() | 0xffff0000u);
            bmv[i] = x;
        }
        memcpy(bmc, bmv, sizeof bmv);

        float sigma = (float)(rnd() % 200u) / 100.0f + 0.05f;
        float thr;
        if ((int)(rnd() % 4u) == 0)
            thr = -1.0f - (float)(rnd() % 100u) / 10.0f;
        else
            thr = (float)(int)(rnd() % 4000u) / 10.0f - 60.0f;

        mk_img2(iv, srv, W, H);
        mk_img2(ic, src, W, H);
        memset(ov, 0, 0x20); memset(oc, 0, 0x20);
        *(int *)(ov + 0x00) = w2; *(int *)(ov + 0x04) = h2;
        *(void **)(ov + 0x08) = sov;
        *(int *)(ov + 0x10) = w2; *(int *)(ov + 0x14) = h2;
        *(int *)(oc + 0x00) = w2; *(int *)(oc + 0x04) = h2;
        *(void **)(oc + 0x08) = soc;
        *(int *)(oc + 0x10) = w2; *(int *)(oc + 0x14) = h2;
        for (int i = 0; i < (MH + 8) * (MW + 8); i++) {
            sov[i] = -1.0f; soc[i] = -1.0f;
        }

        memset(kv, 0, 0x20); memset(kc, 0, 0x20);
        *(int *)(kv + 0x00) = stride; *(int *)(kc + 0x00) = stride;
        *(void **)(kv + 0x08) = bmv;  *(void **)(kc + 0x08) = bmc;
        *(int *)(kv + 0x18) = offc;   *(int *)(kc + 0x18) = offc;
        *(int *)(kv + 0x1c) = offr;   *(int *)(kc + 0x1c) = offr;
        memset(dv, 0, 0x20); memset(dc, 0, 0x20);
        *(float *)(dv + 0x0c) = sigma; *(float *)(dc + 0x0c) = sigma;
        *(int *)(dv + 0x10) = scale;   *(int *)(dc + 0x10) = scale;
        *(float *)(dv + 0x14) = thr;   *(float *)(dc + 0x14) = thr;

        uint16_t ouv = 0, ouc = 0;
        int rv = v(&ouv, ov, kv, iv, dv);
        int rc = cr_mscale_score_2e060(&ouc, (cr_image *)oc, kc,
                                       (const cr_image *)ic, dc);
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }
        if (ouv != ouc) mismatch("out", (u32)t, ouv, ouc);
        cmp_buf("score", (const u8 *)sov, (const u8 *)soc,
                (size_t)w2 * h2 * 4, (u32)t);
        cmp_buf("bits", (const u8 *)bmv, (const u8 *)bmc, sizeof bmv, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_mscale_score_2e060\n");
}

/* ---- 0x180016d00: integer-factor downscale driver ------------------------ */
static void test_mscale_run_16d00(void)
{
    typedef int (WINAPI *v_t)(uint16_t *, void *, const void *, const void *);
    v_t v = (v_t)fn_at(RVA(0x180016d00));
    begin("cr_mscale_run_16d00");
    int bad = g_fail;

    enum { MW = 48, MH = 48, SLACK = 16 };
    static int16_t srv[(MH + SLACK) * (MW + SLACK)];
    static int16_t src[(MH + SLACK) * (MW + SLACK)];
    static uint32_t bmv[4096], bmc[4096];
    static uint8_t iv[0x20], ic[0x20], kv[0x20], kc[0x20];
    static uint8_t dv[0x20], dc[0x20];

    for (int t = 0; t < 3000; t++) {
        int W = 16 + (int)(rnd() % 25u);
        int H = 16 + (int)(rnd() % 25u);
        int n = 1 + (int)(rnd() % 6u);
        if ((t % 23) == 0)
            n = W + (int)(rnd() % 3u);               /* guard path */
        int offc = 8 + (int)(rnd() % 8u);
        int offr = 8 + (int)(rnd() % 8u);
        int stride = W + 16;

        for (int i = 0; i < (MH + SLACK) * (MW + SLACK); i++) {
            int16_t x = (int16_t)((int)(rnd() % 4001) - 2000);
            srv[i] = x; src[i] = x;
        }
        for (int i = 0; i < 4096; i++) {
            uint32_t x = (rnd() & 1u) ? (uint32_t)rnd()
                                      : ((uint32_t)rnd() | 0xffff0000u);
            bmv[i] = x;
        }
        memcpy(bmc, bmv, sizeof bmv);

        float sigma = (float)(rnd() % 200u) / 100.0f + 0.05f;
        float thr = ((int)(rnd() % 4u) == 0)
                        ? (-1.0f - (float)(rnd() % 100u) / 10.0f)
                        : ((float)(int)(rnd() % 4000u) / 10.0f - 60.0f);

        mk_img2(iv, srv, W, H);
        mk_img2(ic, src, W, H);

        memset(kv, 0, 0x20); memset(kc, 0, 0x20);
        *(int *)(kv + 0x00) = stride; *(int *)(kc + 0x00) = stride;
        *(void **)(kv + 0x08) = bmv;  *(void **)(kc + 0x08) = bmc;
        *(int *)(kv + 0x18) = offc;   *(int *)(kc + 0x18) = offc;
        *(int *)(kv + 0x1c) = offr;   *(int *)(kc + 0x1c) = offr;
        memset(dv, 0, 0x20); memset(dc, 0, 0x20);
        *(float *)(dv + 0x0c) = sigma; *(float *)(dc + 0x0c) = sigma;
        *(int *)(dv + 0x10) = n;       *(int *)(dc + 0x10) = n;
        *(float *)(dv + 0x14) = thr;   *(float *)(dc + 0x14) = thr;

        uint16_t ouv = 0, ouc = 0;
        int rv = v(&ouv, kv, iv, dv);
        int rc = cr_mscale_run_16d00(&ouc, kc, (const cr_image *)ic, dc);
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }
        if (ouv != ouc) mismatch("out", (u32)t, ouv, ouc);
        cmp_buf("bits", (const u8 *)bmv, (const u8 *)bmc, sizeof bmv, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_mscale_run_16d00\n");
}

/* ---- 0x18002a620: masked illumination flattening ------------------------- */
static void test_masked_contrast_norm_2a620(void)
{
    typedef int (WINAPI *v_t)(void *, void *, void *);
    v_t v = (v_t)fn_at(RVA(0x18002a620));
    begin("cr_masked_contrast_norm_2a620");
    int bad = g_fail;

    enum { MW = 44, MH = 44 };
    static float   sv[MW * MH], sc[MW * MH];
    static int16_t mv[MW * MH], mc[MW * MH];
    static uint8_t bv[MW * MH], bc[MW * MH];
    static uint8_t pv[0x60], pc[0x60];
    static uint8_t iv[0x20], ic[0x20], kv[0x20], kc[0x20];

    for (int t = 0; t < 2500; t++) {
        int W = 12 + (int)(rnd() % 33u);
        int H = 12 + (int)(rnd() % 33u);
        int n = W * H;
        int8_t flag = (int8_t)((int)(rnd() % 3u) - 1);

        for (int i = 0; i < n; i++) {
            unsigned k = (unsigned)(rnd() % 8u);
            float f;
            if (k == 0)      f = 0.0f;
            else if (k == 1) f = 255.0f;
            else if (k == 2) f = (float)(int)(rnd() % 300u) - 20.0f;
            else             f = (float)(rnd() % 2560u) / 10.0f;
            sv[i] = f; sc[i] = f;
            int16_t m = (int16_t)((int)(rnd() % 2001u) - 1000);
            mv[i] = m; mc[i] = m;
            uint8_t b = (rnd() % 3u) ? 0xff : (uint8_t)rnd();
            bv[i] = b; bc[i] = b;
        }

        memset(pv, 0, sizeof pv); memset(pc, 0, sizeof pc);
        *(int8_t *)(pv + 0x08) = flag; *(int8_t *)(pc + 0x08) = flag;
        *(void **)(pv + 0x58) = mv;    *(void **)(pc + 0x58) = mc;

        memset(iv, 0, 0x20); memset(ic, 0, 0x20);
        *(int *)(iv + 0x00) = W; *(int *)(iv + 0x04) = H;
        *(void **)(iv + 0x08) = sv;
        *(int *)(iv + 0x10) = W; *(int *)(iv + 0x14) = H;
        *(int *)(ic + 0x00) = W; *(int *)(ic + 0x04) = H;
        *(void **)(ic + 0x08) = sc;
        *(int *)(ic + 0x10) = W; *(int *)(ic + 0x14) = H;
        memset(kv, 0, 0x20); memset(kc, 0, 0x20);
        *(int *)(kv + 0x00) = W; *(int *)(kv + 0x04) = H;
        *(void **)(kv + 0x08) = bv;
        *(int *)(kv + 0x10) = W; *(int *)(kv + 0x14) = H;
        *(int *)(kc + 0x00) = W; *(int *)(kc + 0x04) = H;
        *(void **)(kc + 0x08) = bc;
        *(int *)(kc + 0x10) = W; *(int *)(kc + 0x14) = H;

        int rv = v(iv, pv, kv);
        int rc = cr_masked_contrast_norm_2a620((cr_image *)ic, pc,
                                               (cr_image *)kc);
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }
        cmp_buf("src", (const u8 *)sv, (const u8 *)sc, (size_t)n * 4, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_masked_contrast_norm_2a620\n");
}

/* ---- 0x180032580: mask-build + flatten dispatcher ------------------------ */
static void test_mask_norm_32580(void)
{
    typedef int (WINAPI *v_t)(void *, void *, void *, void *, const void *,
                              int, const void *, int);
    v_t v = (v_t)fn_at(RVA(0x180032580));
    begin("cr_mask_norm_32580");
    int bad = g_fail;

    enum { MW = 40, MH = 40 };
    static float   sv[MW * MH], sc[MW * MH];
    static uint8_t pv[MW * MH], pc[MW * MH];
    static int16_t mdv[MW * MH], mdc[MW * MH];
    static uint8_t ctxv[0x80], ctxc[0x80];
    static uint8_t a3v[0x60], a3c[0x60];
    static uint8_t a5v[0x10], a5c[0x10];
    static uint8_t cfgv[0x80], cfgc[0x80];
    static uint8_t iv[0x20], ic[0x20], kv[0x20], kc[0x20], jv[0x20], jc[0x20];
    static uint8_t dv[0x20], dc[0x20];

    for (int t = 0; t < 2500; t++) {
        int W = 16 + (int)(rnd() % 25u);
        int H = 16 + (int)(rnd() % 25u);
        int n = W * H;
        int mode;
        switch (t % 6) {
        case 0:  mode = 0; break;
        case 1:  mode = 2; break;
        case 2:  mode = 3 + (int)(rnd() % 3u); break;
        case 3:  mode = 1; break;
        case 4:  mode = 1; break;
        default: mode = 1; break;
        }
        int flag = (int)(rnd() % 2u);
        int a5val = (int)(rnd() % 3u) - 1;
        int hnull = (int)(rnd() % 2u);
        /* never let mode 1 reach feature_extract_step_2db20 with a dummy
         * handle: either the handle is NULL (0x3ec) or the inner gate is shut */
        if (mode == 1 && !hnull) {
            if ((t & 1) == 0) flag = 1;
            else              a5val = 1;
        }

        for (int i = 0; i < n; i++) {
            float f = (float)(rnd() % 2560u) / 10.0f;
            sv[i] = f; sc[i] = f;
            uint8_t b = (uint8_t)rnd();
            pv[i] = b; pc[i] = b;
            int16_t m = (int16_t)((int)(rnd() % 2001u) - 1000);
            mdv[i] = m; mdc[i] = m;
        }

        memset(ctxv, 0, sizeof ctxv); memset(ctxc, 0, sizeof ctxc);
        *(void **)(ctxv + 0x58) = mdv; *(void **)(ctxc + 0x58) = mdc;

        memset(a3v, 0, sizeof a3v); memset(a3c, 0, sizeof a3c);
        memset(iv, 0, 0x20); memset(ic, 0, 0x20);
        *(int *)(iv + 0x00) = W; *(int *)(iv + 0x04) = H;
        *(void **)(iv + 0x08) = mdv;
        *(int *)(iv + 0x10) = W; *(int *)(iv + 0x14) = H;
        *(int *)(ic + 0x00) = W; *(int *)(ic + 0x04) = H;
        *(void **)(ic + 0x08) = mdc;
        *(int *)(ic + 0x10) = W; *(int *)(ic + 0x14) = H;
        *(void **)(a3v + 0x28) = iv; *(void **)(a3c + 0x28) = ic;
        if (!hnull) {
            *(void **)(a3v + 0x38 + (long)(t % 3) * 8) = a3v;
            *(void **)(a3c + 0x38 + (long)(t % 3) * 8) = a3c;
        }

        memset(a5v, 0, sizeof a5v); memset(a5c, 0, sizeof a5c);
        *(int *)(a5v + 4) = a5val; *(int *)(a5c + 4) = a5val;

        memset(cfgv, 0, sizeof cfgv); memset(cfgc, 0, sizeof cfgc);
        cfgv[0x44] = (uint8_t)mode; cfgc[0x44] = (uint8_t)mode;
        float sig = (float)(rnd() % 50u) / 10.0f + 0.1f;
        *(float *)(cfgv + 0x48) = sig; *(float *)(cfgc + 0x48) = sig;

        memset(kv, 0, 0x20); memset(kc, 0, 0x20);
        *(int *)(kv + 0x00) = W; *(int *)(kv + 0x04) = H;
        *(void **)(kv + 0x08) = pv;
        *(int *)(kv + 0x10) = W; *(int *)(kv + 0x14) = H;
        *(int *)(kc + 0x00) = W; *(int *)(kc + 0x04) = H;
        *(void **)(kc + 0x08) = pc;
        *(int *)(kc + 0x10) = W; *(int *)(kc + 0x14) = H;

        int idx = t % 3;
        int rv = v(iv, ctxv, a3v, kv, a5v, idx, cfgv, flag);
        int rc = cr_mask_norm_32580((cr_image *)ic, ctxc, a3c,
                                    (const cr_image *)kc, a5c, idx, cfgc, flag);
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }
        cmp_buf("src", (const u8 *)sv, (const u8 *)sc, (size_t)n * 4, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_mask_norm_32580\n");
}

/* ---- 0x180026410: masked contrast/sharpness normalisation -------------- */
static void test_masked_contrast_norm_26410(void)
{
    typedef int (WINAPI *v_fn)(int *, int *, cr_image *, const cr_image *,
                               const void *, const void *);
    v_fn v = (v_fn)fn_at(RVA(0x180026410));
    begin("cr_masked_contrast_norm_26410");
    int bad = g_fail;

    static uint8_t srcV[4096],  srcC[4096];
    static uint8_t mdataV[4096], mdataC[4096];
    static int16_t gsrcV[4096], gsrcC[4096];
    static uint8_t ctxV[0x80],  ctxC[0x80];

    for (int t = 0; t < 3000; t++) {
        int W = (int)(rnd() % 40u) + 21;
        int H = (int)(rnd() % 20u) + 21;
        int n = W * H;
        if (n > 4096) continue;

        for (int i = 0; i < n; i++) {
            uint8_t s = (uint8_t)rnd();
            srcV[i] = s;  srcC[i] = s;
            uint8_t m = (uint8_t)rnd();
            mdataV[i] = m; mdataC[i] = m;
            /* ctx+0x50 is an s16 image, read as the residual reference row */
            int16_t g = (int16_t)((int)(rnd() % 4096u) - 2048);
            gsrcV[i] = g; gsrcC[i] = g;
        }

        cr_image sv, sc, mv, mc;
        memset(&sv, 0, sizeof sv); memset(&sc, 0, sizeof sc);
        memset(&mv, 0, sizeof mv); memset(&mc, 0, sizeof mc);
        sv.a = sv.w = W; sv.b = sv.h = H; sv.data = srcV;
        sc.a = sc.w = W; sc.b = sc.h = H; sc.data = srcC;
        mv.a = mv.w = W; mv.b = mv.h = H; mv.data = mdataV;
        mc.a = mc.w = W; mc.b = mc.h = H; mc.data = mdataC;

        memset(ctxV, 0, sizeof ctxV); memset(ctxC, 0, sizeof ctxC);
        float sigma0 = (float)(rnd() % 50u) / 10.0f + 0.1f;
        *(float *)(ctxV + 0x4) = sigma0;
        *(float *)(ctxC + 0x4) = sigma0;
        int8_t flag = (int8_t)((t & 1) ? 1 : -1);
        *(int8_t *)(ctxV + 0x8) = flag;
        *(int8_t *)(ctxC + 0x8) = flag;
        *(int32_t *)(ctxV + 0x50) = W; *(int32_t *)(ctxV + 0x54) = H;
        *(void **)(ctxV + 0x58) = gsrcV;
        *(int32_t *)(ctxV + 0x60) = W; *(int32_t *)(ctxV + 0x64) = H;
        *(int32_t *)(ctxC + 0x50) = W; *(int32_t *)(ctxC + 0x54) = H;
        *(void **)(ctxC + 0x58) = gsrcC;
        *(int32_t *)(ctxC + 0x60) = W; *(int32_t *)(ctxC + 0x64) = H;

        int o1v = 0, o1c = 0, o2v = 0, o2c = 0;
        int rv = v(&o1v, &o2v, &mv, (const cr_image *)&sv, ctxV, ctxV);
        int rc = cr_masked_contrast_norm_26410(&o1c, &o2c, &mc,
                                              (const cr_image *)&sc, ctxC, ctxC);
        if (rv != rc) mismatch("ret", (u32)t, (u32)rv, (u32)rc);
        if (o1v != o1c) mismatch("out1", (u32)t, (u32)o1v, (u32)o1c);
        if (o2v != o2c) mismatch("out2", (u32)t, (u32)o2v, (u32)o2c);
        cmp_buf("mask", (const u8 *)mdataV, (const u8 *)mdataC, (u32)n, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_masked_contrast_norm_26410\n");
}

/* ---- 0x180042150: block variance ratio + adaptive smoothing ------------ */
static void test_block_variance_run_42150(void)
{
    typedef int (WINAPI *v_t)(void *, const void *, int, float *);
    v_t v = (v_t)fn_at(RVA(0x180042150));
    begin("cr_block_variance_run_42150");
    int bad = g_fail;

    enum { MAXW = 48, MAXH = 40 };
    static float iv[MAXW * MAXH], ic[MAXW * MAXH];
    static uint8_t cfgv[0x40], cfgc[0x40];

    for (int t = 0; t < 3000; t++) {
        int bw = 2 + (int)(rnd() % 5u);          /* block_w = 2..6 */
        int nblk = 2 + (int)(rnd() % 4u);        /* ncols   = 2..5 */
        int W = bw * nblk;
        int H = 2 + (int)(rnd() % 24u);
        int n = W * H;
        int flavour = (int)(rnd() % 3u);

        for (int i = 0; i < n; i++) {
            float f;
            if (flavour == 0) {
                f = (float)((i % W) * 4 + (i / W));
                f += (float)(rnd() % 3u) * 0.5f;
            } else if (flavour == 1) {
                f = (float)(rnd() % 2560u) / 10.0f;
            } else {
                f = (rnd() % 5u == 0) ? 255.0f : (float)(rnd() % 256u);
            }
            iv[i] = f; ic[i] = f;
        }

        memset(cfgv, 0, sizeof cfgv); memset(cfgc, 0, sizeof cfgc);
        uint8_t en = (uint8_t)((rnd() % 4u) ? 1 : 0);
        cfgv[0] = cfgc[0] = en;
        float thr = (float)(rnd() % 12u) / 100.0f;
        *(float *)(cfgv + 4) = thr; *(float *)(cfgc + 4) = thr;

        int mode;
        switch (t % 8) {
        case 0:  mode = 0; break;
        case 1:  mode = 1; break;
        case 2:  mode = 2; break;
        case 3:  mode = 3; break;
        case 4:  mode = 5; break;
        case 5:  mode = 7; break;
        case 6:  mode = 4; break;                 /* even -> 0x69 */
        default: mode = 3 + 2 * (int)(rnd() % 3u); break;
        }
        cfgv[8] = cfgc[8] = (uint8_t)mode;
        float sig = (float)(rnd() % 40u) / 10.0f - 0.5f;
        *(float *)(cfgv + 0xc) = sig; *(float *)(cfgc + 0xc) = sig;

        cr_image a, b;
        memset(&a, 0, sizeof a); memset(&b, 0, sizeof b);
        a.a = a.w = W; a.b = a.h = H; a.data = iv;
        b.a = b.w = W; b.b = b.h = H; b.data = ic;

        float rv = -12345.0f, rcv = -12345.0f;
        int r1 = v(&a, cfgv, bw, &rv);
        int r2 = cr_block_variance_run_42150(&b, cfgc, bw, &rcv);
        if (r1 != r2) mismatch("ret", (u32)t, (u32)r1, (u32)r2);
        if (memcmp(&rv, &rcv, 4) != 0)
            mismatch("result", (u32)t, *(const u32 *)&rv, *(const u32 *)&rcv);
        cmp_buf("img", (const u8 *)iv, (const u8 *)ic, (u32)(n * 4), (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_block_variance_run_42150\n");
}

/* ---- 0x1800208a0: mask/feature stage driver ---------------------------- */
static void test_mask_stage_208a0(void)
{
    typedef int (WINAPI *v_t)(void *, void *, const void *, const void *,
                              void **, const uint8_t *, int, int);
    v_t v = (v_t)fn_at(RVA(0x1800208a0));
    begin("cr_mask_stage_208a0");
    int bad = g_fail;

    enum { MAXPIX = 64 * 176 };
    static float    dv[MAXPIX], dc[MAXPIX];
    static uint8_t  iv[MAXPIX], ic[MAXPIX];
    static uint8_t  fsv[MAXPIX], fsc[MAXPIX];
    static uint16_t mkv[MAXPIX], mkc[MAXPIX];
    static uint16_t msv[MAXPIX], msc[MAXPIX];
    static uint16_t m2v[MAXPIX], m2c[MAXPIX];
    static uint16_t n2v[MAXPIX], n2c[MAXPIX];
    static uint8_t  ctxv[0x80], ctxc[0x80];
    static uint8_t  a3v[0x10], a3c[0x10];
    static uint8_t  cfgv[0x100], cfgc[0x100];
    static void    *slv[16], *slc[16];
    static uint8_t  s0v[0x20], s0c[0x20];
    static uint8_t  sfv[0x20], sfc[0x20];
    static uint8_t  s5v[0x20], s5c[0x20];
    static uint8_t  s6v[0x20], s6c[0x20];
    static uint8_t  ilv[0x10], ilc[0x10];
    static uint16_t idv[16], idc[16];

    for (int t = 0; t < 2000; t++) {
        int big = (t % 10) == 9;
        int W, H, bw;
        if (big) {
            W = 64; H = 80; bw = 8;
        } else {
            bw = 4 + (int)(rnd() % 5u);
            W  = bw * (4 + (int)(rnd() % 4u));
            H  = 20 + (int)(rnd() % 21u);
        }
        int n = W * H;
        if (n > MAXPIX) continue;

        for (int i = 0; i < n; i++) {
            float f = (float)(rnd() % 2560u) / 10.0f;
            dv[i] = f; dc[i] = f;
            uint8_t b = (uint8_t)rnd();
            iv[i] = b; ic[i] = b;
            uint8_t s = (uint8_t)rnd();
            fsv[i] = s; fsc[i] = s;
            uint16_t m = (uint16_t)((rnd() % 3u == 0) ? 0xffffu : rnd());
            msv[i] = m; msc[i] = m;
            uint16_t m2 = (uint16_t)rnd();
            n2v[i] = m2; n2c[i] = m2;
        }
        for (int i = 0; i < 8; i++) {
            uint16_t k = (uint16_t)(rnd() % (unsigned)n);
            idv[i] = k; idc[i] = k;
        }

        int idx = 1 + (t % 3);
        int sel = big ? 1 : 0;
        int mode = (t & 1) ? 2 : 0;
        int tsel = (t % 3 == 0) ? 3 : 0;
        int bvary = (t % 4 == 0);
        int pmode = (t % 5 == 0) ? 7 : 0;

        memset(ctxv, 0, sizeof ctxv); memset(ctxc, 0, sizeof ctxc);
        float sig = (float)(rnd() % 50u) / 10.0f + 0.1f;
        *(float *)(ctxv + 4) = sig;  *(float *)(ctxc + 4) = sig;
        int8_t cflag = (int8_t)((t & 1) ? 1 : -1);
        *(int8_t *)(ctxv + 8) = cflag; *(int8_t *)(ctxc + 8) = cflag;
        *(void **)(ctxv + 0x18) = m2v; *(void **)(ctxc + 0x18) = m2c;
        *(void **)(ctxv + 0x58) = mkv; *(void **)(ctxc + 0x58) = mkc;

        memset(a3v, 0, sizeof a3v); memset(a3c, 0, sizeof a3c);
        *(int *)(a3v + 4) = 1; *(int *)(a3c + 4) = 1;

        memset(s0v, 0, 0x20); memset(s0c, 0, 0x20);
        *(int16_t *)(s0v + 0) = (int16_t)W; *(int16_t *)(s0v + 2) = (int16_t)H;
        *(int16_t *)(s0c + 0) = (int16_t)W; *(int16_t *)(s0c + 2) = (int16_t)H;

        memset(sfv, 0, 0x20); memset(sfc, 0, 0x20);
        *(int16_t *)(sfv + 0) = (int16_t)W; *(int16_t *)(sfv + 2) = (int16_t)H;
        *(int16_t *)(sfc + 0) = (int16_t)W; *(int16_t *)(sfc + 2) = (int16_t)H;
        sfv[6] = 8; sfc[6] = 8;
        *(void **)(sfv + 0x10) = fsv; *(void **)(sfc + 0x10) = fsc;

        memset(s5v, 0, 0x20); memset(s5c, 0, 0x20);
        *(int16_t *)(s5v + 0) = (int16_t)W; *(int16_t *)(s5v + 2) = (int16_t)H;
        *(void **)(s5v + 0x10) = msv; *(void **)(s5c + 0x10) = msc;
        *(int16_t *)(s5c + 0) = (int16_t)W; *(int16_t *)(s5c + 2) = (int16_t)H;

        memset(s6v, 0, 0x20); memset(s6c, 0, 0x20);
        *(int16_t *)(s6v + 0) = (int16_t)W; *(int16_t *)(s6v + 2) = (int16_t)H;
        *(void **)(s6v + 0x10) = n2v; *(void **)(s6c + 0x10) = n2c;
        *(int16_t *)(s6c + 0) = (int16_t)W; *(int16_t *)(s6c + 2) = (int16_t)H;

        memset(ilv, 0, 0x10); memset(ilc, 0, 0x10);
        *(uint16_t *)(ilv + 0) = 8; *(uint16_t *)(ilc + 0) = 8;
        *(void **)(ilv + 8) = idv; *(void **)(ilc + 8) = idc;

        for (int i = 0; i < 16; i++) { slv[i] = NULL; slc[i] = NULL; }
        slv[0] = s0v;  slc[0] = s0c;
        slv[5] = s5v;  slc[5] = s5c;
        slv[6] = s6v;  slc[6] = s6c;
        slv[idx] = sfv; slc[idx] = sfc;
        slv[0x0e] = ilv; slc[0x0e] = ilc;

        memset(cfgv, 0, sizeof cfgv); memset(cfgc, 0, sizeof cfgc);
        cfgv[9] = (uint8_t)tsel; cfgc[9] = (uint8_t)tsel;
        *(int16_t *)(cfgv + 6) = (int16_t)bw; *(int16_t *)(cfgc + 6) = (int16_t)bw;
        int16_t thr = (int16_t)((int)(rnd() % 4001u) - 2000);
        *(int16_t *)(cfgv + 0x2c) = thr; *(int16_t *)(cfgc + 0x2c) = thr;
        cfgv[0x30] = (uint8_t)bvary; cfgc[0x30] = (uint8_t)bvary;
        cfgv[0x40] = (uint8_t)sel; cfgc[0x40] = (uint8_t)sel;
        cfgv[0x44] = (uint8_t)mode; cfgc[0x44] = (uint8_t)mode;
        float bsig = (float)(rnd() % 30u) / 10.0f + 0.3f;
        *(float *)(cfgv + 0x48) = bsig; *(float *)(cfgc + 0x48) = bsig;
        cfgv[0xc0] = (uint8_t)pmode; cfgc[0xc0] = (uint8_t)pmode;
        cfgv[0xc1] = (uint8_t)(t & 1); cfgc[0xc1] = (uint8_t)(t & 1);
        *(uint16_t *)(cfgv + 0xc2) = 16; *(uint16_t *)(cfgc + 0xc2) = 16;
        int32_t pthr = (int32_t)(rnd() % 500u);
        *(int32_t *)(cfgv + 0xc4) = pthr; *(int32_t *)(cfgc + 0xc4) = pthr;
        cfgv[0xcc] = 3; cfgc[0xcc] = 3;
        cfgv[0xcd] = 3; cfgc[0xcd] = 3;

        cr_image dimg, dimgc, iimg, iimgc;
        memset(&dimg, 0, sizeof dimg); memset(&dimgc, 0, sizeof dimgc);
        memset(&iimg, 0, sizeof iimg); memset(&iimgc, 0, sizeof iimgc);
        dimg.a  = dimg.w  = W; dimg.b  = dimg.h  = H; dimg.data  = dv;
        dimgc.a = dimgc.w = W; dimgc.b = dimgc.h = H; dimgc.data = dc;
        iimg.a  = iimg.w  = W; iimg.b  = iimg.h  = H; iimg.data  = iv;
        iimgc.a = iimgc.w = W; iimgc.b = iimgc.h = H; iimgc.data = ic;

        int rv = v(&dimg, &iimg, a3v, ctxv, slv, cfgv, idx, (t & 1));
        int rc = cr_mask_stage_208a0(&dimgc, &iimgc, a3c, ctxc,
                                     slc, cfgc, idx, (t & 1));
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }
        cmp_buf("dst", (const u8 *)dv, (const u8 *)dc, (size_t)n * 4, (u32)t);
        cmp_buf("img", (const u8 *)iv, (const u8 *)ic, (size_t)n, (u32)t);
        cmp_buf("mask", (const u8 *)mkv, (const u8 *)mkc, (size_t)n * 2, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_mask_stage_208a0\n");
}

/* ---- 0x180034ed0: descriptor/point-grid feature pipeline ---------------- */
static void test_feature_pipeline_34ed0(void)
{
    typedef int (WINAPI *v_t)(void *, const void *, int, const uint8_t *);
    v_t v = (v_t)fn_at(RVA(0x180034ed0));
    begin("cr_feature_pipeline_34ed0");
    int bad = g_fail;

    enum { PW = 64, PH = 40 };
    static uint8_t  imgv[PW * PH], imgc[PW * PH];
    static uint8_t  objv[0x200], objc[0x200];
    static uint8_t  outv[0x100], outc[0x100];
    static uint8_t  lutv[0x40], lutc[0x40];
    static uint8_t  cfgv[0x80], cfgc[0x80];

    for (int t = 0; t < 1200; t++) {
        int tsel = (t % 4 == 0) ? 0 : ((t % 4 == 1) ? 2 : ((t % 4 == 2) ? 4 : 3));
        int gsel;
        switch (t % 6) {
        case 0:  gsel = 1; break;
        case 1:  gsel = 5; break;
        case 2:  gsel = 4; break;
        default: gsel = (int)(rnd() % 8u); break;
        }
        int arg3 = (int)(rnd() % 2u);

        memset(imgv, 100, sizeof imgv);            /* flat: no local maxima */
        memset(imgc, 100, sizeof imgc);

        memset(objv, 0, sizeof objv); memset(objc, 0, sizeof objc);
        *(int32_t *)(objv + 0x00) = PW; *(int32_t *)(objv + 0x04) = PH;
        *(void   **)(objv + 0x08) = imgv;
        *(int32_t *)(objv + 0x10) = PW; *(int32_t *)(objv + 0x14) = PH;
        *(void   **)(objv + 0x48) = outv;
        *(int32_t *)(objc + 0x00) = PW; *(int32_t *)(objc + 0x04) = PH;
        *(void   **)(objc + 0x08) = imgc;
        *(int32_t *)(objc + 0x10) = PW; *(int32_t *)(objc + 0x14) = PH;
        *(void   **)(objc + 0x48) = outc;

        memset(outv, 0, sizeof outv); memset(outc, 0, sizeof outc);
        memset(lutv, 0, sizeof lutv); memset(lutc, 0, sizeof lutc);

        memset(cfgv, 0, sizeof cfgv); memset(cfgc, 0, sizeof cfgc);
        cfgv[0x01] = (uint8_t)gsel;   cfgc[0x01] = (uint8_t)gsel;
        cfgv[0x08] = 2;               cfgc[0x08] = 2;
        cfgv[0x0b] = (uint8_t)tsel;   cfgc[0x0b] = (uint8_t)tsel;
        cfgv[0x0c] = (uint8_t)(rnd() % 7u); cfgc[0x0c] = cfgv[0x0c];
        *(int32_t *)(cfgv + 0x14) = PH; *(int32_t *)(cfgc + 0x14) = PH;
        float sig = 0.72f + (float)(rnd() % 150u) / 100.0f;
        *(float *)(cfgv + 0x1c) = sig; *(float *)(cfgc + 0x1c) = sig;
        cfgv[0x24] = (uint8_t)((t & 1) ? 2 : 5);
        cfgc[0x24] = cfgv[0x24];
        cfgv[0x25] = 4; cfgc[0x25] = 4;
        cfgv[0x26] = 4; cfgc[0x26] = 4;
        cfgv[0x09] = (uint8_t)((t & 1) ? 2 : 1); cfgc[0x09] = cfgv[0x09];
        cfgv[0x3d] = (uint8_t)((t % 3) ? 0 : 1); cfgc[0x3d] = cfgv[0x3d];

        int rv = v(objv, lutv, arg3, cfgv);
        int rc = cr_feature_pipeline_34ed0(objc, lutc, arg3, cfgc);
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }
        if (rv != 0) continue;
        uint32_t fv, fc;
        #define CF(off) do { fv = *(uint32_t *)(outv + (off)); \
            fc = *(uint32_t *)(outc + (off)); \
            if (fv != fc) mismatch("f" #off, (u32)t, fv, fc); } while (0)
        CF(0x20); CF(0x30); CF(0x31); CF(0x58);
        #undef CF
        if ((*(void **)(outv + 0x00) != NULL) != (*(void **)(outc + 0x00) != NULL))
            mismatch("p0", (u32)t, 0, 0);
        if ((*(void **)(outv + 0x08) != NULL) != (*(void **)(outc + 0x08) != NULL))
            mismatch("p8", (u32)t, 0, 0);
        /* release the vendor's allocations, then ours */
        cr_free_3ptr_and8((void **)outv, NULL);
        cr_free_3ptr_and8((void **)outc, NULL);
        memset(outv, 0, sizeof outv); memset(outc, 0, sizeof outc);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_feature_pipeline_34ed0\n");
}

/* ---- 0x180048310: sharpness-gated mask refinement ---------------------- */
static void test_sharp_gate_48310(void)
{
    typedef int (WINAPI *v_t)(void *, void *, void *, void *, const void *,
                              const void *, int, int, const void *);
    v_t v = (v_t)fn_at(RVA(0x180048310));
    begin("cr_sharp_gate_48310");
    int bad = g_fail;

    enum { MAXW = 80, MAXH = 50, MAXPIX = MAXW * MAXH, MAXW32 = 96 };
    static uint8_t  maskv[MAXPIX], maskc[MAXPIX];
    static uint32_t bitv[MAXW32 / 32 * MAXH], bitc[MAXW32 / 32 * MAXH];
    static int16_t  gsv[MAXPIX], gsc[MAXPIX];
    static uint8_t  a3v[0x80], a3c[0x80];
    static uint8_t  a4v[0x100], a4c[0x100];
    static uint8_t  a5v[0x100], a5c[0x100];
    static uint8_t  a6v[8],    a6c[8];
    static uint8_t  a9v[0x20], a9c[0x20];
    static uint8_t  slv[MAXPIX], slc[MAXPIX];

    for (int t = 0; t < 2000; t++) {
        int W = 40 + (int)(rnd() % 40u);
        int H = 30 + (int)(rnd() % 20u);
        int n = W * H;
        int astride = ((W + 31) / 32) * 32;
        int nwords  = astride / 32 * H;

        for (int i = 0; i < n; i++) {
            uint8_t m = (uint8_t)rnd();
            maskv[i] = m; maskc[i] = m;
            int16_t g = (int16_t)((int)(rnd() % 4096u) - 2048);
            gsv[i] = g; gsc[i] = g;
            uint8_t s = (uint8_t)rnd();
            slv[i] = s; slc[i] = s;
        }
        for (int i = 0; i < nwords; i++) {
            uint32_t w = rnd();
            bitv[i] = w; bitc[i] = w;
        }

        int mode, skip, a7, idx = (int)(rnd() % 3u);
        switch (t % 5) {
        case 0:  mode = 1; skip = 0; a7 = 0; break;
        case 1:  mode = 1; skip = 1; a7 = 0; break;
        case 2:  mode = 1; skip = 0; a7 = 1; break;
        case 3:  mode = 2; skip = (int)(rnd() % 2u); a7 = (int)(rnd() % 2u); break;
        default: mode = (t & 1) ? 0 : 3; skip = 0; a7 = 0; break;
        }
        int null3 = (t % 17 == 0);

        memset(a3v, 0, sizeof a3v); memset(a3c, 0, sizeof a3c);
        int8_t flag = (int8_t)((t & 2) ? 1 : -1);
        *(int8_t *)(a3v + 8) = flag; *(int8_t *)(a3c + 8) = flag;
        *(int32_t *)(a3v + 0x50) = W; *(int32_t *)(a3v + 0x54) = H;
        *(int32_t *)(a3c + 0x50) = W; *(int32_t *)(a3c + 0x54) = H;
        *(void **)(a3v + 0x58) = gsv; *(void **)(a3c + 0x58) = gsc;
        *(int32_t *)(a3v + 0x60) = W; *(int32_t *)(a3v + 0x64) = H;
        *(int32_t *)(a3c + 0x60) = W; *(int32_t *)(a3c + 0x64) = H;

        memset(a4v, 0, sizeof a4v); memset(a4c, 0, sizeof a4c);
        memset(a5v, 0, sizeof a5v); memset(a5c, 0, sizeof a5c);
        a5v[0x44] = (uint8_t)mode; a5c[0x44] = (uint8_t)mode;
        float sig = (float)(rnd() % 50u) / 10.0f + 0.1f;
        *(float *)(a5v + 0x48) = sig; *(float *)(a5c + 0x48) = sig;

        memset(a6v, 0, sizeof a6v); memset(a6c, 0, sizeof a6c);
        *(int32_t *)(a6v + 4) = skip; *(int32_t *)(a6c + 4) = skip;

        memset(a9v, 0, sizeof a9v); memset(a9c, 0, sizeof a9c);
        *(void **)(a9v + 0x10) = slv; *(void **)(a9c + 0x10) = slc;

        cr_image av, ac, mv, mc;
        memset(&av, 0, sizeof av); memset(&ac, 0, sizeof ac);
        memset(&mv, 0, sizeof mv); memset(&mc, 0, sizeof mc);
        av.a = astride; av.b = H; av.data = bitv; av.w = W; av.h = H;
        ac.a = astride; ac.b = H; ac.data = bitc; ac.w = W; ac.h = H;
        mv.a = mv.w = W; mv.b = mv.h = H; mv.data = maskv;
        mc.a = mc.w = W; mc.b = mc.h = H; mc.data = maskc;

        int rv = v(&av, &mv, null3 ? NULL : a3v, a4v, a5v, a6v, a7, idx, a9v);
        int rc = cr_sharp_gate_48310(&ac, &mc, null3 ? NULL : a3c, a4c,
                                     a5c, a6c, a7, idx, a9c);
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }
        cmp_buf("bits", (const u8 *)bitv, (const u8 *)bitc,
                (size_t)nwords * 4, (u32)t);
        cmp_buf("mask", (const u8 *)maskv, (const u8 *)maskc, (size_t)n, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_sharp_gate_48310\n");
}

/* ---- 0x1800344e0: mask refine ------------------------------------------ */
static void test_mask_refine_344e0(void)
{
    typedef int (WINAPI *v_t)(void *, void *, void *, void *, void *, void *,
                              void *, int, int);
    v_t v = (v_t)fn_at(RVA(0x1800344e0));
    begin("cr_mask_refine_344e0");
    int bad = g_fail;

    enum { MAXW = 80, MAXH = 50, MAXPIX = MAXW * MAXH, MAXW32 = 96 };
    static uint8_t  imgv[MAXPIX], imgc[MAXPIX];
    static uint32_t bitv[MAXW32 / 32 * MAXH], bitc[MAXW32 / 32 * MAXH];
    static uint8_t  slv[MAXPIX], slc[MAXPIX];
    static uint8_t  sl2v[MAXPIX], sl2c[MAXPIX];
    static uint8_t  sl3v[MAXPIX], sl3c[MAXPIX];
    static int16_t  gsv[MAXPIX], gsc[MAXPIX];
    static uint8_t  a5v[0x80], a5c[0x80];
    static uint8_t  a4v[0x100], a4c[0x100];
    static uint8_t  a6v[0x80], a6c[0x80];
    static uint8_t  a7v[0x100], a7c[0x100];
    static uint8_t  s0v[0x20], s0c[0x20], s1v[0x20], s1c[0x20];
    static uint8_t  s2v[0x20], s2c[0x20];
    static uint8_t  ilv[0x20], ilc[0x20];
    static uint16_t idv[16], idc[16];

    for (int t = 0; t < 1500; t++) {
        int W = 40 + (int)(rnd() % 40u);
        int H = 30 + (int)(rnd() % 20u);
        int n = W * H;
        int astride = ((W + 31) / 32) * 32;
        int nwords  = astride / 32 * H;

        for (int i = 0; i < n; i++) {
            uint8_t b = (uint8_t)rnd();
            imgv[i] = b; imgc[i] = b;
            uint8_t s = (uint8_t)rnd();
            slv[i] = s; slc[i] = s;
            uint8_t s2 = (uint8_t)rnd();
            sl2v[i] = s2; sl2c[i] = s2;
            uint8_t s3 = (uint8_t)rnd();
            sl3v[i] = s3; sl3c[i] = s3;
            int16_t g = (int16_t)((int)(rnd() % 4096u) - 2048);
            gsv[i] = g; gsc[i] = g;
        }
        for (int i = 0; i < nwords; i++) {
            uint32_t w = rnd();
            bitv[i] = w; bitc[i] = w;
        }
        for (int i = 0; i < 8; i++) {
            uint16_t k = (uint16_t)(rnd() % (unsigned)n);
            idv[i] = k; idc[i] = k;
        }

        int mode;
        switch (t % 6) {
        case 0:  mode = 0; break;
        case 1:  mode = 1; break;
        case 2:  mode = 2; break;
        case 3:  mode = 3; break;
        case 4:  mode = -1; break;
        default: mode = (int)(rnd() % 4u); break;
        }
        int sub  = (t % 2) ? 5 : 0;
        int a8   = (int)(rnd() % 3u);
        int a9   = (int)(rnd() % 3u);

        memset(a5v, 0, sizeof a5v); memset(a5c, 0, sizeof a5c);
        int8_t flag = (int8_t)((t & 2) ? 1 : -1);
        *(int8_t *)(a5v + 8) = flag; *(int8_t *)(a5c + 8) = flag;
        *(int32_t *)(a5v + 0x50) = W; *(int32_t *)(a5v + 0x54) = H;
        *(int32_t *)(a5c + 0x50) = W; *(int32_t *)(a5c + 0x54) = H;
        *(void **)(a5v + 0x58) = gsv; *(void **)(a5c + 0x58) = gsc;
        *(int32_t *)(a5v + 0x60) = W; *(int32_t *)(a5v + 0x64) = H;
        *(int32_t *)(a5c + 0x60) = W; *(int32_t *)(a5c + 0x64) = H;

        memset(a4v, 0, sizeof a4v); memset(a4c, 0, sizeof a4c);

        memset(s0v, 0, 0x20); memset(s0c, 0, 0x20);
        memset(s1v, 0, 0x20); memset(s1c, 0, 0x20);
        memset(s2v, 0, 0x20); memset(s2c, 0, 0x20);
        *(void **)(s0v + 0x10) = slv;  *(void **)(s0c + 0x10) = slc;
        *(void **)(s1v + 0x10) = sl2v; *(void **)(s1c + 0x10) = sl2c;
        *(void **)(s2v + 0x10) = sl3v; *(void **)(s2c + 0x10) = sl3c;

        memset(ilv, 0, 0x20); memset(ilc, 0, 0x20);
        *(uint16_t *)(ilv + 0) = 8; *(uint16_t *)(ilc + 0) = 8;
        *(void **)(ilv + 8) = idv; *(void **)(ilc + 8) = idc;

        memset(a6v, 0, sizeof a6v); memset(a6c, 0, sizeof a6c);
        *(void **)(a6v + 0x00) = s0v; *(void **)(a6c + 0x00) = s0c;
        *(void **)(a6v + 0x08) = s1v; *(void **)(a6c + 0x08) = s1c;
        *(void **)(a6v + 0x10) = s2v; *(void **)(a6c + 0x10) = s2c;
        *(void **)(a6v + 0x70) = ilv; *(void **)(a6c + 0x70) = ilc;

        memset(a7v, 0, sizeof a7v); memset(a7c, 0, sizeof a7c);
        *(int8_t *)(a7v + 0x44) = (int8_t)mode;
        *(int8_t *)(a7c + 0x44) = (int8_t)mode;
        a7v[0xc0] = (uint8_t)sub; a7c[0xc0] = (uint8_t)sub;
        a7v[0xc1] = (uint8_t)(t & 1); a7c[0xc1] = (uint8_t)(t & 1);
        *(uint16_t *)(a7v + 0xc2) = 8; *(uint16_t *)(a7c + 0xc2) = 8;

        cr_image av, ac, mv, mc;
        memset(&av, 0, sizeof av); memset(&ac, 0, sizeof ac);
        memset(&mv, 0, sizeof mv); memset(&mc, 0, sizeof mc);
        av.a = astride; av.b = H; av.data = bitv; av.w = W; av.h = H;
        ac.a = astride; ac.b = H; ac.data = bitc; ac.w = W; ac.h = H;
        mv.a = mv.w = W; mv.b = mv.h = H; mv.data = imgv;
        mc.a = mc.w = W; mc.b = mc.h = H; mc.data = imgc;

        uint8_t fv = 0, fc = 0;
        int rv = v(&fv, &mv, &av, a4v, a5v, a6v, a7v, a8, a9);
        int rc = cr_mask_refine_344e0(&fc, &mc, &ac, a4c, a5c, a6c, a7c,
                                      a8, a9);
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }
        if (fv != fc) mismatch("flag", (u32)t, (u32)fv, (u32)fc);
        cmp_buf("img", (const u8 *)imgv, (const u8 *)imgc, (size_t)n, (u32)t);
        cmp_buf("bits", (const u8 *)bitv, (const u8 *)bitc,
                (size_t)nwords * 4, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_mask_refine_344e0\n");
}

/* ---- 0x180028bc0: feature pipeline driver ------------------------------- */
static void test_feature_run_28bc0(void)
{
    typedef int (WINAPI *v_t)(void *, void *, void *);
    typedef int (WINAPI *v_m)(void **, size_t);
    v_t   v       = (v_t)fn_at(RVA(0x180028bc0));
    v_m   vmalloc = (v_m)fn_at(RVA(0x1800100c0));
    v_v_p vsfree  = (v_v_p)fn_at(RVA(0x18003bf40));
    begin("cr_feature_run_28bc0");
    int bad = g_fail;

    static u8 a1v[0x58], a1c[0x58], p2v[0x90], p2c[0x90];
    static u8 a3v[0x30], a3c[0x30];
    static u8 stv[8],  stc[8];
    static u8 rv8[0x80], rc8[0x80];
    static u8 qv8[0x90], qc8[0x90];
    static u8 cfgv[0x80], cfgc[0x80];
    static u8 imgV[4096], imgC[4096];
    static u32 bmV[2048], bmC[2048];
    static int16_t nsV[64], nsC[64];

    for (int t = 0; t < 600; t++) {
        int w = 64;
        int h = 40;
        int n = (int)(rnd() % 16u);
        int bw = (w + 0x1f) & ~0x1f;
        int tag = (int)(rnd() % 0x10000u) + 1;
        int p78 = (int)(rnd() % 0x1000u);
        int sox = 0;

        /* flat image: the point grid finds no maxima, so the pipeline
         * completes and no partially-built object is torn down. */
        memset(imgV, 100, sizeof imgV); memset(imgC, 100, sizeof imgC);
        for (size_t i = 0; i < 2048; i++) { u32 x = rnd(); bmV[i] = x; bmC[i] = x; }
        for (int i = 0; i < 64; i++) { int16_t x = (int16_t)rnd(); nsV[i] = x; nsC[i] = x; }

        int sel  = (int)(rnd() % 3u);
        int b0   = (int)(rnd() % 2u);
        int r4   = (int)(rnd() % 2u);
        int q84  = (int)(rnd() % 2u);
        int q8b  = (int)(rnd() % 3u);
        int q18  = (int)(rnd() % 64u);
        int q1a  = (int)(rnd() % 64u);
        int q1c  = (int)(rnd() % 64u);
        int a1c1c = (int)(rnd() % 64u);
        int a1w   = (int)(rnd() % 64u);
        int tsel = (t % 3 == 0) ? 4 : 2;
        int gsel;
        switch (t % 6) {
        case 0:  gsel = 1; break;
        case 1:  gsel = 5; break;
        case 2:  gsel = 4; break;
        default: gsel = (int)(rnd() % 8u); break;
        }

        memset(a1v, 0, sizeof a1v); memset(a1c, 0, sizeof a1c);
        *(int16_t *)(a1v + 0) = (int16_t)a1w;  *(int16_t *)(a1c + 0) = (int16_t)a1w;
        *(int32_t *)(a1v + 0x10) = (int32_t)rnd();
        *(int32_t *)(a1c + 0x10) = *(int32_t *)(a1v + 0x10);
        *(int32_t *)(a1v + 0x1c) = a1c1c; *(int32_t *)(a1c + 0x1c) = a1c1c;
        *(int32_t *)(a1v + 0x20) = 0x77777777; *(int32_t *)(a1c + 0x20) = 0x77777777;
        *(int32_t *)(a1v + 0x24) = 0;      *(int32_t *)(a1c + 0x24) = 0;

        /* p2+0x58 is released inside the callee on the selector-0 path, so
         * each side needs a buffer from its own allocator. */
        void *bmvp = NULL, *bmcp = NULL;
        size_t bmsz = (size_t)((bw >> 5) * h * 4);
        if (vmalloc(&bmvp, bmsz) != 0) continue;
        if (cr_malloc_aligned16(&bmcp, bmsz) != 0) { vsfree(&bmvp); continue; }
        memcpy(bmvp, bmV, bmsz);
        memcpy(bmcp, bmC, bmsz);
        setup_p2_17ca0(p2v, imgV, (u32 *)bmvp, nsV, w, h, bw, tag, p78, n, sox);
        setup_p2_17ca0(p2c, imgC, (u32 *)bmcp, nsC, w, h, bw, tag, p78, n, sox);

        memset(stv, 0, sizeof stv); memset(stc, 0, sizeof stc);
        stv[0] = (u8)b0; stc[0] = (u8)b0;
        stv[1] = (u8)sel; stc[1] = (u8)sel;

        memset(rv8, 0, sizeof rv8); memset(rc8, 0, sizeof rc8);
        rv8[4] = (u8)r4; rc8[4] = (u8)r4;
        float r78 = (r4 == 0 && (t & 1)) ? 1.0f : 0.25f;
        *(float *)(rv8 + 0x78) = r78; *(float *)(rc8 + 0x78) = r78;

        memset(qv8, 0, sizeof qv8); memset(qc8, 0, sizeof qc8);
        qv8[0x84] = (u8)q84; qc8[0x84] = (u8)q84;
        qv8[0x8b] = (u8)q8b; qc8[0x8b] = (u8)q8b;
        *(int16_t *)(qv8 + 0x18) = (int16_t)q18; *(int16_t *)(qc8 + 0x18) = (int16_t)q18;
        *(int16_t *)(qv8 + 0x1a) = (int16_t)q1a; *(int16_t *)(qc8 + 0x1a) = (int16_t)q1a;
        *(int16_t *)(qv8 + 0x1c) = (int16_t)q1c; *(int16_t *)(qc8 + 0x1c) = (int16_t)q1c;

        memset(cfgv, 0, sizeof cfgv); memset(cfgc, 0, sizeof cfgc);
        cfgv[0x01] = (u8)gsel; cfgc[0x01] = (u8)gsel;
        cfgv[0x08] = 2;        cfgc[0x08] = 2;
        cfgv[0x0b] = (u8)tsel; cfgc[0x0b] = (u8)tsel;
        cfgv[0x0c] = (u8)(rnd() % 7u); cfgc[0x0c] = cfgv[0x0c];
        *(int32_t *)(cfgv + 0x14) = h; *(int32_t *)(cfgc + 0x14) = h;
        float sig = 0.72f + (float)(rnd() % 150u) / 100.0f;
        *(float *)(cfgv + 0x1c) = sig; *(float *)(cfgc + 0x1c) = sig;
        cfgv[0x24] = (u8)((t % 3 == 0) ? 3 : ((t % 3 == 1) ? 2 : 5));
        cfgc[0x24] = cfgv[0x24];
        cfgv[0x25] = 4; cfgc[0x25] = 4;
        cfgv[0x26] = 4; cfgc[0x26] = 4;
        cfgv[0x09] = (u8)((t & 1) ? 2 : 1); cfgc[0x09] = cfgv[0x09];
        cfgv[0x3d] = 0; cfgc[0x3d] = 0;

        memset(a3v, 0, sizeof a3v); memset(a3c, 0, sizeof a3c);
        *(void **)(a3v + 0x08) = stv; *(void **)(a3c + 0x08) = stc;
        *(void **)(a3v + 0x10) = cfgv; *(void **)(a3c + 0x10) = cfgc;
        *(void **)(a3v + 0x18) = rv8; *(void **)(a3c + 0x18) = rc8;
        *(void **)(a3v + 0x20) = qv8; *(void **)(a3c + 0x20) = qc8;

        int rv = v(a1v, p2v, a3v);
        int rc = cr_feature_run_28bc0(a1c, p2c, a3c);
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); }
        else {
            for (int off = 0x10; off < 0x28; off += 4) {
                u32 a = *(u32 *)(a1v + off), b = *(u32 *)(a1c + off);
                if (a != b) mismatch("a1", (u32)t, a, b);
            }
        }
        /* both sides own a wrapper; each is released by its own allocator */
        vsfree((void **)(a1v + 8));
        cr_wrap_destroy((void **)(a1c + 8));
        if (sel != 0) {
            vsfree((void **)(p2v + 0x58));
            cr_sized_free((void **)(p2c + 0x58));
        }
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_feature_run_28bc0\n");
}

/* ---- 0x180039820: multi-slot mask fusion driver ------------------------- */
static void test_mask_dispatch_39820(void)
{
    typedef int (WINAPI *v_t)(void *, void *, const void *, const void *,
                              void **, const void *, int);
    v_t v = (v_t)fn_at(RVA(0x180039820));
    begin("cr_mask_dispatch_39820");
    int bad = g_fail;

    enum { MAXPIX = 64 * 64 };
    static float    d0v[MAXPIX], d0c[MAXPIX];
    static uint8_t  d1v[MAXPIX], d1c[MAXPIX];
    static uint8_t  ssv[5][MAXPIX], ssc[5][MAXPIX];
    static uint16_t mkv[MAXPIX], mkc[MAXPIX];
    static uint16_t m2v[MAXPIX], m2c[MAXPIX];
    static uint16_t f0v[MAXPIX], f0c[MAXPIX];
    static uint16_t f1v[MAXPIX], f1c[MAXPIX];
    static uint8_t  ctxv[0x80], ctxc[0x80];
    static uint8_t  a3v[0x10], a3c[0x10];
    static uint8_t  cfgv[0x100], cfgc[0x100];
    static void    *slv[16], *slc[16];
    static uint8_t  s0v[0x20], s0c[0x20];
    static uint8_t  s5v[0x20], s5c[0x20];
    static uint8_t  s6v[0x20], s6c[0x20];
    static uint8_t  sdv[5][0x20], sdc[5][0x20];
    static uint8_t  ilv[0x10], ilc[0x10];
    static uint16_t idv[16], idc[16];

    for (int t = 0; t < 800; t++) {
        int W = 24 + (int)(rnd() % 25u);
        int H = 24 + (int)(rnd() % 25u);
        int n = W * H;
        int cnt = 1 + (t % 5);
        /* 0 flat, 1 noise/noise, 2 step, 3 noise source + flat bright slots,
         * 4 saturation-ramp slots (drives the 0.9*sc1/sc0/sc2 selector) */
        int mode = t % 5;
        int noisy = (mode == 1 || mode == 3 || mode == 4);

        for (int i = 0; i < n; i++) {
            float f;
            if (mode == 0)
                f = 0.0f;
            else if (mode == 2)
                f = ((i / W) < (H / 2)) ? 200.0f : 0.0f;
            else
                f = (float)(rnd() % 2560u) / 10.0f;
            d0v[i] = f; d0c[i] = f;
            uint8_t b = noisy ? (uint8_t)rnd() : 0xff;
            d1v[i] = b; d1c[i] = b;
            uint16_t m = (uint16_t)((rnd() % 3u == 0) ? 0xffffu : rnd());
            mkv[i] = m; mkc[i] = m;
            uint16_t m2 = (uint16_t)rnd();
            m2v[i] = m2; m2c[i] = m2;
        }
        {
            static const int frac[5] = { 20, 0, 5, 40, 60 };
            for (int k = 0; k < 5; k++) {
                uint8_t c = (mode == 3) ? 200u : (uint8_t)(2 + k);
                for (int i = 0; i < n; i++) {
                    uint8_t x;
                    if (mode == 1)
                        x = (uint8_t)rnd();
                    else if (mode == 4)
                        x = (uint8_t)(((long)i * 100) / n < frac[k] ? 0 : 128);
                    else
                        x = c;
                    ssv[k][i] = x; ssc[k][i] = x;
                }
            }
        }
        for (int i = 0; i < 8; i++) {
            uint16_t k = (uint16_t)(rnd() % (unsigned)n);
            idv[i] = k; idc[i] = k;
        }

        memset(ctxv, 0, sizeof ctxv); memset(ctxc, 0, sizeof ctxc);
        float sig = (float)(rnd() % 50u) / 10.0f + 0.1f;
        *(float *)(ctxv + 4) = sig;  *(float *)(ctxc + 4) = sig;
        int8_t cflag = (int8_t)((t & 1) ? 1 : -1);
        *(int8_t *)(ctxv + 8) = cflag; *(int8_t *)(ctxc + 8) = cflag;
        *(void **)(ctxv + 0x18) = m2v; *(void **)(ctxc + 0x18) = m2c;
        *(void **)(ctxv + 0x58) = mkv; *(void **)(ctxc + 0x58) = mkc;

        memset(a3v, 0, sizeof a3v); memset(a3c, 0, sizeof a3c);
        *(int *)(a3v + 4) = 1; *(int *)(a3c + 4) = 1;

        memset(s0v, 0, 0x20); memset(s0c, 0, 0x20);
        *(int16_t *)(s0v + 0) = (int16_t)W; *(int16_t *)(s0v + 2) = (int16_t)H;
        *(int16_t *)(s0c + 0) = (int16_t)W; *(int16_t *)(s0c + 2) = (int16_t)H;

        memset(s5v, 0, 0x20); memset(s5c, 0, 0x20);
        *(int16_t *)(s5v + 0) = (int16_t)W; *(int16_t *)(s5v + 2) = (int16_t)H;
        *(int16_t *)(s5c + 0) = (int16_t)W; *(int16_t *)(s5c + 2) = (int16_t)H;
        *(void **)(s5v + 0x10) = f0v; *(void **)(s5c + 0x10) = f0c;

        memset(s6v, 0, 0x20); memset(s6c, 0, 0x20);
        *(int16_t *)(s6v + 0) = (int16_t)W; *(int16_t *)(s6v + 2) = (int16_t)H;
        *(int16_t *)(s6c + 0) = (int16_t)W; *(int16_t *)(s6c + 2) = (int16_t)H;
        *(void **)(s6v + 0x10) = f1v; *(void **)(s6c + 0x10) = f1c;

        for (int k = 0; k < 5; k++) {
            memset(sdv[k], 0, 0x20); memset(sdc[k], 0, 0x20);
            *(int16_t *)(sdv[k] + 0) = (int16_t)W;
            *(int16_t *)(sdv[k] + 2) = (int16_t)H;
            *(int16_t *)(sdc[k] + 0) = (int16_t)W;
            *(int16_t *)(sdc[k] + 2) = (int16_t)H;
            sdv[k][6] = 8; sdc[k][6] = 8;
            *(void **)(sdv[k] + 0x10) = ssv[k];
            *(void **)(sdc[k] + 0x10) = ssc[k];
        }

        memset(ilv, 0, 0x10); memset(ilc, 0, 0x10);
        *(uint16_t *)(ilv + 0) = 8; *(uint16_t *)(ilc + 0) = 8;
        *(void **)(ilv + 8) = idv; *(void **)(ilc + 8) = idc;

        for (int i = 0; i < 16; i++) { slv[i] = NULL; slc[i] = NULL; }
        for (int k = 0; k < cnt; k++) { slv[k] = sdv[k]; slc[k] = sdc[k]; }
        slv[5] = s5v;  slc[5] = s5c;
        slv[6] = s6v;  slc[6] = s6c;
        slv[0x0e] = ilv; slc[0x0e] = ilc;

        memset(cfgv, 0, sizeof cfgv); memset(cfgc, 0, sizeof cfgc);
        int tsel = (t % 3 == 0) ? 3 : 0;
        cfgv[9] = (uint8_t)tsel; cfgc[9] = (uint8_t)tsel;
        int bw = 4 + (int)(rnd() % 5u);
        *(int16_t *)(cfgv + 6) = (int16_t)bw; *(int16_t *)(cfgc + 6) = (int16_t)bw;
        int16_t thr = (int16_t)((int)(rnd() % 4001u) - 2000);
        *(int16_t *)(cfgv + 0x2c) = thr; *(int16_t *)(cfgc + 0x2c) = thr;
        cfgv[0x30] = (uint8_t)(t % 4 == 0); cfgc[0x30] = cfgv[0x30];
        int selm = (t % 5 == 0) ? 7 : 0;
        cfgv[0x40] = (uint8_t)selm; cfgc[0x40] = (uint8_t)selm;
        cfgv[0x44] = (uint8_t)((t % 4 == 0) ? 3 : (t % 3));
        cfgc[0x44] = cfgv[0x44];
        float bsig = (float)(rnd() % 30u) / 10.0f + 0.3f;
        *(float *)(cfgv + 0x48) = bsig; *(float *)(cfgc + 0x48) = bsig;
        int pmode = (t % 5 == 0) ? 7 : 0;
        cfgv[0xc0] = (uint8_t)pmode; cfgc[0xc0] = (uint8_t)pmode;
        cfgv[0xc1] = (uint8_t)(t & 1); cfgc[0xc1] = (uint8_t)(t & 1);
        *(uint16_t *)(cfgv + 0xc2) = 16; *(uint16_t *)(cfgc + 0xc2) = 16;
        int32_t pthr = (int32_t)(rnd() % 500u);
        *(int32_t *)(cfgv + 0xc4) = pthr; *(int32_t *)(cfgc + 0xc4) = pthr;
        cfgv[0xcc] = 3; cfgc[0xcc] = 3;
        cfgv[0xcd] = 3; cfgc[0xcd] = 3;

        cr_image a1v, a1c, a2v, a2c;
        memset(&a1v, 0, sizeof a1v); memset(&a1c, 0, sizeof a1c);
        memset(&a2v, 0, sizeof a2v); memset(&a2c, 0, sizeof a2c);
        a1v.a = a1v.w = W; a1v.b = a1v.h = H; a1v.data = d0v;
        a1c.a = a1c.w = W; a1c.b = a1c.h = H; a1c.data = d0c;
        a2v.a = a2v.w = W; a2v.b = a2v.h = H; a2v.data = d1v;
        a2c.a = a2c.w = W; a2c.b = a2c.h = H; a2c.data = d1c;

        int rv = v(&a1v, &a2v, a3v, ctxv, slv, cfgv, (t & 1));
        int rc = cr_mask_dispatch_39820(&a1c, &a2c, a3c, ctxc, slc, cfgc, (t & 1));
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }
        cmp_buf("d0", (const u8 *)d0v, (const u8 *)d0c, (size_t)n * 4, (u32)t);
        cmp_buf("d1", (const u8 *)d1v, (const u8 *)d1c, (size_t)n, (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_mask_dispatch_39820\n");
}

/* ---- 0x180011170: per-slot quality ranking + mask dispatch -------------- */
static void test_slot_select_11170(void)
{
    typedef int (WINAPI *v_t)(void *, void *, void *, void *, void **,
                              const void *, int);
    v_t v = (v_t)fn_at(RVA(0x180011170));
    begin("cr_slot_select_11170");
    int bad = g_fail;

    enum { MAXPIX = 64 * 64 };
    static float    d0v[MAXPIX], d0c[MAXPIX];
    static uint8_t  d1v[MAXPIX], d1c[MAXPIX];
    static uint8_t  ssv[5][MAXPIX], ssc[5][MAXPIX];
    static uint16_t mkv[MAXPIX], mkc[MAXPIX];
    static uint16_t m2v[MAXPIX], m2c[MAXPIX];
    static uint16_t f0v[MAXPIX], f0c[MAXPIX];
    static uint16_t f1v[MAXPIX], f1c[MAXPIX];
    static uint8_t  ctxv[0x80], ctxc[0x80];
    static uint8_t  a3v[0x100], a3c[0x100];
    static uint8_t  cfgv[0x140], cfgc[0x140];
    static void    *slv[16], *slc[16];
    static uint8_t  s0v[0x20], s0c[0x20];
    static uint8_t  s5v[0x20], s5c[0x20];
    static uint8_t  s6v[0x20], s6c[0x20];
    static uint8_t  sdv[5][0x20], sdc[5][0x20];
    static uint8_t  ilv[0x10], ilc[0x10];
    static uint16_t idv[16], idc[16];

    for (int t = 0; t < 600; t++) {
        int W = 24 + (int)(rnd() % 25u);
        int H = 24 + (int)(rnd() % 25u);
        int n = W * H;
        int cnt = 1 + ((t / 5) % 5);
        int mode = t % 5;              /* 4 -> invalid mode byte */
        int noisy = (t % 3) != 0;

        for (int i = 0; i < n; i++) {
            float f = noisy ? (float)(rnd() % 2560u) / 10.0f : 0.0f;
            d0v[i] = f; d0c[i] = f;
            uint8_t b = noisy ? (uint8_t)rnd() : 0xff;
            d1v[i] = b; d1c[i] = b;
            uint16_t m = (uint16_t)((rnd() % 3u == 0) ? 0xffffu : rnd());
            mkv[i] = m; mkc[i] = m;
            uint16_t m2 = (uint16_t)rnd();
            m2v[i] = m2; m2c[i] = m2;
        }
        for (int k = 0; k < 5; k++) {
            uint8_t c = (uint8_t)(2 + k * 40);
            for (int i = 0; i < n; i++) {
                uint8_t x = noisy ? (uint8_t)rnd() : c;
                ssv[k][i] = x; ssc[k][i] = x;
            }
        }
        for (int i = 0; i < 8; i++) {
            uint16_t k = (uint16_t)(rnd() % (unsigned)n);
            idv[i] = k; idc[i] = k;
        }

        memset(ctxv, 0, sizeof ctxv); memset(ctxc, 0, sizeof ctxc);
        float sig = (float)(rnd() % 50u) / 10.0f + 0.1f;
        *(float *)(ctxv + 4) = sig;  *(float *)(ctxc + 4) = sig;
        int8_t cflag = (int8_t)((t & 1) ? 1 : -1);
        *(int8_t *)(ctxv + 8) = cflag; *(int8_t *)(ctxc + 8) = cflag;
        *(void **)(ctxv + 0x18) = m2v; *(void **)(ctxc + 0x18) = m2c;
        *(void **)(ctxv + 0x58) = mkv; *(void **)(ctxc + 0x58) = mkc;

        memset(s0v, 0, 0x20); memset(s0c, 0, 0x20);
        *(int16_t *)(s0v + 0) = (int16_t)W; *(int16_t *)(s0v + 2) = (int16_t)H;
        *(int16_t *)(s0c + 0) = (int16_t)W; *(int16_t *)(s0c + 2) = (int16_t)H;

        memset(s5v, 0, 0x20); memset(s5c, 0, 0x20);
        *(int16_t *)(s5v + 0) = (int16_t)W; *(int16_t *)(s5v + 2) = (int16_t)H;
        *(int16_t *)(s5c + 0) = (int16_t)W; *(int16_t *)(s5c + 2) = (int16_t)H;
        *(void **)(s5v + 0x10) = f0v; *(void **)(s5c + 0x10) = f0c;

        memset(s6v, 0, 0x20); memset(s6c, 0, 0x20);
        *(int16_t *)(s6v + 0) = (int16_t)W; *(int16_t *)(s6v + 2) = (int16_t)H;
        *(int16_t *)(s6c + 0) = (int16_t)W; *(int16_t *)(s6c + 2) = (int16_t)H;
        *(void **)(s6v + 0x10) = f1v; *(void **)(s6c + 0x10) = f1c;

        for (int k = 0; k < 5; k++) {
            memset(sdv[k], 0, 0x20); memset(sdc[k], 0, 0x20);
            *(int16_t *)(sdv[k] + 0) = (int16_t)W;
            *(int16_t *)(sdv[k] + 2) = (int16_t)H;
            *(int16_t *)(sdc[k] + 0) = (int16_t)W;
            *(int16_t *)(sdc[k] + 2) = (int16_t)H;
            sdv[k][6] = 8; sdc[k][6] = 8;
            *(void **)(sdv[k] + 0x10) = ssv[k];
            *(void **)(sdc[k] + 0x10) = ssc[k];
        }

        memset(ilv, 0, 0x10); memset(ilc, 0, 0x10);
        *(uint16_t *)(ilv + 0) = 8; *(uint16_t *)(ilc + 0) = 8;
        *(void **)(ilv + 8) = idv; *(void **)(ilc + 8) = idc;

        for (int i = 0; i < 16; i++) { slv[i] = NULL; slc[i] = NULL; }
        for (int k = 0; k < cnt; k++) { slv[k] = sdv[k]; slc[k] = sdc[k]; }
        slv[5] = s5v;  slc[5] = s5c;
        slv[6] = s6v;  slc[6] = s6c;
        slv[0x0e] = ilv; slc[0x0e] = ilc;

        memset(cfgv, 0, sizeof cfgv); memset(cfgc, 0, sizeof cfgc);
        int tsel = (t % 3 == 0) ? 3 : 0;
        cfgv[9] = (uint8_t)tsel; cfgc[9] = (uint8_t)tsel;
        int bw = 4 + (int)(rnd() % 5u);
        *(int16_t *)(cfgv + 6) = (int16_t)bw; *(int16_t *)(cfgc + 6) = (int16_t)bw;
        int16_t thr = (int16_t)((int)(rnd() % 4001u) - 2000);
        *(int16_t *)(cfgv + 0x2c) = thr; *(int16_t *)(cfgc + 0x2c) = thr;
        cfgv[0x30] = (uint8_t)(t % 4 == 0); cfgc[0x30] = cfgv[0x30];
        int selm = (t % 5 == 0) ? 7 : 0;
        cfgv[0x40] = (uint8_t)selm; cfgc[0x40] = (uint8_t)selm;
        cfgv[0x44] = (uint8_t)((t % 4 == 0) ? 3 : (t % 3));
        cfgc[0x44] = cfgv[0x44];
        float bsig = (float)(rnd() % 30u) / 10.0f + 0.3f;
        *(float *)(cfgv + 0x48) = bsig; *(float *)(cfgc + 0x48) = bsig;
        int pmode = (t % 5 == 0) ? 7 : 0;
        cfgv[0xc0] = (uint8_t)pmode; cfgc[0xc0] = (uint8_t)pmode;
        cfgv[0xc1] = (uint8_t)(t & 1); cfgc[0xc1] = (uint8_t)(t & 1);
        *(uint16_t *)(cfgv + 0xc2) = 16; *(uint16_t *)(cfgc + 0xc2) = 16;
        int32_t pthr = (int32_t)(rnd() % 500u);
        *(int32_t *)(cfgv + 0xc4) = pthr; *(int32_t *)(cfgc + 0xc4) = pthr;
        cfgv[0xcc] = 3; cfgc[0xcc] = 3;
        cfgv[0xcd] = 3; cfgc[0xcd] = 3;

        cfgv[0x108] = (uint8_t)((mode == 4) ? 7 : mode);
        cfgc[0x108] = cfgv[0x108];
        int16_t thr2 = (int16_t)(int)(rnd() % 2001u);
        *(int16_t *)(cfgv + 0x10a) = thr2; *(int16_t *)(cfgc + 0x10a) = thr2;
        static const int32_t kvals[6] = { 0, 1, 50, 99, 100, 150 };
        int32_t kv = kvals[t % 6];
        *(int32_t *)(cfgv + 0x110) = kv; *(int32_t *)(cfgc + 0x110) = kv;

        memset(a3v, 0, sizeof a3v); memset(a3c, 0, sizeof a3c);

        cr_image a1v, a1c, a2v, a2c;
        memset(&a1v, 0, sizeof a1v); memset(&a1c, 0, sizeof a1c);
        memset(&a2v, 0, sizeof a2v); memset(&a2c, 0, sizeof a2c);
        a1v.a = a1v.w = W; a1v.b = a1v.h = H; a1v.data = d0v;
        a1c.a = a1c.w = W; a1c.b = a1c.h = H; a1c.data = d0c;
        a2v.a = a2v.w = W; a2v.b = a2v.h = H; a2v.data = d1v;
        a2c.a = a2c.w = W; a2c.b = a2c.h = H; a2c.data = d1c;

        for (int step = 0; step <= cnt + 2; step++) {
            int rv = v(&a1v, &a2v, a3v, ctxv, slv, cfgv, (t & 1));
            int rc = cr_slot_select_11170(&a1c, &a2c, a3c, ctxc, slc, cfgc,
                                          (t & 1));
            if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); break; }
            cmp_buf("d0", (const u8 *)d0v, (const u8 *)d0c, (size_t)n * 2,
                    (u32)t);
            cmp_buf("d1", (const u8 *)d1v, (const u8 *)d1c, (size_t)n, (u32)t);
            for (int off = 0; off < 0x0c; off += 4) {
                u32 a = *(u32 *)(a3v + off), b = *(u32 *)(a3c + off);
                if (a != b) mismatch("st", (u32)t, a, b);
            }
            {
                u32 a = (u32)a3v[0x0c], b = (u32)a3c[0x0c];
                if (a != b) mismatch("sel", (u32)t, a, b);
            }
            for (int j = 0; j < cnt; j++) {
                u32 a = *(u32 *)(a3v + 0x10 + j * 4);
                u32 b = *(u32 *)(a3c + 0x10 + j * 4);
                if (a != b) mismatch("ord", (u32)t, a, b);
            }
        }
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_slot_select_11170\n");
}

/* ---- 0x180022b70: per-slot quality ranking over u8 payloads ------------ */
static void test_slot_rank_u8_22b70(void)
{
    typedef int (WINAPI *v_t)(void *, void *, void *, void *, const void *,
                              void **, const void *, int);
    v_t v = (v_t)fn_at(RVA(0x180022b70));
    begin("cr_slot_rank_u8_22b70");
    int bad = g_fail;

    enum { MAXW = 80, MAXH = 50, MAXPIX = MAXW * MAXH, MAXW32 = 96 };
    static uint8_t  imgv[MAXPIX], imgc[MAXPIX];
    static uint32_t bitv[MAXW32 / 32 * MAXH], bitc[MAXW32 / 32 * MAXH];
    static uint8_t  plv[5][MAXPIX], plc[5][MAXPIX];
    static int16_t  gsv[MAXPIX], gsc[MAXPIX];
    static uint8_t  a5v[0x80], a5c[0x80];
    static uint8_t  a3v[0x20], a3c[0x20];
    static uint8_t  stv[0x100], stc[0x100];
    static uint8_t  cfgv[0x140], cfgc[0x140];
    static void    *slv[8], *slc[8];
    static uint8_t  sdv[5][0x20], sdc[5][0x20];
    static uint8_t  ilv[0x20], ilc[0x20];
    static uint16_t idv[16], idc[16];

    for (int t = 0; t < 700; t++) {
        int W = 40 + (int)(rnd() % 40u);
        int H = 30 + (int)(rnd() % 20u);
        int n = W * H;
        int astride = ((W + 31) / 32) * 32;
        int nwords  = astride / 32 * H;
        int cnt = 1 + ((t / 4) % 5);
        int style = t % 4;

        for (int i = 0; i < n; i++) {
            uint8_t b = (uint8_t)rnd();
            imgv[i] = b; imgc[i] = b;
            int16_t g = (int16_t)((int)(rnd() % 4096u) - 2048);
            gsv[i] = g; gsc[i] = g;
        }
        for (int i = 0; i < nwords; i++) {
            uint32_t w = rnd();
            bitv[i] = w; bitc[i] = w;
        }
        /* slot payloads: 0 noise, 1 flat, 2 all-0xff, 3 half-and-half */
        for (int k = 0; k < 5; k++) {
            for (int i = 0; i < n; i++) {
                uint8_t x;
                if (style == 1)
                    x = (uint8_t)(10 + k * 40);
                else if (style == 2)
                    x = 0xff;
                else if (style == 3)
                    x = (i < n / 2) ? 0x00 : 0xff;
                else
                    x = (uint8_t)rnd();
                plv[k][i] = x; plc[k][i] = x;
            }
        }
        for (int i = 0; i < 8; i++) {
            uint16_t k = (uint16_t)(rnd() % (unsigned)n);
            idv[i] = k; idc[i] = k;
        }

        int mode;
        switch (t % 6) {
        case 0:  mode = 0; break;
        case 1:  mode = 1; break;
        case 2:  mode = 2; break;
        case 3:  mode = 3; break;
        case 4:  mode = -1; break;
        default: mode = (int)(rnd() % 4u); break;
        }
        int sub = (t % 2) ? 5 : 0;

        memset(a5v, 0, sizeof a5v); memset(a5c, 0, sizeof a5c);
        int8_t flag = (int8_t)((t & 2) ? 1 : -1);
        *(int8_t *)(a5v + 8) = flag; *(int8_t *)(a5c + 8) = flag;
        *(int32_t *)(a5v + 0x50) = W; *(int32_t *)(a5v + 0x54) = H;
        *(int32_t *)(a5c + 0x50) = W; *(int32_t *)(a5c + 0x54) = H;
        *(void **)(a5v + 0x58) = gsv; *(void **)(a5c + 0x58) = gsc;
        *(int32_t *)(a5v + 0x60) = W; *(int32_t *)(a5v + 0x64) = H;
        *(int32_t *)(a5c + 0x60) = W; *(int32_t *)(a5c + 0x64) = H;

        memset(a3v, 0, sizeof a3v); memset(a3c, 0, sizeof a3c);

        for (int k = 0; k < 5; k++) {
            memset(sdv[k], 0, 0x20); memset(sdc[k], 0, 0x20);
            *(int16_t *)(sdv[k] + 0) = (int16_t)W;
            *(int16_t *)(sdv[k] + 2) = (int16_t)H;
            *(int16_t *)(sdc[k] + 0) = (int16_t)W;
            *(int16_t *)(sdc[k] + 2) = (int16_t)H;
            *(void **)(sdv[k] + 0x10) = plv[k];
            *(void **)(sdc[k] + 0x10) = plc[k];
        }

        memset(ilv, 0, 0x20); memset(ilc, 0, 0x20);
        *(uint16_t *)(ilv + 0) = 8; *(uint16_t *)(ilc + 0) = 8;
        *(void **)(ilv + 8) = idv; *(void **)(ilc + 8) = idc;

        for (int i = 0; i < 8; i++) { slv[i] = NULL; slc[i] = NULL; }
        for (int k = 0; k < cnt; k++) { slv[k] = sdv[k]; slc[k] = sdc[k]; }
        slv[5] = ilv; slc[5] = ilc;

        memset(cfgv, 0, sizeof cfgv); memset(cfgc, 0, sizeof cfgc);
        cfgv[0x44] = (uint8_t)(int8_t)mode; cfgc[0x44] = cfgv[0x44];
        cfgv[0xc0] = (uint8_t)sub; cfgc[0xc0] = (uint8_t)sub;
        cfgv[0xc1] = (uint8_t)(t & 1); cfgc[0xc1] = (uint8_t)(t & 1);
        *(uint16_t *)(cfgv + 0xc2) = 8; *(uint16_t *)(cfgc + 0xc2) = 8;
        cfgv[0x108] = (uint8_t)((t % 8 == 0) ? 3 : 2);
        cfgc[0x108] = cfgv[0x108];
        uint16_t thr2 = (uint16_t)(rnd() % 2001u);
        *(uint16_t *)(cfgv + 0x10a) = thr2; *(uint16_t *)(cfgc + 0x10a) = thr2;
        static const int32_t kvals[6] = { 0, 1, 50, 99, 100, 150 };
        int32_t kv = kvals[t % 6];
        *(int32_t *)(cfgv + 0x110) = kv; *(int32_t *)(cfgc + 0x110) = kv;

        memset(stv, 0, sizeof stv); memset(stc, 0, sizeof stc);
        if ((t & 3) == 3) {
            /* start mid-walk: pre-seed a consistent order list */
            int start = 1 + (int)(rnd() % (unsigned)cnt);
            *(int *)(stv + 4) = start;
            *(int *)(stc + 4) = start;
            *(int *)(stv + 8) = cnt;
            *(int *)(stc + 8) = cnt;
            for (int j = 0; j < 5; j++) {
                *(int *)(stv + 0x10 + j * 4) = (cnt - 1) - (j % cnt);
                *(int *)(stc + 0x10 + j * 4) = *(int *)(stv + 0x10 + j * 4);
            }
        }

        cr_image mv, mc, av, ac;
        memset(&mv, 0, sizeof mv); memset(&mc, 0, sizeof mc);
        memset(&av, 0, sizeof av); memset(&ac, 0, sizeof ac);
        mv.a = mv.w = W; mv.b = mv.h = H; mv.data = imgv;
        mc.a = mc.w = W; mc.b = mc.h = H; mc.data = imgc;
        av.a = astride; av.b = H; av.data = bitv; av.w = W; av.h = H;
        ac.a = astride; ac.b = H; ac.data = bitc; ac.w = W; ac.h = H;

        uint8_t fv = 0, fc = 0;
        for (int step = 0; step <= cnt + 1; step++) {
            int rv = v(&fv, &mv, &av, stv, a5v, slv, cfgv, (t & 1));
            int rc = cr_slot_rank_u8_22b70(&fc, &mc, &ac, stc, a5c, slc,
                                           cfgc, (t & 1));
            if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); break; }
            if (fv != fc) mismatch("flag", (u32)t, (u32)fv, (u32)fc);
            cmp_buf("img", (const u8 *)imgv, (const u8 *)imgc, (size_t)n,
                    (u32)t);
            cmp_buf("bits", (const u8 *)bitv, (const u8 *)bitc,
                    (size_t)nwords * 4, (u32)t);
            cmp_buf("state", (const u8 *)stv, (const u8 *)stc,
                    (size_t)(0x10 + cnt * 4), (u32)t);
        }
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_slot_rank_u8_22b70\n");
}

/* ---- 0x1800222b0: block texture search + 64-tap kernel filter ---------- */
static void test_block_filter_222b0(void)
{
    typedef int (WINAPI *v_t)(void *, int32_t *, const void *, int);
    v_t v = (v_t)fn_at(RVA(0x1800222b0));
    begin("cr_block_filter_222b0");
    int bad = g_fail;

    enum { MAXW = 96, MAXH = 60, MAXPIX = MAXW * MAXH, PAD = 1024 };
    static uint8_t iv[MAXPIX + PAD], ic[MAXPIX + PAD];
    static uint8_t cfgv[0x40], cfgc[0x40];

    for (int t = 0; t < 900; t++) {
        int W = 48 + (int)(rnd() % 49u);
        int H = 32 + (int)(rnd() % 25u);
        int n = W * H;
        int style = t % 4;
        int mode = (t % 7 == 0) ? 3 : ((t % 3 == 0) ? 0 : 6);

        memset(iv, 0, sizeof iv); memset(ic, 0, sizeof ic);
        for (int i = 0; i < n; i++) {
            uint8_t b;
            if (style == 0)
                b = (uint8_t)rnd();
            else if (style == 1)
                b = (uint8_t)((i % W) * 3 + (i / W) * 5);
            else if (style == 2)
                b = (uint8_t)(((i % W) / 3 + (i / W) / 3) & 1 ? 220 : 20);
            else
                b = (uint8_t)(128 + (int)(rnd() % 5u));
            iv[i] = b; ic[i] = b;
        }

        int a4 = (mode == 6) ? 16 : (int)(1u << (2 + (rnd() % 3u)));

        memset(cfgv, 0, sizeof cfgv); memset(cfgc, 0, sizeof cfgc);
        cfgv[2] = (uint8_t)mode; cfgc[2] = (uint8_t)mode;
        float thr = (float)(rnd() % 40u) / 10.0f;
        *(float *)(cfgv + 4) = thr; *(float *)(cfgc + 4) = thr;
        int step = 2 + (int)(rnd() % 6u);
        cfgv[8] = (uint8_t)step; cfgc[8] = (uint8_t)step;
        cfgv[9] = 4; cfgc[9] = 4;
        cfgv[0xa] = 4; cfgc[0xa] = 4;

        int rl = (int)(rnd() % (unsigned)(H / 2));
        int rh = rl + 2 + (int)(rnd() % (unsigned)(H - rl - 2));
        int cl = (int)(rnd() % (unsigned)(W / 2));
        int ch = cl + 2 + (int)(rnd() % (unsigned)(W - cl - 2));
        if (rh > H) rh = H;
        if (ch > W) ch = W;
        *(int32_t *)(cfgv + 0x0c) = rl; *(int32_t *)(cfgc + 0x0c) = rl;
        *(int32_t *)(cfgv + 0x10) = rh; *(int32_t *)(cfgc + 0x10) = rh;
        *(int32_t *)(cfgv + 0x14) = cl; *(int32_t *)(cfgc + 0x14) = cl;
        *(int32_t *)(cfgv + 0x18) = ch; *(int32_t *)(cfgc + 0x18) = ch;

        cr_image av, ac;
        memset(&av, 0, sizeof av); memset(&ac, 0, sizeof ac);
        av.a = av.w = W; av.b = av.h = H; av.data = iv;
        ac.a = ac.w = W; ac.b = ac.h = H; ac.data = ic;

        int32_t ov = -7, oc = -7;
        int rv = v(&av, &ov, cfgv, a4);
        int rc = cr_block_filter_222b0(&ac, &oc, cfgc, a4);
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }
        if (ov != oc) mismatch("out", (u32)t, (u32)ov, (u32)oc);
        cmp_buf("img", (const u8 *)iv, (const u8 *)ic, (size_t)(n + PAD),
                (u32)t);
    }
    if (g_fail == bad) end(); else printf("  FAIL cr_block_filter_222b0\n");
}

/* ---- 0x180015540 — edge-oriented Gaussian padding ----------------------- *
 * W/H stay small so the four border passes finish quickly; the padded buffer
 * (stride a > w, b > h) is compared in full, margins included. */
static void test_gauss_edge_pad_15540(void)
{
    typedef int (WINAPI *v_t)(cr_image *, const cr_image *, float);
    v_t v = (v_t)fn_at(RVA(0x180015540));
    begin("cr_gauss_edge_pad_15540");
    int bad = g_fail;
    static int16_t bv[64 * 64], bc[64 * 64], org[64 * 64];
    static int16_t gv[32 * 32], gc[32 * 32];
    int found = 0, rows_written = 0, cols_written = 0;

    for (int t = 0; t < 500; t++) {
        int W = 9 + (int)(rnd() % 18u);   /* tri9 needs n >= 9 */
        int H = 9 + (int)(rnd() % 13u);
        int ox = (int)(rnd() % 4u);
        int oy = (int)(rnd() % 4u);
        int a = W + ox + 2 + (int)(rnd() % 3u);
        int b = H + 2 * oy + 1 + (int)(rnd() % 3u);
        int n = a * b;
        int style = t % 5;

        if (n > (int)(sizeof bv / sizeof bv[0]))
            continue;

        for (int i = 0; i < n; i++) {
            int16_t p;
            if (style == 0)
                p = (int16_t)(int)(rnd() % 65536u) - 32768;
            else if (style == 1)
                p = (int16_t)((int)(rnd() % 2001u) - 1000);
            else if (style == 2)
                p = (int16_t)((i % a) * 512 + (i / a) * 64);
            else if (style == 3)
                p = (int16_t)(((i % a) / 2 + (i / a) / 2) & 1 ? 8000 : -8000);
            else
                p = (int16_t)(((int)(rnd() % 9u) - 4) * 256);
            bv[i] = p; bc[i] = p;
        }
        for (int i = 0; i < W * H; i++) {
            int16_t p;
            if (style == 2)
                p = (int16_t)((i % W) * 700);
            else if (style == 4)
                p = (int16_t)(((i / W) & 1) ? 12345 : -12345);
            else
                p = (int16_t)(int)(rnd() % 65536u) - 32768;
            gv[i] = p; gc[i] = p;
        }

        cr_image av, ac, qv, qc;
        memset(&av, 0, sizeof av); memset(&ac, 0, sizeof ac);
        memset(&qv, 0, sizeof qv); memset(&qc, 0, sizeof qc);
        av.a = ac.a = a; av.b = ac.b = b;
        av.w = ac.w = W; av.h = ac.h = H;
        av.offx = ac.offx = ox; av.offy = ac.offy = oy;
        av.data = bv; ac.data = bc;
        qv.a = qc.a = qv.w = qc.w = W;
        qv.b = qc.b = qv.h = qc.h = H;
        qv.data = gv; qc.data = gc;

        float sg = 0.5f + (float)(rnd() % 32u) * 0.25f;
        memcpy(org, bv, (size_t)n * sizeof(int16_t));

        int rv = v(&av, &qv, sg);
        int rc = cr_gauss_edge_pad_15540(&ac, &qc, sg);
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }

        /* coverage: did any margin pixel change? */
        for (int r = 0; r < b; r++) {
            for (int c = 0; c < a; c++) {
                if (bc[r * a + c] != org[r * a + c]) {
                    found++;
                    if (r < oy || r >= oy + H) rows_written++;
                    if (c < ox || c >= ox + W) cols_written++;
                }
            }
        }
        cmp_buf("img", (const u8 *)bv, (const u8 *)bc,
                (size_t)n * sizeof(int16_t), (u32)t);
        cmp_buf("ang", (const u8 *)gv, (const u8 *)gc,
                (size_t)W * H * sizeof(int16_t), (u32)t);
    }
    printf("  [15540] margin pixels changed=%d (top/bottom=%d left/right=%d)\n",
           found, rows_written, cols_written);
    if (g_fail == bad) end(); else printf("  FAIL cr_gauss_edge_pad_15540\n");
}

static void test_pad_filter_12aa0(void)
{
    typedef int (WINAPI *v_t)(cr_image *, const cr_image *, int, int8_t);
    v_t v = (v_t)fn_at(RVA(0x180012aa0));
    begin("cr_pad_filter_12aa0");
    int bad = g_fail;
    static int16_t srcv[64 * 64], srcc[64 * 64];
    static int16_t outv[64 * 64], outc[64 * 64];
    static int16_t angv[64 * 64], angc[64 * 64], angorg[64 * 64];
    int nonzero = 0, angchanged = 0;

    for (int t = 0; t < 400; t++) {
        int W = 9 + (int)(rnd() % 24u);
        int H = 9 + (int)(rnd() % 24u);
        int n = W * H;
        int mode = (int)(rnd() % 5u);           /* 4 => invalid mode */
        int sel  = (t % 41 == 0) ? 1 : 0;       /* occasionally invalid */
        int style = t % 4;

        if (t % 53 == 0) mode = 256;            /* low byte is what matters */
        if (t % 67 == 0) mode = -1;

        for (int i = 0; i < n; i++) {
            int16_t p;
            if (style == 0)
                p = (int16_t)(int)(rnd() % 65536u) - 32768;
            else if (style == 1)
                p = (int16_t)((int)(rnd() % 2001u) - 1000);
            else if (style == 2)
                p = (int16_t)((i % W) * 400 - 8000);
            else
                p = (int16_t)(((i / W) & 1) ? 9000 : -9000);
            srcv[i] = srcc[i] = p;
        }
        /* orientation map: stay inside -20000..20000 so the vendor's
         * (v + 0x5a00) * 500/46080 rescale lands in the 0..500 kernel range */
        for (int i = 0; i < n; i++) {
            int16_t p;
            if (style == 0)
                p = (int16_t)((int)(rnd() % 40001u) - 20000);
            else if (style == 1)
                p = (int16_t)((i % W) * 1200 - 20000);
            else if (style == 2)
                p = (int16_t)(((i / W) * 1500) % 40001 - 20000);
            else
                p = (int16_t)(((i % W) / 3 + (i / W) / 3) & 1 ? 15000 : -15000);
            angv[i] = angc[i] = p;
        }

        cr_image av, ac, qv, qc;
        memset(&av, 0, sizeof av); memset(&ac, 0, sizeof ac);
        memset(&qv, 0, sizeof qv); memset(&qc, 0, sizeof qc);
        av.a = ac.a = av.w = ac.w = W;
        av.b = ac.b = av.h = ac.h = H;
        qv.a = qc.a = qv.w = qc.w = W;
        qv.b = qc.b = qv.h = qc.h = H;
        qv.data = angv; qc.data = angc;

        /* a1 is in/out: the source pixels are overwritten by the result */
        memcpy(outv, srcv, (size_t)n * sizeof(int16_t));
        memcpy(outc, srcc, (size_t)n * sizeof(int16_t));
        memcpy(angorg, angv, (size_t)n * sizeof(int16_t));
        av.data = outv; ac.data = outc;

        int rv = v(&av, &qv, mode, (int8_t)sel);
        int rc = cr_pad_filter_12aa0(&ac, &qc, mode, (int8_t)sel);
        if (rv != rc) { mismatch("ret", (u32)t, (u32)rv, (u32)rc); continue; }

        cmp_buf("out", (const u8 *)outv, (const u8 *)outc,
                (size_t)n * sizeof(int16_t), (u32)t);
        cmp_buf("ang", (const u8 *)angv, (const u8 *)angc,
                (size_t)n * sizeof(int16_t), (u32)t);

        for (int i = 0; i < n; i++) {
            if (outc[i] != srcv[i]) nonzero++;
            if (angc[i] != angorg[i]) angchanged++;
        }
    }
    printf("  [12aa0] output written=%d, map rescaled=%d\n", nonzero, angchanged);
    if (g_fail == bad) end(); else printf("  FAIL cr_pad_filter_12aa0\n");
}

static void test_orient_encode_1ba60(void)
{
    typedef int (WINAPI *v_t)(cr_image *, const cr_image *, int, const void *,
                              const uint8_t *);
    v_t v = (v_t)fn_at(RVA(0x18001ba60));
    begin("cr_orient_encode_1ba60");
    int bad = g_fail;
    enum { MAXW = 40, MAXH = 40, MAXN = MAXW * MAXH };
    static int16_t srcd[MAXN], sv[MAXN], sc[MAXN];
    static uint8_t mskv[MAXN], mskc[MAXN];
    static u8 av[0x20], ac[0x20], mv[0x20], mc[0x20];
    static u8 obj[0x20], cfg[0x20];
    int ran = 0;

    for (int t = 0; t < 400; t++) {
        int w = 16 + 2 * (int)(rnd() % 12u);
        int h = 16 + 2 * (int)(rnd() % 12u);
        if (t % 29 == 0) w |= 1;                 /* odd -> 0x69 */
        if (t % 31 == 0) h |= 1;
        int N = w * h;
        if (N > MAXN) continue;

        for (int i = 0; i < N; i++) srcd[i] = (int16_t)rnd();
        for (int i = 0; i < N; i++) {
            mskv[i] = (uint8_t)rnd();
            mskc[i] = mskv[i];
        }

        memcpy(sv, srcd, (size_t)N * sizeof(int16_t));
        memcpy(sc, srcd, (size_t)N * sizeof(int16_t));
        mk_img2(av, sv, w, h);
        mk_img2(ac, sc, w, h);
        mk_img2(mv, (int16_t *)mskv, w, h);
        mk_img2(mc, (int16_t *)mskc, w, h);

        memset(cfg, 0, 0x20);
        memset(obj, 0, 0x20);
        *(float   *)(cfg + 0x04) = (float)(rnd() % 220u) / 100.0f;
        *(float   *)(cfg + 0x08) = (float)(rnd() % 220u) / 100.0f;
        *(int16_t *)(cfg + 0x0c) = (int16_t)((int)(rnd() % 5u) - 1);
        cfg[0x0e] = (uint8_t)(rnd() % 4u);       /* 12aa0 pad mode */
        cfg[0x0f] = (uint8_t)(rnd() % 4u);
        cfg[0x10] = (uint8_t)(rnd() % 3u);       /* 2cfd0 selector */
        cfg[0x11] = (t % 47 == 0) ? 1 : 0;       /* 12aa0 desc selector */
        cfg[0]    = (uint8_t)(rnd() % 3u);       /* 0 / 1 / other */
        *(float *)(obj + 0x00) = (float)(rnd() % 220u) / 100.0f;
        *(float *)(obj + 0x04) = (float)(rnd() % 220u) / 100.0f;
        obj[12] = (uint8_t)rnd();

        int and_mask = (int)rnd();
        int rv = v((cr_image *)av, (const cr_image *)mv, and_mask, obj, cfg);
        int rc = cr_orient_encode_1ba60((cr_image *)ac, (const cr_image *)mc,
                                        and_mask, obj, cfg);
        if (rv != rc) mismatch("ret", (u32)t, (u32)rv, (u32)rc);
        cmp_buf("img", (const u8 *)sv, (const u8 *)sc,
                (size_t)N * sizeof(int16_t), (u32)t);
        ran++;
    }
    printf("  [1ba60] cases=%d\n", ran);
    if (g_fail == bad) end(); else printf("  FAIL cr_orient_encode_1ba60\n");
}

static void test_orient_pipeline_18c60(void)
{
    typedef int (WINAPI *v_t)(cr_image *, const cr_image *, const uint8_t *,
                              const cr_image *, int, int);
    v_t v = (v_t)fn_at(RVA(0x180018c60));
    begin("cr_orient_pipeline_18c60");
    int bad = g_fail;
    enum { MAXW = 24, MAXH = 24, MAXN = MAXW * MAXH, NW = 32 * 32 };
    static int16_t dv[MAXN], dc[MAXN];
    static float wts[NW];
    static uint8_t mbuf[MAXN];
    static u8 av[0x20], ac[0x20], mv[0x20], mc[0x20], qv[0x20], qc[0x20];
    static uint8_t cfg[0x300];
    int ran = 0;

    for (int t = 0; t < 400; t++) {
        int w = 8 + (int)(rnd() % (MAXW - 7));
        int h = 8 + (int)(rnd() % (MAXH - 7));   /* >= 8 for the 7-tap FIR */
        int N = w * h;

        for (int i = 0; i < N; i++) {
            int16_t x = (int16_t)((int)(rnd() % 65536) - 32768);
            dv[i] = x; dc[i] = x;
            mbuf[i] = (uint8_t)rnd();
        }
        for (int i = 0; i < NW; i++)
            wts[i] = (float)((int)(rnd() % 2000) - 1000) * 0.001f;

        mk_img2(av, dv, w, h);
        mk_img2(ac, dc, w, h);
        mk_img2(mv, (int16_t *)mbuf, w, h);
        memcpy(mc, mv, 0x20);
        mk_img2(qv, (int16_t *)wts, w, h);
        memcpy(qc, qv, 0x20);

        memset(cfg, 0, sizeof cfg);
        cfg[0] = (uint8_t)(t % 8);               /* sel when a6 == 0 */
        cfg[1] = (uint8_t)((t / 8) % 8);         /* sel when a6 != 0 */
        cfg[2] = (uint8_t)rnd();
        cfg[3] = (uint8_t)(rnd() % 5);           /* stretch mode */
        cfg[8] = (uint8_t)(rnd() & 1u);
        cfg[0xa8] = (uint8_t)(rnd() % 2u);       /* fft dims selector */
        *(float   *)(cfg + 0xb8) = (float)(rnd() % 201u) / 200.0f;
        *(float   *)(cfg + 0xbc) = (float)(rnd() % 201u) / 200.0f;
        *(float   *)(cfg + 0xe4) = (float)(rnd() % 220u) / 100.0f;
        *(float   *)(cfg + 0xe8) = (float)(rnd() % 220u) / 100.0f;
        cfg[0xf0] = (uint8_t)rnd();
        /* 1ba60 config at +0xf4 */
        cfg[0xf4] = (uint8_t)(rnd() % 2u);
        *(float   *)(cfg + 0xf8) = (float)(rnd() % 220u) / 100.0f;
        *(float   *)(cfg + 0xfc) = (float)(rnd() % 220u) / 100.0f;
        *(int16_t *)(cfg + 0x100) = (int16_t)((int)(rnd() % 5u) - 1);
        cfg[0x102] = (uint8_t)(rnd() % 4u);
        cfg[0x103] = (uint8_t)(rnd() % 4u);
        cfg[0x104] = (uint8_t)(rnd() % 2u);
        cfg[0x105] = 0;                          /* descriptor selector */
        /* blur_divnorm config at +0x2c0 */
        cfg[0x2cc] = (uint8_t)(3 + (rnd() % 2u));
        *(float *)(cfg + 0x2c4) = (float)(rnd() % 220u) / 100.0f;

        int a5 = (int)rnd();
        int a6 = t & 1;
        int rv = v((cr_image *)av, (const cr_image *)qv, cfg,
                   (const cr_image *)mv, a5, a6);
        int rc = cr_orient_pipeline_18c60((cr_image *)ac, (const cr_image *)qc,
                                          cfg, (const cr_image *)mc, a5, a6);
        if (rv != rc) mismatch("ret", (u32)t, (u32)rv, (u32)rc);
        cmp_buf("img", (const u8 *)dv, (const u8 *)dc,
                (size_t)N * sizeof(int16_t), (u32)t);
        ran++;
    }
    printf("  [18c60] cases=%d\n", ran);
    if (g_fail == bad) end(); else printf("  FAIL cr_orient_pipeline_18c60\n");
}

/* ---- batch 101: block orientation / run-length descriptor -------------- */
static void test_block_orient_195d0(void)
{
    typedef int (WINAPI *v_t)(int16_t *, cr_image *, cr_image *, cr_image *,
                              cr_image *, cr_image *, float *, const void *,
                              const cr_image *, const uint8_t *);
    v_t v = (v_t)fn_at(RVA(0x1800195d0));
    begin("cr_block_orient_195d0");
    int bad = g_fail;
    enum { MAXW = 56, MAXH = 56, MAXN = MAXW * MAXH, GRID = 256 };
    static int16_t sv[MAXN], sc[MAXN];
    static float gv[5][GRID], gc[5][GRID];
    static uint32_t bmw[2048], bmc[2048];
    static u8 cfg[0x80];
    static u8 iv[5][0x20], ic[5][0x20];
    static u8 svd[0x20], scd[0x20];
    static u8 bdv[0x20], bdc[0x20];
    static float ov[4], oc[4];
    int ran = 0;

    for (int t = 0; t < 400; t++) {
        int X  = 5 + (int)(rnd() % 5);
        int gw = 2 + (int)(rnd() % 4);
        int gh = 2 + (int)(rnd() % 4);
        int W  = X * gw + (int)(rnd() % (unsigned)X);
        int H  = X * gh + (int)(rnd() % (unsigned)X);
        int N  = W * H;
        int a  = ((W + 31) / 32) * 32;
        int offx = (int)(rnd() % 8), offy = (int)(rnd() % 8);

        for (int i = 0; i < N; i++) {
            int16_t x = (int16_t)((int)(rnd() % 65536) - 32768);
            sv[i] = x; sc[i] = x;
        }
        for (int g = 0; g < 5; g++)
            for (int i = 0; i < GRID; i++) {
                float f = (float)((int)(rnd() % 2001) - 1000) * 0.01f;
                gv[g][i] = f; gc[g][i] = f;
            }
        for (int i = 0; i < (int)(sizeof bmw / sizeof bmw[0]); i++) {
            uint32_t w = (t % 5 < 2) ? 0xffffffffu : rnd();
            bmw[i] = w; bmc[i] = w;
        }
        ov[0] = ov[1] = ov[2] = ov[3] = 0.0f;
        oc[0] = oc[1] = oc[2] = oc[3] = 0.0f;

        memset(cfg, 0, sizeof cfg);
        *(float *)(cfg + 0x0c) = (float)(rnd() % 200u) / 100.0f;
        *(int   *)(cfg + 0x10) = X;
        *(float *)(cfg + 0x14) = (t & 1) ? -1.0f
                                        : (float)(rnd() % 120u);
        {
            static const int plo[8] = { 0x18, 0x1c, 0x28, 0x2c,
                                        0x38, 0x3c, 0x48, 0x4c };
            static const int phi[8] = { 0x24, 0x20, 0x34, 0x30,
                                        0x44, 0x40, 0x54, 0x50 };
            for (int i = 0; i < 8; i++) {
                int lo = plo[i], hi = phi[i];
                switch ((t / 8 + i) % 4) {
                case 0: *(float *)(cfg + lo) = -1e6f;
                        *(float *)(cfg + hi) =  1e6f; break;
                case 1: *(float *)(cfg + lo) =  0.0f;
                        *(float *)(cfg + hi) =  1.0f; break;
                case 2: *(float *)(cfg + lo) = -1.0f;
                        *(float *)(cfg + hi) =  2.0f; break;
                default:*(float *)(cfg + lo) =  0.05f;
                        *(float *)(cfg + hi) =  0.5f;  break;
                }
            }
        }

        for (int g = 0; g < 4; g++)
            mk_img2(iv[g], (int16_t *)gv[g], W, H);
        mk_img2(iv[4], (int16_t *)gv[4], gw, gh);
        memcpy(ic, iv, sizeof iv);
        for (int g = 0; g < 5; g++)
            *(void **)(ic[g] + 0x08) = gc[g];
        mk_img2(svd, sv, W, H);
        mk_img2(scd, sc, W, H);
        mk_img2(bdv, (int16_t *)bmw, W, H);
        memcpy(bdc, bdv, 0x20);
        *(void **)(bdc + 0x08) = bmc;
        *(int *)(bdv + 0x00) = a;
        *(int *)(bdc + 0x00) = a;
        *(int *)(bdv + 0x18) = offx;
        *(int *)(bdc + 0x18) = offx;
        *(int *)(bdv + 0x1c) = offy;
        *(int *)(bdc + 0x1c) = offy;

        int16_t rv = 0x1234, rc = 0x1234;
        int er = v(&rv, (cr_image *)iv[0], (cr_image *)iv[1],
                   (cr_image *)iv[2], (cr_image *)iv[3], (cr_image *)iv[4],
                   ov, bdv, (const cr_image *)svd, cfg);
        int ec = cr_block_orient_195d0(&rc, (cr_image *)ic[0],
                   (cr_image *)ic[1], (cr_image *)ic[2], (cr_image *)ic[3],
                   (cr_image *)ic[4], oc, bdc, (const cr_image *)scd, cfg);

        if (er != ec) mismatch("ret", (u32)t, (u32)er, (u32)ec);
        if (rv != rc) mismatch("q", (u32)t, (u16)rv, (u16)rc);
        for (int g = 0; g < 5; g++)
            cmp_buf("grid", (const u8 *)gv[g], (const u8 *)gc[g],
                    GRID * sizeof(float), (u32)t);
        cmp_buf("out4", (const u8 *)ov, (const u8 *)oc, 16, (u32)t);
        cmp_buf("bmp", (const u8 *)bmw, (const u8 *)bmc,
                sizeof bmw, (u32)t);
        ran++;
    }

    /* Guard paths: X >= W or X >= H must return 0x69 and write -1. */
    for (int t = 0; t < 12; t++) {
        int X = 6 + t, W = 6 + (t / 3), H = 8 + (t / 2);
        memset(cfg, 0, sizeof cfg);
        *(int *)(cfg + 0x10) = X;
        mk_img2(svd, sv, W, H);
        mk_img2(scd, sc, W, H);
        int16_t rv = 7, rc = 7;
        int er = v(&rv, (cr_image *)iv[0], (cr_image *)iv[1],
                   (cr_image *)iv[2], (cr_image *)iv[3], (cr_image *)iv[4],
                   ov, bdv, (const cr_image *)svd, cfg);
        int ec = cr_block_orient_195d0(&rc, (cr_image *)ic[0],
                   (cr_image *)ic[1], (cr_image *)ic[2], (cr_image *)ic[3],
                   (cr_image *)ic[4], oc, bdc, (const cr_image *)scd, cfg);
        if (er != ec) mismatch("gret", (u32)t, (u32)er, (u32)ec);
        if (rv != rc) mismatch("gq", (u32)t, (u16)rv, (u16)rc);
        ran++;
    }
    printf("  [195d0] cases=%d\n", ran);
    if (g_fail == bad) end(); else printf("  FAIL cr_block_orient_195d0\n");
}


/* ---- batch 102: five-grid block-orientation wrapper -------------------- */
static void test_block_orient_48010(void)
{
    typedef int (WINAPI *v_t)(int16_t *, const cr_image *, const cr_image *,
                              const cr_image *);
    v_t v = (v_t)fn_at(RVA(0x180048010));
    begin("cr_block_orient_48010");
    int bad = g_fail;
    enum { MAXW = 56, MAXH = 56, MAXN = MAXW * MAXH };
    static int16_t sv[MAXN], sc[MAXN];
    static uint32_t bmw[2048], bmc[2048];
    static u8 cfg[0x80];
    static u8 svd[0x20], scd[0x20], bdv[0x20], bdc[0x20], cv[0x20], cc[0x20];
    int ran = 0;

    for (int t = 0; t < 400; t++) {
        int X  = 5 + (int)(rnd() % 5);
        int gw = 2 + (int)(rnd() % 4);
        int gh = 2 + (int)(rnd() % 4);
        int W  = X * gw + (int)(rnd() % (unsigned)X);
        int H  = X * gh + (int)(rnd() % (unsigned)X);
        int N  = W * H;
        int a  = ((W + 31) / 32) * 32;
        int offx = (int)(rnd() % 8), offy = (int)(rnd() % 8);

        for (int i = 0; i < N; i++) {
            int16_t x = (int16_t)((int)(rnd() % 65536) - 32768);
            sv[i] = x; sc[i] = x;
        }
        for (int i = 0; i < (int)(sizeof bmw / sizeof bmw[0]); i++) {
            uint32_t w = (t % 5 < 2) ? 0xffffffffu : rnd();
            bmw[i] = w; bmc[i] = w;
        }

        memset(cfg, 0, sizeof cfg);
        *(float *)(cfg + 0x0c) = (float)(rnd() % 200u) / 100.0f;
        *(int   *)(cfg + 0x10) = X;
        *(float *)(cfg + 0x14) = (t & 1) ? -1.0f : (float)(rnd() % 120u);
        {
            static const int plo[8] = { 0x18, 0x1c, 0x28, 0x2c,
                                        0x38, 0x3c, 0x48, 0x4c };
            static const int phi[8] = { 0x24, 0x20, 0x34, 0x30,
                                        0x44, 0x40, 0x54, 0x50 };
            for (int i = 0; i < 8; i++) {
                int lo = plo[i], hi = phi[i];
                switch ((t / 8 + i) % 4) {
                case 0: *(float *)(cfg + lo) = -1e6f;
                        *(float *)(cfg + hi) =  1e6f; break;
                case 1: *(float *)(cfg + lo) =  0.0f;
                        *(float *)(cfg + hi) =  1.0f; break;
                case 2: *(float *)(cfg + lo) = -1.0f;
                        *(float *)(cfg + hi) =  2.0f; break;
                default:*(float *)(cfg + lo) =  0.05f;
                        *(float *)(cfg + hi) =  0.5f;  break;
                }
            }
        }

        mk_img2(svd, sv, W, H);
        mk_img2(scd, sc, W, H);
        mk_img2(cv, (int16_t *)cfg, W, H);
        memcpy(cc, cv, 0x20);
        *(int *)(cv + 0x10) = X;
        *(int *)(cc + 0x10) = X;
        mk_img2(bdv, (int16_t *)bmw, W, H);
        memcpy(bdc, bdv, 0x20);
        *(void **)(bdc + 0x08) = bmc;
        *(int *)(bdv + 0x00) = a;
        *(int *)(bdc + 0x00) = a;
        *(int *)(bdv + 0x18) = offx;
        *(int *)(bdc + 0x18) = offx;
        *(int *)(bdv + 0x1c) = offy;
        *(int *)(bdc + 0x1c) = offy;

        int16_t rv = 0x1234, rc = 0x1234;
        int er = v(&rv, (const cr_image *)bdv, (const cr_image *)svd,
                   (const cr_image *)cv);
        int ec = cr_block_orient_48010(&rc, (const cr_image *)bdc,
                                       (const cr_image *)scd,
                                       (const cr_image *)cc);

        if (er != ec) mismatch("ret", (u32)t, (u32)er, (u32)ec);
        if (rv != rc) mismatch("q", (u32)t, (u16)rv, (u16)rc);
        cmp_buf("bmp", (const u8 *)bmw, (const u8 *)bmc, sizeof bmw, (u32)t);
        ran++;
    }

    for (int t = 0; t < 10; t++) {
        int X = 6 + t, W = 6 + (t / 3), H = 8 + (t / 2);
        memset(cfg, 0, sizeof cfg);
        *(int *)(cfg + 0x10) = X;
        mk_img2(svd, sv, W, H);
        mk_img2(scd, sc, W, H);
        mk_img2(cv, (int16_t *)cfg, W, H);
        memcpy(cc, cv, 0x20);
        *(int *)(cv + 0x10) = X;
        *(int *)(cc + 0x10) = X;
        int16_t rv = 7, rc = 7;
        int er = v(&rv, (const cr_image *)bdv, (const cr_image *)svd,
                   (const cr_image *)cv);
        int ec = cr_block_orient_48010(&rc, (const cr_image *)bdc,
                                       (const cr_image *)scd,
                                       (const cr_image *)cc);
        if (er != ec) mismatch("gret", (u32)t, (u32)er, (u32)ec);
        if (rv != rc) mismatch("gq", (u32)t, (u16)rv, (u16)rc);
        ran++;
    }
    printf("  [48010] cases=%d\n", ran);
    if (g_fail == bad) end(); else printf("  FAIL cr_block_orient_48010\n");
}


/* ---- batch 103: orientation-scorer selector ---------------------------- */
static void test_orient_score_dispatch_1c220(void)
{
    typedef int (WINAPI *v_t)(int16_t *, const cr_image *, const cr_image *,
                              const void *);
    v_t v = (v_t)fn_at(RVA(0x18001c220));
    begin("cr_orient_score_dispatch_1c220");
    int bad = g_fail;
    enum { MAXW = 56, MAXH = 56, MAXN = MAXW * MAXH };
    static int16_t sv[MAXN], sc[MAXN];
    static uint32_t bmw[2048], bmc[2048];
    static u8 cfg[0x80];
    static u8 svd[0x20], scd[0x20], bdv[0x20], bdc[0x20];
    int ran = 0;

    for (int t = 0; t < 30; t++) {
        int X  = 5 + (int)(rnd() % 5);
        int gw = 2 + (int)(rnd() % 3);
        int gh = 2 + (int)(rnd() % 3);
        int W  = X * gw + (int)(rnd() % (unsigned)X);
        int H  = X * gh + (int)(rnd() % (unsigned)X);
        int N  = W * H;
        int a  = ((W + 31) / 32) * 32;
        int offx = (int)(rnd() % 8), offy = (int)(rnd() % 8);

        for (int i = 0; i < N; i++) {
            int16_t x = (int16_t)((int)(rnd() % 65536) - 32768);
            sv[i] = x; sc[i] = x;
        }
        for (int i = 0; i < (int)(sizeof bmw / sizeof bmw[0]); i++) {
            uint32_t w = (t % 4 < 2) ? 0xffffffffu : rnd();
            bmw[i] = w; bmc[i] = w;
        }

        memset(cfg, 0, sizeof cfg);
        cfg[8] = 1;                              /* sigma for 0x180029870 */
        *(float *)(cfg + 0x0c) = (float)(rnd() % 200u) / 100.0f;
        *(int   *)(cfg + 0x10) = X;
        *(float *)(cfg + 0x14) = -1.0f;
        {
            static const int plo[8] = { 0x18, 0x1c, 0x28, 0x2c,
                                        0x38, 0x3c, 0x48, 0x4c };
            static const int phi[8] = { 0x24, 0x20, 0x34, 0x30,
                                        0x44, 0x40, 0x54, 0x50 };
            for (int i = 0; i < 8; i++) {
                *(float *)(cfg + plo[i]) = -1e6f;
                *(float *)(cfg + phi[i]) =  1e6f;
            }
        }

        mk_img2(svd, sv, W, H);
        mk_img2(scd, sc, W, H);
        mk_img2(bdv, (int16_t *)bmw, W, H);
        memcpy(bdc, bdv, 0x20);
        *(void **)(bdc + 0x08) = bmc;
        *(int *)(bdv + 0x00) = a;
        *(int *)(bdc + 0x00) = a;
        *(int *)(bdv + 0x18) = offx;
        *(int *)(bdc + 0x18) = offx;
        *(int *)(bdv + 0x1c) = offy;
        *(int *)(bdc + 0x1c) = offy;

        for (int sel = 0; sel <= 12; sel++) {
            int16_t rv = 0x4321, rc = 0x4321;
            u8 cv[0x80], cc[0x80];
            memcpy(cv, cfg, sizeof cfg);
            cv[0] = (u8)sel;
            memcpy(cc, cv, sizeof cfg);

            int er = v(&rv, (const cr_image *)bdv, (const cr_image *)svd, cv);
            int ec = cr_orient_score_dispatch_1c220(&rc,
                        (const cr_image *)bdc, (const cr_image *)scd, cc);
            if (er != ec) mismatch("ret", (u32)(t * 16 + sel), (u32)er, (u32)ec);
            if (rv != rc) mismatch("q", (u32)(t * 16 + sel), (u16)rv, (u16)rc);
            cmp_buf("bmp", (const u8 *)bmw, (const u8 *)bmc,
                    sizeof bmw, (u32)(t * 16 + sel));
            ran++;
        }
    }
    printf("  [1c220] cases=%d\n", ran);
    if (g_fail == bad) end(); else printf("  FAIL cr_orient_score_dispatch_1c220\n");
}

/* ---- batch 104: block feature pipeline -------------------------------- */
static void test_feature_pipeline_1ad30(void)
{
    typedef int (WINAPI *v_t)(cr_image *, int *, const u8 *, int, int);
    v_t v = (v_t)fn_at(RVA(0x18001ad30));
    begin("cr_feature_pipeline_1ad30");
    int bad = g_fail;
    enum { MAXW = 80, MAXH = 64, MAXN = MAXW * MAXH };
    static int16_t sv[MAXN], sc[MAXN];
    static u8 cfg[0x40];
    static u8 av[0x20], ac[0x20];
    int ran = 0;

    /* Four geometry families that satisfy every guard:
     *   A: W=H=64, m=1 s=1, desc 16 (0x100), calib 6 (0x1000), a5 = 16
     *   B: W=H=64, m=2 s=2, desc 16,          calib 6,          a5 = 64
     *   C: W=16 H=14, m=7 s=4, desc 15 (0x620), calib 6,        a5 = 8
     *   D: W=80 H=64, m=2 s=2, desc 16,       calib 6,          a5 = 80
     * A exercises the valid 42150 block path (64 % 16 == 0), B the
     * "block_w >= w" rejection (a5 == W), C the odd m / stride path and D
     * the W != n branch (q == n == 64, W == 80). */
    static const int famW[4]    = { 64, 64, 16, 80 };
    static const int famH[4]    = { 64, 64, 14, 64 };
    static const int famM[4]    = {  1,  2,  7,  2 };
    static const int famS[4]    = {  1,  2,  4,  2 };
    static const int famDsel[4] = { 16, 16, 15, 16 };
    static const int famA5[4]   = { 16, 64,  8, 80 };
    static const int famCemax[4]= { 63, 31, 15, 31 };
    static const int famRemax[4]= { 63, 63, 11, 63 };
    static const u8  modes[4]   = {  3,  5,  4,  6 };

    for (int fam = 0; fam < 4; fam++) {
        int W   = famW[fam];
        int H   = famH[fam];
        int m   = famM[fam];
        int s   = famS[fam];
        int dsel= famDsel[fam];
        int a5  = famA5[fam];
        int cemax = famCemax[fam];
        int remax = famRemax[fam];
        int N   = W * H;

        for (int t = 0; t < 20; t++) {
            u32 seed = (u32)(fam * 100 + t);
            for (int i = 0; i < N; i++) {
                int16_t x = (int16_t)((int)(rnd() % 65536) - 32768);
                sv[i] = x; sc[i] = x;
            }
            memset(cfg, 0, sizeof cfg);
            *(int *)(cfg + 0x0c) = 0;
            *(int *)(cfg + 0x10) = remax;
            *(int *)(cfg + 0x14) = 0;
            *(int *)(cfg + 0x18) = cemax;
            *(int *)(cfg + 0x1c) = 0;
            *(int *)(cfg + 0x20) = W - 1;
            cfg[0x01] = 6;
            cfg[0x02] = (u8)dsel;
            cfg[0x24] = 1;
            cfg[0x25] = (t & 1) ? 1 : 0;
            cfg[0x26] = modes[t & 3];   /* 4 and 6 -> 0x69 */
            cfg[0x27] = (u8)s;
            cfg[0x28] = (u8)m;
            cfg[0x29] = (t & 4) ? 1 : 0;
            /* first half takes the "passed" early return, second half the
             * full pipeline */
            *(float *)(cfg + 0x04) = (t < 10) ? 1.0e30f : -1.0e30f;

            mk_img2(av, sv, W, H);
            mk_img2(ac, sc, W, H);

            int rv = 0x1234, rc = 0x1234;
            int a4 = (t & 8) ? 1 : 0;
            int er = v((cr_image *)av, &rv, cfg, a4, a5);
            int ec = cr_feature_pipeline_1ad30((cr_image *)ac, &rc, cfg,
                                               a4, a5);
            if (er != ec) mismatch("ret", seed, (u32)er, (u32)ec);
            if (rv != rc) mismatch("a2", seed, (u32)rv, (u32)rc);
            cmp_buf("img", (const u8 *)sv, (const u8 *)sc,
                    (size_t)N * 2, seed);
            ran++;
        }
    }

    /* guard paths: all of these bail out before the heavy pipeline */
    for (int t = 0; t < 16; t++) {
        static const int a5s[8] = { 1, 0, 2, 16, -1, 3, 1, 1 };
        static const u8  sels[8] = { 16, 16, 16, 16, 16, 3, 16, 16 };
        static const u8  cals[8] = { 6, 6, 6, 6, 6, 6, 7, 0 };
        int W = 16, H = 16, N = W * H;
        int k = t & 7;
        u32 seed = (u32)(900 + t);
        for (int i = 0; i < N; i++) {
            int16_t x = (int16_t)((int)(rnd() % 65536) - 32768);
            sv[i] = x; sc[i] = x;
        }
        memset(cfg, 0, sizeof cfg);
        *(int *)(cfg + 0x0c) = 0;
        *(int *)(cfg + 0x10) = H - 1;
        *(int *)(cfg + 0x14) = 0;
        *(int *)(cfg + 0x18) = W - 1;
        *(int *)(cfg + 0x1c) = 0;
        *(int *)(cfg + 0x20) = W - 1;
        cfg[0x01] = cals[k];
        cfg[0x02] = sels[k];
        cfg[0x24] = 1;
        cfg[0x25] = 1;
        cfg[0x26] = 3;
        cfg[0x27] = 1;
        cfg[0x28] = 1;
        *(float *)(cfg + 0x04) = 1.0e30f;

        mk_img2(av, sv, W, H);
        mk_img2(ac, sc, W, H);

        int rv = 0x55, rc = 0x55;
        int er = v((cr_image *)av, &rv, cfg, 1, a5s[k]);
        int ec = cr_feature_pipeline_1ad30((cr_image *)ac, &rc, cfg, 1,
                                           a5s[k]);
        if (er != ec) mismatch("gret", seed, (u32)er, (u32)ec);
        if (rv != rc) mismatch("ga2", seed, (u32)rv, (u32)rc);
        cmp_buf("gimg", (const u8 *)sv, (const u8 *)sc, (size_t)N * 2, seed);
        ran++;
    }

    printf("  [1ad30] cases=%d\n", ran);
    if (g_fail == bad) end(); else printf("  FAIL cr_feature_pipeline_1ad30\n");
}

/* ---- batch 107: BEP block-processing front end ------------------------- */
static void test_bep_process_368d0(void)
{
    typedef int (WINAPI *v_t)(void *, const void *, void *, void *,
                              const void *, int);
    v_t v = (v_t)fn_at(RVA(0x1800368d0));
    begin("cr_bep_process_368d0");
    int bad = g_fail;

    enum { MAXW = 96, MAXH = 80, MAXPIX = MAXW * MAXH,
           MAXW32 = MAXH * ((MAXW + 31) / 32) };
    static uint8_t  imgv[MAXPIX], imgc[MAXPIX];
    static uint32_t bitv[MAXW32], bitc[MAXW32];
    static uint8_t  plv[5][MAXPIX], plc[5][MAXPIX];
    static int16_t  gsv[MAXPIX], gsc[MAXPIX];
    static uint8_t  prmv[0x80], prmc[0x80];
    static uint8_t  a3v[0x100], a3c[0x100];
    static uint8_t  cfgv[0x300], cfgc[0x300];
    static void    *slv[16], *slc[16];
    static uint8_t  sdv[5][0x20], sdc[5][0x20];
    static uint8_t  ilv[0x20], ilc[0x20];
    static uint16_t idv[16], idc[16];
    static uint8_t  a1v[0x90], a1c[0x90];
    static uint8_t  a2v[0x20], a2c[0x20];
    static uint8_t  s1v[0x90], s1c[0x90];
    static uint8_t  simgv[MAXPIX], simgc[MAXPIX];
    static uint32_t sbitv[MAXW32], sbitc[MAXW32];
    static uint8_t  splv[5][MAXPIX], splc[5][MAXPIX];
    static uint8_t  sa3v[0x100], sa3c[0x100];
    static uint8_t  wctxv[0x30], wctxc[0x30];
    int ran = 0;

    {
        int er = v(NULL, a2v, a3v, slv, cfgv, 0);
        int ec = cr_bep_process_368d0(NULL, a2c, a3c, slc, cfgc, 0);
        if (er != ec) mismatch("null", 0, (u32)er, (u32)ec);
        ran++;
    }

    for (int t = 0; t < 60; t++) {
        int fam = t % 5;
        int W = 80 + (int)(rnd() % 17u);
        int H = 72 + (int)(rnd() % 9u);
        int n = W * H;
        int astride = ((W + 31) / 32) * 32;
        int nwords  = astride / 32 * H;
        int cnt = 1 + (t % 4);
        int style = t % 4;
        int pipe = (fam == 1 || fam == 3);
        int gain = (fam == 1);
        int sub  = (fam == 1) ? 3 : 0;
        int bsel = (fam == 3) ? 2 : 3;
        int gate = (fam == 2) ? 1 : 0;
        u32 seed = (u32)t;

        for (int i = 0; i < n; i++) {
            uint8_t b = (uint8_t)rnd();
            imgv[i] = b; imgc[i] = b;
            int16_t g = (int16_t)((int)(rnd() % 4096u) - 2048);
            gsv[i] = g; gsc[i] = g;
        }
        for (int i = 0; i < nwords; i++) {
            uint32_t w = rnd();
            bitv[i] = w; bitc[i] = w;
        }
        for (int k = 0; k < 5; k++) {
            for (int i = 0; i < n; i++) {
                uint8_t x;
                if (style == 1)      x = (uint8_t)(10 + k * 40);
                else if (style == 2) x = 0xff;
                else if (style == 3) x = (i < n / 2) ? 0x00 : 0xff;
                else                 x = (uint8_t)rnd();
                plv[k][i] = x; plc[k][i] = x;
            }
        }
        for (int i = 0; i < 8; i++) {
            idv[i] = (uint16_t)(rnd() % (unsigned)n);
            idc[i] = idv[i];
        }

        memset(prmv, 0, sizeof prmv); memset(prmc, 0, sizeof prmc);
        *(int8_t *)(prmv + 8) = (int8_t)((t & 2) ? 1 : -1);
        *(int8_t *)(prmc + 8) = *(int8_t *)(prmv + 8);
        *(int32_t *)(prmv + 0x50) = W; *(int32_t *)(prmv + 0x54) = H;
        *(int32_t *)(prmc + 0x50) = W; *(int32_t *)(prmc + 0x54) = H;
        *(void **)(prmv + 0x58) = gsv; *(void **)(prmc + 0x58) = gsc;
        *(int32_t *)(prmv + 0x60) = W; *(int32_t *)(prmv + 0x64) = H;
        *(int32_t *)(prmc + 0x60) = W; *(int32_t *)(prmc + 0x64) = H;

        memset(a3v, 0, sizeof a3v); memset(a3c, 0, sizeof a3c);

        for (int k = 0; k < 5; k++) {
            memset(sdv[k], 0, 0x20); memset(sdc[k], 0, 0x20);
            *(int16_t *)(sdv[k] + 0) = (int16_t)W;
            *(int16_t *)(sdv[k] + 2) = (int16_t)H;
            *(int16_t *)(sdc[k] + 0) = (int16_t)W;
            *(int16_t *)(sdc[k] + 2) = (int16_t)H;
            *(void **)(sdv[k] + 0x10) = plv[k];
            *(void **)(sdc[k] + 0x10) = plc[k];
        }
        memset(ilv, 0, 0x20); memset(ilc, 0, 0x20);
        *(uint16_t *)(ilv + 0) = 8; *(uint16_t *)(ilc + 0) = 8;
        *(void **)(ilv + 8) = idv; *(void **)(ilc + 8) = idc;

        for (int i = 0; i < 16; i++) { slv[i] = NULL; slc[i] = NULL; }
        for (int k = 0; k < cnt; k++) { slv[k] = sdv[k]; slc[k] = sdc[k]; }
        slv[5] = ilv; slc[5] = ilc;

        memset(cfgv, 0, sizeof cfgv); memset(cfgc, 0, sizeof cfgc);
        cfgv[0x44] = 0; cfgc[0x44] = 0;              /* skip sharp gate */
        cfgv[0xc0] = 5; cfgc[0xc0] = 5;              /* inpaint percentile */
        cfgv[0xc1] = (uint8_t)(t & 1); cfgc[0xc1] = cfgv[0xc1];
        *(uint16_t *)(cfgv + 0xc2) = 8; *(uint16_t *)(cfgc + 0xc2) = 8;
        cfgv[0x108] = 2; cfgc[0x108] = 2;
        *(uint16_t *)(cfgv + 0x10a) = (uint16_t)(rnd() % 2001u);
        *(uint16_t *)(cfgc + 0x10a) = *(uint16_t *)(cfgv + 0x10a);
        *(int32_t *)(cfgv + 0x110) = 50; *(int32_t *)(cfgc + 0x110) = 50;

        cfgv[2] = (uint8_t)((fam == 4) ? 1 : 2);
        cfgc[2] = cfgv[2];
        *(int16_t *)(cfgv + 6) = (int16_t)((W * W) / 256);
        *(int16_t *)(cfgc + 6) = *(int16_t *)(cfgv + 6);
        *(int16_t *)(cfgv + 0x1e) = 0; *(int16_t *)(cfgc + 0x1e) = 0;
        cfgv[0x28] = (uint8_t)gate; cfgc[0x28] = (uint8_t)gate;
        cfgv[0x78] = (uint8_t)pipe; cfgc[0x78] = (uint8_t)pipe;
        cfgv[0x79] = (uint8_t)bsel; cfgc[0x79] = (uint8_t)bsel;
        cfgv[0x7a] = 4; cfgc[0x7a] = 4;               /* block filter mode */
        *(float *)(cfgv + 0x7c) = 0.5f; *(float *)(cfgc + 0x7c) = 0.5f;
        cfgv[0x80] = 4; cfgc[0x80] = 4;               /* step */
        cfgv[0x81] = 4; cfgc[0x81] = 4;
        cfgv[0x82] = 4; cfgc[0x82] = 4;
        *(int32_t *)(cfgv + 0x84) = 0; *(int32_t *)(cfgc + 0x84) = 0;
        *(int32_t *)(cfgv + 0x88) = H - 1; *(int32_t *)(cfgc + 0x88) = H - 1;
        *(int32_t *)(cfgv + 0x8c) = 0; *(int32_t *)(cfgc + 0x8c) = 0;
        *(int32_t *)(cfgv + 0x90) = W - 1; *(int32_t *)(cfgc + 0x90) = W - 1;
        *(float *)(cfgv + 0xb0) = 0.02f; *(float *)(cfgc + 0xb0) = 0.02f;
        *(float *)(cfgv + 0xb4) = 0.98f; *(float *)(cfgc + 0xb4) = 0.98f;
        cfgv[0xd0] = (uint8_t)gain; cfgc[0xd0] = (uint8_t)gain;
        *(int32_t *)(cfgv + 0xd4) = sub; *(int32_t *)(cfgc + 0xd4) = sub;
        *(int32_t *)(cfgv + 0xd8) = sub; *(int32_t *)(cfgc + 0xd8) = sub;
        *(int32_t *)(cfgv + 0xdc) = sub; *(int32_t *)(cfgc + 0xdc) = sub;
        *(int32_t *)(cfgv + 0xe0) = sub; *(int32_t *)(cfgc + 0xe0) = sub;
        cfgv[0x250] = 4; cfgc[0x250] = 4;
        *(float *)(cfgv + 0x254) = 1.25f; *(float *)(cfgc + 0x254) = 1.25f;
        cfgv[4] = 1; cfgc[4] = 1;                     /* 0x17420 dispatch */

        memset(a1v, 0, sizeof a1v); memset(a1c, 0, sizeof a1c);
        mk_img2(a1v + 0x10, (int16_t *)imgv, W, H);
        mk_img2(a1c + 0x10, (int16_t *)imgc, W, H);
        memset(a1v + 0x50, 0, 0x20); memset(a1c + 0x50, 0, 0x20);
        *(int32_t *)(a1v + 0x50) = astride; *(int32_t *)(a1c + 0x50) = astride;
        *(int32_t *)(a1v + 0x54) = H;       *(int32_t *)(a1c + 0x54) = H;
        *(void **)(a1v + 0x58) = bitv;      *(void **)(a1c + 0x58) = bitc;
        *(int32_t *)(a1v + 0x60) = W;       *(int32_t *)(a1c + 0x60) = W;
        *(int32_t *)(a1v + 0x64) = H;       *(int32_t *)(a1c + 0x64) = H;
        *(uint32_t *)(a1v + 0x74) = 0;      *(uint32_t *)(a1c + 0x74) = 0;

        memset(a2v, 0, sizeof a2v); memset(a2c, 0, sizeof a2c);
        *(void **)(a2v + 0) = prmv; *(void **)(a2c + 0) = prmc;

        int a6 = (t & 4) ? 1 : 0;
        memcpy(s1v, a1v, 0x90); memcpy(s1c, a1c, 0x90);
        memcpy(simgv, imgv, (size_t)n); memcpy(simgc, imgc, (size_t)n);
        memcpy(sbitv, bitv, (size_t)nwords * 4);
        memcpy(sbitc, bitc, (size_t)nwords * 4);
        memcpy(sa3v, a3v, 0x100); memcpy(sa3c, a3c, 0x100);
        for (int k = 0; k < 5; k++) {
            memcpy(splv[k], plv[k], (size_t)n);
            memcpy(splc[k], plc[k], (size_t)n);
        }
        int rv = v(a1v, a2v, a3v, slv, cfgv, a6);
        int rc = cr_bep_process_368d0(a1c, a2c, a3c, slc, cfgc, a6);

        if (rv != rc) mismatch("ret", seed, (u32)rv, (u32)rc);
        {
            u8 tv[0x90], tc[0x90];
            memcpy(tv, a1v, 0x90); memcpy(tc, a1c, 0x90);
            memset(tv + 0x18, 0, 8); memset(tc + 0x18, 0, 8);
            memset(tv + 0x58, 0, 8); memset(tc + 0x58, 0, 8);
            cmp_buf("a1", tv, tc, 0x90, seed);
        }
        cmp_buf("img", imgv, imgc, (size_t)n, seed);
        cmp_buf("bm", (const u8 *)bitv, (const u8 *)bitc,
                (size_t)nwords * 4, seed);
        cmp_buf("st", a3v, a3c, 0x100, seed);
        for (int k = 0; k < 5; k++)
            cmp_buf("slot", plv[k], plc[k], (size_t)n, seed);

        if ((t & 1) == 0) {
            typedef int (WINAPI *vw_t)(void *, void *, void *, void *,
                                       void *, int);
            vw_t vw = (vw_t)fn_at(RVA(0x180017420));
            memcpy(a1v, s1v, 0x90); memcpy(a1c, s1c, 0x90);
            memcpy(imgv, simgv, (size_t)n); memcpy(imgc, simgc, (size_t)n);
            memcpy(bitv, sbitv, (size_t)nwords * 4);
            memcpy(bitc, sbitc, (size_t)nwords * 4);
            memcpy(a3v, sa3v, 0x100); memcpy(a3c, sa3c, 0x100);
            for (int k = 0; k < 5; k++) {
                memcpy(plv[k], splv[k], (size_t)n);
                memcpy(plc[k], splc[k], (size_t)n);
            }
            memset(wctxv, 0, sizeof wctxv); memset(wctxc, 0, sizeof wctxc);
            *(void **)(wctxv + 0x28) = cfgv;
            *(void **)(wctxc + 0x28) = cfgc;
            int wrv = vw(slv, a2v, a3v, a1v, wctxv, a6);
            int wrc = cr_bep_dispatch_17420(slc, a2c, a3c, a1c, wctxc, a6);
            if (wrv != wrc) mismatch("wret", seed, (u32)wrv, (u32)wrc);
            {
                u8 tv[0x90], tc[0x90];
                memcpy(tv, a1v, 0x90); memcpy(tc, a1c, 0x90);
                memset(tv + 0x18, 0, 8); memset(tc + 0x18, 0, 8);
                memset(tv + 0x58, 0, 8); memset(tc + 0x58, 0, 8);
                cmp_buf("wa1", tv, tc, 0x90, seed);
            }
            cmp_buf("wimg", imgv, imgc, (size_t)n, seed);
            cmp_buf("wbm", (const u8 *)bitv, (const u8 *)bitc,
                    (size_t)nwords * 4, seed);
            cmp_buf("wst", a3v, a3c, 0x100, seed);
            for (int k = 0; k < 5; k++)
                cmp_buf("wslot", plv[k], plc[k], (size_t)n, seed);
        }
        ran++;
    }

    printf("  [368d0] cases=%d\n", ran);
    if (g_fail == bad) end(); else printf("  FAIL cr_bep_process_368d0\n");
}

/* ---- batch 106: BEP image front end ----------------------------------- */
static void mk_bmp_desc(u8 *d, int w, int h, void *words)
{
    memset(d, 0, 0x20);
    *(int *)(d + 0x00) = (w + 31) & ~31;
    *(int *)(d + 0x04) = h;
    *(void **)(d + 0x08) = words;
    *(int *)(d + 0x10) = w;
    *(int *)(d + 0x14) = h;
}

static void test_bep_process_1c810(void)
{
    typedef int (WINAPI *v_t)(void *, const void *, void *, void **,
                              void *, int);
    v_t v = (v_t)fn_at(RVA(0x18001c810));
    begin("cr_bep_process_1c810");
    int bad = g_fail;

    enum { MAXW = 160, MAXH = 160, MAXPIX = MAXW * MAXH,
           MAXW32 = MAXH * ((MAXW + 31) / 32) };
    static uint8_t  ssv[5][MAXPIX], ssc[5][MAXPIX];
    static uint32_t f0v[MAXPIX], f0c[MAXPIX];
    static uint32_t f1v[MAXPIX], f1c[MAXPIX];
    static float    f32v[MAXPIX], f32c[MAXPIX];
    static uint8_t  a3v[0x100], a3c[0x100];
    static uint8_t  ctxv[0x40], ctxc[0x40];
    static uint8_t  flgv[0x40], flgc[0x40];
    static uint8_t  cfgv[0x300], cfgc[0x300];
    static uint8_t  a1v[0x90], a1c[0x90];
    static uint8_t  pixv[MAXPIX], pixc[MAXPIX];
    static int16_t  imv[MAXPIX], imc[MAXPIX];
    static uint32_t bmwv[MAXW32], bmwc[MAXW32];
    static void    *slv[16], *slc[16];
    static uint8_t  a4v[0x80], a4c[0x80];
    static uint16_t mkv[MAXPIX], mkc[MAXPIX];
    static uint8_t  sdv[5][0x20], sdc[5][0x20];
    static uint8_t  adv[5][0x40], adc[5][0x40];
    static uint8_t  s5v[0x20], s5c[0x20], s6v[0x20], s6c[0x20];
    static uint8_t  ilv[0x10], ilc[0x10];
    static uint16_t idv[16], idc[16];
    static uint8_t  a2v[0x20], a2c[0x20];
    static uint8_t  pcv[0x80], pcc[0x80];
    static uint8_t  s1v[0x90], s1c[0x90];
    static uint8_t  spixv[MAXPIX * 2], spixc[MAXPIX * 2];
    static int16_t  simv[MAXPIX], simc[MAXPIX];
    static uint32_t sbmwv[MAXW32], sbmwc[MAXW32];
    static uint8_t  sa3v[0x100], sa3c[0x100];
    static uint8_t  sflgv[0x40], sflgc[0x40];
    static uint8_t  sssv[5][MAXPIX], sssc[5][MAXPIX];
    int ran = 0;

    {
        int er = v(NULL, a2v, a3v, (void **)a4v, ctxv, 0);
        int ec = cr_bep_process_1c810(NULL, a2c, a3c, (void **)a4c,
                                      ctxc, 0);
        if (er != ec) mismatch("null", 0, (u32)er, (u32)ec);
        ran++;
    }

    for (int t = 0; t < 60; t++) {
        int fam = t % 5;
        int W, H, aw, ah, pipe, gain, sub, rsz, csel, osc, shrt, gfl;
        int osel = 0;
        switch (fam) {
        case 0:  W=64; H=64; aw=64; ah=64; pipe=1; gain=0; sub=0; rsz=0;
                 csel=12; osc=10; shrt=1; gfl=0; break;
        case 1:  W=88; H=88; aw=88; ah=88; pipe=0; gain=0; sub=0; rsz=0;
                 csel=12; osc=2;  shrt=0; gfl=0; break;
        case 2:  W=32; H=32; aw=16; ah=16; pipe=0; gain=1; sub=2; rsz=1;
                 csel=0;  osc=0;  shrt=0; gfl=1; break;
        case 3:  W=152; H=152; aw=152; ah=152; pipe=0; gain=0; sub=0; rsz=0;
                 csel=13; osc=2;  shrt=0; gfl=0; break;
        default: W=88; H=88; aw=88; ah=88; pipe=0; gain=0; sub=0; rsz=0;
                 csel=12; osc=2;  shrt=0; gfl=0; osel=2; break;
        }
        int N = W * H;
        int cnt = 1 + (t % 2);
        u32 seed = (u32)t;

        for (int i = 0; i < N; i++) {
            uint8_t b = (uint8_t)rnd();
            for (int k = 0; k < 5; k++) ssv[k][i] = (uint8_t)(b + k * 17);
            pixv[i] = (uint8_t)rnd();
            imv[i] = (int16_t)((int)(rnd() % 65536) - 32768);
            f32v[i] = (float)(int)(rnd() % 2000) - 1000.0f;
            f0v[i] = rnd();
            f1v[i] = rnd();
            mkv[i] = (uint16_t)rnd();
        }
        for (int i = 0; i < N; i++) {
            for (int k = 0; k < 5; k++) ssc[k][i] = ssv[k][i];
            pixc[i] = pixv[i];
            imc[i] = imv[i];
            f32c[i] = f32v[i];
            f0c[i] = f0v[i];
            f1c[i] = f1v[i];
            mkc[i] = mkv[i];
        }
        for (int i = 0; i < 8; i++) {
            idv[i] = (uint16_t)(rnd() % (unsigned)N);
            idc[i] = idv[i];
        }

        memset(a3v, 0, sizeof a3v); memset(a3c, 0, sizeof a3c);
        *(int *)(a3v + 4) = 1; *(int *)(a3c + 4) = 1;

        memset(ctxv, 0, sizeof ctxv); memset(ctxc, 0, sizeof ctxc);
        *(void **)(ctxv + 0x10) = flgv; *(void **)(ctxc + 0x10) = flgc;
        *(void **)(ctxv + 0x28) = cfgv; *(void **)(ctxc + 0x28) = cfgc;

        memset(flgv, 0, sizeof flgv); memset(flgc, 0, sizeof flgc);
        flgv[0x3d] = (uint8_t)gfl; flgc[0x3d] = flgv[0x3d];

        for (int k = 0; k < 5; k++) {
            memset(sdv[k], 0, 0x20); memset(sdc[k], 0, 0x20);
            *(int16_t *)(sdv[k] + 0) = (int16_t)W;
            *(int16_t *)(sdv[k] + 2) = (int16_t)H;
            sdv[k][6] = 8;
            *(void **)(sdv[k] + 0x10) = ssv[k];
            memcpy(sdc[k], sdv[k], 0x20);
            sdc[k][6] = 8;
            *(void **)(sdc[k] + 0x10) = ssc[k];
        }
        memset(s5v, 0, 0x20); memset(s5c, 0, 0x20);
        *(int16_t *)(s5v + 0) = (int16_t)W; *(int16_t *)(s5v + 2) = (int16_t)H;
        *(void **)(s5v + 0x10) = f0v;
        memcpy(s5c, s5v, 0x20);
        *(void **)(s5c + 0x10) = f0c;
        memset(s6v, 0, 0x20); memset(s6c, 0, 0x20);
        *(int16_t *)(s6v + 0) = (int16_t)W; *(int16_t *)(s6v + 2) = (int16_t)H;
        *(void **)(s6v + 0x10) = f1v;
        memcpy(s6c, s6v, 0x20);
        *(void **)(s6c + 0x10) = f1c;
        memset(ilv, 0, 0x10); memset(ilc, 0, 0x10);
        *(uint16_t *)(ilv + 0) = 8; *(uint16_t *)(ilc + 0) = 8;
        *(void **)(ilv + 8) = idv; *(void **)(ilc + 8) = idc;

        for (int i = 0; i < 16; i++) { slv[i] = NULL; slc[i] = NULL; }
        for (int k = 0; k < cnt; k++) { slv[k] = sdv[k]; slc[k] = sdc[k]; }
        slv[5] = s5v;  slc[5] = s5c;
        slv[6] = s6v;  slc[6] = s6c;
        slv[0x0e] = ilv; slc[0x0e] = ilc;

        memset(a4v, 0, sizeof a4v); memset(a4c, 0, sizeof a4c);
        memset(pcv, 0, sizeof pcv); memset(pcc, 0, sizeof pcc);
        *(float *)(pcv + 4) = 0.5f;    *(float *)(pcc + 4) = 0.5f;
        *(int8_t *)(pcv + 8) = 1;      *(int8_t *)(pcc + 8) = 1;
        *(void **)(pcv + 0x18) = mkv;  *(void **)(pcc + 0x18) = mkc;
        *(void **)(pcv + 0x58) = mkv;  *(void **)(pcc + 0x58) = mkc;
        for (int k = 0; k < 5; k++) {
            memset(adv[k], 0, 0x40); memset(adc[k], 0, 0x40);
            *(int16_t *)(adv[k] + 0) = (int16_t)W;
            *(int16_t *)(adv[k] + 2) = (int16_t)H;
            adv[k][6] = 8;
            *(void **)(adv[k] + 0x10) = ssv[k];
            memcpy(adc[k], adv[k], 0x40);
            adc[k][6] = 8;
            *(void **)(adc[k] + 0x10) = ssc[k];
            *(void **)(a4v + k * 8) = adv[k];
            *(void **)(a4c + k * 8) = adc[k];
        }

        memset(a2v, 0, sizeof a2v); memset(a2c, 0, sizeof a2c);
        *(void **)(a2v + 0) = pcv; *(void **)(a2c + 0) = pcc;
        *(void **)(a2v + 8) = f32v; *(void **)(a2c + 8) = f32c;

        memset(cfgv, 0, sizeof cfgv);
        cfgv[0] = 0;                          /* orientation pipeline sel */
        cfgv[2] = 0;                          /* stretch mode            */
        cfgv[5] = (uint8_t)rsz;
        cfgv[9] = 0;                          /* normaliser map mode     */
        cfgv[0x1c] = (uint8_t)shrt;
        *(float *)(cfgv + 0x24) = 50.0f;      /* chain threshold         */
        cfgv[0x28] = (uint8_t)csel;
        cfgv[0x29] = 1;                       /* grad-score enabled      */
        *(uint16_t *)(cfgv + 0x2a) = 2;       /* grad margin             */
        *(int16_t *)(cfgv + 0x2c) = 0;        /* mask threshold          */
        cfgv[0x30] = 0;
        cfgv[0x40] = 0;
        cfgv[0x44] = (uint8_t)((fam == 0) ? 2 : (fam == 2 ? 1 : 0));
        *(float *)(cfgv + 0x48) = 0.5f;
        cfgv[0x78] = (uint8_t)pipe;
        cfgv[0x79] = 6;
        cfgv[0x7a] = 16;
        *(float *)(cfgv + 0x7c) = -1.0e30f;
        *(int *)(cfgv + 0x84) = 0;
        *(int *)(cfgv + 0x88) = H - 1;
        *(int *)(cfgv + 0x8c) = 0;
        *(int *)(cfgv + 0x90) = W - 1;
        *(int *)(cfgv + 0x94) = 0;
        *(int *)(cfgv + 0x98) = W - 1;
        cfgv[0x9c] = 1;
        cfgv[0x9d] = 0;
        cfgv[0x9e] = 3;
        cfgv[0x9f] = 1;
        cfgv[0xa0] = 1;
        *(int16_t *)(cfgv + 6) = (int16_t)((W * W) / 256);
        *(float *)(cfgv + 0xb0) = 1.0f;
        *(float *)(cfgv + 0xb4) = 0.0f;
        cfgv[0xc0] = 0;
        cfgv[0xc1] = (uint8_t)(t & 1);
        *(uint16_t *)(cfgv + 0xc2) = 16;
        *(int32_t *)(cfgv + 0xc4) = 0;
        cfgv[0xcc] = 3;
        cfgv[0xcd] = 3;
        cfgv[0xd0] = (uint8_t)gain;
        *(int *)(cfgv + 0xd4) = sub;
        *(int *)(cfgv + 0xd8) = sub;
        *(int *)(cfgv + 0xdc) = sub;
        *(int *)(cfgv + 0xe0) = sub;
        cfgv[0x108] = 0;
        *(int16_t *)(cfgv + 0x10a) = 0;
        *(int32_t *)(cfgv + 0x110) = 0;
        cfgv[0x250] = (uint8_t)osc;
        *(float *)(cfgv + 0x258) = 1.0f;
        if (osel) {
            cfgv[0] = (uint8_t)osel;
            cfgv[1] = (uint8_t)osel;
            cfgv[3] = 2;                       /* stretch percentile mode */
            cfgv[8] = 1;
            cfgv[0xa8] = 1;
            *(float *)(cfgv + 0xb8) = 0.35f;
            *(float *)(cfgv + 0xbc) = 0.75f;
            *(float *)(cfgv + 0xe4) = 0.9f;
            *(float *)(cfgv + 0xe8) = 1.4f;
            cfgv[0xf0] = 0;
            cfgv[0xf4] = 0;
            *(float *)(cfgv + 0xf8) = 1.1f;
            *(float *)(cfgv + 0xfc) = 0.6f;
            *(int16_t *)(cfgv + 0x100) = 0;
            cfgv[0x102] = 1;
            cfgv[0x103] = 2;
            cfgv[0x104] = 0;
            cfgv[0x105] = 0;
            cfgv[0x2cc] = 4;
            *(float *)(cfgv + 0x2c4) = 1.3f;
        }
        memcpy(cfgc, cfgv, sizeof cfgv);

        memset(a1v, 0, 0x90); memset(a1c, 0, 0x90);
        mk_img2(a1v + 0x10, (int16_t *)pixv, aw, ah);
        mk_img2(a1c + 0x10, (int16_t *)pixc, aw, ah);
        mk_img2(a1v + 0x30, imv, W, H);
        mk_img2(a1c + 0x30, imc, W, H);
        mk_bmp_desc(a1v + 0x50, W, H, bmwv);
        mk_bmp_desc(a1c + 0x50, W, H, bmwc);
        memset(bmwv, 0, sizeof bmwv); memset(bmwc, 0, sizeof bmwc);
        *(uint32_t *)(a1v + 0x74) = (t & 1) ? 0xffffffffu : 0xfffffffeu;
        *(uint32_t *)(a1c + 0x74) = *(uint32_t *)(a1v + 0x74);

        int a6 = (t & 4) ? 1 : 0;
        memcpy(s1v, a1v, 0x90); memcpy(s1c, a1c, 0x90);
        memcpy(spixv, pixv, (size_t)(aw * ah) * 2);
        memcpy(spixc, pixc, (size_t)(aw * ah) * 2);
        memcpy(simv, imv, (size_t)N * 2); memcpy(simc, imc, (size_t)N * 2);
        memcpy(sbmwv, bmwv, sizeof bmwv); memcpy(sbmwc, bmwc, sizeof bmwc);
        memcpy(sa3v, a3v, 0x100); memcpy(sa3c, a3c, 0x100);
        memcpy(sflgv, flgv, 0x40); memcpy(sflgc, flgc, 0x40);
        for (int k = 0; k < 5; k++) {
            memcpy(sssv[k], ssv[k], (size_t)N);
            memcpy(sssc[k], ssc[k], (size_t)N);
        }
        int rv = v(a1v, a2v, a3v, (void **)a4v, ctxv, a6);
        int rc = cr_bep_process_1c810(a1c, a2c, a3c, (void **)a4c,
                                      ctxc, a6);

        if (rv != rc) mismatch("ret", seed, (u32)rv, (u32)rc);
        {
            u8 tv[0x90], tc[0x90];
            memcpy(tv, a1v, 0x90); memcpy(tc, a1c, 0x90);
            memset(tv + 0x18, 0, 8); memset(tc + 0x18, 0, 8);
            memset(tv + 0x38, 0, 8); memset(tc + 0x38, 0, 8);
            memset(tv + 0x58, 0, 8); memset(tc + 0x58, 0, 8);
            cmp_buf("a1", tv, tc, 0x90, seed);
        }
        cmp_buf("pix", pixv, pixc, (size_t)(aw * ah), seed);
        cmp_buf("im", (const u8 *)imv, (const u8 *)imc, (size_t)N * 2, seed);
        cmp_buf("bm", (const u8 *)bmwv, (const u8 *)bmwc,
                sizeof bmwv, seed);
        cmp_buf("st", a3v, a3c, 0x100, seed);
        for (int k = 0; k < 5; k++)
            cmp_buf("slot", ssv[k], ssc[k], (size_t)N, seed);

        if ((t & 1) == 0) {
            typedef int (WINAPI *vw_t)(void *, void *, void *, void *,
                                       void *, int);
            vw_t vw = (vw_t)fn_at(RVA(0x180017420));
            memcpy(a1v, s1v, 0x90); memcpy(a1c, s1c, 0x90);
            memcpy(pixv, spixv, (size_t)(aw * ah) * 2);
            memcpy(pixc, spixc, (size_t)(aw * ah) * 2);
            memcpy(imv, simv, (size_t)N * 2);
            memcpy(imc, simc, (size_t)N * 2);
            memcpy(bmwv, sbmwv, sizeof bmwv);
            memcpy(bmwc, sbmwc, sizeof bmwc);
            memcpy(a3v, sa3v, 0x100); memcpy(a3c, sa3c, 0x100);
            memcpy(flgv, sflgv, 0x40); memcpy(flgc, sflgc, 0x40);
            for (int k = 0; k < 5; k++) {
                memcpy(ssv[k], sssv[k], (size_t)N);
                memcpy(ssc[k], sssc[k], (size_t)N);
            }
            int wrv = vw(a4v, a2v, a3v, a1v, ctxv, a6);
            int wrc = cr_bep_dispatch_17420(a4c, a2c, a3c, a1c, ctxc, a6);
            if (wrv != wrc) mismatch("wret", seed, (u32)wrv, (u32)wrc);
            {
                u8 tv[0x90], tc[0x90];
                memcpy(tv, a1v, 0x90); memcpy(tc, a1c, 0x90);
                memset(tv + 0x18, 0, 8); memset(tc + 0x18, 0, 8);
                memset(tv + 0x38, 0, 8); memset(tc + 0x38, 0, 8);
                memset(tv + 0x58, 0, 8); memset(tc + 0x58, 0, 8);
                cmp_buf("wa1", tv, tc, 0x90, seed);
            }
            cmp_buf("wpix", pixv, pixc, (size_t)(aw * ah) * 2, seed);
            cmp_buf("wim", (const u8 *)imv, (const u8 *)imc,
                    (size_t)N * 2, seed);
            cmp_buf("wbm", (const u8 *)bmwv, (const u8 *)bmwc,
                    sizeof bmwv, seed);
            cmp_buf("wst", a3v, a3c, 0x100, seed);
            for (int k = 0; k < 5; k++)
                cmp_buf("wslot", ssv[k], ssc[k], (size_t)N, seed);
        }
        ran++;
    }

    printf("  [1c810] cases=%d\n", ran);
    if (g_fail == bad) end(); else printf("  FAIL cr_bep_process_1c810\n");
}

/* ---- batch 105: chain stages ------------------------------------------ */
static void test_chain_stages(void)
{
    enum { MAXW = 96, MAXH = 96, MAXN = MAXW * MAXH };
    static int16_t sv[MAXN];
    static uint32_t bits[MAXH * 4];
    static u8 bdv[0x20], bdc[0x20], imv[0x20], imc[0x20];
    static u8 ctv[0x80], ctc[0x80];
    static u8 cfg[8];

    /* ---- 0x180026a70: the scale is passed in xmm3 ---------------------- */
    {
        typedef int (WINAPI *v7)(int16_t *, const void *, const void *,
                                 float, float, float, float);
        v7 v = (v7)fn_at(RVA(0x180026a70));
        begin("cr_chain_score_26a70");
        int bad = g_fail, ran = 0;

        for (int t = 0; t < 40; t++) {
            int w = 52 + (int)(rnd() % 45);
            int h = 76 + (int)(rnd() % 21);
            int sw = (w + 31) / 32;
            for (int i = 0; i < h * sw; i++) bits[i] = rnd();
            for (int i = 0; i < w * h; i++)
                sv[i] = (int16_t)((int)(rnd() % 65536) - 32768);
            memset(bdv, 0, 0x20);
            *(int *)(bdv + 0x00) = sw * 32;
            *(void **)(bdv + 0x08) = bits;
            *(int *)(bdv + 0x10) = w;
            *(int *)(bdv + 0x14) = h;
            memcpy(bdc, bdv, 0x20);
            mk_img2(imv, sv, w, h);
            mk_img2(imc, sv, w, h);

            float scale;
            switch (t % 4) {
            case 0: scale = 1.0f; break;
            case 1: scale = 1.0f + (float)(rnd() % 1000u) * 0x1p-10f; break;
            case 2: scale = 0.5f; break;
            default: scale = 2.0f + (float)(rnd() % 4u); break;
            }

            int16_t rv = 0x4321, rc = 0x4321;
            int er = v(&rv, bdv, imv, scale, scale, scale, scale);
            int ec = cr_chain_score_26a70(&rc, bdc, imc, scale);
            if (er != ec) mismatch("ret", (u32)t, (u32)er, (u32)ec);
            if (rv != rc) mismatch("out", (u32)t, (u16)rv, (u16)rc);
            ran++;
        }
        printf("  [26a70] cases=%d\n", ran);
        if (g_fail == bad) end(); else printf("  FAIL cr_chain_score_26a70\n");
    }

    /* ---- 0x180043020: selector gate ----------------------------------- */
    {
        typedef int (WINAPI *v4)(int16_t *, const void *, const void *,
                                 const void *);
        v4 v = (v4)fn_at(RVA(0x180043020));
        begin("cr_chain_gate_43020");
        int bad = g_fail, ran = 0;

        for (int t = 0; t < 40; t++) {
            int w = 52 + (int)(rnd() % 45);
            int h = 76 + (int)(rnd() % 21);
            int sw = (w + 31) / 32;
            for (int i = 0; i < h * sw; i++) bits[i] = rnd();
            for (int i = 0; i < w * h; i++)
                sv[i] = (int16_t)((int)(rnd() % 65536) - 32768);
            memset(bdv, 0, 0x20);
            *(int *)(bdv + 0x00) = sw * 32;
            *(void **)(bdv + 0x08) = bits;
            *(int *)(bdv + 0x10) = w;
            *(int *)(bdv + 0x14) = h;
            memcpy(bdc, bdv, 0x20);
            mk_img2(imv, sv, w, h);
            mk_img2(imc, sv, w, h);

            memset(cfg, 0, sizeof cfg);
            cfg[0] = (u8)((t % 5 == 0) ? 3 : 4);
            *(float *)(cfg + 4) = 1.0f + (float)(rnd() % 1000u) * 0x1p-10f;

            int16_t rv = 0x7777, rc = 0x7777;
            int er = v(&rv, bdv, imv, cfg);
            int ec = cr_chain_gate_43020(&rc, bdc, imc, cfg);
            if (er != ec) mismatch("ret", (u32)t, (u32)er, (u32)ec);
            if (rv != rc) mismatch("out", (u32)t, (u16)rv, (u16)rc);
            ran++;
        }
        printf("  [43020] cases=%d\n", ran);
        if (g_fail == bad) end(); else printf("  FAIL cr_chain_gate_43020\n");
    }

    /* ---- 0x180043040: centroid + chain classify ----------------------- */
    {
        typedef int (WINAPI *v4)(void *, const void *, uint8_t, int);
        v4 v = (v4)fn_at(RVA(0x180043040));
        begin("cr_chain_stage_43040");
        int bad = g_fail, ran = 0;

        for (int t = 0; t < 40; t++) {
            int w = 8 + (int)(rnd() % 56);
            int h = 8 + (int)(rnd() % 56);
            int sw = (w + 31) / 32;
            for (int i = 0; i < h * sw; i++) bits[i] = rnd();
            for (int i = 0; i < w * h; i++)
                sv[i] = (int16_t)((int)(rnd() % 65536) - 32768);
            memset(bdv, 0, 0x20);
            *(int *)(bdv + 0x00) = sw * 32;
            *(void **)(bdv + 0x08) = bits;
            *(int *)(bdv + 0x10) = w;
            *(int *)(bdv + 0x14) = h;
            memcpy(bdc, bdv, 0x20);
            mk_img2(imv, sv, w, h);
            mk_img2(imc, sv, w, h);

            memset(ctv, 0x5a, sizeof ctv);
            memcpy(ctv + 0x50, bdv, 0x20);
            memcpy(ctc, ctv, sizeof ctv);

            static const uint8_t sels[8] = { 0, 6, 8, 10, 12, 13, 3, 14 };
            uint8_t sel = sels[t % 8];
            int margin = (int)(rnd() % 6);

            int er = v(ctv, imv, sel, margin);
            int ec = cr_chain_stage_43040(ctc, imc, sel, margin);
            if (er != ec) mismatch("ret", (u32)t, (u32)er, (u32)ec);
            cmp_buf("ctx", ctv, ctc, sizeof ctv, (u32)t);
            ran++;
        }
        printf("  [43040] cases=%d\n", ran);
        if (g_fail == bad) end(); else printf("  FAIL cr_chain_stage_43040\n");
    }
}

/* ---- main -------------------------------------------------------------- */
/* ---- batch 108: BEP frame dispatcher ---------------------------------- */
static void test_bep_dispatch_17420(void)
{
    typedef int (WINAPI *v_t)(void *, void *, void *, void *, void *, int);
    v_t v = (v_t)fn_at(RVA(0x180017420));
    begin("cr_bep_dispatch_17420");
    int bad = g_fail, ran = 0;

    enum { W = 8, H = 8, N = W * H };
    static uint8_t  pxv[N], pxc[N];
    static int16_t  gsv[N], gsc[N];
    static uint32_t bmv[4], bmc[4];
    static uint8_t  prmv[0x80], prmc[0x80];
    static uint8_t  a3v[0x100], a3c[0x100];
    static uint8_t  cfgv[0x300], cfgc[0x300];
    static uint8_t  a1v[0x10], a1c[0x10];
    static uint8_t  a4v[0x90], a4c[0x90];
    static uint8_t  ctxv[0x30], ctxc[0x30];
    static uint8_t  sdv[0x20], sdc[0x20];
    static void    *slv[16], *slc[16];

    /* NULL slot array -> 0x69 before anything is dereferenced */
    {
        int er = v(NULL, a1v, a3v, a4v, ctxv, 0);
        int ec = cr_bep_dispatch_17420(NULL, a1c, a3c, a4c, ctxc, 0);
        if (er != ec) mismatch("null", 0, (u32)er, (u32)ec);
        ran++;
    }

    for (int t = 0; t < 20; t++) {
        int sel = (t < 8) ? (t % 4) : 1;
        int a6 = t & 1;

        for (int i = 0; i < N; i++) {
            uint8_t b = (uint8_t)rnd();
            pxv[i] = b; pxc[i] = b;
            int16_t g = (int16_t)((int)(rnd() % 4096u) - 2048);
            gsv[i] = g; gsc[i] = g;
        }
        for (int i = 0; i < 4; i++) {
            uint32_t w = rnd();
            bmv[i] = w; bmc[i] = w;
        }
        memset(prmv, 0, sizeof prmv); memset(prmc, 0, sizeof prmc);
        *(int8_t *)(prmv + 8) = 1; *(int8_t *)(prmc + 8) = 1;
        *(int32_t *)(prmv + 0x50) = W; *(int32_t *)(prmv + 0x54) = H;
        *(int32_t *)(prmc + 0x50) = W; *(int32_t *)(prmc + 0x54) = H;
        *(void **)(prmv + 0x58) = gsv; *(void **)(prmc + 0x58) = gsc;
        *(int32_t *)(prmv + 0x60) = W; *(int32_t *)(prmv + 0x64) = H;
        *(int32_t *)(prmc + 0x60) = W; *(int32_t *)(prmc + 0x64) = H;

        memset(a3v, 0, sizeof a3v); memset(a3c, 0, sizeof a3c);
        memset(sdv, 0, 0x20); memset(sdc, 0, 0x20);
        *(int16_t *)(sdv + 0) = W; *(int16_t *)(sdv + 2) = H;
        *(void **)(sdv + 0x10) = pxv;
        memcpy(sdc, sdv, 0x20);
        *(void **)(sdc + 0x10) = pxc;
        for (int i = 0; i < 16; i++) { slv[i] = NULL; slc[i] = NULL; }
        slv[0] = sdv; slc[0] = sdc;

        memset(a1v, 0, sizeof a1v); memset(a1c, 0, sizeof a1c);
        *(void **)(a1v + 0) = prmv; *(void **)(a1c + 0) = prmc;

        memset(a4v, 0, sizeof a4v); memset(a4c, 0, sizeof a4c);
        mk_img2(a4v + 0x10, (int16_t *)pxv, W, H);
        mk_img2(a4c + 0x10, (int16_t *)pxc, W, H);
        mk_bmp_desc(a4v + 0x50, W, H, bmv);
        mk_bmp_desc(a4c + 0x50, W, H, bmc);
        *(int32_t *)(a4v + 0x60) = W; *(int32_t *)(a4v + 0x64) = H;
        *(int32_t *)(a4c + 0x60) = W; *(int32_t *)(a4c + 0x64) = H;

        memset(cfgv, 0, sizeof cfgv); memset(cfgc, 0, sizeof cfgc);
        cfgv[2] = 2; cfgc[2] = 2;
        cfgv[4] = (uint8_t)sel; cfgc[4] = (uint8_t)sel;
        cfgv[0x79] = 3; cfgc[0x79] = 3;
        cfgv[0x250] = 4; cfgc[0x250] = 4;
        *(float *)(cfgv + 0x254) = 1.25f; *(float *)(cfgc + 0x254) = 1.25f;
        *(float *)(cfgv + 0xb0) = 0.02f; *(float *)(cfgc + 0xb0) = 0.02f;
        *(float *)(cfgv + 0xb4) = 0.98f; *(float *)(cfgc + 0xb4) = 0.98f;

        memset(ctxv, 0, sizeof ctxv); memset(ctxc, 0, sizeof ctxc);
        *(void **)(ctxv + 0x28) = cfgv; *(void **)(ctxc + 0x28) = cfgc;

        int rv = v(slv, a1v, a3v, a4v, ctxv, a6);
        int rc = cr_bep_dispatch_17420(slc, a1c, a3c, a4c, ctxc, a6);
        if (rv != rc) mismatch("ret", (u32)t, (u32)rv, (u32)rc);
        {
            u8 tv[0x90], tc[0x90];
            memcpy(tv, a4v, 0x90); memcpy(tc, a4c, 0x90);
            memset(tv + 0x18, 0, 8); memset(tc + 0x18, 0, 8);
            memset(tv + 0x58, 0, 8); memset(tc + 0x58, 0, 8);
            cmp_buf("a4", tv, tc, 0x90, (u32)t);
        }
        cmp_buf("px", pxv, pxc, N, (u32)t);
        cmp_buf("bm", (const u8 *)bmv, (const u8 *)bmc, sizeof bmv, (u32)t);
        cmp_buf("st", a3v, a3c, 0x100, (u32)t);
        ran++;
    }

    printf("  [17420] cases=%d\n", ran);
    if (g_fail == bad) end(); else printf("  FAIL cr_bep_dispatch_17420\n");
}

int main(int argc, char **argv)
{    const char *dll = (argc > 1) ? argv[1] : "../FingerPrint_Carewe_20.26.23.27_W11x64/"
        "12b431fd-7d7e-4dd7-b87c-9ab3f9a3d01b/x64/fpc_enclave.dll";

    setup_teb();
    g_base = (u8 *)pe_load(dll, shim_lookup);
    if (!g_base) { fprintf(stderr, "failed to load %s\n", dll); return 2; }
    g_cr_image_base = (uintptr_t)g_base;
    win32_shims_set_image_base(g_base);
    printf("[+] loaded %s at %p\n\n", dll, g_base);

    /* DllMainCRTStartup(base, DLL_PROCESS_ATTACH, NULL) — initialise CRT globals */
    pe_dos_header *dos = (pe_dos_header *)g_base;
    u8 *nt = g_base + dos->e_lfanew;
    pe_file_header *fh = (pe_file_header *)(nt + 4);
    pe_optional_header64 *opt = (pe_optional_header64 *)(fh + 1);
    int (WINAPI *dmain)(void *, u32, void *) = (void *)(g_base + opt->AddressOfEntryPoint);
    int ok = dmain(g_base, 1, NULL);
    printf("[+] DllMain -> %d\n\n", ok);

    if (argc > 2 && strcmp(argv[2], "probe7") == 0) {
        /* Empirically recover the vendor's tap -> input index map for
         * 0x180033b40: with coef[k]=32767 and in[i]=i, out[j] == index. */
        typedef void (WINAPI *v_v_pppii)(int16_t *, const int16_t *,
                                         const int16_t *, int, int);
        v_v_pppii v = (v_v_pppii)fn_at(RVA(0x180033b40));
        int16_t in[512], out[512], coef[7];
        for (int i = 0; i < 512; i++) in[i] = (int16_t)i;
        for (int W = 1; W <= 10; W++) {
            printf("W=%d:", W);
            for (int k = 0; k < 7; k++) {
                for (int i = 0; i < 7; i++) coef[i] = 0;
                coef[k] = 32767;
                for (int i = 0; i < W; i++) out[i] = -12345;
                v(out, in, coef, W, 1);
                printf(" k%d[", k);
                for (int j = 0; j < W; j++) printf("%s%d", j ? "," : "", out[j]);
                printf("]");
            }
            printf("\n");
        }
        return 0;
    }

    if (argc > 2 && strcmp(argv[2], "probe_box") == 0) {
        /* Impulse response of 0x18002c600 (in-place separable box mean).
         * Struct: { int a,b; float *data@8; int w@0x10; int h@0x14; } */
        struct { int a, b; float *data; int w, h; } img;
        typedef int (WINAPI *v_i_pppi)(void *, void *, int);
        v_i_pppi v = (v_i_pppi)fn_at(RVA(0x18002c600));
        enum { WW = 8, HH = 8 };
        static float buf[WW * HH];
        static const int pts[][2] = {{0,0},{0,1},{1,0},{1,1},{2,2},{3,3},{5,5},{6,6},{7,7}};
        for (int mode = 3; mode <= 5; mode += 2) {
            for (int p = 0; p < (int)(sizeof pts / sizeof pts[0]); p++) {
                int oy = pts[p][0], ox = pts[p][1];
                {
                    for (int i = 0; i < WW * HH; i++) buf[i] = 0.0f;
                    buf[oy * WW + ox] = 1.0f;
                    img.a = 0; img.b = 0; img.data = buf; img.w = WW; img.h = HH;
                    int r = v(&img, &img, mode);
                    printf("mode=%d delta(%d,%d) ret=%d:\n", mode, oy, ox, r);
                    for (int y = 0; y < HH; y++) {
                        printf("   ");
                        for (int x = 0; x < WW; x++)
                            printf(" %8.5f", buf[y * WW + x]);
                        printf("\n");
                    }
                }
            }
        }
        return 0;
    }

    if (argc > 2 && strcmp(argv[2], "probe_lf") == 0) {
        /* Empirical tap geometry of 0x1800433b0 (7-tap vertical FIR).
         * in[r*n+c] = r+1, cfg[tap] = 32767  =>  out[orow*n+c] = input_row+1
         * (or 0 when the tap contributes nothing).  Printed as input_row
         * (i.e. value-1) per tap per output row, first column only. */
        int n = (argc > 3) ? atoi(argv[3]) : 8;
        int sel = (argc > 4) ? atoi(argv[4]) : 10;
        typedef void (WINAPI *v_v_pppii)(int16_t *, const int16_t *,
                                         const int16_t *, int, unsigned);
        v_v_pppii v = (v_v_pppii)fn_at(RVA(0x1800433b0));
        enum { ROWS = 64, COLS = 64 };
        static int16_t in[ROWS * COLS], out[ROWS * COLS];
        int16_t cfg[7];
        printf("probe_lf n=%d sel=%d\n", n, sel);
        for (int tap = 0; tap < 7; tap++) {
            for (int i = 0; i < ROWS * COLS; i++) in[i] = -12345;
            for (int r = 0; r < ROWS; r++)
                for (int c = 0; c < n; c++) in[r * n + c] = (int16_t)(r + 1);
            for (int i = 0; i < 7; i++) cfg[i] = 0;
            cfg[tap] = 32767;
            for (int i = 0; i < ROWS * COLS; i++) out[i] = -12345;
            v(out, in, cfg, n, (unsigned)sel);
            printf(" tap%d:", tap);
            for (int r = 0; r < sel + 3; r++)
                printf(" %d", (int)out[r * n] - 1);
            printf("\n");
        }
        return 0;
    }

    printf("== math kernel ==\n");
    test_float_fn("cr_sqrtf",         RVA(0x180003080), (void *)cr_sqrtf,          0);
    test_float_fn("cr_expf",          RVA(0x180002dd0), (void *)cr_expf,           0);
    test_float_fn("cr_roundf_to_int", RVA(0x180003020), (void *)cr_roundf_to_int,  1);
    test_float_fn("cr_floorf_to_int", RVA(0x180002f70), (void *)cr_floorf_to_int,  1);
    test_float_fn("cr_lroundf",       RVA(0x180002d60), (void *)cr_lroundf,        1);
    test_ldexpf();

    test_correlate_34930();   /* runs early: verified in isolation; survives the
                                 pre-existing heap crash that aborts at calib_blob */

    printf("\n== buffer predicates ==\n");
    test_type_predicates();

    printf("\n== metadata store ==\n");
    test_metadata();
    test_image_fill_desc();
    test_grad_score_from_desc();
    test_masked_sharpness();
    test_masked_sharpness_f32();
    test_mask_boxmax_fir_clear();
    test_bitmap_build_masked();
    test_bitmap_unpack_boxmax_fir();
    test_bitmap_fill_extents();

    printf("\n== image slots ==\n");
    test_image_slots();

    printf("\n== util kernel ==\n");
    test_status_helpers();
    test_fill_copy();
    test_modff();
    test_bitmap_bitmask();
    test_s16_clamp();
    test_prng_range();
    test_clz();
    test_sincos();
    test_dot_f32();

    printf("\n== image leaves ==\n");
    test_image_leaves();

    printf("\n== rect fills / bitmap ops ==\n");
    test_rect_fills();
    test_bitmap_ops();
    test_classify_mark();
    test_copy_or_relu();
    test_array_rotate();
    test_type_desc();

    printf("\n== image copies / stats / affine ==\n");
    test_image_copies();
    test_masked_variance();
    test_read_quad();
    test_buffer_pixels_setup();
    test_affine_transform();

    printf("\n== 256-byte leaves ==\n");
    test_atan2_deg();
    test_vfir4_u8();
    test_masked_minmax();
    test_orient_pick();

    printf("\n== 272-byte leaves ==\n");
    test_matmul_nt();
    test_mean_stddev();
    test_masked_minmax_s16();

    printf("\n== 288-byte leaves ==\n");
    test_masked_minmax_f32();
    test_i16_to_f32_scaled();

    printf("\n== 304-byte leaves ==\n");
    test_bilinear_sample_u8();
    test_box_blur_h_f32();
    test_masked_box_sum();

    printf("\n== 320-byte leaves ==\n");
    test_f32_to_i16_scaled();
    test_block_extreme_bitmap();
    test_bitmap_popcount();

    printf("\n== 336-byte leaf ==\n");
    test_downsample_mean();
    printf("\n== 384-byte leaf (sincos) ==\n");
    test_sincos_f32();
    printf("\n== 384-byte leaf (border fill) ==\n");
    test_image_border_fill();
    printf("\n== 400-byte leaf (border extend) + 96-byte leaf (saturation) ==\n");
    test_image_border_extend();
    test_image_border_extend_s16();
    test_saturation_score();
    printf("\n== allocator wrappers ==\n");
    test_alloc_wrappers();
    printf("\n== bitmap morphology ==\n");
    test_bitmap_morph();
    printf("\n== affine resample + 4-phase FIR ==\n");
    test_affine_sample_u8();
    test_affine_sample_u8_clamped();
    test_warp_rotate_u8();
    test_polyphase_fir4();
    printf("\n== bilinear splat ==\n");
    test_splat_bilinear();
    printf("\n== bitmap border set ==\n");
    test_bitmap_border_set();
    printf("\n== 3x3 Laplacian ==\n");
    test_laplacian_3x3();
    printf("\n== 7-tap clamped FIR ==\n");
    test_fir7_s16();
    printf("\n== in-place row permutation ==\n");
    test_permute_rows();
    printf("\n== bit-shifted bitmap blit ==\n");
    test_bitmap_copy_shift();
    printf("\n== right-shifted bitmap extract ==\n");
    test_bitmap_extract_shift();
    printf("\n== column-wise 7-tap clamped FIR ==\n");
    test_fir7_s16_col();
    printf("\n== masked per-column mean correction ==\n");
    test_bitmap_mean_correct();
    printf("\n== bit-packed sign signature ==\n");
    test_signpack_dot();
    printf("\n== u8->i16 shift widen ==\n");
    test_u8_to_u16_shifted();
    printf("\n== symmetric int16 border extend ==\n");
    test_mirror_extend_s16();
    printf("\n== box sum excluding an index list ==\n");
    test_box_sum_excl();
    printf("\n== separable 15x15 box filter (int16) ==\n");
    test_boxsum15_s16();
    printf("\n== separable 15x15 box filter (u8) ==\n");
    test_boxsum15_u8();
    printf("\n== u8 row widen + m-tap symmetric FIR ==\n");
    test_u8_expand_convolve();
    printf("\n== spatial top-K accumulator ==\n");
    test_grid_insert();
    printf("\n== bitmap set-bit centroid ==\n");
    test_bitmap_centroid();
    test_bitmap_extend_border();
    printf("\n== descriptor / table-pointer getters ==\n");
    test_desc_getters();
    printf("\n== 9-tap triangular filter (n x 9) ==\n");
    test_tri9_filter();
    printf("\n== reflect-101-padded column FIR ==\n");
    test_fir_reflect();
    printf("\n== reflect-101-padded row FIR ==\n");
    test_fir_reflect_rows();
    printf("\n== fixed 7-tap reflect-101 row FIR ==\n");
    test_fir7_reflect();
    printf("\n== in-place separable box mean (3x3 / 5x5) ==\n");
    test_box_mean();
    printf("\n== stack-based Hoare quicksort (8-byte records) ==\n");
    test_sort_records();
    printf("\n== short-line orientation fit (9 hypotheses) ==\n");
    test_line_orient_fit();
    printf("\n== fixed 7-tap reflect-101 column FIR ==\n");
    test_vfir7_cols();
    printf("\n== separable 11x11 int16 FIR (one row) ==\n");
    test_sep11_row();
    printf("\n== per-pixel kernel-bank 2D correlation ==\n");
    test_corr_kbank();
    printf("\n== object-tree lifecycle helpers + image-data accessors ==\n");
    test_tree_helpers();
    printf("\n== object constructors / flag-driven destructors ==\n");
    test_tree_ctors();
    printf("\n== higher-level destructors / accessors ==\n");
    test_tree_higher();
    printf("\n== nested destructor chain ==\n");
    test_tree_nested();
    printf("\n== small ready wrappers ==\n");
    test_tree_wrappers();
    printf("\n== batch 52: ready wrappers / allocators ==\n");
    test_tree_batch52();
    printf("\n== batch 53: ready wrappers (size 160-500) ==\n");
    test_tree_batch53();
    printf("\n== batch 54: ready wrappers (size 192-512) ==\n");
    test_tree_batch54();
    printf("\n== batch 55: pool users + ready wrappers ==\n");
    test_tree_batch55();
    printf("\n== batch 56: streaming FIR + correlation / splat ==\n");
    test_tree_batch56();
    printf("\n== batch 57: destructor / constructor wrappers + misc ==\n");
    test_tree_batch57();

    printf("\n== batch 58: window generators + masked median + angle sampler ==\n");
    test_tree_batch58();

    printf("\n== batch 59: gaussian-blur wrapper + blit-to-subview wrappers ==\n");
    test_tree_batch59();

    printf("\n== batch 60: Gaussian-derivative blur pair + box-median filter ==\n");
    test_tree_batch60();

    printf("\n== vendor FFT (fwd/inv) ==\n");
    test_fft();

    printf("\n== calibration/data blob accessor ==\n");
    test_calib_blob();

    printf("\n== batch 63: Gaussian-windowed FIR orchestration ==\n");
    test_gauss_fir();
    test_gauss_fir7();

    printf("\n== batch 64: image-data dump + pixel-buffer setup ==\n");
    test_image_data_dump();
    test_pixel_buf_setup();

    printf("\n== batch 65: object constructor (0x180020aa0) ==\n");
    test_obj_ctor_20aa0();
    test_gaussian_fir_2pass();
    test_feature_qualify();
    test_obj_init_17ca0();
    test_gauss_deriv_3img();
    test_warp_bilinear_q15();
    test_cordic_atan_q15();
    test_gauss_deriv_triple();
    test_gauss_deriv_triple_guarded();
    test_gauss_deriv_triple_coef();
    test_struct_tensor_aniso();
    test_struct_tensor_dispatch();
    test_hist_percentiles_f32();
    test_stretch_f32();
    test_harris_response();
    test_harris_local_max_grid();
    test_bio_init();
    test_bio_get_ctx();
    test_ctx_find_node();
    test_fir_ctx_init();
    test_fir7_image_u8();
    test_box_sum_u8();
    test_fir_ctx_init_i8();
    test_fft_real_n();
    test_fft_real_fwd();
    test_fft_real_inv();
    test_fft_real_bwd();
    test_filter_bank_max5x5();
    test_filter_bank_max3x3_f32();
    test_filter_bank_max5x5_f32();
    test_filter_chain_run();
    test_filter_bank_max3x3_i16();
    test_filter_chain_run_i16();
    test_fft2d_real_bwd();
    test_bitmap_margin_extract();
    test_keypoint_grid_sample();
    test_fir_norm_s16();
    test_fir_norm_rows_s16();
    test_sep_gauss_blur_s16();
    test_linear_softmax2();
    test_chain_classify_i16();
    test_structure_tensor_score();
    test_block_conv_231a0();
    test_structure_tensor_score_img();
    test_template_ncc_35150();
    test_template_ncc_283d0();
    test_fft2d_prep_1e920();
    test_ncc_apply_f8b0();
    test_ncc_apply_34390();
    test_obj_init_12fe0();
    test_resize_pair_18000();
    test_hist_percentiles();
    test_hist_percentiles_u8();
    test_stretch_u8_mode();
    test_grad_mag_score();
    test_stretch_14bit();
    test_bandpass_diff_i8();
    test_bandpass_dispatch();
    test_haar16_orient();
    test_orient_map_haar();
    test_thresh_open_mark();
    test_angle_field_downsample();
    test_angle_field_ds_run();

    /* NOTE: added last on purpose.  The suite shares one deterministic RNG
     * stream across tests, and some existing tests (e.g. cr_template_ncc_283d0)
     * are sensitive to it; inserting a test earlier shifts the stream and can
     * expose latent divide-by-zero paths.  Keep new tests at the tail. */
    test_bitmap_filter_fir();
    test_bitmap_filter_apply_s16();
    test_fft_weighted_apply_32af0();
    test_obj_init_13340();
    test_harris_local_minmax_grid();
    test_blur_dispatch_1c6a0();
    test_sep_gauss_blur_reflect();
    test_blur_diff_norm();
    test_blur_diff_norm_u8();
    test_blur_divnorm_stretch();
    test_matched_filter_45eb0();
    test_quality_gate_35cf0();
    test_blob_detect_1bbf0();
    test_structure_orient_d3b0();
    test_structure_orient_3b960();
    test_bin_select_14320();
    test_structure_orient_dispatch_2cfd0();
    test_grid_populate_dispatch_38020();
    test_feature_extract_step_26dc0();
    test_feature_extract_step_2db20();
    test_dirbank_3de60();
    test_pyramid_364c0();
    test_template_remove_25960();
    test_grid_pick_37460();
    test_mask_pipeline_25050();
    test_norm_2bd60();
    test_pick_dispatch_16b90();
    test_mask_inpaint_317a0();
    test_pick_points_2f2e0();
    test_feat_pack_0e850();
    test_maxpool_stream_21000();
    test_pick_points_dispatch_2b680();
    test_stage_run_273a0();
    test_mscale_score_2e060();
    test_mscale_run_16d00();
    test_masked_contrast_norm_2a620();
    test_mask_norm_32580();
    test_masked_contrast_norm_26410();
    test_block_variance_run_42150();
    test_mask_stage_208a0();
    test_feature_pipeline_34ed0();
    test_sharp_gate_48310();
    test_mask_refine_344e0();
    test_feature_run_28bc0();
    test_mask_dispatch_39820();
    test_slot_select_11170();
    test_slot_rank_u8_22b70();
    test_block_filter_222b0();
    test_gauss_edge_pad_15540();
    test_pad_filter_12aa0();
    test_orient_encode_1ba60();
    test_orient_pipeline_18c60();
    test_block_orient_195d0();
    test_block_orient_48010();
    test_orient_score_dispatch_1c220();
    test_feature_pipeline_1ad30();
    test_chain_stages();
    test_bep_process_1c810();
    test_bep_process_368d0();
    test_bep_dispatch_17420();



    printf("\n=============================\n");
    printf("functions ok : %d\n", g_pass);
    printf("mismatches   : %d\n", g_fail);
    printf("%s\n", g_fail ? "RESULT: FAIL" : "RESULT: PASS");
    return g_fail ? 1 : 0;
}
