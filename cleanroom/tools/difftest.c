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

/* ---- main -------------------------------------------------------------- */
int main(int argc, char **argv)
{
    const char *dll = (argc > 1) ? argv[1] : "../FingerPrint_Carewe_20.26.23.27_W11x64/"
        "12b431fd-7d7e-4dd7-b87c-9ab3f9a3d01b/x64/fpc_enclave.dll";

    setup_teb();
    g_base = (u8 *)pe_load(dll, shim_lookup);
    if (!g_base) { fprintf(stderr, "failed to load %s\n", dll); return 2; }
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

    printf("== math kernel ==\n");
    test_float_fn("cr_sqrtf",         RVA(0x180003080), (void *)cr_sqrtf,          0);
    test_float_fn("cr_expf",          RVA(0x180002dd0), (void *)cr_expf,           0);
    test_float_fn("cr_roundf_to_int", RVA(0x180003020), (void *)cr_roundf_to_int,  1);
    test_float_fn("cr_floorf_to_int", RVA(0x180002f70), (void *)cr_floorf_to_int,  1);
    test_float_fn("cr_lroundf",       RVA(0x180002d60), (void *)cr_lroundf,        1);
    test_ldexpf();

    printf("\n== buffer predicates ==\n");
    test_type_predicates();

    printf("\n== metadata store ==\n");
    test_metadata();

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

    printf("\n=============================\n");
    printf("functions ok : %d\n", g_pass);
    printf("mismatches   : %d\n", g_fail);
    printf("%s\n", g_fail ? "RESULT: FAIL" : "RESULT: PASS");
    return g_fail ? 1 : 0;
}
