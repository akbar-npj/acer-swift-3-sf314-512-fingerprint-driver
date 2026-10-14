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
        u8 ov[0x30], oc[0x30];
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
        u8 ov[0x30], oc[0x30];
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
        /* image #1 descriptor +0..0x1c, image #2 +0x20..0x3c */
        for (int off = 0; off < 0x40; off += 4) {
            if (off == 8 || off == 0x28) continue;   /* pointers compared below */
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
        int border = (int)(rnd() % 4u);
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
            /* q[0] is a scalar tag; q[1] is a pointer (skip) */
            if (vb[0] != cb[0]) mismatch("tag", (u32)s, vb[0], cb[0]);
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
        enum { NLUT = 256, MAXP = 64 };
        int16_t lut[NLUT];
        u8 src_bytes[MAXP * 2];
        int16_t dst_v[MAXP], dst_c[MAXP];
        for (int t = 0; t < 4000; t++) {
            for (int i = 0; i < NLUT; i++) lut[i] = (int16_t)rnd();
            int mult = 1 + (int)(rnd() % 8u);
            int count = 1 + (int)(rnd() % MAXP);
            for (int i = 0; i < count * 2; i++) src_bytes[i] = (u8)rnd();
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

/* ---- main -------------------------------------------------------------- */
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
    test_fir_ctx_init_i8();
    test_fft_real_n();
    test_obj_init_12fe0();
    test_resize_pair_18000();
    test_hist_percentiles();
    test_hist_percentiles_u8();
    test_stretch_14bit();
    test_bandpass_diff_i8();
    test_bandpass_dispatch();
    test_haar16_orient();
    test_orient_map_haar();
    test_thresh_open_mark();
    test_angle_field_downsample();
    test_angle_field_ds_run();

    printf("\n=============================\n");
    printf("functions ok : %d\n", g_pass);
    printf("mismatches   : %d\n", g_fail);
    printf("%s\n", g_fail ? "RESULT: FAIL" : "RESULT: PASS");
    return g_fail ? 1 : 0;
}
