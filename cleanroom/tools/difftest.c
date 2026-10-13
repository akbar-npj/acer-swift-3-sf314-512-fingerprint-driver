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

/* ---- batch 4: rect fills, bitmap ops, misc leaves ---------------------- */

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

    printf("\n=============================\n");
    printf("functions ok : %d\n", g_pass);
    printf("mismatches   : %d\n", g_fail);
    printf("%s\n", g_fail ? "RESULT: FAIL" : "RESULT: PASS");
    return g_fail ? 1 : 0;
}
