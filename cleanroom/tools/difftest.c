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

    printf("\n== buffer predicates ==\n");
    test_type_predicates();

    printf("\n== metadata store ==\n");
    test_metadata();

    printf("\n== image slots ==\n");
    test_image_slots();

    printf("\n=============================\n");
    printf("functions ok : %d\n", g_pass);
    printf("mismatches   : %d\n", g_fail);
    printf("%s\n", g_fail ? "RESULT: FAIL" : "RESULT: PASS");
    return g_fail ? 1 : 0;
}
