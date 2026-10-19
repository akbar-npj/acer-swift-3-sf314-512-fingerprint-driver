#define _GNU_SOURCE
/*
 * fpc_recon_native — run the FPC 10a5:e340 BEP reconstruction natively on Linux,
 * with no Wine.
 *
 * It maps the vendor's fpc_enclave.dll (plain no_sgx x86-64) with a small PE
 * loader, supplies native shims for the Win32 imports, then drives the same
 * path the Wine harness uses:
 *
 *   fpc_setup_enclave(ocall) ; FpcTaInitialize_ecall(0x0300)
 *   FpcTaOp_ecall(11,0)                      begin_enrol
 *   memcpy(raw, cap+0x0c) ; fpc_copy_buffer_into_fmi(8,&out,11264)   inject
 *   FpcTaOp_ecall(11,1)                      enrol -> FUN_18001c810
 *
 * FUN_18001c810 is hooked (entry trampoline) to dump the reconstructed 8-bit
 * image it writes to param_1[3] (width/height at param_1+0x20/+0x24, 64x176).
 *
 * The DLL is Microsoft-ABI code, so every call across the boundary is ms_abi.
 */
#include "pe_loader.h"
#include "win32_shims.h"
#include "bep_snap.h"
#include "fpc_bep.h"   /* clean-room BEP (optional --cleanroom backend) */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <asm/prctl.h>

#define WINAPI __attribute__((ms_abi))

/* Windows x64 code reads the TEB through %gs (e.g. __chkstk loads the stack
 * limit from gs:0x10). On Linux %gs is free (glibc uses %fs), so we point it at
 * a fake TEB with a valid NT_TIB header. Without this, any function that
 * allocates >4 KiB of stack faults. */
struct fake_teb {
    u64 exception_list;      /* 0x00 */
    u64 stack_base;          /* 0x08 */
    u64 stack_limit;         /* 0x10 */
    u64 subsystem_tib;       /* 0x18 */
    u64 fiber_data;          /* 0x20 */
    u64 arbitrary_user;      /* 0x28 */
    u64 self;                /* 0x30 */
    u64 environment_pointer; /* 0x38 */
    u32 client_pid;          /* 0x40 */
    u32 client_tid;          /* 0x44 */
    u64 tls_pointer;         /* 0x50 */
    u64 peb;                 /* 0x58 */
    u64 pad[64];
};
static struct fake_teb g_teb;

static void setup_teb(void) {
    pthread_attr_t attr;
    void *addr = NULL;
    size_t size = 0;
    if (pthread_getattr_np(pthread_self(), &attr) == 0 &&
        pthread_attr_getstack(&attr, &addr, &size) == 0) {
        g_teb.stack_limit = (u64)addr;
        g_teb.stack_base = (u64)addr + size;
        pthread_attr_destroy(&attr);
    } else {
        g_teb.stack_base = (u64)&attr;
        g_teb.stack_limit = g_teb.stack_base - (8u << 20);
    }
    g_teb.exception_list = ~0ULL;
    g_teb.self = (u64)&g_teb;
    g_teb.client_pid = (u32)getpid();
    g_teb.client_tid = (u32)syscall(SYS_gettid);
    if (syscall(SYS_arch_prctl, ARCH_SET_GS, (unsigned long)&g_teb) != 0)
        perror("[!] arch_prctl(ARCH_SET_GS)");
    else
        printf("[+] fake TEB installed at %p (stack %#llx..%#llx)\n",
               (void *)&g_teb, (unsigned long long)g_teb.stack_limit,
               (unsigned long long)g_teb.stack_base);
}

/* ---- enclave exports (Microsoft ABI) ---- */
typedef int (WINAPI *fn_setup)(void *ocall_table);
typedef int (WINAPI *fn_init)(unsigned short hwid);
typedef int (WINAPI *fn_op)(void *in, unsigned inlen, void *out, unsigned outlen);
typedef int (WINAPI *fn_fmi)(int type, void *out, int len);
typedef int (WINAPI *fn_dllmain)(void *inst, unsigned reason, void *reserved);
typedef long long (WINAPI *fn_metaget)(void *blob, long long key, void *out);

/* ---- fixed internal RVAs (from RE) ---- */
#define RVA_CAPTURE_STRUCT 0x1728e0u   /* +0x0c payload, +0x22 pixels */
#define RVA_FMI            0x68470u    /* fpc_copy_buffer_into_fmi */
#define RVA_OUT_IMAGE      0x1c810u    /* FUN_18001c810 */

#define IMG_PAYLOAD_MAX 131072
#define IMG_PIXELS      11264

static void *g_base;
static const char *g_out_path;
static int g_dumped;
static int g_cleanroom;

/* ---- entry trampoline ---- */
static void patch(void *addr, void *fn) {
    long pg = (long)addr & ~0xfffL;
    mprotect((void *)pg, 0x2000, PROT_READ | PROT_WRITE | PROT_EXEC);
    unsigned char c[12] = {0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xE0};
    *(void **)(c + 2) = fn;
    memcpy(addr, c, sizeof c);
    __builtin___clear_cache((char *)addr, (char *)addr + sizeof c);
}
static void unpatch(void *addr, unsigned char *orig) {
    long pg = (long)addr & ~0xfffL;
    mprotect((void *)pg, 0x2000, PROT_READ | PROT_WRITE | PROT_EXEC);
    memcpy(addr, orig, 12);
    __builtin___clear_cache((char *)addr, (char *)addr + 12);
}

static void *g_orig_1c810;
static unsigned char g_orig_bytes[16];

/* FUN_18001c810(param_1..param_6): param_1[3]=out px, +0x20 w, +0x24 h */
static long long WINAPI hk_1c810(void *a, void *b, void *c, void *d, void *e, long long f) {
    long long r;

    /* FPC_BEP_SNAP=<file>: one-shot snapshot of the whole input graph, used
     * by the standalone (DLL-free) BEP runner.  Must run at entry, before
     * the BEP mutates a1/a3. */
    {
        const char *snap = getenv("FPC_BEP_SNAP");
        static int snapped;
        if (snap && !snapped) {
            snapped = 1;
            bep_snap_dump(snap, a, b, c, (void **)d, e, (int)f,
                          (uintptr_t)g_base);
        }
    }
    /* optional threshold override for probing the internal mx value.
     * 1c810 passes cfg+0x78 to the feature pipeline, whose cfg+4 is the
     * branch threshold, so the override goes to outer cfg+0x7c. */
    const char *thr = getenv("FPC_THR");
    if (thr && e) {
        unsigned char *cfg = *(unsigned char **)((unsigned char *)e + 0x28);
        if (cfg) *(float *)(cfg + 0x7c) = strtof(thr, NULL);
    }
    if (g_cleanroom) {
        /* Run the clean-room implementation instead of the vendor body.  The
         * clean-room reads the static chain tables through g_cr_image_base,
         * which must point at the mapped vendor image. */
        g_cr_image_base = (uintptr_t)g_base;
        r = (long long)cr_bep_process_1c810(a, b, c, (void **)d, e, (int)f);
    } else {
        unpatch(g_orig_1c810, g_orig_bytes);
        r = ((long long(WINAPI *)(void *, void *, void *, void *, void *, long long))
                 g_orig_1c810)(a, b, c, d, e, f);
    }
    unsigned char *p = (unsigned char *)a;
    u64 pix = *(u64 *)(p + 0x18);
    int w = *(int *)(p + 0x20), h = *(int *)(p + 0x24);
    {
        unsigned char *e5 = (unsigned char *)e;
        unsigned char *cfg = e5 ? *(unsigned char **)(e5 + 0x28) : NULL;
        printf("    > FUN_18001c810 -> %lld  out_img=%p %dx%d hdr=%x%s\n",
               r, (void *)pix, w, h, *(unsigned int *)p,
               g_cleanroom ? " [clean]" : " [vendor]");
        if (cfg)
            printf("      cfg: s2=%u s28=%u s44=%u s78=%u s79=%u d0=%u s250=%u "
                   "f24=%.3f f254=%.3f | out: 04=%d 08=%d 70=%d 74=%x 78=%d "
                   "7c=%u 7e=%u\n",
                   cfg[2], cfg[0x28], cfg[0x44], cfg[0x78], cfg[0x79],
                   cfg[0xd0], cfg[0x250], *(float *)(cfg + 0x24),
                   *(float *)(cfg + 0x254),
                   *(int *)(p + 0x04), *(int *)(p + 0x08), *(int *)(p + 0x70),
                   *(unsigned *)(p + 0x74), *(int *)(p + 0x78),
                   *(unsigned char *)(p + 0x7c), *(unsigned short *)(p + 0x7e));
    }
    /* FPC_BEP_DUMP=<prefix>: one-shot dump of the exact input buffers the
     * enclave hands to the BEP.  Used to build a standalone (DLL-free) BEP
     * runner: the control buffers are constant per sensor, only the pixels
     * change, so we capture them once and replay them against libfpcbep. */
    {
        const char *dump = getenv("FPC_BEP_DUMP");
        static int dumped;
        if (dump && !dumped) {
            char path[512];
            FILE *fp;
            unsigned char *e5 = (unsigned char *)e;
            unsigned char *cfg2 = e5 ? *(unsigned char **)(e5 + 0x28) : NULL;
            unsigned char *flg2 = e5 ? *(unsigned char **)(e5 + 0x10) : NULL;
            unsigned char *a2p0 = b ? *(unsigned char **)b : NULL;
            unsigned char *a2p8 = b ? *(unsigned char **)((unsigned char *)b + 8) : NULL;
            unsigned char *a4p0 = d ? *(unsigned char **)d : NULL;
            int i;
            dumped = 1;
#define DUMPBUF(tag, ptr, n) do {                                    \
                snprintf(path, sizeof path, "%s.%s", dump, tag);     \
                fp = (ptr) ? fopen(path, "wb") : NULL;               \
                if (fp) { fwrite((ptr), 1, (n), fp); fclose(fp); }   \
            } while (0)
            DUMPBUF("a2", b, 0x20);
            DUMPBUF("a3", c, 0x100);
            DUMPBUF("a4", d, 0x80);
            DUMPBUF("a5", e, 0x40);
            DUMPBUF("cfg", cfg2, 0x300);
            DUMPBUF("flg", flg2, 0x40);
            DUMPBUF("a2p0", a2p0, 0x80);
            DUMPBUF("a2p8", a2p8, 0x80);
            DUMPBUF("a4p0", a4p0, 0x40);
#undef DUMPBUF
            printf("      [dump] a2=%p a2p0=%p a2p8=%p a4=%p a4p0=%p cfg=%p flg=%p a6=%lld\n",
                   b, a2p0, a2p8, d, a4p0, cfg2, flg2, f);
            if (a2p0) {
                printf("      [dump] a2p0[0..15]=");
                for (i = 0; i < 16; i++) printf("%02x", a2p0[i]);
                printf("\n");
            }
            if (a4p0) {
                printf("      [dump] a4p0 i16[0..3]=%d %d %d %d\n",
                       *(int16_t *)(a4p0 + 0), *(int16_t *)(a4p0 + 2),
                       *(int16_t *)(a4p0 + 4), *(int16_t *)(a4p0 + 6));
            }
            for (i = 0; i < 8; i++) {
                unsigned char *p = d ? *(unsigned char **)((unsigned char *)d + i * 8) : NULL;
                if (p) printf("      [dump] a4[%d]=%p\n", i, p);
            }
        }
    }
    if (pix && w > 0 && h > 0 && (long long)w * h <= 262144 && g_out_path) {
        FILE *fp = fopen(g_out_path, "wb");
        if (fp) {
            fwrite((void *)pix, 1, (size_t)w * h, fp);
            fclose(fp);
            printf("      wrote %s (%d bytes)\n", g_out_path, w * h);
            g_dumped = 1;
        } else {
            perror(g_out_path);
        }
    }
    if (!g_cleanroom)
        patch(g_orig_1c810, hk_1c810);
    return r;
}

static long long WINAPI ocall0(void) { return 0; }

/* optional metadata tracing (FPC_TRACE=1), mirrors the Wine harness hooks */
static void *g_orig_put;
static unsigned char g_orig_put_bytes[16];
static int g_trace;

static long long WINAPI hk_put(void *i, long long k, long long v) {
    unpatch(g_orig_put, g_orig_put_bytes);
    long long r = ((long long(WINAPI *)(void *, long long, long long))g_orig_put)(i, k, v);
    if (g_trace)
        printf("      [meta_put] key=0x%llx val=0x%llx -> %lld  rva=0x%llx\n",
               (unsigned long long)k, (unsigned long long)v, r,
               (unsigned long long)((uintptr_t)__builtin_return_address(0) -
                                    (uintptr_t)g_base));
    patch(g_orig_put, hk_put);
    return r;
}

/* ---- optional 0x180018c60 probe --------------------------------------- *
 * Dumps the s16 image entering and leaving the orientation pipeline
 * (FPC_TRACE_18C60=<dir>).  Pair it with CR_TRACE_DIR=<dir> on the
 * standalone runner to bisect a divergence inside/outside the pipeline. */
static void *g_orig_18c60;
static unsigned char g_orig_18c60_bytes[16];
static const char *g_dump_18c60;

static void dump_img_file(const char *dir, const char *tag, const cr_image *im,
                          int bytespp) {
    char path[512];
    FILE *fp;

    if (!dir || !im || !im->data || im->w <= 0 || im->h <= 0)
        return;
    snprintf(path, sizeof path, "%s/%s.s16", dir, tag);
    fp = fopen(path, "wb");
    if (!fp)
        return;
    fwrite(im->data, (size_t)bytespp, (size_t)im->w * im->h, fp);
    fclose(fp);
    printf("      [dump] %s %dx%d\n", path, im->w, im->h);
}

static void dump_s16_file(const char *dir, const char *tag, const cr_image *im) {
    dump_img_file(dir, tag, im, 2);
}

static long long WINAPI hk_18c60(void *a1, void *a2, void *a3, void *a4,
                                 long long a5, long long a6) {
    long long r;

    dump_s16_file(g_dump_18c60, "18c60-in", (const cr_image *)a1);
    unpatch(g_orig_18c60, g_orig_18c60_bytes);
    r = ((long long(WINAPI *)(void *, void *, void *, void *, long long, long long))
             g_orig_18c60)(a1, a2, a3, a4, a5, a6);
    patch(g_orig_18c60, hk_18c60);
    dump_s16_file(g_dump_18c60, "18c60-out", (const cr_image *)a1);
    return r;
}

/* ---- optional 0x180011170 probe --------------------------------------- *
 * Dumps the mask-stage s16 output and its u8 partner (FPC_TRACE_11170=<dir>). */
static void *g_orig_11170;
static unsigned char g_orig_11170_bytes[16];
static const char *g_dump_11170;
static int g_n_11170;

static long long WINAPI hk_11170(void *a1, void *a2, void *a3, void *a4,
                                 void *a5, void *a6, long long a7) {
    long long r;
    int n = g_n_11170++;
    char tag[64];

    unpatch(g_orig_11170, g_orig_11170_bytes);
    r = ((long long(WINAPI *)(void *, void *, void *, void *, void *, void *,
                              long long))g_orig_11170)(a1, a2, a3, a4, a5, a6, a7);
    patch(g_orig_11170, hk_11170);
    snprintf(tag, sizeof tag, "sel%d-s16", n);
    dump_s16_file(g_dump_11170, tag, (const cr_image *)a1);
    snprintf(tag, sizeof tag, "sel%d-u8", n);
    dump_img_file(g_dump_11170, tag, (const cr_image *)a2, 1);
    return r;
}

/* ---- optional 0x18002a620 / 0x18000f9d0 probes ------------------------- *
 * Dump the f32 image after masked contrast normalisation and the f32 image
 * handed to the final f32->s16 conversion (FPC_TRACE_F32=<dir>). */
static void *g_orig_2a620, *g_orig_0f9d0;
static unsigned char g_orig_2a620_bytes[16], g_orig_0f9d0_bytes[16];
static const char *g_dump_f32;
static int g_n_2a620, g_n_0f9d0;

static long long WINAPI hk_2a620(void *a1, void *a2, void *a3) {
    long long r;
    int n = g_n_2a620++;
    char tag[64];
    const cr_image *i1 = (const cr_image *)a1, *i2 = (const cr_image *)a2;

    printf("      [2a620] a1=%p %dx%d data=%p | a2=%p %dx%d data=%p\n",
           a1, i1->w, i1->h, i1->data, a2, i2->w, i2->h, i2->data);
    {
        const cr_image *m = (const cr_image *)a3;
        void *mu = a2 ? *(void **)((unsigned char *)a2 + 0x58) : NULL;
        printf("      [2a620] mask=%p %dx%d data=%p mask16=%p flag=%d\n",
               a3, m->w, m->h, m->data, mu,
               a2 ? *(signed char *)((unsigned char *)a2 + 8) : -99);
        snprintf(tag, sizeof tag, "mask%d", n);
        dump_img_file(g_dump_f32, tag, m, 1);
        if (mu) {
            char p2[512];
            FILE *f;
            snprintf(p2, sizeof p2, "%s/mask16_%d.u16", g_dump_f32, n);
            f = fopen(p2, "wb");
            if (f) { fwrite(mu, 2, (size_t)m->w * m->h, f); fclose(f); }
        }
    }
    snprintf(tag, sizeof tag, "cnorm_in%d", n);
    dump_img_file(g_dump_f32, tag, (const cr_image *)a1, 4);
    snprintf(tag, sizeof tag, "cnorm_inb%d", n);
    dump_img_file(g_dump_f32, tag, (const cr_image *)a2, 4);
    unpatch(g_orig_2a620, g_orig_2a620_bytes);
    r = ((long long(WINAPI *)(void *, void *, void *))g_orig_2a620)(a1, a2, a3);
    patch(g_orig_2a620, hk_2a620);
    snprintf(tag, sizeof tag, "cnorm%d", n);
    dump_img_file(g_dump_f32, tag, (const cr_image *)a1, 4);
    snprintf(tag, sizeof tag, "cnormb%d", n);
    dump_img_file(g_dump_f32, tag, (const cr_image *)a2, 4);
    printf("      [2a620] ret=%lld\n", r);
    return r;
}

static void *g_orig_334c0;
static unsigned char g_orig_334c0_bytes[16];
static int g_n_334c0;

static void *g_orig_357a0;
static unsigned char g_orig_357a0_bytes[16];

static long long WINAPI hk_357a0(void *a, void *b) {
    long long r;
    short *p = a ? *(short **)((unsigned char *)a + 0x28) : NULL;
    short *q = a ? *(short **)((unsigned char *)a + 0x30) : NULL;
    void *dst1 = b ? *(void **)((unsigned char *)b + 0x58) : NULL;
    void *dst2 = b ? *(void **)((unsigned char *)b + 0x18) : NULL;

    printf("      [copyfields] a=%p b=%p p=%p(%dx%d) q=%p dst1=%p dst2=%p\n",
           a, b, p, p ? p[0] : -1, p ? p[1] : -1, q, dst1, dst2);
    if (p && dst1)
        printf("      [copyfields]   pdata=%p first=%d %d %d %d\n",
               *(void **)((unsigned char *)p + 0x10),
               ((short *)*(void **)((unsigned char *)p + 0x10))[0],
               ((short *)*(void **)((unsigned char *)p + 0x10))[1],
               ((short *)*(void **)((unsigned char *)p + 0x10))[2],
               ((short *)*(void **)((unsigned char *)p + 0x10))[3]);
    unpatch(g_orig_357a0, g_orig_357a0_bytes);
    r = ((long long(WINAPI *)(void *, void *))g_orig_357a0)(a, b);
    patch(g_orig_357a0, hk_357a0);
    if (dst1)
        printf("      [copyfields]   dst1 after: %d %d %d %d\n",
               ((short *)dst1)[0], ((short *)dst1)[1], ((short *)dst1)[2],
               ((short *)dst1)[3]);
    return r;
}

static void *g_orig_33f60;
static unsigned char g_orig_33f60_bytes[16];
static int g_n_33f60;

static long long WINAPI hk_33f60(void *a1, void *a2, long long a3, long long a4,
                                 void *a5) {
    long long r;

    unpatch(g_orig_33f60, g_orig_33f60_bytes);
    r = ((long long(WINAPI *)(void *, void *, long long, long long, void *))
             g_orig_33f60)(a1, a2, a3, a4, a5);
    patch(g_orig_33f60, hk_33f60);
    printf("      [sharp%d] w=%lld h=%lld -> r=%lld metric=%d\n",
           g_n_33f60++, a3, a4, r, a1 ? *(int *)a1 : -1);
    return r;
}

static long long WINAPI hk_334c0(void *a1, void *a2, long long a3) {
    long long r;
    int n = g_n_334c0++;
    char tag[64];

    snprintf(tag, sizeof tag, "i2f_src%d", n);
    dump_s16_file(g_dump_f32, tag, (const cr_image *)a2);
    unpatch(g_orig_334c0, g_orig_334c0_bytes);
    r = ((long long(WINAPI *)(void *, void *, long long))g_orig_334c0)(a1, a2, a3);
    patch(g_orig_334c0, hk_334c0);
    snprintf(tag, sizeof tag, "i2f_dst%d", n);
    dump_img_file(g_dump_f32, tag, (const cr_image *)a1, 4);
    return r;
}

static long long WINAPI hk_0f9d0(void *a1, void *a2, long long a3) {
    long long r;
    int n = g_n_0f9d0++;
    char tag[64];

    snprintf(tag, sizeof tag, "conv%d", n);
    dump_img_file(g_dump_f32, tag, (const cr_image *)a2, 4);
    unpatch(g_orig_0f9d0, g_orig_0f9d0_bytes);
    r = ((long long(WINAPI *)(void *, void *, long long))g_orig_0f9d0)(a1, a2, a3);
    patch(g_orig_0f9d0, hk_0f9d0);
    return r;
}

/* ---- optional 0x18001ad30 probe --------------------------------------- *
 * Dumps the s16 image the vendor hands to the block-feature pipeline
 * (CR_S16_OUT=<path>) and/or replaces the vendor body with the clean-room
 * implementation (--clean-1ad30).  Running with --clean-1ad30 isolates
 * divergence inside 1ad30 from divergence upstream of it. */
static void *g_orig_1ad30;
static unsigned char g_orig_1ad30_bytes[16];
static int g_dump_s16;
static int g_clean_1ad30;

static long long WINAPI hk_1ad30(void *a1, void *a2, void *a3,
                                 long long a4, long long a5) {
    cr_image *im = (cr_image *)a1;
    if (g_dump_s16 && im && im->data) {
        const char *p = getenv("CR_S16_OUT");
        if (p) {
            FILE *fp = fopen(p, "wb");
            if (fp) {
                fwrite(im->data, 2, (size_t)im->w * im->h, fp);
                fclose(fp);
                fprintf(stderr, "[s16] %s %dx%d\n", p, im->w, im->h);
            }
        }
    }
    if (g_clean_1ad30) {
        g_cr_image_base = (uintptr_t)g_base;
        return (long long)cr_feature_pipeline_1ad30(
            im, (int *)a2, (const uint8_t *)a3, (int)a4, (int)a5);
    }
    unpatch(g_orig_1ad30, g_orig_1ad30_bytes);
    long long r = ((long long(WINAPI *)(void *, void *, void *, long long, long long))
                       g_orig_1ad30)(a1, a2, a3, a4, a5);
    patch(g_orig_1ad30, hk_1ad30);
    return r;
}

static void *entry_point(void *base) {
    pe_dos_header *dos = (pe_dos_header *)base;
    u8 *nt = (u8 *)base + dos->e_lfanew;
    pe_file_header *fh = (pe_file_header *)(nt + 4);
    pe_optional_header64 *opt = (pe_optional_header64 *)(fh + 1);
    return (u8 *)base + opt->AddressOfEntryPoint;
}

static unsigned char *read_raw(const char *path, int *out_n) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return NULL; }
    static unsigned char buf[IMG_PAYLOAD_MAX];
    int n = (int)fread(buf, 1, sizeof buf, f);
    fclose(f);
    if (n <= 0) { fprintf(stderr, "%s: empty\n", path); return NULL; }
    *out_n = n;
    return buf;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    const char *raw_path = NULL, *dll_path = NULL, *out_path = NULL;
    int do_dllmain = 1;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--dll") == 0 && i + 1 < argc) dll_path = argv[++i];
        else if (strcmp(argv[i], "--no-dllmain") == 0) do_dllmain = 0;
        else if (strcmp(argv[i], "--clean-1ad30") == 0) g_clean_1ad30 = 1;
        else if (!raw_path) raw_path = argv[i];
        else if (!out_path) out_path = argv[i];
        else if (!strcmp(argv[i], "--cleanroom")) g_cleanroom = 1;
        else { fprintf(stderr, "unexpected arg: %s\n", argv[i]); return 2; }
    }
    if (!raw_path) {
        fprintf(stderr,
                "usage: %s <raw.bin> [out.raw] [--dll fpc_enclave.dll] [--no-dllmain] [--cleanroom]\n",
                argv[0]);
        return 2;
    }
    if (!out_path) out_path = getenv("FPC_OUTIMG");
    if (!out_path) out_path = "recon.raw";
    if (!dll_path) dll_path = getenv("FPC_ENCLAVE_DLL");
    if (!dll_path) dll_path = "fpc_enclave.dll";
    g_out_path = out_path;

    g_base = pe_load(dll_path, shim_lookup);
    if (!g_base) return 1;
    printf("[+] mapped %s at %p\n", dll_path, g_base);
    win32_shims_set_image_base(g_base);
    setup_teb();

    if (do_dllmain) {
        fn_dllmain dmain = (fn_dllmain)entry_point(g_base);
        printf("[*] DllMainCRTStartup(%p, DLL_PROCESS_ATTACH) ...\n", g_base);
        int ok = dmain(g_base, 1 /*DLL_PROCESS_ATTACH*/, NULL);
        printf("[+] DllMain returned %d\n", ok);
        if (!ok) return 1;
    }

    fn_setup setup = (fn_setup)pe_export(g_base, "fpc_setup_enclave");
    fn_init init = (fn_init)pe_export(g_base, "FpcTaInitialize_ecall");
    fn_op op = (fn_op)pe_export(g_base, "FpcTaOp_ecall");
    if (!setup || !init || !op) {
        fprintf(stderr, "[-] could not find required exports\n");
        return 1;
    }

    /* install the output-image hook */
    g_orig_1c810 = (u8 *)g_base + RVA_OUT_IMAGE;
    memcpy(g_orig_bytes, g_orig_1c810, 16);
    patch(g_orig_1c810, hk_1c810);

    if (getenv("CR_S16_OUT") || g_clean_1ad30) {
        g_orig_1ad30 = (u8 *)g_base + 0x1ad30;
        memcpy(g_orig_1ad30_bytes, g_orig_1ad30, 16);
        g_dump_s16 = getenv("CR_S16_OUT") != NULL;
        patch(g_orig_1ad30, hk_1ad30);
    }

    g_dump_18c60 = getenv("FPC_TRACE_18C60");
    if (g_dump_18c60) {
        g_orig_18c60 = (u8 *)g_base + 0x18c60;
        memcpy(g_orig_18c60_bytes, g_orig_18c60, 16);
        patch(g_orig_18c60, hk_18c60);
    }

    g_dump_11170 = getenv("FPC_TRACE_11170");
    if (g_dump_11170) {
        g_orig_11170 = (u8 *)g_base + 0x11170;
        memcpy(g_orig_11170_bytes, g_orig_11170, 16);
        patch(g_orig_11170, hk_11170);
    }

    g_dump_f32 = getenv("FPC_TRACE_F32");
    if (g_dump_f32) {
        g_orig_2a620 = (u8 *)g_base + 0x2a620;
        memcpy(g_orig_2a620_bytes, g_orig_2a620, 16);
        patch(g_orig_2a620, hk_2a620);
        g_orig_0f9d0 = (u8 *)g_base + 0x0f9d0;
        memcpy(g_orig_0f9d0_bytes, g_orig_0f9d0, 16);
        patch(g_orig_0f9d0, hk_0f9d0);
        g_orig_334c0 = (u8 *)g_base + 0x334c0;
        memcpy(g_orig_334c0_bytes, g_orig_334c0, 16);
        patch(g_orig_334c0, hk_334c0);
        g_orig_33f60 = (u8 *)g_base + 0x33f60;
        memcpy(g_orig_33f60_bytes, g_orig_33f60, 16);
        patch(g_orig_33f60, hk_33f60);
        g_orig_357a0 = (u8 *)g_base + 0x357a0;
        memcpy(g_orig_357a0_bytes, g_orig_357a0, 16);
        patch(g_orig_357a0, hk_357a0);
    }

    g_trace = getenv("FPC_TRACE") != NULL;
    if (g_trace) {
        g_orig_put = (u8 *)g_base + 0x00c570;   /* metadata_put (as called by fmi) */
        memcpy(g_orig_put_bytes, g_orig_put, 16);
        patch(g_orig_put, hk_put);
    }

    void *tbl[8] = {ocall0, ocall0, ocall0, ocall0, ocall0, ocall0, ocall0, ocall0};
    setup(tbl);
    printf("[+] FpcTaInitialize_ecall(0x0300) -> %d\n", init(0x0300));

    static unsigned char in[65536], out[262144];
#define OP(t, c)                                                                    \
    do {                                                                            \
        memset(in, 0, sizeof in);                                                   \
        memset(out, 0, sizeof out);                                                 \
        *(unsigned int *)(in + 0) = (t);                                            \
        *(unsigned int *)(in + 4) = (c);                                            \
        int _r = op(in, sizeof in, out, sizeof out);                                \
        printf("op(t=%d c=%d) -> %d out[8]=%u out[12]=%u\n", (t), (c), _r,          \
               *(unsigned int *)(out + 8), *(unsigned int *)(out + 12));            \
    } while (0)

    fn_fmi fmi = (fn_fmi)((u8 *)g_base + RVA_FMI);
    unsigned char *cap = (u8 *)g_base + RVA_CAPTURE_STRUCT;

    OP(11, 0); /* begin_enrol */

    int rn = 0;
    unsigned char *raw = read_raw(raw_path, &rn);
    if (!raw) return 1;
    memset(cap, 0, 0x22 + IMG_PIXELS);
    memcpy(cap + 0x0c, raw, rn);
    int outv = 0;
    printf("  inject(%s) n=%d fmi->%d\n", raw_path, rn, fmi(8, &outv, IMG_PIXELS));

    if (g_trace) {
        /* read back the metadata keys fpc_copy_buffer_into_fmi writes */
        fn_metaget mg = (fn_metaget)((u8 *)g_base + 0x4b4e0);
        u64 img = *(u64 *)((u8 *)g_base + 0x16f490);
        u64 inner = img ? *(u64 *)img : 0;
        u32 **arr = (u32 **)(inner + 0x10);
        static const long long keys[] = {0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xda};
        printf("      [meta] blob=%p\n", inner ? (void *)arr[0] : NULL);
        for (size_t i = 0; i < sizeof keys / sizeof keys[0]; i++) {
            int v = 0;
            long long r = mg(arr[0], keys[i], &v);
            printf("      [meta_get] key=0x%llx -> %lld val=0x%x\n",
                   (unsigned long long)keys[i], r, v);
        }
    }
    OP(11, 1); /* enrol -> FpcBioEnrolAdd -> FUN_18001c810 */

    if (!g_dumped) {
        fprintf(stderr, "[-] no reconstructed image produced\n");
        return 1;
    }
    printf("== done ==\n");
    return 0;
}
