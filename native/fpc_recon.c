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
    unpatch(g_orig_1c810, g_orig_bytes);
    long long r = ((long long(WINAPI *)(void *, void *, void *, void *, void *, long long))
                       g_orig_1c810)(a, b, c, d, e, f);
    unsigned char *p = (unsigned char *)a;
    u64 pix = *(u64 *)(p + 0x18);
    int w = *(int *)(p + 0x20), h = *(int *)(p + 0x24);
    printf("    > FUN_18001c810 -> %lld  out_img=%p %dx%d hdr=%x\n",
           r, (void *)pix, w, h, *(unsigned int *)p);
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
        printf("      [meta_put] key=0x%llx val=0x%llx -> %lld\n",
               (unsigned long long)k, (unsigned long long)v, r);
    patch(g_orig_put, hk_put);
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
        else if (!raw_path) raw_path = argv[i];
        else if (!out_path) out_path = argv[i];
        else { fprintf(stderr, "unexpected arg: %s\n", argv[i]); return 2; }
    }
    if (!raw_path) {
        fprintf(stderr,
                "usage: %s <raw.bin> [out.raw] [--dll fpc_enclave.dll] [--no-dllmain]\n",
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
