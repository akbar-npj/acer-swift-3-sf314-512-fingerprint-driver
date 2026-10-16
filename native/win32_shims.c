/* Native implementations of the Win32 imports used by fpc_enclave.dll.
 *
 * The DLL is Windows x64 code: it calls its imports with the Microsoft ABI
 * (args in rcx/rdx/r8/r9). Every shim here is therefore declared ms_abi so the
 * register layout matches. The same applies to anything that calls into the
 * DLL (see fpc_recon.c).
 *
 * Only the subset the reconstruction path touches needs to be faithful; the
 * rest are benign stubs (bcrypt/TLS are never reached from FpcBioEnrolAdd).
 */
#include "win32_shims.h"

#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <wchar.h>
#include <sys/random.h>
#include <sys/syscall.h>
#include <malloc.h>

/* ---- Win32 type aliases (kept minimal) ---- */
typedef void *HANDLE;
typedef void *LPVOID;
typedef const void *LPCVOID;
typedef void *LPSECURITY_ATTRIBUTES;
typedef unsigned long DWORD;
typedef int BOOL;
typedef size_t SIZE_T;
typedef unsigned short WCHAR;
typedef WCHAR *LPWSTR;
typedef const WCHAR *LPCWSTR;
typedef char *LPSTR;
typedef const char *LPCSTR;

#define WINAPI __attribute__((ms_abi))

static void *g_image_base = NULL;   /* set by fpc_recon before init */

void win32_shims_set_image_base(void *base) { g_image_base = base; }

/* ---------------------------------------------------------------- heap ---- */
#define HEAP_ZERO_MEMORY 0x00000008

/* The DLL (fpc_enclave.dll) runs its own sub-allocator on top of the Win32
 * heap: FUN_18006afa0 / FUN_180002fb0 carve big HeapAlloc blocks into
 * sub-pointers and return / free those sub-pointers through HeapFree.  A blind
 * free(subpointer) corrupts glibc's heap metadata (newer glibc aborts with
 * "unaligned tcache chunk" / ASAN "bad-free").  We therefore track the pointers
 * sh_HeapAlloc actually hands back from malloc and only forward those to free();
 * every other pointer (a DLL sub-pointer) is a no-op — the underlying block
 * stays valid inside the DLL's pool.  This keeps the process heap intact.
 *
 * Open-addressing hash set, single-threaded (the enclave is serialised).
 *
 * The set MUST be growable.  sh_HeapFree is a no-op (we deliberately never free
 * DLL blocks), so the live set only ever grows; a fixed-size table eventually
 * fills completely and the probe loop below spins forever looking for an empty
 * slot (observed: difftest wedged at 99.7% CPU in hs_insert after ~800k
 * allocations).  We rehash — dropping tombstones — once the load factor passes
 * 1/2, which also keeps probing O(1). */
static uintptr_t *g_hs    = NULL;   /* 0 = empty, 1 = tombstone */
static size_t    *g_hs_sz = NULL;   /* requested size, same slot as g_hs */
static size_t     g_hs_cap = 0;     /* power of two; 0 until first insert */
static size_t     g_hs_live = 0;    /* non-tombstone entries */

static unsigned hs_hash(uintptr_t p, size_t cap) {
    p >>= 4; p ^= p >> 17; p ^= p >> 34;
    return (unsigned)(p & (cap - 1));
}

static void hs_grow(void) {
    size_t ncap = g_hs_cap ? g_hs_cap * 2 : (size_t)1 << 12;
    uintptr_t *nh = calloc(ncap, sizeof *nh);
    size_t    *ns = calloc(ncap, sizeof *ns);
    if (!nh || !ns) { free(nh); free(ns); return; }   /* best effort */
    for (size_t i = 0; i < g_hs_cap; i++) {
        uintptr_t v = g_hs[i];
        if (v > 1) {                                  /* skip empty/tombstone */
            unsigned h = hs_hash(v, ncap);
            while (nh[h]) h = (h + 1u) & (unsigned)(ncap - 1);
            nh[h] = v;
            ns[h] = g_hs_sz[i];
        }
    }
    free(g_hs); free(g_hs_sz);
    g_hs = nh; g_hs_sz = ns; g_hs_cap = ncap;
}

static int hs_find(uintptr_t p, unsigned *out) {
    if (!g_hs_cap) return 0;
    unsigned mask = (unsigned)(g_hs_cap - 1);
    unsigned h = hs_hash(p, g_hs_cap);
    for (size_t n = 0; n < g_hs_cap; n++) {           /* bounded: never spins */
        uintptr_t v = g_hs[h];
        if (v == 0) return 0;
        if (v == p) { *out = h; return 1; }
        h = (h + 1u) & mask;                          /* tombstones skipped */
    }
    return 0;
}
static void hs_insert(uintptr_t p) {
    if (g_hs_live * 2 >= g_hs_cap) hs_grow();         /* also handles cap == 0 */
    if (!g_hs_cap) return;                            /* grow failed: drop it */
    unsigned mask = (unsigned)(g_hs_cap - 1);
    unsigned h = hs_hash(p, g_hs_cap);
    for (;;) {
        uintptr_t v = g_hs[h];
        if (v == 0 || v == 1) { g_hs[h] = p; g_hs_live++; return; }
        if (v == p) return;
        h = (h + 1u) & mask;
    }
}
static int hs_remove(uintptr_t p) {
    unsigned h;
    if (hs_find(p, &h)) { g_hs[h] = 1; if (g_hs_live) g_hs_live--; return 1; }
    return 0;
}

/* Size accessors: the size the DLL *asked* for, so sh_HeapSize reports the
 * Windows-visible size, not our padded block. */
static void hs_set_sz(uintptr_t p, size_t sz) {
    unsigned h;
    if (hs_find(p, &h)) g_hs_sz[h] = sz;
}
static size_t hs_get_sz(uintptr_t p) {
    unsigned h;
    return hs_find(p, &h) ? g_hs_sz[h] : 0;
}

/* The DLL's BEP routines occasionally write a few bytes past the end of a
 * scratch buffer they allocated (e.g. a sliding-window box sum whose tail loop
 * runs one window too far).  On Windows the process heap rounds every block up
 * to a 16-byte granularity *and* keeps free-list slack after it, so the overrun
 * lands harmlessly in unused space.  glibc does not: the bytes after the block
 * are the next chunk's size/prev_size header, so the overrun trips
 * `sysmalloc: assertion failed`.  We therefore hand the DLL blocks that are
 * SHIM_GUARD bytes larger than requested, restoring the Windows-like slack.
 * The extra bytes are filled with a canary so `SHIM_GUARD_LOG` can report the
 * overrun (size + how far past the end) for diagnosis. */
#define SHIM_GUARD 64

/* Head slack: some DLL routines read a few dozen bytes *before* a heap block
 * (e.g. the streaming vertical-FIR mirror branch indexes `ring + rem*w` with a
 * negative `rem`, reaching before the ring).  On Windows that lands in the
 * preceding heap block / unused slack; on glibc it lands in the previous
 * chunk's header, which differs from the clean-room side's neighbouring chunk
 * and breaks bit-parity.  Handing out blocks preceded by SHIM_HEAD *zeroed*
 * bytes makes every such read deterministic (zero) and identical to the
 * clean-room allocator (which reserves the same head slack). */
#define SHIM_HEAD 4096

#define GC_N 64
static unsigned char *g_gc_ptr[GC_N];
static size_t         g_gc_sz[GC_N];
static int            g_gc_i;
static int            g_guard_log = -1;   /* -1 = unread, 0/1 = cached env */
static void guard_check(void) {
    if (g_guard_log < 0) g_guard_log = getenv("SHIM_GUARD_LOG") ? 1 : 0;
    if (!g_guard_log) return;   /* the padded block already prevents corruption */
    for (int i = 0; i < GC_N; i++) {
        unsigned char *p = g_gc_ptr[i];
        if (!p) continue;
        unsigned char *g = p + g_gc_sz[i];
        for (int k = 0; k < SHIM_GUARD; k++) {
            if (g[k] != 0xC5) {
                fprintf(stderr, "[GUARD] block size=%zu overrun +%d byte=0x%02x\n",
                        g_gc_sz[i], k, g[k]);
                g_gc_ptr[i] = NULL;
                break;
            }
        }
    }
}
static void guard_push(unsigned char *p, size_t size) {
    g_gc_ptr[g_gc_i] = p;
    g_gc_sz[g_gc_i]  = size;
    g_gc_i = (g_gc_i + 1) % GC_N;
}

static void *WINAPI sh_GetProcessHeap(void) { return (void *)0x1; }

static void *WINAPI sh_HeapAlloc(void *heap, DWORD flags, SIZE_T size) {
    (void)heap;
    if (size == 0) size = 1;
    guard_check();
    void *p = malloc(SHIM_HEAD + size + SHIM_GUARD);
    if (!p) return NULL;
    memset(p, 0, SHIM_HEAD + size);   /* deterministic head slack + body */
    if (flags & HEAP_ZERO_MEMORY) memset((char *)p + SHIM_HEAD, 0, size);
    memset((unsigned char *)p + SHIM_HEAD + size, 0xC5, SHIM_GUARD);
    p = (char *)p + SHIM_HEAD;
    hs_insert((uintptr_t)p);
    hs_set_sz((uintptr_t)p, size);
    guard_push((unsigned char *)p, size);
    return p;
}

/* The DLL's allocator (flmalloc) carves sub-pointers out of HeapAlloc blocks and
 * passes those sub-pointers back to HeapFree.  A blind free(subpointer) corrupts
 * glibc (ASAN "bad-free" / "unaligned tcache chunk").  Distinguishing a real
 * malloc base from a sub-pointer reliably is fragile, so the robust choice for a
 * short-lived test harness is to NEVER free here — leaked DLL pools are bounded
 * and far cheaper than heap corruption.  The tracking set is still used by
 * sh_HeapSize to avoid calling malloc_usable_size on sub-pointers (which would
 * abort glibc). */
static BOOL WINAPI sh_HeapFree(void *heap, DWORD flags, void *p) {
    (void)heap; (void)flags; (void)p;
    return 1;   /* success, no-op */
}

static void *WINAPI sh_HeapReAlloc(void *heap, DWORD flags, void *p, SIZE_T size) {
    (void)heap;
    if (size == 0) size = 1;
    unsigned h;
    if (p && hs_find((uintptr_t)p, &h)) {
        /* p is one of our (padded) blocks: realloc and re-track the new base.
         * Keep the old base as an integer so hs_remove does not read `p` after
         * realloc invalidated it. */
        size_t old = g_hs_sz[h];
        uintptr_t pv = (uintptr_t)p;
        void *raw = (char *)p - SHIM_HEAD;
        void *q = realloc(raw, SHIM_HEAD + size + SHIM_GUARD);
        if (!q) return NULL;
        hs_remove(pv);
        memset(q, 0, SHIM_HEAD);
        if ((flags & HEAP_ZERO_MEMORY) && size > old)
            memset((char *)q + SHIM_HEAD + old, 0, size - old);
        memset((char *)q + SHIM_HEAD + size, 0xC5, SHIM_GUARD);
        q = (char *)q + SHIM_HEAD;
        hs_insert((uintptr_t)q);
        hs_set_sz((uintptr_t)q, size);
        guard_push((unsigned char *)q, size);
        return q;
    }
    /* sub-pointer: the DLL's sub-allocator owns it; cannot realloc a slice of
     * someone else's block, so leave it in place (best effort, never realloc()). */
    return p;
}

static SIZE_T WINAPI sh_HeapSize(void *heap, DWORD flags, void *p) {
    (void)heap; (void)flags;
    /* Report the size the DLL requested (Windows-visible), not our padded
     * block, and never call malloc_usable_size on an unknown pointer. */
    return p ? (SIZE_T)hs_get_sz((uintptr_t)p) : 0;
}

/* ----------------------------------------------------- critical sections -- */
/* The MSVC CRITICAL_SECTION is 40 bytes on x64 and is *recursive*: the owning
 * thread may re-enter. We serialise all sections on one recursive mutex (the
 * enclave is effectively single-threaded). A non-recursive mutex deadlocks on
 * re-entry (observed in the CRT init). */
static pthread_mutex_t g_cs;
static pthread_once_t g_cs_once = PTHREAD_ONCE_INIT;
static void cs_make(void) {
    pthread_mutexattr_t a;
    pthread_mutexattr_init(&a);
    pthread_mutexattr_settype(&a, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&g_cs, &a);
    pthread_mutexattr_destroy(&a);
}

static BOOL WINAPI sh_InitializeCriticalSectionAndSpinCount(void *cs, DWORD spin) {
    (void)spin; if (cs) memset(cs, 0, 40); return 1;
}
static void WINAPI sh_EnterCriticalSection(void *cs) {
    (void)cs; pthread_once(&g_cs_once, cs_make); pthread_mutex_lock(&g_cs);
}
static void WINAPI sh_LeaveCriticalSection(void *cs) {
    (void)cs; pthread_mutex_unlock(&g_cs);
}
static void WINAPI sh_DeleteCriticalSection(void *cs) { (void)cs; }

/* --------------------------------------------------------------- TLS ------ */
#define MAX_TLS 256
static pthread_key_t g_tls_keys[MAX_TLS];
static int g_tls_n = 0;

static DWORD WINAPI sh_TlsAlloc(void) {
    if (g_tls_n >= MAX_TLS) return 0xFFFFFFFFu;
    if (pthread_key_create(&g_tls_keys[g_tls_n], NULL) != 0) return 0xFFFFFFFFu;
    return (DWORD)g_tls_n++;
}
static void *WINAPI sh_TlsGetValue(DWORD i) {
    return (i < (DWORD)g_tls_n) ? pthread_getspecific(g_tls_keys[i]) : NULL;
}
static BOOL WINAPI sh_TlsSetValue(DWORD i, void *v) {
    if (i >= (DWORD)g_tls_n) return 0;
    return pthread_setspecific(g_tls_keys[i], v) == 0;
}
static BOOL WINAPI sh_TlsFree(DWORD i) { (void)i; return 1; }

/* --------------------------------------------------------------- time ----- */
static u64 filetime_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (u64)(ts.tv_sec + 11644473600ULL) * 10000000ULL + (u64)(ts.tv_nsec / 100);
}
static void WINAPI sh_GetSystemTimeAsFileTime(void *ft) {
    if (ft) *(u64 *)ft = filetime_now();
}
static void WINAPI sh_GetLocalTime(void *st) {
    if (!st) return;
    time_t t = time(NULL);
    struct tm tmv; localtime_r(&t, &tmv);
    u16 *w = (u16 *)st;
    w[0] = (u16)(tmv.tm_year + 1900); w[1] = (u16)(tmv.tm_mon + 1); w[2] = 1;
    w[3] = (u16)tmv.tm_mday; w[4] = (u16)tmv.tm_hour; w[5] = (u16)tmv.tm_min;
    w[6] = (u16)tmv.tm_sec; w[7] = 0;
}
static BOOL WINAPI sh_SystemTimeToFileTime(const void *st, void *ft) {
    (void)st; if (ft) *(u64 *)ft = filetime_now(); return 1;
}
static BOOL WINAPI sh_QueryPerformanceFrequency(u64 *f) { if (f) *f = 1000000000ULL; return 1; }
static BOOL WINAPI sh_QueryPerformanceCounter(u64 *c) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    if (c) *c = (u64)ts.tv_sec * 1000000000ULL + (u64)ts.tv_nsec;
    return 1;
}

/* ---------------------------------------------------------- process id ---- */
static HANDLE WINAPI sh_GetCurrentProcess(void) { return (HANDLE)-1; }
static DWORD WINAPI sh_GetCurrentProcessId(void) { return (DWORD)getpid(); }
static DWORD WINAPI sh_GetCurrentThreadId(void) { return (DWORD)syscall(SYS_gettid); }

/* --------------------------------------------------------- startup info --- */
static void WINAPI sh_GetStartupInfoW(void *si) {
    if (!si) return;
    memset(si, 0, 104);              /* STARTUPINFOW, x64 */
    *(DWORD *)si = 104;              /* cb */
}
static BOOL WINAPI sh_GetModuleHandleExW(DWORD flags, LPCWSTR name, void **out) {
    (void)flags; (void)name;
    if (out) *out = g_image_base;
    return 1;
}
static void *WINAPI sh_GetModuleHandleW(LPCWSTR name) { (void)name; return g_image_base; }
static void *WINAPI sh_GetModuleHandleA(LPCSTR name) { (void)name; return g_image_base; }
static void *WINAPI sh_LoadLibraryExW(LPCWSTR name, HANDLE f, DWORD flags) {
    (void)name; (void)f; (void)flags; return NULL;
}
static BOOL WINAPI sh_FreeLibrary(HANDLE h) { (void)h; return 1; }

static void *WINAPI sh_GetProcAddress(HANDLE h, const char *name) {
    (void)h;
    extern void *pe_export(void *base, const char *name);
    return g_image_base ? pe_export(g_image_base, name) : NULL;
}

static DWORD WINAPI sh_GetModuleFileNameA(HANDLE h, char *buf, DWORD n) {
    (void)h;
    const char *s = "fpc_enclave.dll";
    if (!buf || !n) return 0;
    size_t len = strlen(s); if (len >= n) len = n - 1;
    memcpy(buf, s, len); buf[len] = 0;
    return (DWORD)len;
}

/* ----------------------------------------------------- cmdline / env ------ */
static const char *WINAPI sh_GetCommandLineA(void) { return ""; }
static const WCHAR *WINAPI sh_GetCommandLineW(void) { static const WCHAR e[1] = {0}; return e; }
static WCHAR *WINAPI sh_GetEnvironmentStringsW(void) {
    static WCHAR block[2] = {0, 0};   /* empty environment, double NUL */
    return block;
}
static BOOL WINAPI sh_FreeEnvironmentStringsW(WCHAR *p) { (void)p; return 1; }

/* ------------------------------------------------------------- stdio ------ */
static HANDLE WINAPI sh_GetStdHandle(DWORD n) { (void)n; return (HANDLE)0x10; }
static BOOL WINAPI sh_SetStdHandle(DWORD n, HANDLE h) { (void)n; (void)h; return 1; }
static DWORD WINAPI sh_GetFileType(HANDLE h) { (void)h; return 2; /* FILE_TYPE_CHAR */ }
static BOOL WINAPI sh_WriteFile(HANDLE h, const void *buf, DWORD n, DWORD *written, void *ov) {
    (void)h; (void)ov;
    if (buf && n) fwrite(buf, 1, n, stderr);
    if (written) *written = n;
    return 1;
}
static BOOL WINAPI sh_WriteConsoleW(HANDLE h, const void *buf, DWORD n, DWORD *written, void *r) {
    (void)h; (void)buf; (void)r;
    if (written) *written = n;
    return 1;
}
static DWORD WINAPI sh_GetConsoleCP(void) { return 437; }
static BOOL WINAPI sh_GetConsoleMode(HANDLE h, DWORD *mode) {
    (void)h; if (mode) *mode = 0; return 0;
}
static HANDLE WINAPI sh_CreateFileW(LPCWSTR n, DWORD a, DWORD s, void *sa, DWORD c, DWORD f, HANDLE t) {
    (void)n; (void)a; (void)s; (void)sa; (void)c; (void)f; (void)t;
    return (HANDLE)-1;   /* INVALID_HANDLE_VALUE */
}
static BOOL WINAPI sh_SetFilePointerEx(HANDLE h, long long d, long long *np, DWORD m) {
    (void)h; (void)d; (void)m; if (np) *np = 0; return 1;
}
static BOOL WINAPI sh_FlushFileBuffers(HANDLE h) { (void)h; return 1; }
static BOOL WINAPI sh_CloseHandle(HANDLE h) { (void)h; return 1; }
static HANDLE WINAPI sh_FindFirstFileExA(const char *p, int l, void *d, int i, void *f, void *s) {
    (void)p; (void)l; (void)d; (void)i; (void)f; (void)s; return (HANDLE)-1;
}
static BOOL WINAPI sh_FindNextFileA(HANDLE h, void *d) { (void)h; (void)d; return 0; }
static BOOL WINAPI sh_FindClose(HANDLE h) { (void)h; return 1; }

/* -------------------------------------------------------------- locale ---- */
static unsigned WINAPI sh_GetACP(void) { return 1252; }
static unsigned WINAPI sh_GetOEMCP(void) { return 437; }
static BOOL WINAPI sh_IsValidCodePage(unsigned cp) { (void)cp; return 1; }
static BOOL WINAPI sh_GetCPInfo(unsigned cp, void *info) {
    (void)cp; if (info) memset(info, 0, 20); return 1;
}
static BOOL WINAPI sh_GetStringTypeW(DWORD t, LPCWSTR s, int n, u16 *out) {
    (void)t; (void)s; (void)n; (void)out; return 1;
}
static int WINAPI sh_LCMapStringW(DWORD f, LPCWSTR a, int b, LPCWSTR c, LPWSTR d, int e) {
    (void)f; (void)a; (void)b; (void)c; (void)d; (void)e; return 0;
}
static int WINAPI sh_MultiByteToWideChar(unsigned cp, DWORD f, const char *src, int srclen,
                                         WCHAR *dst, int dstlen) {
    (void)cp; (void)f;
    int n = srclen < 0 ? (int)strlen(src) + 1 : srclen;
    if (dstlen == 0) return n;
    int k = n < dstlen ? n : dstlen;
    for (int i = 0; i < k; i++) dst[i] = (WCHAR)(unsigned char)src[i];
    return k;
}
static int WINAPI sh_WideCharToMultiByte(unsigned cp, DWORD f, const WCHAR *src, int srclen,
                                         char *dst, int dstlen, const char *def, BOOL *used) {
    (void)cp; (void)f; (void)def; (void)used;
    int n = srclen < 0 ? (int)(wcslen((const wchar_t *)src) + 1) : srclen;
    if (dstlen == 0) return n;
    int k = n < dstlen ? n : dstlen;
    for (int i = 0; i < k; i++) dst[i] = (char)src[i];
    return k;
}

/* ------------------------------------------------------- errors / SEH ----- */
static DWORD g_last_error = 0;
static void WINAPI sh_SetLastError(DWORD e) { g_last_error = e; }
static DWORD WINAPI sh_GetLastError(void) { return g_last_error; }
static BOOL WINAPI sh_IsDebuggerPresent(void) { return 0; }
static BOOL WINAPI sh_IsProcessorFeaturePresent(DWORD f) { (void)f; return 0; }
static void *WINAPI sh_SetUnhandledExceptionFilter(void *f) { (void)f; return NULL; }
static int WINAPI sh_UnhandledExceptionFilter(void *info) { (void)info; return 1; }
static void WINAPI sh_RaiseException(DWORD code, DWORD flags, DWORD n, const void *args) {
    (void)flags; (void)n; (void)args;
    fprintf(stderr, "[shim] RaiseException(%#lx)\n", (unsigned long)code);
    abort();
}
static void WINAPI sh_RtlCaptureContext(void *ctx) { if (ctx) memset(ctx, 0, 1232); }
static void *WINAPI sh_RtlLookupFunctionEntry(u64 pc, u64 *base, void *hist) {
    (void)pc; (void)base; (void)hist; return NULL;
}
static void *WINAPI sh_RtlVirtualUnwind(DWORD a, u64 b, u64 c, void *d, void *e, void *f, void *g) {
    (void)a; (void)b; (void)c; (void)d; (void)e; (void)f; (void)g; return NULL;
}
static void WINAPI sh_RtlUnwindEx(void *t, void *frame, void *rec, void *ret, void *ctx, void *hist) {
    (void)t; (void)frame; (void)rec; (void)ret; (void)ctx; (void)hist;
}
static void WINAPI sh_ExitProcess(unsigned code) { exit((int)code); }
static BOOL WINAPI sh_TerminateProcess(HANDLE h, unsigned code) {
    (void)h; exit((int)code); return 1;
}
static void WINAPI sh_InitializeSListHead(void *head) { if (head) memset(head, 0, 16); }
static void *WINAPI sh_InterlockedFlushSList(void *head) { (void)head; return NULL; }

/* -------------------------------------------------------------- bcrypt ---- */
/* The TLS handshake (not reached from the reconstruction path) uses the full
 * bcrypt API; only BCryptGenRandom is needed by the BEP path (fpc_secure_random
 * seeds a per-capture value), so that one is implemented for real. */
static int WINAPI sh_BCryptGenRandom(void *alg, unsigned char *buf, unsigned len,
                                     unsigned flags) {
    (void)alg; (void)flags;
    if (!buf) return 0xC0000001u;   /* STATUS_UNSUCCESSFUL */
    size_t i = 0;
    while (i < len) {
        ssize_t r = getrandom(buf + i, len - i, 0);
        if (r < 0) { if (errno == EINTR) continue; break; }
        i += (size_t)r;
    }
    for (; i < len; i++) buf[i] = (unsigned char)(rand() >> 8);
    return 0;                        /* STATUS_SUCCESS */
}

static int WINAPI bc_stub(void) { return 0xC0000001u; }   /* STATUS_UNSUCCESSFUL */

/* -------------------------------------------------------------- table ----- */
typedef struct { const char *name; void *fn; } shim_entry;

#define S(n) { #n, (void *)sh_##n }
#define B(n) { #n, (void *)bc_stub }

static const shim_entry g_shims[] = {
    S(GetProcessHeap), S(HeapAlloc), S(HeapFree), S(HeapReAlloc), S(HeapSize),
    S(InitializeCriticalSectionAndSpinCount), S(EnterCriticalSection),
    S(LeaveCriticalSection), S(DeleteCriticalSection),
    S(TlsAlloc), S(TlsGetValue), S(TlsSetValue), S(TlsFree),
    S(GetSystemTimeAsFileTime), S(GetLocalTime), S(SystemTimeToFileTime),
    S(QueryPerformanceFrequency), S(QueryPerformanceCounter),
    S(GetCurrentProcess), S(GetCurrentProcessId), S(GetCurrentThreadId),
    S(GetStartupInfoW), S(GetModuleHandleExW), S(GetModuleHandleW), S(GetModuleHandleA),
    S(LoadLibraryExW), S(FreeLibrary), S(GetProcAddress), S(GetModuleFileNameA),
    S(GetCommandLineA), S(GetCommandLineW), S(GetEnvironmentStringsW),
    S(FreeEnvironmentStringsW),
    S(GetStdHandle), S(SetStdHandle), S(GetFileType), S(WriteFile), S(WriteConsoleW),
    S(GetConsoleCP), S(GetConsoleMode), S(CreateFileW), S(SetFilePointerEx),
    S(FlushFileBuffers), S(CloseHandle), S(FindFirstFileExA), S(FindNextFileA), S(FindClose),
    S(GetACP), S(GetOEMCP), S(IsValidCodePage), S(GetCPInfo), S(GetStringTypeW),
    S(LCMapStringW), S(MultiByteToWideChar), S(WideCharToMultiByte),
    S(SetLastError), S(GetLastError), S(IsDebuggerPresent), S(IsProcessorFeaturePresent),
    S(SetUnhandledExceptionFilter), S(UnhandledExceptionFilter), S(RaiseException),
    S(RtlCaptureContext), S(RtlLookupFunctionEntry), S(RtlVirtualUnwind), S(RtlUnwindEx),
    S(ExitProcess), S(TerminateProcess), S(InitializeSListHead), S(InterlockedFlushSList),
    B(BCryptCloseAlgorithmProvider), B(BCryptCreateHash), B(BCryptDecrypt),
    B(BCryptDestroyHash), B(BCryptDestroyKey), B(BCryptEncrypt), B(BCryptExportKey),
    B(BCryptFinishHash), S(BCryptGenRandom), B(BCryptGenerateSymmetricKey),
    B(BCryptHashData), B(BCryptOpenAlgorithmProvider),
};

void *shim_lookup(const char *dll, const char *name) {
    (void)dll;
    if (!name) return NULL;
    for (size_t i = 0; i < sizeof(g_shims) / sizeof(g_shims[0]); i++)
        if (strcasecmp(g_shims[i].name, name) == 0)
            return g_shims[i].fn;
    return NULL;
}
