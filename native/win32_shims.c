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

static void *WINAPI sh_GetProcessHeap(void) { return (void *)0x1; }

static void *WINAPI sh_HeapAlloc(void *heap, DWORD flags, SIZE_T size) {
    (void)heap;
    if (size == 0) size = 1;
    return (flags & HEAP_ZERO_MEMORY) ? calloc(1, size) : malloc(size);
}

static BOOL WINAPI sh_HeapFree(void *heap, DWORD flags, void *p) {
    (void)heap; (void)flags; free(p); return 1;
}

static void *WINAPI sh_HeapReAlloc(void *heap, DWORD flags, void *p, SIZE_T size) {
    (void)heap;
    if (flags & HEAP_ZERO_MEMORY) {
        /* grow-and-zero semantics: approximate with realloc + zero tail */
        size_t old = p ? malloc_usable_size(p) : 0;
        void *q = realloc(p, size ? size : 1);
        if (q && size > old) memset((char *)q + old, 0, size - old);
        return q;
    }
    return realloc(p, size ? size : 1);
}

static SIZE_T WINAPI sh_HeapSize(void *heap, DWORD flags, void *p) {
    (void)heap; (void)flags; return p ? malloc_usable_size(p) : 0;
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
