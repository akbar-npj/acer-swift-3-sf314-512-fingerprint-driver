/*
 * fpc_enclave rehost harness (v15) — drive the BEP algorithm on injected frames and
 * dump the RECONSTRUCTED image.
 *
 * The enclave receives the sensor capture over TLS and memcpy's it to the global
 * struct at 0x1801728e0:
 *    +0x00 : 12-byte event header
 *    +0x0c : EVT_IMG payload (22-byte sub-header; first 10 bytes = metadata)
 *    +0x22 : image[11264]
 * fpc_copy_buffer_into_fmi(8,&out,11264) (0x180068470) copies pixels + writes metadata
 * keys 0xd2,0xd3,0xd4,0xd5,0xd6,0xd7,0xda into the live bep image. We replicate that.
 *
 * KEY FINDING (v15): the BEP pipeline FUN_18001c810 (0x18001c810, called via
 * FUN_180017420 <- core FUN_180013f70 <- FpcBioEnrolAdd) writes an 8-bit OUTPUT IMAGE:
 *     *(char*)(param_1[3] + i) = (short_img[i] + 0x20) >> 6;
 * with param_1[3] = output pixels, width at param_1+0x20, height at param_1+0x24.
 * We hook FUN_18001c810 and dump that buffer -> outimg_<n>_<w>x<h>.raw.
 *
 * Modes:
 *   harness.exe <raw> 11 1            single enrol, dumps buffers + reconstructed image
 *   harness.exe <raw> 11 1 recon      begin->inject->enrol only, just the reconstructed image
 *   harness.exe <raw> 11 1 full <b>   begin->enrol->end->get_ids->identify(a)->identify(b)
 *   harness.exe <raw> 11 1 multi <b..> load_empty_db, begin, enrol each frame, end, ids, identify
 *
 * Env:
 *   FPC_OUTIMG   absolute/relative path for the reconstructed image dump
 *                (default: outimg_<seq>_<w>x<h>.raw in the cwd). Used by
 *                fpc_reconstruct.sh to name one output per input frame.
 */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef int (*fn_setup)(void *table);
typedef int (*fn_init)(unsigned short hwid);
typedef int (*fn_op)(void *in, unsigned inlen, void *out, unsigned outlen);
typedef int (*fn_getpx)(void *img_data, void *info_out);
typedef int (*fn_fmi)(int type, void *out, int len);
typedef long long (*fn_metaget)(void *blob, long long key, void *out);

static long long ocall0(void) { return 0; }
static unsigned char *g_base;

typedef struct { void *addr; unsigned char orig[16]; void *hook; } Hook;
static void patch(Hook *h){DWORD o;unsigned char c[12]={0x48,0xB8,0,0,0,0,0,0,0,0,0xFF,0xE0};*(void**)(c+2)=h->hook;
    VirtualProtect(h->addr,16,PAGE_EXECUTE_READWRITE,&o);memcpy(h->addr,c,12);VirtualProtect(h->addr,16,o,&o);
    FlushInstructionCache(GetCurrentProcess(),h->addr,16);}
static void unpatch(Hook*h){DWORD o;VirtualProtect(h->addr,16,PAGE_EXECUTE_READWRITE,&o);memcpy(h->addr,h->orig,12);
    VirtualProtect(h->addr,16,o,&o);FlushInstructionCache(GetCurrentProcess(),h->addr,16);}
static void install(Hook*h,void*a,void*f){h->addr=a;h->hook=f;memcpy(h->orig,a,16);patch(h);}

static Hook H_b4e0, H_11170, H_cf0, H_c570, H_memcpy, H_1c810;
static int g_log = 0;
static int g_memlog = 0, g_memn = 0;
static int g_imgseq = 0;
static void* hk_memcpy(void*dst,void*src,size_t n){unpatch(&H_memcpy);
    void*r=((void*(*)(void*,void*,size_t))H_memcpy.addr)(dst,src,n);
    if(g_memlog && n>=1024 && g_memn<500){printf("      [memcpy] dst=%p src=%p n=%zu\n",dst,src,n);g_memn++;}
    patch(&H_memcpy);return r;}
/* FUN_18001c810 writes the reconstructed 8-bit image to param_1[3], dims at +0x20/+0x24 */
static long long hk_1c810(void*a,void*b,void*c,void*d,void*e,long long f){unpatch(&H_1c810);
    long long r=((long long(*)(void*,void*,void*,void*,void*,long long))H_1c810.addr)(a,b,c,d,e,f);
    unsigned char*p=(unsigned char*)a;
    uint64_t pix=*(uint64_t*)(p+0x18);
    int w=*(int*)(p+0x20), h=*(int*)(p+0x24);
    printf("    > FUN_18001c810 -> %lld  out_img=%p %dx%d hdr=%x\n",r,(void*)pix,w,h,*(unsigned int*)p);
    if(pix && w>0 && h>0 && (long long)w*h<=262144){
        char fn[256];
        const char *oe = getenv("FPC_OUTIMG");
        if(oe && *oe) snprintf(fn,sizeof fn,"%s",oe);
        else snprintf(fn,sizeof fn,"outimg_%d_%dx%d.raw",g_imgseq++,w,h);
        FILE*fp=fopen(fn,"wb"); if(fp){fwrite((void*)pix,1,(size_t)w*h,fp);fclose(fp);printf("      wrote %s (%d bytes)\n",fn,w*h);}
        else printf("      !! could not open %s\n",fn);
    }
    patch(&H_1c810); return r;}
static long long hk_b4e0(void*i,long long k,void*o){unpatch(&H_b4e0);long long r=((long long(*)(void*,long long,void*))H_b4e0.addr)(i,k,o);
    if(g_log)printf("      [meta_get] key=0x%llx -> %lld out=%d\n",(unsigned long long)k,r,o?*(int*)o:-1);patch(&H_b4e0);return r;}
static long long hk_c570(void*i,long long k,long long v){unpatch(&H_c570);long long r=((long long(*)(void*,long long,long long))H_c570.addr)(i,k,v);
    if(g_log)printf("      [meta_put] key=0x%llx val=0x%llx -> %lld\n",(unsigned long long)k,(unsigned long long)v,r);patch(&H_c570);return r;}
static long long hk_11170(void*a,void*b,void*c,void*d,void*e,void*f,void*g){unpatch(&H_11170);
    long long r=((long long(*)(void*,void*,void*,void*,void*,void*,void*))H_11170.addr)(a,b,c,d,e,f,g);
    printf("    > FUN_180011170 -> %lld (0x%llx)\n",r,(unsigned long long)r);patch(&H_11170);return r;}
static long long hk_cf0(void*a,void*b,void*c,void*d,void*e,void*f,void*g){unpatch(&H_cf0);
    long long r=((long long(*)(void*,void*,void*,void*,void*,void*,void*))H_cf0.addr)(a,b,c,d,e,f,g);
    printf("    > FUN_180035cf0 -> %lld (0x%llx)\n",r,(unsigned long long)r);patch(&H_cf0);return r;}

/* dump one buffer: header fields + pixel payload to <tag>.raw */
static void dump_buf(const char *tag, uint32_t *b){
    if(!b){ printf("  %s: (null)\n", tag); return; }
    printf("  %s @ %p: hdr[0]=%u size=%u [2]=%u w=%u h=%u [5]=%u [6]=%u [7]=%u [8]=%u\n",
        tag, (void*)b, b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7],b[8]);
    int sz = (int)b[1] - 0x18; if(sz<0) sz=0; if(sz>200000) sz=200000;
    char fn[128]; snprintf(fn,sizeof fn,"%s.raw",tag);
    FILE *f=fopen(fn,"wb"); if(f){ fwrite((unsigned char*)b+0x24,1,sz,f); fclose(f); printf("      wrote %s (%d bytes)\n",fn,sz); }
}

static void dump_all(const char *when, uint64_t inner){
    printf("--- buffers %s ---\n", when);
    uint32_t **arr = (uint32_t**)(inner + 0x10);
    for(int i=0;i<22;i++){
        char tag[64]; snprintf(tag,sizeof tag,"%s_b%02d", when, i);
        dump_buf(tag, arr[i]);
    }
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    const char *rawfile = (argc >= 2) ? argv[1] : "raw.bin";
    int target = (argc >= 3) ? atoi(argv[2]) : 11;
    int cmd    = (argc >= 4) ? atoi(argv[3]) : 1;
    int full   = (argc >= 5 && strcmp(argv[4], "full") == 0);

    HMODULE h = LoadLibraryA("fpc_enclave.dll");
    if (!h) { printf("LoadLibrary failed\n"); return 2; }
    g_base = (unsigned char *)h;
    fn_setup setup = (fn_setup)GetProcAddress(h, "fpc_setup_enclave");
    fn_init  init  = (fn_init) GetProcAddress(h, "FpcTaInitialize_ecall");
    fn_op    op    = (fn_op)   GetProcAddress(h, "FpcTaOp_ecall");
    void *tbl[8] = { ocall0, ocall0, ocall0, ocall0, ocall0, ocall0, ocall0, ocall0 };
    setup(tbl);
    printf("init -> %d\n", init(0x0300));

    install(&H_b4e0,  g_base + 0x4b4e0, hk_b4e0);
    install(&H_c570,  g_base + 0xc570,  hk_c570);
    install(&H_11170, g_base + 0x11170, hk_11170);
    install(&H_cf0,   g_base + 0x35cf0, hk_cf0);
    install(&H_memcpy,g_base + 0x70800, hk_memcpy);
    install(&H_1c810, g_base + 0x1c810, hk_1c810);

    static unsigned char in[65536], out[262144];
    #define OP(t,c) do{memset(in,0,sizeof in);memset(out,0,sizeof out);*(unsigned int*)(in+0)=(t);*(unsigned int*)(in+4)=(c);\
        int _r=op(in,sizeof in,out,sizeof out);printf("op(t=%d c=%d) -> %d out[8]=%u out[12]=%u\n",(t),(c),_r,*(unsigned int*)(out+8),*(unsigned int*)(out+12));}while(0)

    fn_fmi fmi = (fn_fmi)(g_base + 0x68470);
    unsigned char *cap = g_base + 0x1728e0;

    /* inject a raw file through the real capture path */
    #define INJECT(fn) do{ \
        FILE*_f=fopen(fn,"rb"); if(!_f){printf("no raw %s\n",fn);return 1;} \
        static unsigned char _raw[131072]; int _n=(int)fread(_raw,1,sizeof _raw,_f); fclose(_f); \
        memset(cap,0,0x22+11264); memcpy(cap+0x0c,_raw,_n); \
        g_log=1; int _r=fmi(8,&outv,11264); g_log=0; \
        printf("  inject(%s) n=%d fmi->%d\n",fn,_n,_r); }while(0)
    int outv = 0;

    OP(11,0); /* begin_enrol */

    if (argc >= 5 && strcmp(argv[4], "recon") == 0) {
        /* production path: begin -> inject -> enrol; hk_1c810 dumps the image */
        INJECT(rawfile);
        OP(11,1);   /* enrol / FpcBioEnrolAdd -> FUN_18001c810 */
        printf("== recon done ==\n");
        return 0;
    }

    if (argc >= 5 && strcmp(argv[4], "multi") == 0) {
        /* load empty template DB first, then enrol several frames */
        printf("--- load_empty_db ---\n"); OP(11,6);
        printf("--- begin_enrol ---\n"); OP(11,0);
        INJECT(rawfile);
        OP(11,1);
        for (int a=5; a<argc; a++) { printf("--- enrol add %s ---\n", argv[a]); INJECT(argv[a]); OP(11,1); }
        printf("--- end_enrol ---\n"); OP(11,2);
        printf("--- get_template_ids ---\n"); OP(11,7);
        printf("--- identify frame0 ---\n"); INJECT(rawfile); OP(11,3);
        if (argc >= 6) { printf("--- identify %s ---\n", argv[5]); INJECT(argv[5]); OP(11,3); }
        printf("== done ==\n");
        return 0;
    }

    if (full) {
        INJECT(rawfile);
        OP(11,1);   /* enrol / add */
        OP(11,2);   /* end_enrol */
        OP(11,7);   /* get_template_ids */
        printf("--- identify same frame ---\n");
        INJECT(rawfile);
        OP(11,3);   /* identify */
        if (argc >= 6) {
            printf("--- identify different frame (%s) ---\n", argv[5]);
            INJECT(argv[5]);
            OP(11,3);
        }
        printf("== done ==\n");
        return 0;
    }

    /* --- single-shot mode (default) --- */
    INJECT(rawfile);
    uint64_t img = *(uint64_t *)(g_base + 0x16f490);
    uint64_t inner = img ? *(uint64_t *)img : 0;
    printf("img=%p inner=%p\n",(void*)img,(void*)inner);

    fn_metaget mg = (fn_metaget)(g_base + 0x4b4e0);
    uint32_t **arr = (uint32_t**)(inner + 0x10);
    int idx=0; long long mr = mg(arr[0], 200, &idx);
    printf("key200 meta_get -> %lld idx=%d\n", mr, idx);

    dump_all("before", inner);

    printf("--- op ---\n");
    g_memlog = 1;
    OP(target, cmd);
    g_memlog = 0;

    idx=0; mr = mg(arr[0], 200, &idx);
    printf("after op: key200 -> %lld idx=%d\n", mr, idx);
    dump_all("after", inner);

    if (cmd != 7) OP(11, 7);
    printf("== done ==\n");
    return 0;
}
