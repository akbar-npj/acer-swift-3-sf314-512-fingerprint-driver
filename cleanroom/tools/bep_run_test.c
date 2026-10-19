/*
 * bep_run_test.c — exercise cr_bep_run_frame() against a captured oracle.
 *
 *   bep_run_test <frame.raw> <out.raw> [oracle.raw]
 *
 * The frame file may include the 22-byte sensor header (11286 bytes) or be
 * the bare 11264-byte pixel plane.
 */
#include "fpc_bep.h"
#include "fpc_bep_template.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/mman.h>
#include <unistd.h>

static void probe_handler(int sig, siginfo_t *si, void *ctx)
{
    (void)sig;
    (void)ctx;
    dprintf(2, "PROBE fault at rva %#lx\n",
            (unsigned long)((uintptr_t)si->si_addr - g_cr_image_base));
    _exit(3);
}

static uint8_t *probe_image(void)
{
    long pg = sysconf(_SC_PAGESIZE);
    size_t size = (cr_bep_image_size + pg - 1) / pg * pg;
    uint8_t *im = mmap(NULL, size, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    int i;

    if (im == MAP_FAILED)
        return NULL;
    for (i = 0; i < cr_bep_static_count; i++)
        memcpy(im + cr_bep_static[i].rva, cr_bep_static[i].data,
               cr_bep_static[i].size);

    /* Guard every page that is not fully covered by a region. */
    for (size_t off = 0; off < cr_bep_image_size; off += pg) {
        int covered = 0;

        for (i = 0; i < cr_bep_static_count; i++)
            if (off < cr_bep_static[i].rva + cr_bep_static[i].size &&
                off + pg > cr_bep_static[i].rva)
                covered = 1;
        if (!covered)
            mprotect(im + off, pg, PROT_NONE);
    }
    return im;
}


int main(int argc, char **argv)
{
    FILE *f;
    uint8_t buf[12000], out[11264];
    size_t n;
    const uint8_t *hdr = NULL, *pix;
    int rc;

    if (argc < 3) {
        fprintf(stderr, "usage: %s <frame.raw> <out.raw> [oracle.raw]\n",
                argv[0]);
        return 2;
    }
    f = fopen(argv[1], "rb");
    if (!f) {
        perror("frame");
        return 1;
    }
    n = fread(buf, 1, sizeof buf, f);
    fclose(f);
    if (n == 11286) {
        hdr = buf;
        pix = buf + 22;
    } else if (n == 11264) {
        pix = buf;
    } else {
        fprintf(stderr, "unexpected frame size %zu\n", n);
        return 1;
    }

    if (getenv("CR_PROBE")) {
        struct sigaction sa;

        memset(&sa, 0, sizeof sa);
        sa.sa_sigaction = probe_handler;
        sa.sa_flags = SA_SIGINFO;
        sigaction(SIGSEGV, &sa, NULL);
        g_cr_image_base = (uintptr_t)probe_image();
        if (!g_cr_image_base) {
            perror("mmap");
            return 1;
        }
    }

    if (getenv("CR_IMAGE")) {
        FILE *imf = fopen(getenv("CR_IMAGE"), "rb");
        long sz;
        uint8_t *im;

        if (!imf) {
            perror("image");
            return 1;
        }
        fseek(imf, 0, SEEK_END);
        sz = ftell(imf);
        fseek(imf, 0, SEEK_SET);
        im = calloc(1, (size_t)sz);
        if (!im || fread(im, 1, (size_t)sz, imf) != (size_t)sz) {
            fprintf(stderr, "short image\n");
            return 1;
        }
        fclose(imf);
        g_cr_image_base = (uintptr_t)im;
    }

    rc = cr_bep_run_frame(hdr, pix, out);
    printf("cr_bep_run_frame -> %d\n", rc);
    if (rc != 0)
        return 1;

    f = fopen(argv[2], "wb");
    if (!f) {
        perror("out");
        return 1;
    }
    fwrite(out, 1, sizeof out, f);
    fclose(f);

    if (argc >= 4) {
        uint8_t ref[11264];
        FILE *o = fopen(argv[3], "rb");
        size_t rn;

        if (!o) {
            perror("oracle");
            return 1;
        }
        rn = fread(ref, 1, sizeof ref, o);
        fclose(o);
        if (rn != sizeof ref) {
            fprintf(stderr, "oracle size %zu\n", rn);
            return 1;
        }
        if (memcmp(ref, out, sizeof out) == 0) {
            printf("PARITY OK (11264 bytes byte-identical)\n");
            return 0;
        }
        {
            size_t k, diff = 0;

            for (k = 0; k < sizeof out; k++)
                if (ref[k] != out[k])
                    diff++;
            printf("PARITY FAIL (%zu/11264 bytes differ)\n", diff);
            return 1;
        }
    }
    return 0;
}
