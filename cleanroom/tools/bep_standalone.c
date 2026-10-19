/*
 * bep_standalone.c — run the clean-room BEP with no vendor code.
 *
 * Consumes a graph snapshot produced by `fpc_recon_native` (FPC_BEP_SNAP),
 * rebuilds the pointer graph, and calls cr_bep_process_1c810 directly.
 *
 * Usage:
 *   bep_standalone <snapshot> <out.raw> [oracle.raw]
 *
 * If an oracle image is given, the two are compared byte-for-byte.
 *
 * x86-64 only (the snapshot contains the vendor image data layout).
 */
#define _GNU_SOURCE
#include "fpc_bep.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define SNAP_MAGIC "BEPSNAP1"
#define MAX_BLOCKS 1024

typedef struct {
    uint64_t orig;
    uint32_t size;
    uint8_t *data;
    uint64_t neu;
} Blk;

static Blk blocks[MAX_BLOCKS];
static uint32_t nblocks;

static int read_all(FILE *f, void *p, size_t n)
{
    return fread(p, 1, n, f) == n;
}

static uint64_t relocate_value(uint64_t v)
{
    uint32_t i;

    for (i = 0; i < nblocks; i++)
        if (blocks[i].orig == v)
            return blocks[i].neu;
    return v;
}

static void relocate_block(Blk *b)
{
    uint32_t off;

    for (off = 0; off + 8 <= b->size; off += 8) {
        uint64_t v = *(uint64_t *)(b->data + off);
        uint64_t nv = relocate_value(v);

        if (nv != v)
            *(uint64_t *)(b->data + off) = nv;
    }
}

/* The metadata store keys d2..da mirror fields of the 22-byte image header. */
static void patch_metadata(uint64_t store_orig, const uint8_t *hdr)
{
    static const struct { uint32_t key, off, wide; } map[] = {
        { 0xd2, 4, 1 }, { 0xd3, 0, 0 }, { 0xd4, 6, 1 }, { 0xd5, 1, 0 },
        { 0xd6, 8, 1 }, { 0xd7, 2, 0 }, { 0xda, 3, 0 },
    };
    uint32_t i;

    for (i = 0; i < nblocks; i++) {
        uint8_t *b = blocks[i].data;
        uint32_t used, p;
        size_t k;

        if (blocks[i].orig != store_orig)
            continue;
        used = *(uint32_t *)(b + 8);
        for (p = 0x0c; p + 12 <= 0x0c + used; p += 12) {
            uint32_t key = *(uint32_t *)(b + p);
            uint32_t sz = *(uint32_t *)(b + p + 4);
            uint32_t *val = (uint32_t *)(b + p + 8);

            for (k = 0; k < sizeof map / sizeof map[0]; k++)
                if (map[k].key == key) {
                    *val = map[k].wide
                         ? *(const uint16_t *)(hdr + map[k].off)
                         : hdr[map[k].off];
                    printf("meta 0x%x <- %#x\n", key, *val);
                }
            if (sz != 4)
                break;
        }
        return;
    }
}

int main(int argc, char **argv)
{
    FILE *f;
    char magic[8];
    uint32_t img_size, i;
    uint64_t image_base;
    uint64_t roots[5];
    int32_t a6;
    uint8_t *image;
    uint8_t *a1;
    void *a2, *a3, **a4, *a5;
    int rc;
    uint64_t pix;
    int32_t w, h;
    FILE *out;

    if (argc < 3) {
        fprintf(stderr, "usage: %s <snapshot> <out.raw> [oracle.raw]\n", argv[0]);
        return 2;
    }

    f = fopen(argv[1], "rb");
    if (!f) {
        perror("snapshot");
        return 1;
    }
    if (!read_all(f, magic, 8) || memcmp(magic, SNAP_MAGIC, 8) != 0) {
        fprintf(stderr, "bad snapshot magic\n");
        fclose(f);
        return 1;
    }
    if (!read_all(f, &nblocks, 4) ||
        !read_all(f, &img_size, 4) ||
        !read_all(f, &image_base, 8) ||
        !read_all(f, roots, sizeof roots) ||
        !read_all(f, &a6, 4)) {
        fprintf(stderr, "truncated snapshot header\n");
        fclose(f);
        return 1;
    }
    {
        uint32_t pad;

        if (!read_all(f, &pad, 4)) {
            fclose(f);
            return 1;
        }
    }
    if (nblocks > MAX_BLOCKS) {
        fprintf(stderr, "too many blocks (%u)\n", nblocks);
        fclose(f);
        return 1;
    }

    image = malloc(img_size);
    if (!image || !read_all(f, image, img_size)) {
        fprintf(stderr, "cannot read image\n");
        fclose(f);
        return 1;
    }
    g_cr_image_base = (uintptr_t)image;

    for (i = 0; i < nblocks; i++) {
        uint32_t size, pad;

        if (!read_all(f, &blocks[i].orig, 8) ||
            !read_all(f, &size, 4) ||
            !read_all(f, &pad, 4)) {
            fprintf(stderr, "truncated block header %u\n", i);
            fclose(f);
            return 1;
        }
        blocks[i].size = size;
        blocks[i].data = malloc(size ? size : 1);
        if (!blocks[i].data || !read_all(f, blocks[i].data, size)) {
            fprintf(stderr, "truncated block %u\n", i);
            fclose(f);
            return 1;
        }
        blocks[i].neu = (uint64_t)(uintptr_t)blocks[i].data;
    }
    fclose(f);

    /* Optional: prove the large scratch buffers need not be captured. */
    if (getenv("CR_ZERO_SCRATCH")) {
        uint64_t pix = 0;
        uint32_t j;

        for (i = 0; i < nblocks; i++) {
            if (blocks[i].orig == roots[3]) {
                uint64_t pb = *(uint64_t *)blocks[i].data;

                for (j = 0; j < nblocks; j++)
                    if (blocks[j].orig == pb)
                        pix = *(uint64_t *)(blocks[j].data + 0x10);
                break;
            }
        }
        for (i = 0; i < nblocks; i++) {
            if (blocks[i].size >= 0x8000 && blocks[i].orig != pix) {
                printf("zeroing block %u (%#x bytes)\n", i, blocks[i].size);
                memset(blocks[i].data, 0, blocks[i].size);
            }
        }
    }

    /* Optional: replace the captured frame with a fresh raw frame. */
    if (getenv("CR_FRAME")) {
        FILE *rf = fopen(getenv("CR_FRAME"), "rb");
        uint8_t *raw = malloc(20000);
        size_t rn;
        uint8_t hdr[22];
        uint64_t pix = 0, store = 0;
        uint32_t j;

        if (!rf || !raw) {
            perror("frame");
            return 1;
        }
        rn = fread(raw, 1, 20000, rf);
        fclose(rf);
        if (rn > 11264) {          /* 22-byte image header */
            memcpy(hdr, raw, 22);
            memmove(raw, raw + 22, rn - 22);
            rn -= 22;
        } else {
            memset(hdr, 0, sizeof hdr);
        }
        for (i = 0; i < nblocks; i++)
            if (blocks[i].orig == roots[3]) {
                uint64_t pb = *(uint64_t *)blocks[i].data;

                store = *(uint64_t *)(blocks[i].data + 0x38);
                for (j = 0; j < nblocks; j++)
                    if (blocks[j].orig == pb)
                        pix = *(uint64_t *)(blocks[j].data + 0x10);
                break;
            }
        for (i = 0; i < nblocks; i++)
            if (blocks[i].orig == pix) {
                if (rn != blocks[i].size && rn != 11264) {
                    fprintf(stderr, "frame size %zu unexpected\n", rn);
                    return 1;
                }
                memcpy(blocks[i].data, raw, 11264);
                printf("patched frame %s (%zu bytes)\n", getenv("CR_FRAME"), rn);
            }
        if (store)
            patch_metadata(store, hdr);
        free(raw);
    }

    /* Rebuild pointers inside every block. */
    for (i = 0; i < nblocks; i++)
        relocate_block(&blocks[i]);

    a1 = (uint8_t *)(uintptr_t)relocate_value(roots[0]);
    a2 = (void *)(uintptr_t)relocate_value(roots[1]);
    a3 = (void *)(uintptr_t)relocate_value(roots[2]);
    a4 = (void **)(uintptr_t)relocate_value(roots[3]);
    a5 = (void *)(uintptr_t)relocate_value(roots[4]);

    printf("blocks=%u image=%u base=%#llx\n", nblocks, img_size,
           (unsigned long long)image_base);
    printf("a1=%p a2=%p a3=%p a4=%p a5=%p a6=%d\n", a1, a2, a3, a4, a5, a6);
    printf("a2[0]=%p a4[0..4]=%p %p %p %p %p\n",
           *(void **)a2, a4[0], a4[1], a4[2], a4[3], a4[4]);
    if (a4[0]) {
        const uint8_t *p = a4[0];

        printf("slot0 w=%d h=%d data=%p\n",
               *(const int16_t *)(p + 0), *(const int16_t *)(p + 2),
               *(void *const *)(p + 0x10));
    }
    {
        const uint8_t *st = a3;
        const uint8_t *cfg = *(uint8_t *const *)((const uint8_t *)a5 + 0x28);
        int k;

        printf("a3[0..0x20]:");
        for (k = 0; k < 0x20; k++)
            printf(" %02x", st[k]);
        printf("\ncfg[0x108]=%u cfg[0x78]=%u\n", cfg[0x108], cfg[0x78]);
    }

    rc = cr_bep_process_1c810(a1, a2, a3, a4, a5, a6);
    printf("cr_bep_process_1c810 -> %d\n", rc);

    pix = *(uint64_t *)(a1 + 0x18);
    w = *(int32_t *)(a1 + 0x20);
    h = *(int32_t *)(a1 + 0x24);
    printf("out_img=%p %dx%d hdr=%#x\n", (void *)(uintptr_t)pix, w, h,
           *(uint32_t *)a1);

    if (pix == 0 || w <= 0 || h <= 0) {
        fprintf(stderr, "no output image\n");
        return 1;
    }

    out = fopen(argv[2], "wb");
    if (!out) {
        perror("out");
        return 1;
    }
    if (fwrite((void *)(uintptr_t)pix, 1, (size_t)w * h, out) != (size_t)w * h) {
        fprintf(stderr, "short write\n");
        fclose(out);
        return 1;
    }
    fclose(out);
    printf("wrote %s (%d bytes)\n", argv[2], w * h);

    if (argc >= 4) {
        FILE *o = fopen(argv[3], "rb");
        uint8_t *ref;
        size_t n, got;

        if (!o) {
            perror("oracle");
            return 1;
        }
        ref = malloc((size_t)w * h);
        n = fread(ref, 1, (size_t)w * h, o);
        got = (size_t)w * h;
        fclose(o);
        if (n != got) {
            fprintf(stderr, "oracle size mismatch (%zu vs %zu)\n", n, got);
            return 1;
        }
        if (memcmp(ref, (void *)(uintptr_t)pix, got) == 0) {
            printf("PARITY OK (%zu bytes byte-identical)\n", got);
            return 0;
        } else {
            size_t k, diff = 0;

            for (k = 0; k < got; k++)
                if (ref[k] != ((uint8_t *)(uintptr_t)pix)[k])
                    diff++;
            printf("PARITY FAIL (%zu/%zu bytes differ)\n", diff, got);
            return 1;
        }
    }

    return 0;
}
