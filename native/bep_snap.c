/*
 * bep_snap.c — dump the live BEP input graph for standalone replay.
 *
 * Format (little-endian):
 *   char magic[8] = "BEPSNAP1"
 *   u32  nblocks
 *   u32  img_size
 *   u64  image_base
 *   u64  roots[5]        (a1..a5)
 *   i64  a6
 *   u8   img[img_size]   (copy of the mapped vendor image data)
 *   per block: u64 addr, u32 size, u32 pad, u8 data[size]
 */
#define _GNU_SOURCE
#include "bep_snap.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_BLOCKS 1024
#define MAX_MAPS   512
#define SNAP_MAGIC "BEPSNAP1"

typedef struct { uintptr_t lo, hi; } MapRange;

static MapRange g_maps[MAX_MAPS];
static int g_nmaps;

static void load_maps(void)
{
    FILE *f = fopen("/proc/self/maps", "r");
    char line[512];

    g_nmaps = 0;
    if (!f)
        return;
    while (fgets(line, sizeof line, f) && g_nmaps < MAX_MAPS) {
        unsigned long lo, hi;
        if (sscanf(line, "%lx-%lx", &lo, &hi) == 2) {
            g_maps[g_nmaps].lo = (uintptr_t)lo;
            g_maps[g_nmaps].hi = (uintptr_t)hi;
            g_nmaps++;
        }
    }
    fclose(f);
}

static int mapped(uintptr_t a, size_t n)
{
    int i;

    if (a == 0 || n == 0)
        return 0;
    if (a + n < a)
        return 0;
    for (i = 0; i < g_nmaps; i++)
        if (a >= g_maps[i].lo && a + n <= g_maps[i].hi)
            return 1;
    return 0;
}

typedef struct {
    uintptr_t addr;
    uint32_t size;   /* bytes dumped/allocated */
    uint32_t scan;   /* bytes scanned for pointers (<= size) */
} Blk;

static Blk g_blk[MAX_BLOCKS];
static int g_nblk;
static uintptr_t g_img_lo, g_img_hi;

static int have_blk(uintptr_t a)
{
    int i;

    for (i = 0; i < g_nblk; i++)
        if (g_blk[i].addr == a)
            return 1;
    return 0;
}

static void add_blk(uintptr_t a, uint32_t size, uint32_t scan)
{
    int i;

    if (a == 0 || g_nblk >= MAX_BLOCKS || have_blk(a))
        return;
    if (!mapped(a, 8))
        return;

    /* Clamp to the end of the containing mapping.  Unknown blocks get a
     * generous size because the mask bank holds 64x176 (11264-byte) images
     * and a too-small block would be overrun by the BEP. */
    for (i = 0; i < g_nmaps; i++) {
        if (a >= g_maps[i].lo && a < g_maps[i].hi) {
            uintptr_t avail = g_maps[i].hi - a;

            if (size > avail)
                size = (uint32_t)avail;
            break;
        }
    }
    if (size < 8)
        size = 8;
    if (scan > size)
        scan = size;

    g_blk[g_nblk].addr = a;
    g_blk[g_nblk].size = size;
    g_blk[g_nblk].scan = scan;
    g_nblk++;
}

static int is_image_ptr(uintptr_t v)
{
    return v >= g_img_lo && v < g_img_hi;
}

static void walk(uintptr_t a, uint32_t size, uint32_t scan, int depth)
{
    uint32_t off;
    int before;

    if (depth > 4 || a == 0 || g_nblk >= MAX_BLOCKS)
        return;
    add_blk(a, size, scan);
    if (!mapped(a, size))
        return;
    if (scan > size)
        scan = size;

    before = g_nblk;
    for (off = 0; off + 8 <= scan; off += 8) {
        uintptr_t v = *(uintptr_t *)(a + off);

        if (v < 0x10000 || v >= 0x800000000000ULL)
            continue;
        if (is_image_ptr(v))
            continue;
        if (!mapped(v, 8))
            continue;
        add_blk(v, 0x10000, 0x200);
    }

    /* Recurse into newly discovered blocks (they may point further). */
    for (; before < g_nblk; before++)
        walk(g_blk[before].addr, g_blk[before].size,
             g_blk[before].scan, depth + 1);
}

static int write_all(FILE *f, const void *p, size_t n)
{
    return fwrite(p, 1, n, f) == n;
}

int bep_snap_dump(const char *path,
                  void *a1, void *a2, void *a3, void **a4, void *a5, int a6,
                  uintptr_t image_base)
{
    FILE *f;
    uint32_t nblocks, img_size = 0x17d000;
    uint64_t roots[5];
    uint64_t ib = (uint64_t)image_base;
    int i;

    load_maps();
    g_nblk = 0;
    g_img_lo = image_base;
    g_img_hi = image_base + img_size;

    /* Explicit seeds with known struct sizes. */
    add_blk((uintptr_t)a1, 0x90, 0x90);      /* result struct */
    add_blk((uintptr_t)a2, 0x20, 0x20);
    add_blk((uintptr_t)a3, 0x100, 0x100);
    add_blk((uintptr_t)a4, 0x80, 0x80);
    add_blk((uintptr_t)a5, 0x40, 0x40);

    if (a2 && mapped((uintptr_t)a2, 8))
        add_blk(*(uintptr_t *)a2, 0x80, 0x80);   /* image descriptor */
    if (a5) {
        uintptr_t flg = *(uintptr_t *)((uint8_t *)a5 + 0x10);
        uintptr_t cfg = *(uintptr_t *)((uint8_t *)a5 + 0x28);

        add_blk(flg, 0x40, 0x40);
        add_blk(cfg, 0x300, 0x300);
    }
    if (a4) {
        for (i = 0; i < 5; i++) {
            uintptr_t p = (uintptr_t)a4[i];

            if (p && !is_image_ptr(p))
                add_blk(p, 0x18, 0x18);          /* cr_pixbuf */
        }
        /* slots[7] is the TLV metadata store read by cr_meta_get_u32.
         * Layout: {u32 type; u32 capacity; u32 used; records...}.  Size it
         * from the capacity word so keys 0xd2/0xd6/0xda/0xdd are captured. */
        {
            uintptr_t m = (uintptr_t)a4[7];

            if (m && !is_image_ptr(m) && mapped(m, 0xc)) {
                uint32_t cap = *(const uint32_t *)(m + 4);

                add_blk(m, 0xc + cap, 0xc + cap);
            }
        }
    }

    /* Walk each seed. */
    for (i = 0; i < g_nblk; i++)
        walk(g_blk[i].addr, g_blk[i].size, g_blk[i].scan, 0);

    f = fopen(path, "wb");
    if (!f) {
        perror("[snap] fopen");
        return -1;
    }

    nblocks = (uint32_t)g_nblk;
    roots[0] = (uint64_t)(uintptr_t)a1;
    roots[1] = (uint64_t)(uintptr_t)a2;
    roots[2] = (uint64_t)(uintptr_t)a3;
    roots[3] = (uint64_t)(uintptr_t)a4;
    roots[4] = (uint64_t)(uintptr_t)a5;

    if (!write_all(f, SNAP_MAGIC, 8) ||
        !write_all(f, &nblocks, 4) ||
        !write_all(f, &img_size, 4) ||
        !write_all(f, &ib, 8) ||
        !write_all(f, roots, sizeof roots) ||
        !write_all(f, &a6, 4)) {
        fclose(f);
        return -1;
    }
    /* a6 is stored as i32; pad to keep the image 8-byte aligned. */
    {
        uint32_t pad = 0;

        if (!write_all(f, &pad, 4)) {
            fclose(f);
            return -1;
        }
    }

    if (mapped(image_base, img_size)) {
        if (!write_all(f, (const void *)image_base, img_size)) {
            fclose(f);
            return -1;
        }
    } else {
        fclose(f);
        fprintf(stderr, "[snap] image range not mapped\n");
        return -1;
    }

    for (i = 0; i < g_nblk; i++) {
        uint32_t size = g_blk[i].size;
        uint32_t pad = 0;

        if (!write_all(f, &g_blk[i].addr, 8) ||
            !write_all(f, &size, 4) ||
            !write_all(f, &pad, 4) ||
            !write_all(f, (const void *)g_blk[i].addr, size)) {
            fclose(f);
            return -1;
        }
    }

    fclose(f);
    printf("[snap] wrote %s (%u blocks, %u-byte image)\n", path, nblocks, img_size);
    return 0;
}
