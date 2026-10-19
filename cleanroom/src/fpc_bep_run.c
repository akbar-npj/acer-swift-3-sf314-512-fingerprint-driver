/*
 * fpc_bep_run.c — DLL-free entry point for the clean-room BEP.
 *
 * Rebuilds the captured input graph, drops in one frame, and calls
 * cr_bep_process_1c810.  No vendor code is involved.
 */
#include "fpc_bep.h"
#include "fpc_bep_template.h"

#include <stdlib.h>
#include <string.h>

#define MAX_TPL 64

/* The metadata store mirrors seven fields of the 22-byte image header. */
static void patch_meta(uint8_t *store, const uint8_t *hdr)
{
    static const struct { uint32_t key, off, wide; } map[] = {
        { 0xd2, 4, 1 }, { 0xd3, 0, 0 }, { 0xd4, 6, 1 }, { 0xd5, 1, 0 },
        { 0xd6, 8, 1 }, { 0xd7, 2, 0 }, { 0xda, 3, 0 },
    };
    uint32_t used = *(const uint32_t *)(store + 8);
    uint32_t p;
    size_t k;

    for (p = 0x0c; p + 12 <= 0x0c + used; p += 12) {
        uint32_t key = *(const uint32_t *)(store + p);
        uint32_t sz = *(const uint32_t *)(store + p + 4);
        uint32_t *val = (uint32_t *)(store + p + 8);

        for (k = 0; k < sizeof map / sizeof map[0]; k++)
            if (map[k].key == key)
                *val = map[k].wide
                     ? *(const uint16_t *)(hdr + map[k].off)
                     : hdr[map[k].off];
        if (sz != 4)
            break;
    }
}

/* Rebuild the sparse vendor image holding the static tables the BEP reads. */
static int ensure_image(void)
{
    uint8_t *img;
    int i;

    if (g_cr_image_base)
        return 0;
    img = calloc(1, cr_bep_image_size);
    if (!img)
        return -1;
    for (i = 0; i < cr_bep_static_count; i++) {
        const cr_bep_region *r = &cr_bep_static[i];

        memcpy(img + r->rva, r->data, r->size);
    }
    g_cr_image_base = (uintptr_t)img;
    return 0;
}

int cr_bep_run_frame(const uint8_t *hdr22, const uint8_t *pix, uint8_t *out)
{
    static const uint8_t zero_hdr[22];
    uint8_t *blk[MAX_TPL];
    int i, rc;
    uint8_t *a1, *a4, *frame, *img;
    int32_t w, h;

    if (cr_bep_template_count > MAX_TPL)
        return -1;
    if (ensure_image() != 0)
        return -1;

    memset(blk, 0, sizeof blk);
    for (i = 0; i < cr_bep_template_count; i++) {
        const cr_bep_blk *b = &cr_bep_template[i];

        blk[i] = calloc(1, b->size ? b->size : 1);
        if (!blk[i]) {
            rc = -1;
            goto out;
        }
        if (b->data)
            memcpy(blk[i], b->data, b->size);
    }

    for (i = 0; i < cr_bep_template_count; i++) {
        const cr_bep_blk *b = &cr_bep_template[i];
        uint16_t k;

        for (k = 0; k < b->nptr; k++)
            *(uint64_t *)(blk[i] + b->ptr[k].off) =
                (uint64_t)(uintptr_t)blk[b->ptr[k].tgt];
    }

    a1 = blk[cr_bep_template_a1];
    a4 = blk[cr_bep_template_a4];
    frame = blk[cr_bep_template_frame];

    patch_meta(blk[cr_bep_template_meta], hdr22 ? hdr22 : zero_hdr);
    memcpy(frame, pix, 11264);

    rc = cr_bep_process_1c810(a1, blk[cr_bep_template_a2],
                              blk[cr_bep_template_a3], (void **)a4,
                              blk[cr_bep_template_a5],
                              cr_bep_template_a6);

    if (rc == 0 && out) {
        img = *(uint8_t **)(a1 + 0x18);
        w = *(int32_t *)(a1 + 0x20);
        h = *(int32_t *)(a1 + 0x24);
        if (img && w > 0 && h > 0)
            memcpy(out, img, (size_t)w * h);
        else
            rc = -1;
    }

out:
    for (i = 0; i < cr_bep_template_count; i++)
        free(blk[i]);
    return rc;
}
