/*
 * fpc_match_tool.c — command line front-end for the ridge-image matcher.
 *
 *   fpc_match_tool A.raw B.raw              score one pair
 *   fpc_match_tool --gallery DIR PROBE.raw  best score against every *.raw in DIR
 *   fpc_match_tool --matrix DIR             full score matrix (CSV)
 *
 * Images are 64x176 8-bit grayscale (the BEP reconstruction output).
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#include "fpc_match.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint8_t *load_raw(const char *path, int *w, int *h)
{
    FILE *f = fopen(path, "rb");
    long n;
    uint8_t *b;

    if (!f) {
        perror(path);
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n != FPC_TPL_PIXELS) {
        fprintf(stderr, "%s: expected %d bytes, got %ld\n",
                path, FPC_TPL_PIXELS, n);
        fclose(f);
        return NULL;
    }
    b = malloc((size_t)n);
    if (!b || fread(b, 1, (size_t)n, f) != (size_t)n) {
        free(b);
        fclose(f);
        return NULL;
    }
    fclose(f);
    *w = FPC_TPL_W;
    *h = FPC_TPL_H;
    return b;
}

static int build(const char *path, fpc_tpl *tpl)
{
    int w, h;
    uint8_t *img = load_raw(path, &w, &h);
    int r;

    if (!img)
        return -1;
    r = fpc_tpl_build(img, w, h, tpl);
    free(img);
    if (r) {
        fprintf(stderr, "%s: no usable ridge area\n", path);
        return -1;
    }
    return 0;
}

static int cmp_str(const void *a, const void *b)
{
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

static char **list_raw(const char *dir, int *count)
{
    DIR *d = opendir(dir);
    struct dirent *e;
    char **v = NULL;
    int n = 0, cap = 0;

    if (!d) {
        perror(dir);
        return NULL;
    }
    while ((e = readdir(d))) {
        size_t len = strlen(e->d_name);
        char *p;
        if (len < 5 || strcmp(e->d_name + len - 4, ".raw") != 0)
            continue;
        if (n == cap) {
            cap = cap ? cap * 2 : 32;
            v = realloc(v, (size_t)cap * sizeof *v);
        }
        p = malloc(strlen(dir) + len + 2);
        sprintf(p, "%s/%s", dir, e->d_name);
        v[n++] = p;
    }
    closedir(d);
    if (v)
        qsort(v, (size_t)n, sizeof *v, cmp_str);
    *count = n;
    return v;
}

int main(int argc, char **argv)
{
    if (argc == 3 && strcmp(argv[1], "--matrix") != 0) {
        fpc_tpl a, b;
        if (build(argv[1], &a) || build(argv[2], &b))
            return 1;
        printf("%s vs %s: score=%d (coverage %u%% / %u%%)\n",
               argv[1], argv[2], fpc_tpl_match(&a, &b),
               a.coverage, b.coverage);
        return 0;
    }
    if (argc == 4 && strcmp(argv[1], "--gallery") == 0) {
        int n, i, best_i = -1;
        char **files = list_raw(argv[2], &n);
        fpc_tpl probe, *gal;
        int best;

        if (!files || n == 0)
            return 1;
        gal = calloc((size_t)n, sizeof *gal);
        if (!gal)
            return 1;
        for (i = 0; i < n; i++) {
            if (build(files[i], &gal[i])) {
                fprintf(stderr, "skip %s\n", files[i]);
                gal[i].coverage = 0;
            }
        }
        if (build(argv[3], &probe))
            return 1;
        best = fpc_tpl_match_gallery(&probe, gal, n, &best_i);
        printf("probe %s: best=%d", argv[3], best);
        if (best_i >= 0)
            printf(" (%s)", files[best_i]);
        printf("  threshold=%d -> %s\n", FPC_MATCH_THRESHOLD,
               best >= FPC_MATCH_THRESHOLD ? "MATCH" : "NO MATCH");
        return 0;
    }
    if (argc == 3 && strcmp(argv[1], "--matrix") == 0) {
        int n, i, j;
        char **files = list_raw(argv[2], &n);
        fpc_tpl *t;

        if (!files || n == 0)
            return 1;
        t = calloc((size_t)n, sizeof *t);
        if (!t)
            return 1;
        for (i = 0; i < n; i++)
            build(files[i], &t[i]);
        printf(",");
        for (j = 0; j < n; j++)
            printf("%s%c", files[j], j + 1 < n ? ',' : '\n');
        for (i = 0; i < n; i++) {
            printf("%s", files[i]);
            for (j = 0; j < n; j++)
                printf(",%d", i == j ? 1000 : fpc_tpl_match(&t[i], &t[j]));
            printf("\n");
        }
        return 0;
    }
    fprintf(stderr,
            "usage: %s A.raw B.raw\n"
            "       %s --gallery DIR PROBE.raw\n"
            "       %s --matrix DIR\n", argv[0], argv[0], argv[0]);
    return 2;
}
