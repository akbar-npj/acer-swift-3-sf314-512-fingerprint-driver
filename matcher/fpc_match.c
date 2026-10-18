/*
 * fpc_match.c — masked correlation matcher for FPC 2040 ridge images.
 *
 * See fpc_match.h for the rationale.  No external dependencies beyond libm;
 * this file is meant to be linked into the libfprint driver as well as the
 * standalone tools.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#include "fpc_match.h"

#include <math.h>
#include <stdlib.h>
#include <string.h>

#define MAXW 64
#define MAXH 176

/* ------------------------------------------------------------------ */
/* small helpers                                                      */
/* ------------------------------------------------------------------ */

static float clampf(float v, float lo, float hi)
{
    return v < lo ? lo : (v > hi ? hi : v);
}

/* Separable gaussian blur, edge-clamped, into a caller buffer. */
static void gauss_blur(const float *src, float *dst, int w, int h, float sigma)
{
    int r = (int)ceilf(3.0f * sigma);
    int n = 2 * r + 1;
    float *k = malloc((size_t)n * sizeof *k);
    float *tmp = malloc((size_t)w * h * sizeof *tmp);
    float sum = 0.0f;
    int i, x, y;

    for (i = 0; i < n; i++) {
        float d = (float)(i - r);
        k[i] = expf(-0.5f * d * d / (sigma * sigma));
        sum += k[i];
    }
    for (i = 0; i < n; i++)
        k[i] /= sum;

    /* horizontal */
    for (y = 0; y < h; y++) {
        const float *row = src + (size_t)y * w;
        float *out = tmp + (size_t)y * w;
        for (x = 0; x < w; x++) {
            float acc = 0.0f;
            for (i = -r; i <= r; i++) {
                int xx = x + i;
                xx = xx < 0 ? 0 : (xx >= w ? w - 1 : xx);
                acc += row[xx] * k[i + r];
            }
            out[x] = acc;
        }
    }
    /* vertical */
    for (y = 0; y < h; y++) {
        float *out = dst + (size_t)y * w;
        for (x = 0; x < w; x++) {
            float acc = 0.0f;
            for (i = -r; i <= r; i++) {
                int yy = y + i;
                yy = yy < 0 ? 0 : (yy >= h ? h - 1 : yy);
                acc += tmp[(size_t)yy * w + x] * k[i + r];
            }
            out[x] = acc;
        }
    }
    free(tmp);
    free(k);
}

/* Box mean over a (2r+1)^2 window, edge-clamped. */
static void box_mean(const float *src, float *dst, int w, int h, int r)
{
    int x, y, i, j;
    for (y = 0; y < h; y++) {
        for (x = 0; x < w; x++) {
            float acc = 0.0f;
            int cnt = 0;
            for (j = -r; j <= r; j++) {
                int yy = y + j;
                yy = yy < 0 ? 0 : (yy >= h ? h - 1 : yy);
                for (i = -r; i <= r; i++) {
                    int xx = x + i;
                    xx = xx < 0 ? 0 : (xx >= w ? w - 1 : xx);
                    acc += src[(size_t)yy * w + xx];
                    cnt++;
                }
            }
            dst[(size_t)y * w + x] = acc / (float)cnt;
        }
    }
}

static inline int mask_get(const uint8_t *m, int idx)
{
    return (m[idx >> 3] >> (idx & 7)) & 1;
}

static inline void mask_set(uint8_t *m, int idx, int v)
{
    if (v)
        m[idx >> 3] |= (uint8_t)(1u << (idx & 7));
    else
        m[idx >> 3] &= (uint8_t)~(1u << (idx & 7));
}

/* ------------------------------------------------------------------ */
/* template construction                                              */
/* ------------------------------------------------------------------ */

int fpc_tpl_build(const uint8_t *img, int w, int h, fpc_tpl *out)
{
    int n = w * h, i;
    float *f = malloc((size_t)n * sizeof *f);
    float *blur = malloc((size_t)n * sizeof *blur);
    float *hp = malloc((size_t)n * sizeof *hp);
    float *lm = malloc((size_t)n * sizeof *lm);
    float *lv = malloc((size_t)n * sizeof *lv);
    float *e = malloc((size_t)n * sizeof *e);
    float mean = 0.0f, var = 0.0f;
    int cnt = 0;

    if (!f || !blur || !hp || !lm || !lv || !e) {
        free(f); free(blur); free(hp); free(lm); free(lv); free(e);
        return -1;
    }

    for (i = 0; i < n; i++)
        f[i] = (float)img[i];

    /* hp = img - gaussian(img, 7)  (removes shading, keeps ~11 px ridges) */
    gauss_blur(f, blur, w, h, 7.0f);
    for (i = 0; i < n; i++)
        hp[i] = f[i] - blur[i];
    /* gentle denoise */
    gauss_blur(hp, blur, w, h, 0.8f);
    memcpy(hp, blur, (size_t)n * sizeof *hp);

    /* local mean / variance over 15x15 */
    box_mean(hp, lm, w, h, 7);
    {
        float *sq = malloc((size_t)n * sizeof *sq);
        if (!sq) { free(f); free(blur); free(hp); free(lm); free(lv); free(e); return -1; }
        for (i = 0; i < n; i++)
            sq[i] = hp[i] * hp[i];
        box_mean(sq, lv, w, h, 7);
        free(sq);
    }

    /* usable-ridge mask: local high-pass energy > 4.0 */
    {
        float *sq = malloc((size_t)n * sizeof *sq);
        if (!sq) { free(f); free(blur); free(hp); free(lm); free(lv); free(e); return -1; }
        for (i = 0; i < n; i++)
            sq[i] = hp[i] * hp[i];
        box_mean(sq, e, w, h, 4);
        free(sq);
    }

    memset(out, 0, sizeof *out);
    out->w = (uint8_t)w;
    out->h = (uint8_t)h;

    for (i = 0; i < n; i++) {
        float v = (hp[i] - lm[i]) / sqrtf(fmaxf(lv[i], 1e-3f));
        if (e[i] > 4.0f) {
            mask_set(out->mask, i, 1);
            out->z[i] = (int8_t)clampf(rintf(v * 32.0f), -127.0f, 127.0f);
            mean += v;
            cnt++;
        } else {
            out->z[i] = 0;
        }
    }
    if (cnt < 200) {
        free(f); free(blur); free(hp); free(lm); free(lv); free(e);
        return -1;
    }
    mean /= (float)cnt;
    for (i = 0; i < n; i++) {
        if (mask_get(out->mask, i)) {
            float d = (float)out->z[i] / 32.0f - mean;
            var += d * d;
        }
    }
    var = sqrtf(var / (float)cnt);
    if (var < 1e-4f)
        var = 1.0f;
    /* renormalise to unit std (in the int8 domain) */
    for (i = 0; i < n; i++) {
        if (mask_get(out->mask, i)) {
            float d = ((float)out->z[i] / 32.0f - mean) / var;
            out->z[i] = (int8_t)clampf(rintf(d * 32.0f), -127.0f, 127.0f);
        }
    }
    out->coverage = (uint8_t)((cnt * 100) / n);

    free(f); free(blur); free(hp); free(lm); free(lv); free(e);
    return 0;
}

/* ------------------------------------------------------------------ */
/* rotation                                                           */
/* ------------------------------------------------------------------ */

/* Rotate @z/@mask by @deg degrees about the centre into @rz/@rm. */
static void rotate_tpl(const int8_t *z, const uint8_t *mask, int w, int h,
                       float deg, int8_t *rz, uint8_t *rm)
{
    float rad = deg * 3.14159265358979f / 180.0f;
    float c = cosf(rad), s = sinf(rad);
    float cx = (w - 1) * 0.5f, cy = (h - 1) * 0.5f;
    int x, y;

    memset(rz, 0, (size_t)w * h);
    memset(rm, 0, (size_t)((w * h + 7) / 8));
    for (y = 0; y < h; y++) {
        for (x = 0; x < w; x++) {
            float dx = (float)x - cx, dy = (float)y - cy;
            float sx = cx + c * dx + s * dy;
            float sy = cy - s * dx + c * dy;
            int x0 = (int)floorf(sx), y0 = (int)floorf(sy);
            float fx = sx - (float)x0, fy = sy - (float)y0;
            float acc = 0.0f, wsum = 0.0f;
            int o;
            for (o = 0; o < 4; o++) {
                int xx = x0 + (o & 1), yy = y0 + (o >> 1);
                float wt = ((o & 1) ? fx : 1.0f - fx) *
                           ((o >> 1) ? fy : 1.0f - fy);
                if (xx < 0 || xx >= w || yy < 0 || yy >= h)
                    continue;
                if (!mask_get(mask, yy * w + xx))
                    continue;
                acc += (float)z[yy * w + xx] * wt;
                wsum += wt;
            }
            if (wsum > 0.5f) {
                rz[y * w + x] = (int8_t)clampf(rintf(acc / wsum), -127.0f, 127.0f);
                mask_set(rm, y * w + x, 1);
            }
        }
    }
}

/* 4x4 box downsample used for the coarse search. */
static void downsample4(const int8_t *z, const uint8_t *mask, int w, int h,
                        int8_t *dz, uint8_t *dm)
{
    int dw = w / 4, dh = h / 4, x, y, i, j;

    memset(dz, 0, (size_t)dw * dh);
    memset(dm, 0, (size_t)((dw * dh + 7) / 8));
    for (y = 0; y < dh; y++) {
        for (x = 0; x < dw; x++) {
            int acc = 0, cnt = 0;
            for (j = 0; j < 4; j++) {
                for (i = 0; i < 4; i++) {
                    int idx = (y * 4 + j) * w + (x * 4 + i);
                    if (mask_get(mask, idx)) {
                        acc += z[idx];
                        cnt++;
                    }
                }
            }
            if (cnt >= 8) {
                dz[y * dw + x] = (int8_t)(acc / cnt);
                mask_set(dm, y * dw + x, 1);
            }
        }
    }
}

/* ------------------------------------------------------------------ */
/* NCC                                                                */
/* ------------------------------------------------------------------ */

/* NCC of @a (shifted by dx,dy) against @b, restricted to the overlap of
 * both masks.  *overlap receives the number of contributing pixels. */
static float ncc_at(const int8_t *a, const uint8_t *ma, int aw, int ah,
                    const int8_t *b, const uint8_t *mb, int bw, int bh,
                    int dx, int dy, int *overlap)
{
    int x, y;
    double num = 0.0, sa = 0.0, sb = 0.0;
    int cnt = 0;
    int minx = dx < 0 ? 0 : dx;
    int miny = dy < 0 ? 0 : dy;
    int maxx = bw < aw + dx ? bw : aw + dx;
    int maxy = bh < ah + dy ? bh : ah + dy;

    if (maxx <= minx || maxy <= miny) {
        *overlap = 0;
        return -1.0f;
    }
    for (y = miny; y < maxy; y++) {
        int ay = y - dy;
        for (x = minx; x < maxx; x++) {
            int ax = x - dx;
            int bi = y * bw + x;
            int ai = ay * aw + ax;
            float av, bv;
            if (!mask_get(mb, bi) || !mask_get(ma, ai))
                continue;
            av = (float)a[ai];
            bv = (float)b[bi];
            num += av * bv;
            sa += av * av;
            sb += bv * bv;
            cnt++;
        }
    }
    *overlap = cnt;
    if (cnt < 100 || sa < 1.0 || sb < 1.0)
        return -1.0f;
    return (float)(num / sqrt(sa * sb));
}

/* Count set bits in a mask (used to size the overlap requirement). */
static int mask_count(const uint8_t *m, int n)
{
    int i, c = 0;
    for (i = 0; i < n; i++)
        c += mask_get(m, i);
    return c;
}

static float match_rotated(const int8_t *rz, const uint8_t *rm, int w, int h,
                           const int8_t *bz, const uint8_t *bm,
                           int *out_dx, int *out_dy)
{
    enum { DW = MAXW / 4, DH = MAXH / 4 };
    int8_t dz[DW * DH], bz4[DW * DH];
    uint8_t dm[(DW * DH + 7) / 8], bm4[(DW * DH + 7) / 8];
    int dw = w / 4, dh = h / 4;
    int cdx, cdy, cax, cay, best_dx = 0, best_dy = 0;
    float best = -1.0f;
    int min_area, ov;

    downsample4(rz, rm, w, h, dz, dm);
    downsample4(bz, bm, w, h, bz4, bm4);
    min_area = mask_count(dm, dw * dh);
    {
        int bc = mask_count(bm4, dw * dh);
        if (bc < min_area)
            min_area = bc;
    }
    min_area = min_area / 2;

    for (cdy = -dh / 2; cdy <= dh / 2; cdy++) {
        for (cdx = -dw / 2; cdx <= dw / 2; cdx++) {
            float s = ncc_at(dz, dm, dw, dh, bz4, bm4, dw, dh, cdx, cdy, &ov);
            if (ov < min_area)
                continue;
            if (s > best) {
                best = s;
                best_dx = cdx;
                best_dy = cdy;
            }
        }
    }
    if (best < -0.5f) {
        *out_dx = *out_dy = 0;
        return 0.0f;
    }

    /* refine at full resolution: +-6 px around the coarse peak (coarse step 4) */
    cax = best_dx * 4;
    cay = best_dy * 4;
    {
        int full_area = mask_count(rm, w * h);
        int bc = mask_count(bm, w * h);
        if (bc < full_area)
            full_area = bc;
        full_area = full_area / 2;

        best = -1.0f;
        for (cdy = cay - 6; cdy <= cay + 6; cdy++) {
            for (cdx = cax - 6; cdx <= cax + 6; cdx++) {
                float s = ncc_at(rz, rm, w, h, bz, bm, w, h, cdx, cdy, &ov);
                if (ov < full_area)
                    continue;
                if (s > best) {
                    best = s;
                    best_dx = cdx;
                    best_dy = cdy;
                }
            }
        }
    }
    *out_dx = best_dx;
    *out_dy = best_dy;
    return best < 0.0f ? 0.0f : best;
}

int fpc_tpl_match(const fpc_tpl *a, const fpc_tpl *b)
{
    static const float coarse_angles[] = {
        -30, -25, -20, -15, -10, -5, 0, 5, 10, 15, 20, 25, 30
    };
    static const float fine_steps[] = { -2.0f, -1.0f, 0.0f, 1.0f, 2.0f };
    int8_t rz[MAXW * MAXH];
    uint8_t rm[(MAXW * MAXH + 7) / 8];
    float best = 0.0f, best_angle = 0.0f;
    int best_dx = 0, best_dy = 0;
    size_t i;

    if (a->w != b->w || a->h != b->h)
        return 0;
    if (a->w > MAXW || a->h > MAXH)
        return 0;

    for (i = 0; i < sizeof coarse_angles / sizeof coarse_angles[0]; i++) {
        float s;
        int dx, dy;
        rotate_tpl(a->z, a->mask, a->w, a->h, coarse_angles[i], rz, rm);
        s = match_rotated(rz, rm, a->w, a->h, b->z, b->mask, &dx, &dy);
        if (s > best) {
            best = s;
            best_angle = coarse_angles[i];
            best_dx = dx;
            best_dy = dy;
        }
    }

    /* fine angle refinement around the winner, keeping the translation near
     * the coarse optimum (re-search +-2 px) */
    for (i = 0; i < sizeof fine_steps / sizeof fine_steps[0]; i++) {
        float ang = best_angle + fine_steps[i];
        float s;
        int dx, dy;
        rotate_tpl(a->z, a->mask, a->w, a->h, ang, rz, rm);
        s = match_rotated(rz, rm, a->w, a->h, b->z, b->mask, &dx, &dy);
        if (s > best) {
            best = s;
            best_angle = ang;
            best_dx = dx;
            best_dy = dy;
        }
    }
    (void)best_dx;
    (void)best_dy;

    if (best <= 0.0f)
        return 0;
    return (int)lrintf(clampf(best, 0.0f, 1.0f) * 1000.0f);
}

int fpc_tpl_match_gallery(const fpc_tpl *probe, const fpc_tpl *gallery,
                          int n, int *best_index)
{
    int i, best = 0, best_i = -1;
    for (i = 0; i < n; i++) {
        int s = fpc_tpl_match(probe, &gallery[i]);
        if (s > best) {
            best = s;
            best_i = i;
        }
    }
    if (best_index)
        *best_index = best_i;
    return best;
}
