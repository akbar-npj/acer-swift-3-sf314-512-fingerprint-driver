/*
 * fpc_grid.c — clean-room reimplementation of a spatial top-K accumulator leaf
 * from the reachable BEP tree.  Derived from disassembly of fpc_enclave.dll;
 * the RVA <-> cr_ map is in MAP.md.
 *
 *   cr_grid_insert  0x18002f070  per-cell bounded slot list with eviction
 */
#include "fpc_bep.h"

/*
 * 0x18002f070 — insert a weighted sample (x, y, v) into a W*H cell grid.
 *
 * The grid `g` keeps a bounded pool of `cap` slots.  Each sample is mapped to
 * a cell (px, py) via px = x*W/divx, py = y*H/divy (both clamped to the grid),
 * and the slot is pushed onto that cell's singly-linked list, which is kept in
 * ASCENDING value order (head = smallest).  Once the pool is full, the cell
 * with the largest `key*val` score is chosen (the target cell is seeded with
 * `(key+1)*val`), its list head (the smallest-valued slot in that cell) is
 * evicted, and the freed slot is reused for the new sample.
 *
 * cfg->mode selects the behaviour: 2 appends to the flat coords2/values2
 * arrays (bounded by cfg->cap2), 5 runs the grid accumulator above, and any
 * other value returns 0x69.
 */
int cr_grid_insert(cr_grid *g, uint8_t x, uint8_t y, float v, cr_grid_cfg *cfg)
{
    if (cfg->mode == 2) {
        int c = g->count2;
        if (c < (int)cfg->cap2) {
            g->count2 = c + 1;
            g->coords2[2 * c]     = x;
            g->coords2[2 * c + 1] = y;
            g->values2[c] = v;
        }
        return 0;
    }
    if (cfg->mode != 5)
        return 0x69;

    int W = g->W, H = g->H;
    int px = (int32_t)((uint32_t)x * (uint32_t)W) / g->divx;
    if (px < 0) px = 0;
    int py = (int32_t)((uint32_t)y * (uint32_t)H) / g->divy;
    if (py < 0) py = 0;
    if (H - 1 <= py) py = H - 1;
    if (W - 1 <= px) px = W - 1;
    int idx = px + py * W;

    int slot;
    if (g->count < g->cap) {
        slot = g->count;
        g->count = slot + 1;
    } else {
        /* pick the cell with the largest key*val score (target seeded with
         * (key+1)*val); evict its list head and reuse the freed slot. */
        int best = -1;
        float maxsc = 0.0f;
        int16_t k0 = g->nodes[idx].key;
        if (k0 != 0) {
            best = idx;
            maxsc = (float)(k0 + 1) * g->nodes[idx].val;
        }
        int n = W * H;
        for (int j = 0; j < n; j++) {
            int16_t kj = g->nodes[j].key;
            if (kj != 0) {
                float sc = (float)kj * g->nodes[j].val;
                if (sc > maxsc) { best = j; maxsc = sc; }
            }
        }
        int16_t h = g->nodes[best].head;
        if (h == -1)
            return 0;
        if (idx == best && g->values[h] >= v)
            return 0;
        slot = h;
        g->nodes[best].head = g->next[h];
        g->nodes[best].key--;
    }

    g->coords[2 * slot]     = x;
    g->coords[2 * slot + 1] = y;
    g->values[slot] = v;

    /* insert `slot` into node[idx]'s ascending-by-value list */
    int16_t h = g->nodes[idx].head;
    if (h == -1 || !(g->values[h] < v)) {
        g->next[slot] = h;
        g->nodes[idx].head = (int16_t)slot;
    } else {
        int16_t prev = h;
        int16_t cur = g->next[h];
        while (cur != -1 && v > g->values[cur]) {
            prev = cur;
            cur = g->next[cur];
        }
        g->next[prev] = (int16_t)slot;
        g->next[slot] = cur;
    }
    g->nodes[idx].key++;
    return 0;
}
