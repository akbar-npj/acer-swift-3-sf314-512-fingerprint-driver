/*
 * fpc_sort.c — clean-room reimplementation of 0x18003bf90, a stack-based
 * Hoare quicksort over an array of 8-byte records.
 *
 * Each record is { uint32_t v; uint32_t key; } (key at byte offset 4).  The
 * two selector arguments pick the comparison:
 *   key_type == 0 : compare the key as int32_t
 *   key_type == 1 : compare the key as float32
 *   dir      == 0 : ascending
 *   dir      == 1 : descending
 * Any other (key_type, dir) returns 0x69.  A record count n > 0x100000 is a
 * no-op returning 1 (the array is left untouched).  Otherwise it returns 0.
 *
 * The partition is a specific Hoare variant.  It walks i up from the left while
 * recs[i].key stays on the "already ordered" side of the pivot and walks j down
 * from the right, swapping the first out-of-place pair it finds.  Afterwards it
 * pushes the two sub-ranges and immediately processes the smaller one, deferring
 * the larger on an explicit stack of (lo, hi) dword pairs.  The exact (unstable)
 * permutation must be reproduced verbatim, so the loop bounds, the pivot index
 * ((lo + hi + 1) >> 1) and the push order all mirror the vendor assembly.
 *
 * Comparison directions (derived from the four vendor loops):
 *   advance i   : asc  less(ki, pivot)   desc less(pivot, ki)
 *   skip swap   : asc  less(pivot, kj)   desc less(kj, pivot)
 * A plain C `<` matches the vendor's UCOMISS/JA (float) and CMP/Jcc (int) even
 * for NaN keys, because an unordered UCOMISS clears neither CF nor ZF, so JA is
 * not taken exactly as `<` yields false.
 */
#include "fpc_bep.h"
#include <string.h>

typedef struct { uint32_t v; uint32_t k; } cr_rec8;

static float sort_f32(uint32_t b)
{
    float f;
    memcpy(&f, &b, sizeof f);
    return f;
}

static int lt_i(uint32_t a, uint32_t b) { return (int32_t)a < (int32_t)b; }
static int lt_f(uint32_t a, uint32_t b) { return sort_f32(a) < sort_f32(b); }

int cr_sort_records(void *recs, int n, int key_type, int dir)
{
    if ((key_type != 0 && key_type != 1) || (dir != 0 && dir != 1))
        return 0x69;
    if (n > 0x100000)
        return 1;

    uint32_t *r = (uint32_t *)recs;                 /* key of rec i at r[2i+1] */
    int (*less)(uint32_t, uint32_t) = (key_type == 1) ? lt_f : lt_i;
    int desc = (dir == 1);

    /* 40 dwords = 20 pending ranges in the vendor frame; smaller-side-first
     * keeps the depth O(log n), so this is ample for the tested sizes. */
    int stack[64];
    int top = 0;
    stack[0] = 0;
    stack[1] = n - 1;
    int lo = 0;
    int hi = n - 1;

    for (;;) {
        if (lo < hi) {
            int p = (lo + hi + 1) >> 1;
            uint32_t pivot = r[p * 2 + 1];
            int i = lo;
            int j = hi;
            for (;;) {
                uint32_t ki = r[i * 2 + 1];
                int adv = desc ? less(pivot, ki) : less(ki, pivot);
                if (adv) {
                    i++;
                } else {
                    int jo = j;
                    j--;
                    uint32_t kj = r[jo * 2 + 1];
                    int skip = desc ? less(kj, pivot) : less(pivot, kj);
                    if (!skip) {
                        uint32_t tv = r[i * 2], tk = r[i * 2 + 1];
                        r[i * 2]     = r[jo * 2];
                        r[i * 2 + 1] = r[jo * 2 + 1];
                        r[jo * 2]     = tv;
                        r[jo * 2 + 1] = tk;
                        i++;
                    }
                }
                if (i > j)
                    break;
            }
            /* push the smaller side on top and process it next; defer larger */
            if (j - lo < hi - i) {
                stack[top * 2]     = i;      /* current slot becomes (i, hi)   */
                stack[top * 2 + 2] = lo;     /* new slot: (lo, j)              */
                stack[top * 2 + 3] = j;
            } else {
                stack[top * 2 + 1] = j;      /* current slot becomes (lo, j)   */
                stack[top * 2 + 2] = i;      /* new slot: (i, hi)              */
                stack[top * 2 + 3] = hi;
            }
            top++;
        } else {
            top--;
            if (top < 0)
                return 0;
        }
        lo = stack[top * 2];
        hi = stack[top * 2 + 1];
    }
}
