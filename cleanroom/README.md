# Clean-room rewrite of the FPC e340 BEP algorithm

A from-scratch C reimplementation of the `fpc_bio_bep_sw23_*` ridge-image
reconstruction that lives inside the vendor's `fpc_enclave.dll`. The goal is to
drop the vendor code bytes entirely and keep only original C, while producing
**bit-for-bit identical** output to the vendor binary.

This directory is the **starting point** of that effort. It contains the
inventory, the methodology, the differential-test harness, and the first batch
of rewritten functions.

## Why a clean-room rewrite

`native/` runs the vendor DLL as-is on Linux (no Wine). That removes the
platform dependency but still ships and executes FPC's binary. A clean-room
rewrite removes the binary too — it is the only way to get a fully original,
auditable implementation.

## The correctness oracle

There is exactly one requirement: **parity**. A function is "done" only when it
returns byte-identical results to the vendor function for a large battery of
inputs. `tools/difftest.c` enforces this: it maps `fpc_enclave.dll` with the
same minimal PE loader the native rehost uses, then calls each vendor function
at its RVA (with the Microsoft x64 ABI) and the clean-room equivalent, and
compares results bit-for-bit.

```sh
make check        # build + run the differential test (x86-64 only)
```

The end-to-end oracle is the 27-frame reconstruction parity already established
in [`../WINE_REHOST.md`](../WINE_REHOST.md): once enough of the tree is
rewritten, the whole clean-room pipeline must reproduce those same images.

## Method (per function)

1. **Locate** it in [`REACHABLE.md`](REACHABLE.md) / [`reachable.txt`](reachable.txt)
   (address, vendor symbol, size).
2. **Read the disassembly** (`~/fpwork/enclave.asm`, or IDA/REA MCP
   `procedure_assembly`). Ghidra's decompilation in `~/fpwork/enclave_decompiled/`
   is a good first pass but its types are often wrong — the assembly is
   authoritative.
3. **Establish semantics** from the body. The vendor symbol names are
   *adversarial*: they are present but frequently wrong. Never trust the name.
4. **Transcribe** into clean C, preserving the exact order of float operations.
5. **Add a case to `difftest.c`** and run `make check` until zero mismatches.

## Hard requirements

- **`-ffp-contract=off`.** Without it the compiler fuses `a*b + c` into an FMA,
  changing the rounding and breaking parity. This is not optional.
- **x86-64 only.** The vendor code is Microsoft-ABI and the difftest calls it
  directly; `ms_abi` is an x86 attribute. The clean-room *library* is portable
  C, but the test harness only builds on x86-64.
- **Integer casts of out-of-range floats** rely on `cvttss2si` semantics
  (`INT_MIN` on overflow/NaN). Reproduced by plain `(int)` casts under gcc on
  x86-64.

## Layout

```
cleanroom/
├── include/fpc_bep.h     types + clean-room prototypes
├── src/fpc_math.c        math kernel (sqrtf, expf, round/floor/ldexp/lround)
├── src/fpc_buffer.c      buffer / metadata / image-slot helpers
├── src/fpc_util.c        util kernel (mem, prng, clz, sincos, dot, rotate)
├── src/fpc_image.c       image-descriptor leaves
├── src/fpc_rect.c        rectangle fills (u8/u16/f32)
├── src/fpc_bitmap.c      bitmap clear/set/unpack
├── src/fpc_copy.c        image copies (u8/u32/u16-shift)
├── src/fpc_affine.c      table-driven affine transform
├── src/fpc_stats.c       masked variance + big-endian quad probe
├── src/fpc_filter.c      Q15 vertical FIR (4 columns at a time)
├── src/fpc_orient.c      orientation pick (fwd/rev correlation + half-swap)
├── src/fpc_matmul.c      float N x T matrix multiply
├── tools/difftest.c      differential test vs the vendor DLL
├── Makefile              make / make check
├── REACHABLE.md          inventory of all 355 reachable functions
├── reachable.txt         machine-readable list (addr, size, vendor symbol)
└── MAP.md                vendor RVA <-> clean-room name <-> semantics
```

## Gotchas discovered while transcribing

- **`jbe`/`ja` are not `<=`/`>`.** The vendor's SSE compares branch on the raw
  flags. `ucomiss a,b ; jbe` is taken when `CF|ZF`, i.e. **also when unordered
  (NaN)**. So `if (x >= c)` in C is *wrong* for the branch — the faithful form is
  `if (!(c > x))`. This bit `cr_expf`: the vendor sends NaN down the *normal*
  path, not the clamp. The mirror case is `if (x <= c)`: MSVC (non-strict) emits
  `ucomiss x,c ; ja` — i.e. it clamps when `!(x > c)`, which is **true for NaN**.
  `cr_norm_corr_score`'s `if (std <= 0.1f) std = 0.1f;` therefore had to be
  written `if (!(std > 0.1f))`: an empty patch gives a NaN std and the vendor
  clamps it to 0.1 (result 0), whereas the IEEE `<=` leaves NaN (result INT_MIN).
- **Exponent scaling is a 32-bit shift, not a multiply.** `ldexp` is done as
  `bits(f) + (k << 23)` with `k` an `int`; for `k = INT_MIN` (the NaN path) the
  shift yields 0. Use `(uint32_t)k << 23`, never `k * 0x800000` (signed-overflow
  UB and a different value).
- **Table-driven seeds must be copied byte-exact.** `cr_sqrtf`'s 256-byte
  inverse-sqrt seed table lives at `0x180159500`; the difftest confirms parity
  only because it is reproduced verbatim.
- **Prototypes must match the vendor's argument *position*, including floats.**
  GCC's `ms_abi` assigns registers *positionally*: a `float` at argument index
  *i* (1-based) lands in `xmm(i-1)` (not "the i-th float in xmm0..3"), and a
  non-float at index *i* lands in `rcx,rdx,r8,r9` for *i*=1..4. Arguments at
  index *i* ≥ 5 go **on the stack**, whatever their class — so a prototype with
  more than four register arguments silently pushes its floats instead of
  loading `xmm` (this bit `cr_blur_dispatch_1c6a0`: modelled as
  `(void*,void*,int,int,int,float,float,float)` its `sigma` went to the stack
  and the vendor read a stale `xmm2`). So
  `fpc_bio_bep_sw23_3d13ea8103` — whose float is the 2nd argument and whose
  body does `movss [..],xmm1` — must be declared `void (*)(void*, float)`, not
  `(void*, float, float)`. Getting this wrong makes the vendor read a stale
  register (symptom: it silently fills with 0). Same class of bug as
  `0x180016720`'s flag being the 2nd arg in `dl`, and `0x18001b990`'s phase
  being the 3rd arg in `r8d`.
- **`maxss` is not `if (v <= 0) v = 0`.** `maxss xmm0, 0` returns `0.0` for NaN
  as well as for `v <= 0`; the faithful form is `(v > 0.0f) ? v : 0.0f`.
- **Count the table rows from the *index range*, not the data you first see.**
  `cr_affine_transform` scores `scores[0..9)`, so `k` ranges over 9 values and the
  basis table at `0x18008ec40` is **9**x32 floats, not 8x32. Missing the 9th row
  only breaks the ~1/9 of cases where `k==8`, which is easy to misread as a
  rounding bug. The table also contains **signed zeros** (`-0.0`) that are
  load-bearing for bit parity — transcribe them, never normalise to `0.0`.
- **A "pointer to a mask" is dereferenced once, not indexed per row.**
  `cr_masked_variance`'s 4th arg is a `const uint8_t **`: the vendor does
  `mov rdx,[r9]` once and then walks a *flat* column-major byte array
  `(*mask)[i + j*rows]`, not `mask[j][i]`.
- **Count do-while iterations from the *guard*, not the initial value.**
  `cr_orient_pick` (0x1800309a0) decrements its index at the *top* of the loop
  and exits when it reaches `base-1`, so a `k*k`-tap correlation runs `k*k`
  times, not `k*k-1`. Transcribing it as `i < kk-1` shifted every correlation by
  one tap (~16% of random inputs flipped the branch decision).
- **Preserve the vendor's *sub-expression grouping*, not just the operators.**
  `cr_splat_accum16` computes `p4sq = p4*p4` once (in `xmm10`) and then
  `a = pts[i] * p4sq`. Writing the "same" formula as `pts[i]*p4*p4` is
  `(pts[i]*p4)*p4` — a different rounding — and produced 1-ULP mismatches on a
  large fraction of inputs. Same lesson as `-ffp-contract=off`: the *order and
  association* of float ops is part of the spec.
- **A streaming ring buffer can be read *before* its start.** The vertical-FIR
  mirror branch computes `rem = (2h - srcrow - n/2 - 3) % n`, which is
  **negative** when `target > 2h - 2*(n/2) - 3`; `ring + rem*w` then indexes
  *before* the ring. That is legal in the real caller (the ring lives inside a
  larger allocation), but a test that places the ring at a small offset will
  read the two sides' out-of-bounds padding and report false mismatches. Give
  the test buffer generous head-room before the ring so the negative indices
  stay inside identically-initialised memory.

## Progress

| metric | value |
|---|---|
| reachable functions | 355 |
| total `.text` size | 169,488 B (165.5 KiB) |
| leaf functions (rewrite frontier) | 118 |
| rewritten + parity-verified | **353** (99.4% of functions, 168,576 B = 99.5% of bytes) |
| deferred | 0 |

One hundred and two batches so far:
1. math kernel + buffer/metadata helpers (11 functions)
2. util kernel + image leaves (14 functions, incl. two byte-identical duplicate pairs)
3. more math/util/image leaves (10 functions, incl. a third `cr_image_set` duplicate)
4. rect fills + bitmap ops + misc leaves (10 functions)
5. image copies + masked variance + affine transform (7 functions)
6. 256-byte leaves: Q15 FIR, masked min/max, orientation pick, atan2-degrees (4 functions)
7. 272-byte leaves: NxT matmul, mean/stddev, masked int16 min/max (3 functions)
8. 288-byte leaves: masked float min/max, int16→float scaled convert (2 functions)
9. 304-byte leaves: Q15 bilinear sampler, horizontal box blur, masked box sum (3 functions)
10. 320-byte leaves: float→int16 convert, block-extreme bitmap, bitmap popcount (3 functions)
11. 336-byte leaf: integer-factor block-average downsample (1 function)
12. 384-byte leaf: high-accuracy sin/cos pair (1 function)
13. 384-byte leaf: int16 multi-region border fill (1 function)
14. 400/96-byte leaves: byte border-extend + saturation score (2 functions)
15. 416-byte leaf: int16 border-extend (1 function)
16. allocator wrappers: malloc / free / sized-free (3 functions)
17. bitmap morphology: dilate / erode pair (2 functions)
18. affine resample + 4-phase FIR: Q15 bilinear sampler, polyphase FIR (2 functions)
19. 464-byte leaf: bilinear splat of 16 weighted points (1 function)
20. 480-byte leaf: bitmap border-set with partial-word masks (1 function)
21. 480-byte leaf: 8-neighbour 3x3 Laplacian, 4-wide vectorised (1 function)
22. 528-byte leaf: 7-tap edge-clamped int16 FIR over image rows (1 function)
23. 496-byte leaf: in-place row permutation via cycle following (1 function)
24. 528-byte leaf: bit-shifted bitmap blit (left shift into destination) (1 function)
25. 528-byte leaf: right-shifted bitmap window extract with last-word mask (1 function)
26. 608-byte leaf: column-wise 7-tap clamped int16 FIR (1 function)
27. 576-byte leaf: bitmap-masked per-column mean correction (1 function)
28. 560-byte leaf: SIMD bit-packed sign signature of a small filter bank (1 function)
29. 768-byte leaf: u8→int16 shift widen, 656-byte leaf: symmetric int16 border extend (2 functions)
30. 464-byte leaf: box sum/count excluding a u16 index list (1 function)
31. 704-byte leaf: 15x15 separable box filter (int16) + edge replication (1 function)
32. 656-byte leaf: byte twin of the 15x15 separable box filter (1 function)
33. 752-byte leaf: u8 row widen + reflect-101 padding + m-tap symmetric FIR (1 function)
34. 624-byte leaf: spatial top-K accumulator with per-cell bounded slot lists (1 function)
35. 656-byte leaf: bitmap set-bit centroid with clamped window output (1 function)
36. 32–112-byte leaves: small descriptor / table-pointer getters (9 functions)
37. 832-byte leaf: 9-tap triangular (Bartlett) filter over the 9 lines of an n×9 float buffer (1 function)
38. 928-byte leaf: reflect-101-padded int16 FIR down each column (1 function)
39. 976-byte leaf: row-wise twin of the reflect-101 column FIR (1 function)
40. 1024-byte leaf: fixed 7-tap reflect-101 FIR down each row (1 function)
41. 1072-byte leaf: in-place separable box mean (3x3 / 5x5) on a float image (1 function)
42. 1152-byte leaf: stack-based Hoare quicksort over 8-byte records (1 function)
43. 1184-byte leaf: short-line bilinear sampler + 9-hypothesis orientation fit (1 function)
44. 1200-byte leaf: fixed 7-tap reflect-101 FIR down each column (folded sliding window) (1 function)
45. 1280-byte leaf: separable 11x11 int16 FIR, one output row (vertical + horizontal passes) (1 function)
46. 1776-byte leaf: per-pixel kernel-bank 2D correlation with per-pixel kernel selection (1 function)
47. object-tree lifecycle helpers + image-data accessors: int16 metadata put, sized-pointer
    destructors (×2 duplicates), zero-then-free, 8-pointer struct destructor, 16-byte-aligned
    sized malloc, definition-table getter, image-data descriptor fill (9 functions)
48. object constructors / flag-driven destructors: fixed-object destructor, metadata-set-on-slot,
    0x58-byte object init, two aligned-handle allocators, u8/s16 image-descriptor allocators,
    flag-word destructor, packed-bitmap allocator (9 functions)
49. higher-level destructors / accessors: clz-with-zero-case, 8-slot destructor, 0x58-object
    allocator, metadata-get-on-slot, and the crop-then-extend-border pair (int16/u8) (6 functions)
50. nested destructor chain: 8-slot slot-destructor, object destructor (8-slot slot + 28/8
    sub-objects), and the two wrapper destructors that release the held object then the
    wrapper slot (4 functions)
51. small ready wrappers: guarded sized-free, 2-slot/4-slot/4-arg destructors, guarded
    ptr8 cleanup + its clear twin, highest-set-bit index, and the metadata-class definition
    getter (9 functions)
52. ready wrappers / allocators: NULL-guarded 4-slot destructor, 6-pointer clear, zeroed
    bit-vector allocator, f32/quarter image allocators, image-field copy, Q16 sqrt, guarded
    u8→u16 / u16-shift-copy / column-FIR / row-FIR wrappers, and the palette LUT remap
    (12 functions)
53. ready wrappers (160–500 B): seeded index shuffle, two-way softmax, centroid→affine
    builder, running average, fixed-point atan2, and the edge-replicating box mean
    (6 functions)
54. ready wrappers (192–512 B): atan2 orientation image, u8/s16 ridge gain normalisation
    (lane-0/7 quirk), nearest-neighbour int16 affine resample, weighted running average,
    and the descriptor-pool builder (6 functions)
55. pool users + ready wrappers: nearest-neighbour u8 affine resample, mirror-extend +
    polyphase FIR, masked box-mean inpainting, and the five descriptor-pool builders
    (cr_pool_alloc1..5, now with the pool_builder status code) (8 functions)
56. streaming vertical FIR + correlation/splat: Pearson correlation of two int16 images,
    index-list box-mean inpainting, the 16-point bilinear splat accumulator, and the
    int16/uint8 streaming n-tap vertical FIR pair (with mirror-extend at the bottom
    edge and the shared coefficient-rotation ring) (5 functions)
57. destructor / constructor wrappers + misc: the 4-/9-slot destructor pair, the 3-pointer
    sized-free, the 0x60-byte aligned constructor, power-of-two dimension rounding, the
    n*n normalised correlation score, the separable FIR pair, and the mirror-extend
    streaming-FIR row (8 functions)
58. window generators + masked median + angle sampler: the masked float median, the Q15
    Gaussian window, the Q15 Gaussian 1st/2nd-derivative window trio, and the bilinear
    orientation-field angle sampler (4 functions)
59. gaussian-blur + blit wrappers: the separable 7-tap Gaussian blur of two int16 images
    and the three "copy source into a sub-window of a container, then fix its border"
    wrappers (mirror-extend / edge-replicate / constant-fill) (4 functions)
60. blur/kernel-apply dispatcher: the 96-byte leaf tail-jump at `0x18001c6a0` that
    routes on a stack selector to `cr_gauss_fir_apply` / `cr_sep_gauss_blur_s16_reflect`
    / `cr_correlate_34930` / `cr_ncc_apply_34390` / `cr_sep_gauss_blur_s16` (1 function).
    Watch the ABI: `(ptr, ptr, float sigma, int count, int sel)` — the position-3 float
    lands in `xmm2`, not `xmm0`.
61. blurred-pair difference normaliser: the 496-byte `0x18001ee30` that allocates two
    int16 scratch blocks, blurs the source twice (sigma `obj[0]`/`obj[1]`, selector byte
    `obj+12`, count `0xf`), writes the scaled/clamped difference back into `src->data` in
    place, and frees the pool on every post-allocation path (1 function).
62. u8 blurred-pair difference normaliser: the 624-byte `0x1800148c0` sibling that
    scales a float source by 64 into an int16 scratch (`cr_f32_to_i16_scaled`),
    blurs it twice, and writes the normalised difference as u8 (bias `0x80`, clamped
    to `[0, 0xff]`) into the destination image (1 function).
63. local-contrast normaliser: the 784-byte `0x180013720` that mean-subtracts the
    int16 image (unsigned load), takes abs, blurs it, applies a floored divisive
    normalisation and contrast-stretches the result back into the image in place
    (1 function).
64. oriented matched filter: the 1504-byte `0x180045eb0` that runs a 5×5 matched
    filter over six row pointers (rows[0..4] and rows[1..5]), max-pools four
    horizontal offsets per chunk, scales by `<<6` with a per-row `<<14` bias and a
    `SAR 0xf`, and optionally clamps the int16 output non-negative (1 function).
65. frame quality gate: the 1232-byte `0x180035cf0` that reads four TLV metadata
    keys, computes a frame quality and running average, downsamples + (optionally)
    NCC-diffs the image, runs a Pearson correlation against the previous frame,
    shifts a 19-byte history and sets a pass flag (1 function).
66. scale-space Laplacian blob detector: the 1248-byte `0x18001bbf0` that validates
    a scaled-image descriptor, smooths successive source rows with an 11-tap Q15
    Gaussian into a rotating ring buffer, takes the 3×3 Laplacian of three
    consecutive rows, and inserts every masked 3×3 local maximum into the grid
    (1 function).
67. Gaussian-derivative structure-tensor orientation: the 1328-byte `0x18000d3b0`
    that builds the A=d/dx / B=d/dy Gaussian-derivative pair, computes the 2×2
    structure-tensor eigen-decomposition per pixel, encodes the dominant
    eigenvector scaled by coherence (zeroed per-pixel when `flag==1` and the mask
    bit is clear), blurs it (`count==1` → single dispatch, `count>0` → that many
    FIR passes), and finishes with `cr_cordic_atan_q15` (1 function).
68. Gaussian-derivative structure-tensor orientation, 3-image twin: the 1408-byte
    `0x18003b960` sibling that takes the three tensor planes precomputed from
    `cr_gauss_deriv_triple_guarded` (tensor `[[o1,o2],[o2,o3]]`), applies the
    identical per-pixel eigen/coherence encoding, writes `output1`/`output2` back
    into the o1/o3 planes, blurs those two planes and feeds `(I3,I1)` to
    `cr_cordic_atan_q15` (1 function).
69. mask-weighted spatial bin selection: the 1440-byte `0x180014320` that bins
    points into an NX×NY grid (per-bin linked list + population), caps each bin
    to a mask-density threshold `cr_lroundf(bits*weight/(bw*bh*nb))`, then
    round-robins the shuffled bins popping one point at a time into the front of
    the array (1 function).
70. orientation / grid dispatchers + feature-extraction step: the 64-byte
    `0x18002cfd0` tail-jump on `cfg[0x10]` to `cr_structure_orient_d3b0`/`_3b960`,
    the 64-byte `0x180038020` that stores `grid->count=0` then tail-jumps on
    `cfg[1]` to the blob/harris grid populators, and the 496-byte `0x180026dc0`
    feature-extraction step that runs the quality gate, allocates a u8 image
    (filled `0xff` on first frame, `cr_bitmap_unpack_boxmax_fir` otherwise),
    folds it via `cr_weighted_running_avg`, and qualifies when the state byte
    clears (3 functions).
71. float-source feature-extraction step: the 688-byte `0x18002db20` twin of
    `0x180026dc0` whose source image holds **float** pixels — it rounds/clamps
    them into a u8 working image, runs the same quality gate, expands the
    packed image with `cr_mask_boxmax_fir_clear(..., 0xf, ...)`, folds it into
    the running average and qualifies (1 function).
72. directional 5x5 matched-filter bank: the 1808-byte `0x18003de60` that slides
    a 5×5 Q15 correlation over `ncoef` orientation blocks per output row,
    max-pools two shifted responses into two int16 channels (`>>15`, with a
    per-row `coefB[r]*0x4000` bias), uses a reduced 5-tap kernel for the trailing
    partial column, and optionally clamps the whole plane non-negative
    (1 function).
73. three-level matched-filter pyramid: the 1008-byte `0x1800364c0` that
    partitions the caller's `out` into per-level row-pointer arrays from a
    3×0x30-byte descriptor (planes 5/3/5), then streams output blocks through
    bilinear resampling → `cr_matched_filter_45eb0` → `cr_block_conv_231a0` →
    `cr_dirbank_3de60` (rotating each pointer ring by 2), and finally
    interleaves the block planes back into the front of `out` (1 function).
74. fixed-pattern (ridge template) removal: the 1088-byte `0x180025960` that
    seeds a scratch `h×64` float plane with a separable ridge template
    (`tab[o]` / `tab[h/2-1]` plus a 32-entry mirrored ramp), blends it toward
    the centre sample by `src/255`, fits a least-squares gain over the
    `mask == 0xff` samples (`0.9*cov/var`, clamped at 0), subtracts
    `(buf - mean)*gain` from the image and blends the residual back toward
    `max(src)` by the mask (1 function).
75. point-grid picker, mask pipeline and i16 normaliser: three more
    `src/fpc_comp.c` routines. `cr_grid_pick_37460` (1488 B) buckets 8-byte
    point records into a `gw×gh` grid, scores each cell from a 1-bit bitmap and
    emits a seeded-shuffle selection; `cr_mask_pipeline_25050` (1632 B) is the
    `cfg[0]`-dispatched inpaint/classify chain plus a two-pass row/column gap
    interpolator; `cr_norm_2bd60` (2176 B) does top/bottom row-mean correction
    followed by a per-column gain, offset or one of six fixed table maps;
    `cr_pick_dispatch_16b90` (64 B) forwards to one of the three point
    pickers on `cfg[0x24]` (4 functions).
76. mask-aware gap inpainting: `cr_mask_inpaint_317a0` (2176 B) in
    `src/fpc_comp.c`. Mode 5 fills the u16-listed pixels of a byte image from
    the mean of the surrounding unlisted pixels, sweeping windows 3/5 over the
    whole list and then retrying border pixels with 5/7 until the window-9
    give-up check; mode 7 is a pair of transposed gap interpolators (scan rows
    / fill columns, then scan columns / fill rows) with 10-bit fixed-point
    steps and signed per-axis run caps (1 function).
77. point-selection wrapper: `cr_pick_points_2f2e0` (464 B) in
    `src/fpc_comp.c` builds `{index, value}` records, sorts them by value
    descending, swaps the value for the two coordinate bytes, forwards to
    `cr_pick_dispatch_16b90` with `want = min(npts, want)` and copies the
    selected records back out as coordinates and original values (1 function).
78. feature packing: `cr_feat_pack_0e850` (1104 B) in `src/fpc_comp.c` resolves
    the warp/signpack and triple descriptors, fills the feature object's
    selector/bin fields, warps and sign-packs every keypoint into its row
    block, optionally orientation-picks and scores it, then sorts the score
    records, permutes the parallel arrays and builds the threshold->index bin
    table (1 function).
79. row-streaming 5x5 max-pool stage runner: `cr_maxpool_stream_21000` (1744 B)
    in `src/fpc_filter.c` keeps a six-row byte window of the source image,
    pre-rolls four rows through the Q15 bilinear sampler, then per output row
    shifts the window up two rows and samples the next two before running
    every kernel of stage 0 (four 2x2 sub-offset correlations, signed max,
    bias and `>>15`), copies the plane back to the head of the buffer and
    chains the remaining stages through `cr_filter_chain_run_i16` (1
    function).
80. point-selection gate + stage-run driver: `cr_pick_points_dispatch_2b680`
    (112 B) forwards to `cr_pick_points_2f2e0` only when `cfg[0x24] == 2`;
    `cr_stage_run_273a0` (768 B) sizes and allocates the stage buffer for
    either the three-level pyramid (`cr_pyramid_364c0`) or the row-streaming
    5x5 max-pool path (`cr_maxpool_stream_21000`), then runs the chain's
    per-block projection rows (`(sum + bias*0x4000) >> 15`, optional clamp,
    copy back to the buffer head) and finishes with `cr_softmax2` on the first
    two shorts (2 functions).
81. multi-scale score map + its downscale driver: `cr_mscale_score_2e060`
    (1600 B) builds the per-block structure-tensor coherence map from the two
    Gaussian-derivative planes (centring origin `0.5*(W-(w2*scale-2*scale))`,
    score index origin `(y0!=0)*w2 + (x0!=0)`, mask shift `(off_col+x)&31`),
    thresholds it into the mask and returns the mean of the non-`-1` scores;
    `cr_mscale_run_16d00` (240 B) allocates the map, fills it with `-1.0f` and
    dispatches to it (2 functions).
82. masked illumination flattening + its dispatcher + block-variance gate:
    `cr_masked_contrast_norm_2a620` (1760 B) builds a 64x-scaled int16 copy of
    the source, subtracts a 7-tap Gaussian plane, repeats the same for the u16
    mask, fits a single scale over the interior (`mask == 0xff`, 10-px border)
    from the covariance of the two residuals, blends the flattened source back
    with the mask-weighted mean and keeps the result only when the sharpness
    metric does not drop below 80% of the input;
    `cr_mask_norm_32580` (320 B) dispatches on `cfg[0x44]` (0 = no-op, 1 =
    optional feature-extract step, 2 = flatten, else 0x69);
    `cr_block_variance_run_42150` (3792 B) reduces each row to block means
    (first/last block trimmed by 3, saturation flag when any pixel >= 255),
    computes the masked-variance ratio of the 3-tap-blurred means, then
    subtracts the block residual, differentiates at the block boundaries
    (1/4/3-tap by ratio), median-filters five rows, integrates along the
    columns and smooths with a 7-tap FIR, optionally preceded by a box median
    of width `cfg[8]` (3 functions).
83. masked contrast/sharpness normalisation:
    `cr_masked_contrast_norm_26410` (1632 B) box-max-unpacks the source,
    reports its masked sharpness, differences a 0.7-sigma Gaussian of the s16
    reference against that reference, fits a single scale over the interior
    (10-px border, `img1 == 0xff`) from the covariance of the residual with a
    7-tap FIR of the mask, and rewrites every mask byte as
    `((mask - (ref-mean)*scale)*img1 + (255-img1)*max_mask)/255 + 0.5`,
    clamping to `[0,255]`; the rewritten mask's sharpness is the second output
    (1 function).
84. mask stage driver and descriptor/point-grid feature pipeline:
    `cr_mask_stage_208a0` (512 B) allocates and fills the s16 plane, thresholds
    it into the byte mask, runs the masked-template blend, the mask
    normalisation, the block-variance gate and the mask pipeline;
    `cr_feature_pipeline_34ed0` (640 B) drives the point-grid constructor,
    populate and selector, then packs the angle field and allocates the bit
    table (2 functions).
85. sharpness gate and mask refine:
    `cr_sharp_gate_48310` (320 B) block-extreme-unpacks the mask, gates on the
    mode byte, runs the feature-extraction step, compares the two masked
    sharpness outputs at 0.8x and copies the slot payload when it improves;
    `cr_mask_refine_344e0` (272 B) copies the slot payload, runs the gate for
    modes 1/2, inpaints from the index list and writes the final bitmap
    (2 functions).
86. feature pipeline driver:
    `cr_feature_run_28bc0` (544 B) allocates and initialises the feature
    wrapper, drives the point-grid pipeline, patches the output bit table and
    releases the descriptor's sub-buffers under the byte/float guards
    (1 function). Also fixed three `cr_obj_ctor_20aa0` transcription errors
    found while wiring it up (fill target, sel-5 buffer fields, sel-2 first
    allocation status).
87. multi-slot mask fusion driver:
    `cr_mask_dispatch_39820` (2112 B) counts the populated slots, short-circuits
    a single slot to one mask stage, and otherwise runs the five-slot fusion:
    saturation-gated selector, two mask stages, two boxmax/FIR bitmaps, an
    agreement score over the covered pixels, then either a stretch + per-pixel
    weighted blend or a straight copy-out (1 function).
88. per-slot quality ranking + mask dispatch:
    `cr_slot_select_11170` (1856 B) reads the pixel geometry from `slots[0]`,
    validates that each populated slot matches `a1`'s w/h, allocates a f32
    scratch, then dispatches on `cfg[0x108]`: mode 0/3 (cnt==1) runs one mask
    stage at idx 0, mode 1 picks idx 0 or 1 from the slot count, mode 3 runs
    the multi-slot fusion driver, mode 2 walks a ranked index list (computing
    it on the first call from a 1000-weighted blend of "usable pixel" and 15×15
    gradient scores, then stable descending bubble sort). Finally the f32
    scratch is scaled back into `a1` with `cr_f32_to_i16_scaled(..., 6) (1
    function).
89. per-slot quality ranking over u8 payloads:
    `cr_slot_rank_u8_22b70` (1312 B) validates the populated slot run against
    the image geometry, requires `cfg[0x108] == 2`, and on the first call
    scores each slot with a 1000-weighted blend of a 0xff-fraction "usable"
    score and a 15×15 box-mean gradient score (`cr_boxsum15_u8` twice over
    `|v - boxmean(v)|`), sorts the (score, index) pairs descending, and walks
    one entry into `cr_mask_refine_344e0` as its selector (1 function).
90. block texture search + 64-tap kernel filter:
    `cr_block_filter_222b0` (2240 B) validates the geometry against the int32
    range fields at `cfg+0xc..+0x18`, scans a `cfg[8]`-step block grid for one
    whose adjacent-difference energy ratio exceeds `cfg+4` (setting `*out` to
    100), then builds a Q6 mean-subtracted row buffer with mirrored edges and
    runs four 64-tap convolutions against the embedded 8x8 kernel table,
    writing the clamped `(32 + mean + v - conv) >> 6` result back (1 function).
91. edge-oriented Gaussian padding:
    `cr_gauss_edge_pad_15540` (4576 B) builds a 17-tap Gaussian window from
    `sigma`, allocates five float planes (`17*dim`, `17*dim`, `9*dim`, `9*dim`,
    `27*dim`), then fits nine orientation hypotheses along each of the four
    image borders (top/bottom rows and left/right columns of `a2`), smooths the
    nine scores with `cr_tri9_filter`, projects the winner through
    `cr_affine_transform`, and splats the border pixels along the fitted
    direction with `cr_splat_accum16`. Two division passes per axis write the
    padded margin rows (`a1->a` stride, `offy` rows above and below) and
    columns (`offx` columns left and right) of `a1` (1 function).
92. orientation-mapped kernel-bank padding + correlation:
    `cr_pad_filter_12aa0` (1136 B) pulls the descriptor tag (`K=9`, 501-kernel
    bank) from `cr_desc_get_tag_ptr`, allocates a `w*h*4` int32 scratch and an
    `((w+K+2)&~3) x (h+K-1)` padded image, and blits the source in with a
    `(K-1)/2` margin using extend / fill-zero / extend / mirror for modes 0-3
    (mode 0 also edge-pads the subview with `cr_gauss_edge_pad_15540`). The
    orientation map is rescaled in place from degrees*256 to kernel indices,
    `cr_corr_kbank` correlates the padded image with `kbank[map[i]]`, and the
    int32 results are min/max-normalised to int16 with `scale = range/16384+1`
    (1 function). It also fixed `cr_desc_get_tag_ptr` to hand out the embedded
    501x81 kernel bank at `0x180145240` (new `src/fpc_kbank.c`).
93. orientation-encode front end:
    `cr_orient_encode_1ba60` (400 B) rejects odd dimensions, allocates a
    same-size int16 scratch, then either encodes the source directly
    (`cfg[0] == 0`) or first copies it, runs `cr_blur_diff_norm` on the copy
    with the caller's float pair (`cfg[0] == 1`), and hands the result to
    `cr_structure_orient_dispatch_2cfd0`. The resulting orientation map is
    consumed by `cr_pad_filter_12aa0` with `cfg[0x0e]`/`cfg[0x11]` as the pad
    mode and descriptor selector (1 function).
94. orientation post-processing selector:
    `cr_orient_pipeline_18c60` (496 B) picks `cfg[1]` or `cfg[0]` depending on
    `a6` and dispatches six ways: identity, FFT-weighted filtering, blurred-pair
    difference, blur + 14-bit stretch, `cr_orient_encode_1ba60` + stretch, and
    blur + `cr_blur_divnorm_stretch`; the non-FFT paths optionally finish with
    `cr_bitmap_filter_apply_s16` (1 function).
95. block orientation / run-length descriptor:
    `cr_block_orient_195d0` (3808 B, ten arguments) walks an `X`-sized cell grid
    over the Gaussian-derivative pair, popcounts each cell against the bitmap,
    eigen-decomposes the 2×2 structure tensor, samples an oriented `X×X` patch,
    thresholds its column profile between the local extrema means, and reports
    four run statistics plus a masked coherence score while clearing
    low-quality cells from the bitmap (1 function).
96. five-grid block-orientation wrapper:
    `cr_block_orient_48010` (768 B) derives the `gw`/`gh` grid size from
    `W/X` and `H/X` (with the vendor's crossed remainder tests), allocates and
    `-1.0f`-fills five float grids, runs `cr_block_orient_195d0` over them and
    frees every grid on both paths (1 function).
97. orientation-scorer selector:
    `cr_orient_score_dispatch_1c220` (96 B) switches on `cfg[0]` (rejecting
    `> 10`) into `cr_structure_tensor_score`, `cr_mscale_run_16d00`,
    `cr_block_orient_48010`, or the two constant stores `*out = -1` / `1000`
    (1 function).
98. block feature pipeline:
    `cr_feature_pipeline_1ad30` (3168 B) validates a descriptor/calibration
    pair and a block grid (`m`, `s`, `d`, `e2`, `n`, `mn`, `q`, with `a5` as
    the block row stride), centres the float image, runs a calibration matmul
    plus a row-dot reduction, gates on the max of a box-mean edge pass against
    `cfg.f32[4]`, and — when the gate fails — builds a second mean-subtracted
    plane, multiplies it by the descriptor chain, subtracts the per-block
    result from the image and finishes with the block-variance and box-mean
    stages (1 function).  This batch also fixed `cr_desc_get_ptr_size_69`,
    which was not storing the `image+0x1229e0` / `image+0xa0c80` pointers for
    selectors 15/16.
99. trained-model chain stages:
    `cr_chain_score_26a70` (192 B), `cr_chain_gate_43020` (32 B) and
    `cr_chain_stage_43040` (224 B) resolve the static chain descriptors through
    `cr_desc_get_ptr1`/`cr_desc_get_ptr2`, seed an affine sampler from the
    bitmap centroid, run the pyramid stage or the int16 chain classifier, and
    store the scaled score.  `cr_desc_get_ptr1` (sel 4) and
    `cr_desc_get_ptr2` (sel 12/13) now return the real `image+0x159ea0` /
    `image+0x122980` / `image+0x1598e0` chain addresses instead of NULL, which
    is what unblocked this batch (3 functions).
100. BEP image front end:
    `cr_bep_process_1c810` (1408 B) drives the whole per-frame pipeline over a
    0x90-byte result object: s16/u8 allocation at the slot-descriptor size,
    slot selection (`cr_slot_select_11170`, with 0x3e9/0x3ec/0x3ed recorded as
    stages 1/2/3), gradient score, the block-feature or gain-normalisation
    branch, optional sub-view extension and resize, normalisation, 14-bit
    stretch, bitmap build/margin/popcount, orientation dispatch, structure
    tensor, optional chain stage, orientation pipeline, the `(x+0x20)>>6`
    s16→u8 conversion and the `cfg[0x250] == 2` structure-tensor score.  The
    slot selector's fourth argument is `*(void**)a2` (the mask/params block)
    and its fifth is the slot array `a4` — the two were swapped in the first
    draft, which made the vendor dereference a NULL mask (1 function).
101. BEP frame pipeline (u8 path):
    `cr_bep_process_368d0` (816 B) is the byte-image twin of `1c810`: it views
    the caller's u8 plane and bitmap, ranks/selects a slot, then runs the
    optional block filter, gain normalisation, sub-view extension, mean
    correction, stretch, margin extract, population count, the selector-4
    chain gate and the bandpass dispatch.  This batch also fixed
    `cr_chain_score_26a70`, which was calling `cr_centroid_affine` with the
    image pointer in the `win_w` slot and omitting the vendor's `margin = 2`
    (visible in the disassembly as `mov dword ptr [rsp+0x28], 2`); the old
    call only ever produced `0x82`, which is why the earlier 26a70/43020
    tests passed without exercising the success path.  Both chain tests now
    use 96×96 buffers so the centroid window actually fits (1 function).
102. BEP frame dispatcher:
    `cr_bep_dispatch_17420` (176 B) is the six-argument front door used by the
    enrolment path: it reads `cfg[4]` from `ctx+0x28` and routes to
    `cr_bep_process_1c810` (selector 0, s16) or `cr_bep_process_368d0`
    (selector 1, u8), passing the slot array as the pipeline's fourth argument
    and the result object as its first.  On failure it clears the result
    image and folds the status to `0xdc` (0x3e9/0x3ec/0x3ed), `0x69`, or
    `0xc8`.  Both existing pipeline tests now re-run their inputs through the
    vendor and clean wrappers and compare the return code and every mutated
    buffer (1 function).

See [`REACHABLE.md`](REACHABLE.md) for the full frontier and
[`MAP.md`](MAP.md) for what each completed function actually does.
