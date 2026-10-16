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
| rewritten + parity-verified | **311** (87.6% of functions, 116,496 B = 68.7% of bytes) |

Seventy-two batches done so far:
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

See [`REACHABLE.md`](REACHABLE.md) for the full frontier and
[`MAP.md`](MAP.md) for what each completed function actually does.
