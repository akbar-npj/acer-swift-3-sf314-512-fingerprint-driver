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
  path, not the clamp.
- **Exponent scaling is a 32-bit shift, not a multiply.** `ldexp` is done as
  `bits(f) + (k << 23)` with `k` an `int`; for `k = INT_MIN` (the NaN path) the
  shift yields 0. Use `(uint32_t)k << 23`, never `k * 0x800000` (signed-overflow
  UB and a different value).
- **Table-driven seeds must be copied byte-exact.** `cr_sqrtf`'s 256-byte
  inverse-sqrt seed table lives at `0x180159500`; the difftest confirms parity
  only because it is reproduced verbatim.
- **Prototypes must match the vendor's argument *position*, including floats.**
  GCC's `ms_abi` assigns XMM registers *positionally*: a `float` at argument
  index *i* lands in `xmm_i` (not "the i-th float in xmm0..3"). So
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

## Progress

| metric | value |
|---|---|
| reachable functions | 355 |
| total `.text` size | 169,488 B (165.5 KiB) |
| leaf functions (rewrite frontier) | 118 |
| rewritten + parity-verified | **110** (31.0% of functions, 28,224 B = 16.65% of bytes) |

Forty batches done so far:
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

See [`REACHABLE.md`](REACHABLE.md) for the full frontier and
[`MAP.md`](MAP.md) for what each completed function actually does.
