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
├── src/fpc_math.c        math kernel (sqrtf, expf, round/floor)
├── src/fpc_buffer.c      buffer / metadata / image-slot helpers
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

## Progress

| metric | value |
|---|---|
| reachable functions | 355 |
| total `.text` size | 169,488 B (165.5 KiB) |
| leaf functions (rewrite frontier) | 118 |
| rewritten + parity-verified | **35** (9.9% of functions, 2,528 B = 1.49% of bytes) |

Three batches done so far:
1. math kernel + buffer/metadata helpers (11 functions)
2. util kernel + image leaves (14 functions, incl. two byte-identical duplicate pairs)
3. more math/util/image leaves (10 functions, incl. a third `cr_image_set` duplicate)

See [`REACHABLE.md`](REACHABLE.md) for the full frontier and
[`MAP.md`](MAP.md) for what each completed function actually does.
