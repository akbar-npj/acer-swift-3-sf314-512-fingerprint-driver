# Testing guide — FPC e340 clean-room BEP (`cleanroom/difftest`)

How to build and run the differential test (`difftest`) that validates the
clean-room rewrite of the vendor BEP algorithm against the real
`fpc_enclave.dll`.

> **Read this first.** The test must run on the **x86-64 test laptop** (it has the
> vendor DLL and, for hardware work, the fingerprint sensor). The laptop is on a
> LAN whose **IP changes** — always rediscover it (step 1). The development
> machine is an **arm64 Asahi/Fedora laptop** and **cannot** run x86-64 binaries
> directly, so all building/testing happens over SSH on the test laptop.

---

## 0. Quickstart (copy-paste)

```sh
# 1. find the test laptop (see §1 if this fails)
LAPTOP=192.168.31.184

# 2. run the suite (non-ASan, the canonical check)
ssh shaan@$LAPTOP 'cd ~/cleanroom && make -s && ./difftest \
  ../FingerPrint_Carewe_20.26.23.27_W11x64/12b431fd-7d7e-4dd7-b87c-9ab3f9a3d01b/x64/fpc_enclave.dll'
```

If it aborts, see §6 (Troubleshooting).

---

## 1. Find the test laptop

The laptop's IP is DHCP and changes. Options, in order:

- `~/.ssh/known_hosts` on the dev machine lists previously-seen LAN IPs
  (`grep -oE '^[0-9.]+' ~/.ssh/known_hosts | sort -u`).
- Ping the usual candidates and check port 22:
  ```sh
  for ip in 192.168.31.184 192.168.31.185 192.168.10.1 10.240.74.234; do
    ping -c1 -W1 "$ip" >/dev/null 2>&1 && \
    (exec 3<>/dev/tcp/$ip/22) 2>/dev/null && echo "candidate: $ip"; done
  ```
- Or scan the LAN: `nmap -p22 --open 192.168.31.0/24` (if `nmap` is installed).

**Credentials** (test laptop, LAN-only, low sensitivity — do not push publicly):

| field | value |
| --- | --- |
| user | `shaan` |
| password | `11111111` |
| auth | password (ssh key is **not** set up for the dev machine) |

Non-interactive SSH from a script needs `sshpass` (installed on the dev machine):

```sh
sshpass -p 11111111 ssh -o StrictHostKeyChecking=accept-new \
  -o PreferredAuthentications=password -o PubkeyAuthentication=no shaan@$LAPTOP '<cmd>'
```

---

## 2. Where things live

| | dev machine (arm64) | test laptop (x86-64) |
| --- | --- | --- |
| clean-room source | `~/Projects/FingerPrintSensors/Acer Swift 3 SF314-512/cleanroom/` (git) | `~/cleanroom/` |
| native rehost (shims) | `.../Acer Swift 3 SF314-512/native/` | `~/native/` |
| vendor DLL | `.../Acer Swift 3 SF314-512/FingerPrint_Carewe_20.26.23.27_W11x64/.../x64/fpc_enclave.dll` | `~/FingerPrint_Carewe_20.26.23.27_W11x64/.../x64/fpc_enclave.dll` |

- **The dev machine's git repo is the source of truth.** Edit there, then copy
  the changed files to the laptop (§5).
- The laptop's `~/cleanroom/` mirrors `cleanroom/` **flat** (it also has an
  older flat `difftest.c` copy — ignore it; the Makefile builds `src/*.c` +
  `tools/difftest.c`).
- The Makefile resolves the DLL and the shims **relative to `~/cleanroom`**
  (`../FingerPrint_.../fpc_enclave.dll`, `../native/{pe_loader,win32_shims}.c`),
  which is why the layout above matters.

---

## 3. What `difftest` does

`tools/difftest.c` maps the vendor `fpc_enclave.dll` with the same minimal PE
loader the native rehost uses, then for **every rewritten function** runs a
battery of inputs through **both** the vendor function (at its RVA, Microsoft
x64 ABI) and the clean-room implementation, and compares results bit-for-bit.

- Prints `  ok  <name>` for a passing function, `  FAIL <name>` otherwise, plus
  `  MISMATCH <name> ...` lines (capped) showing the differing inputs.
- Exit code 0 = all pass.
- **`make check` is the canonical command** (non-ASan). An **ASan build** is also
  used to catch memory bugs (§4).

Current baseline (2026-10-18): the suite **passes** — 346 functions `ok`, 0
`FAIL`. The last failures were vendor routines that read *uninitialised* or
*out-of-bounds* heap memory (e.g. the streaming vertical-FIR mirror branch
indexes `ring + rem*w` with a negative `rem`, reaching before the ring). The
harness now gives both sides a deterministic heap — allocations are zero-filled
and preceded by head slack (`SHIM_HEAD` in `native/win32_shims.c`, `CR_HEAD` in
`cleanroom/src/fpc_alloc.c`) — so those reads observe identical zeros.

---

## 4. Build & run

All commands run **on the laptop** (`ssh shaan@$LAPTOP`), from `~/cleanroom`.

```sh
# canonical build + run
make && ./difftest ../FingerPrint_Carewe_20.26.23.27_W11x64/12b431fd-7d7e-4dd7-b87c-9ab3f9a3d01b/x64/fpc_enclave.dll

# same thing via the Makefile target
make check

# AddressSanitizer build (catches heap OOB in the clean-room code)
make clean
make CFLAGS="-O2 -g -Wall -Wextra -ffp-contract=off -fno-strict-aliasing -fsanitize=address" \
     LDFLAGS="-lpthread -fsanitize=address"
ASAN_OPTIONS=detect_leaks=0 ./difftest <DLL path>
```

Notes:
- `-ffp-contract=off` is **required** — without it gcc fuses `a*b+c` into an FMA
  and bit-parity breaks.
- The suite takes ~2 min (non-ASan) / ~2 min (ASan). Force line-buffering to see
  progress before a crash: prefix with `stdbuf -oL -eL`.
- `ulimit -c 0` avoids core dumps / `drkonqi` popups if it aborts.

---

## 5. Edit workflow (dev machine → laptop)

```sh
# edit in the git repo, then push the changed file(s):
scp "~/Projects/FingerPrintSensors/Acer Swift 3 SF314-512/cleanroom/tools/difftest.c" \
    shaan@$LAPTOP:/home/shaan/cleanroom/tools/difftest.c
scp "~/Projects/FingerPrintSensors/Acer Swift 3 SF314-512/native/win32_shims.c" \
    shaan@$LAPTOP:/home/shaan/native/win32_shims.c
# then rebuild + run on the laptop (§4)
```

Commit in the dev-machine repo; the laptop copy is disposable.

---

## 6. Troubleshooting

### `Fatal glibc error: malloc.c: ... (sysmalloc): assertion failed`
Heap-metadata corruption. Two known causes:

1. **Vendor overrun of a scratch buffer.** The DLL's BEP routines occasionally
   write a few bytes past a heap block they allocated. Windows' heap absorbs it;
   glibc does not. Fixed in `native/win32_shims.c`: `sh_HeapAlloc` now hands the
   DLL blocks that are `SHIM_GUARD` (64) bytes larger than requested (filled with
   a `0xC5` canary), restoring Windows-like slack. Run with `SHIM_GUARD_LOG=1` to
   print `[GUARD] block size=… overrun +N byte=…` reports for diagnosis.
2. **DLL sub-pointer passed to `HeapFree`.** The DLL's allocator returns
   sub-pointers that must never reach glibc `free()`. `sh_HeapFree` is a no-op
   and `sh_HeapSize` reports only tracked sizes — keep it that way.

### `difftest` wedges at ~100% CPU (no output, no crash)
A hang, not a crash. The heap shims keep an open-addressing set of every pointer
`sh_HeapAlloc` handed out, but `sh_HeapFree` is a no-op, so the set only ever
*grows*. A **fixed-size** table fills after enough allocations and the probe loop
spins forever looking for an empty slot (seen in `hs_insert`, ~800k allocations
in). The set in `native/win32_shims.c` is therefore **growable** (rehash — dropping
tombstones — once the load factor passes 1/2) and its probe loops are bounded.
Keep it that way; do not reintroduce a fixed capacity.

### ASan: `heap-buffer-overflow ... in cr_<fn>`
A genuine OOB **read/write in clean-room code** (or a faithful transcription of a
vendor over-read). The stack names the function and line. If it is a *faithful*
vendor over-read (e.g. the vendor scans a border margin `c == 0` and reads one
pixel outside), the fix is to constrain the **test input** so it respects the
function's implicit contract — see the guards in `tools/difftest.c`:
- `test_harris_local_max_grid`: `border` kept `>= 1`.
- `test_correlate_34930`: `n` kept odd (the vendor writes one short past its
  scratch for even `n`).
- `test_bitmap_margin_extract`: `dst->h` kept `<= src->h + 6` (the scratch is
  `src->h + 12` rows and the final extract reads `dst->h` rows from row 6).
- `test_linear_softmax2`: the filter-bank kernel table is sized for `nch*nk`
  kernels (4 here), not 2 — the bank reads `nch*nk` kernels of 25 floats.
- `test_block_conv_231a0`: the kernel table is sized for `R*K` 3x3 rows — the
  function advances the kernel base by `K*9` shorts per slice.
- `test_template_ncc_35150`: `ref` is sized for the maximum `radius` (= `rows`,
  up to 67), not 64.
Document the reason in a comment at the guard.

### `MISMATCH <name>` flood
The clean-room function is not yet parity-correct (WIP). Check
`cleanroom/REACHABLE.md` / `MAP.md` / `done.txt` for its status. A function is
"done" only at zero mismatches.

### ASan-only: `cr_image_alloc_u8` / `cr_image_alloc_s16` / `cr_bitmap_alloc` fail
The **ASan build alone** reports these three allocator tests as `FAIL` (with
`ia-fields … vendor=0 clean=0` style lines). This is **pre-existing** — it
reproduces unchanged on the baseline commit — and is an artefact of the ASan
allocator changing the descriptor-address fields those tests compare; it is not
a regression and not a clean-room bug. The **canonical non-ASan `make check`
passes** (346 ok / 0 FAIL as of 2026-10-18). Judge parity by the non-ASan run;
use ASan only to catch heap overflows/underflows.

The same `ia-fields … vendor=0 clean=0` line can also appear **rarely** (roughly
1 run in 10) in the non-ASan build. The allocator test `memcmp`s the *high half*
of the descriptor's data pointer (`+0x0c..+0x0f`) between the vendor heap and
the clean-room heap; under ASLR those two heaps occasionally land in different
high-word regions, so the comparison false-fails even though the pointer is
valid, non-NULL and 16-byte aligned (the test separately checks NULL-ness via
`ia-ptr` and alignment via `ia-align`). It is an environment artefact, not a
parity bug — re-run to confirm; only a mismatch that reproduces on every run is
real.

### `Exec format error` / muvm errors on the dev machine
You tried to run the x86-64 binary on the arm64 dev host. Use the laptop (or a
`podman run --platform linux/amd64` container with qemu — see below).

### Running x86-64 on the arm64 dev machine (fallback only)
The dev host routes x86-64 ELF through a broken `binfmt-dispatcher`
(`/usr/bin/binfmt-dispatcher` is missing). A working path is an amd64 container
with `qemu-x86_64-static` bind-mounted, plus a fresh `binfmt_misc` in a user
namespace so child `exec`s route to qemu. Prefer the real laptop — it is native
and has the hardware.

---

## 7. Related docs

- `cleanroom/README.md` — method, hard requirements, transcription gotchas.
- `cleanroom/REACHABLE.md` — per-function rewrite status.
- `cleanroom/MAP.md` — vendor RVA ↔ clean-room name ↔ real semantics.
- `native/README.md` — the PE loader / Win32 shims / ms_abi details.
- `WINE_REHOST.md`, `ENCLAVE_IMAGE_PIPELINE.md` — how the pipeline was reversed.
