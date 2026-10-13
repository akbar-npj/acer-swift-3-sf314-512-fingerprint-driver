# Native rehost — `fpc_enclave.dll` BEP reconstruction without Wine

`fpc_recon_native` runs the vendor's ridge-image reconstruction **natively on
Linux**, with no Wine. It maps `fpc_enclave.dll` (a plain `no_sgx` x86-64 DLL)
into the process with a small PE loader, supplies native implementations of the
Win32 imports the code needs, and drives the same BEP path the Wine harness uses.

Output is **byte-identical** to the Wine rehost (validated on 27 distinct captured
frames — see "Validation" below) and has been driven **end-to-end against live
hardware** (three real finger taps → clear ridge image; see
`../analysis/reconstructed/live-native/`).

## Build & run

```sh
cd native
make                                    # gcc, x86-64 only (ms_abi)
./fpc_recon_native <raw.bin> [out.raw] [--dll fpc_enclave.dll]
```

`<raw.bin>` is a captured `EVT_IMG` frame (11286 B: 22-byte sub-header + 11264
px). `out.raw` defaults to `$FPC_OUTIMG` or `recon.raw`. The DLL is found via
`--dll`, then `$FPC_ENCLAVE_DLL`, then `./fpc_enclave.dll`.

Debug: `PE_DEBUG=1` (loader dump), `FPC_TRACE=1` (metadata put/get),
`--no-dllmain` (skip CRT init).

The normal entry point is `../wine-rehost/fpc_reconstruct.sh`, which prefers this
binary when present and falls back to Wine otherwise (`FPC_BACKEND=native|wine`).

## What it does

1. **PE loader** (`pe_loader.c`) — maps the image at its preferred base
   `0x180000000` (falls back to relocating via `.reloc`), resolves imports
   through `shim_lookup`, and looks up exports by name.
2. **Win32 shims** (`win32_shims.c`) — heap (`HeapAlloc`…→ `malloc`), critical
   sections, TLS, time, process/thread ids, locale, stdio, plus a real
   `BCryptGenRandom` (`getrandom(2)`). The rest are benign stubs.
3. **Driver** (`fpc_recon.c`) — `DllMainCRTStartup` → `fpc_setup_enclave` →
   `FpcTaInitialize_ecall(0x0300)` → `FpcTaOp_ecall(11,0)` → inject →
   `fpc_copy_buffer_into_fmi(8,…)` → `FpcTaOp_ecall(11,1)` → `FUN_18001c810`,
   which is hooked to dump the reconstructed 64×176 image.

## The four things that make Windows code run on Linux

These were the non-obvious blockers; each produced a hang or a crash until fixed:

1. **Microsoft x64 ABI.** The DLL uses `rcx/rdx/r8/r9` for arguments. Every shim
   and every call into the DLL is `__attribute__((ms_abi))` — on x86-64 gcc this
   makes the register layout match. (Ignored on non-x86 hosts, so this only
   builds on x86-64.)
2. **Fake TEB on `%gs`.** The code reads the TEB through `%gs` (e.g. `__chkstk`
   loads the stack limit from `gs:0x10`). Linux glibc uses `%fs` for TLS, so
   `%gs` is free: `arch_prctl(ARCH_SET_GS, &fake_teb)` with a valid `NT_TIB`
   header (StackBase/StackLimit/Self).
3. **`CRITICAL_SECTION` is recursive.** A plain `pthread_mutex` deadlocks when
   the CRT re-enters during init; a `PTHREAD_MUTEX_RECURSIVE` does not.
4. **`BCryptGenRandom` must work.** The BEP path calls `fpc_secure_random` to
   seed a per-capture value; a failing stub made `fpc_copy_buffer_into_fmi`
   return `-6` (the image was still correct, but the status diverged from Wine).

Also: `pe_section_header` must start with the 8-byte `Name` field — omitting it
shifts every field and corrupts the section table (a `memcpy` with a garbage
size).

## Validation

Run both backends on the same captured frames and `cmp` the outputs. Over **all
27 distinct captured frames** (collected from every capture directory on the
laptop, de-duplicated by md5) the native and Wine backends produce
**byte-identical** images — driven through the real wrapper:

```sh
FPC_BACKEND=native fpc_reconstruct.sh --from <frame>   # -> x_recon.raw
FPC_BACKEND=wine   fpc_reconstruct.sh --from <frame>   # -> x_recon.raw
cmp native/x_recon.raw wine/x_recon.raw
# 27/27 identical
```

Internal status lines also match (Wine's logs are CRLF; compare after normalising
path, pointer and line endings): `fpc_copy_buffer_into_fmi -> 0`,
`FUN_18001c810 -> 0  out_img=… 64x176 hdr=0x3e800xx`,
`op(t=11,c=1) -> 0 out[8]=1 out[12]=15`.

Backend auto-selection: `fpc_reconstruct.sh` reports `[*] backend: native` when
`fpc_recon_native` is built.

### Live hardware validation (2026-10-13)

Driven against a real sensor with **no Wine**: `FPC_BACKEND=native
fpc_reconstruct.sh 3 ~/caps-native`. The tool armed the sensor, the user tapped
three times, and each captured `EVT_IMG` frame was reconstructed by
`fpc_recon_native` into a clear whorl/loop ridge pattern. Evidence committed at
`../analysis/reconstructed/live-native/`: `montage.png`, the three
`*_recon.png`, the source `*.raw` frames, and the per-frame `*.recon.log`
(`fpc_copy_buffer_into_fmi -> 0`, `op(t=11,c=1) -> 0`).

## Scope / caveats

- **x86-64 only** (the DLL is x86-64 and `ms_abi` is an x86 attribute).
- The **vendor code bytes are still shipped** (`fpc_enclave.dll`). This removes
  the *Wine* dependency, not the DLL. A clean-room C rewrite of the reachable
  BEP tree (359 functions, ~166 KiB) is the alternative — the Wine/native builds
  serve as its correctness oracle.
- Only the reconstruction path is exercised; the TLS-handshake bcrypt calls are
  stubbed.
