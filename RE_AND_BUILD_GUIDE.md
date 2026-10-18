# FPC `10a5:e340` — Complete Reverse-Engineering & Build Guide

This document is the end-to-end guide for the Acer Swift 3 SF314-512 fingerprint
sensor: how the vendor stack was reverse-engineered, how the clean-room
reimplementation is structured and validated, and how to build and run every
component on Linux.

Everything here was verified against real hardware (USB `10a5:e340`,
firmware `20.26.23.27`). Do not assume behaviour from the sibling `10a5:9201`
part — it differs in endianness, TLS roles, and geometry.

---

## 0. TL;DR

```sh
# 1. Clean-room BEP library + differential test (x86-64 only)
cd cleanroom && make && make check

# 2. Native rehost of the vendor enclave (still needs the DLL for bootstrap)
cd ../native && make

# 3. Correlation matcher
cd ../matcher && make

# 4. libfprint driver (see §4.5 for the meson integration)
#    build libfprint 1.94.100 with -Ddrivers=fpc2040
```

Live validation already achieved:

| Test | Result |
|---|---|
| Enrol right index ×5 via libfprint | 5/5 stages, print saved |
| Verify same finger | `FPI_MATCH_SUCCESS` |
| Verify different finger | `FPI_MATCH_FAIL` |

---

## 1. Hardware & software inventory

| Item | Value |
|---|---|
| USB VID:PID | `0x10a5:0xe340` ("FPC Sensor Controller") |
| Interface string | `FPC L:0001 FW:20262327` |
| Firmware (`GET_STATE`) | `20.26.23.27` |
| Bulk IN endpoint | `0x81`, 64-byte MPS (Acer); `0x82` on `10a5:9201` |
| Raw contact frame | 128 × 88, 8-bit, 11 264 bytes |
| Reconstructed ridge image | 64 × 176, 8-bit, 11 264 bytes |
| Vendor package | `FingerPrint_Carewe_20.26.23.27_W11x64` |
| Enclave DLL | `.../x64/fpc_enclave.dll` (plain `no_sgx` x86-64 PE) |
| Host driver | `fpc_disum.dll` |

The sensor is **match-on-host**, but the `EVT_IMG` stream carries only a
ridge-free capacitive contact buffer. Ridge recovery happens in the host-side
enclave DLL. There is no SGX barrier and the calibration blob
(`calibrationimg.pndat`) is effectively empty — the blocker was purely
algorithmic.

---

## 2. Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│ Applications / PAM                                              │
│   fprintd  ←  pam_fprintd                                        │
└───────────────────────────┬──────────────────────────────────────┘
                            │ libfprint API
┌───────────────────────────▼──────────────────────────────────────┐
│ libfprint 1.94.100                                               │
│   driver: fpc2040  (custom FP_TYPE_DEVICE, NOT an image device)   │
│     • USB control + bulk transfers (GUsb)                        │
│     • TLS 1.2 PSK client                                         │
│     • event reassembly (plain + decrypted inner events)          │
│     • enrol / verify / identify                                  │
│     • 5-template gallery in FpPrint "fpi-data"                   │
└───────────┬───────────────────────────────┬──────────────────────┘
            │ raw 128×88 payload            │ ridge templates
┌───────────▼──────────────┐   ┌────────────▼─────────────────────┐
│ bep_runner.c             │   │ fpc_match.c                      │
│  fpc_bep_ridge()         │   │  band-pass + local norm +        │
│   → fpc_recon_native     │   │  masked rotation-search NCC      │
│     --cleanroom          │   │  score 0..1000, threshold 550    │
└───────────┬──────────────┘   └──────────────────────────────────┘
            │
┌───────────▼──────────────────────────────────────────────────────┐
│ native/fpc_recon_native                                          │
│   • PE loader maps fpc_enclave.dll                               │
│   • Win32 shims (heap, locks, time, printf)                       │
│   • --cleanroom routes BEP op 0x18001c810 → cr_bep_process_1c810  │
│   • enclave bootstrap (setup / ecall / fmi) still vendor code     │
└───────────┬──────────────────────────────────────────────────────┘
            │ bit-exact C
┌───────────▼──────────────────────────────────────────────────────┐
│ cleanroom/libfpcbep.a                                            │
│   355/355 reachable functions reimplemented in plain C           │
└──────────────────────────────────────────────────────────────────┘
```

---

## 3. Part I — Reverse engineering

### 3.1 Target artifacts

1. **`fpc_disum.dll`** — host driver. Contains the USB/TLS protocol and the
   orchestration around the enclave.
2. **`fpc_enclave.dll`** — plain x86-64 PE, no SGX. Contains the BEP
   (`fpc_bio_bep_sw23_*`) and the biometric state machine.
3. **USB captures / raw frames** — ground truth for protocol and image parity.

### 3.2 Tooling and workflow

- **REA / IDA MCP** for disassembly, xrefs, call graphs and decompilation.
- **Ghidra** decompilation as a first pass — types are often wrong.
- **`native/pe_loader.c`** to map the DLL on Linux and call RVAs directly with
  the Microsoft x64 ABI.
- **`cleanroom/tools/difftest.c`** to compare vendor vs clean-room results
  bit-for-bit.

Rule of thumb: **the assembly is authoritative**. Vendor symbol names are
present but frequently wrong or misleading. Never infer semantics from a name.

### 3.3 USB protocol

Two channels:

**Control transfers (endpoint 0)**

| `bmRequestType` | Direction |
|---|---|
| `0x40` | host → device |
| `0xc0` | device → host |

| Command | Value | Notes |
|---|---|---|
| `CMD_INIT` | `0x01` | `wValue=1`, payload `10 2f 11 17` |
| `CMD_ARM` | `0x02` | `wValue=1`, `11 2f 11 17` arm / `12 2f 11 17` disarm |
| `CMD_ABORT` | `0x03` | |
| `CMD_TLS_INIT` | `0x05` | `wValue=1` |
| `CMD_TLS_DATA` | `0x06` | TLS records, ≤64-byte chunks |
| `CMD_INDICATE_S_STATE` | `0x08` | `wValue=0x10` |
| `CMD_GET_IMG` | `0x09` | request frame after finger-down |
| `CMD_GET_DEAD_PIXELS` | `0x0a` | |
| `CMD_GET_TLS_KEY` | `0x0b` | returns sealed PSK blob |
| `CMD_GET_KPI` | `0x0c` | quality metrics |
| `CMD_FINGERPRINT_SESSION_OFF` | `0x12` | |
| `CMD_REFRESH_SENSOR` | `0x20` | |
| `CMD_GET_FW_VERSION` | `0x30` | |
| `CMD_GET_HW_UNIQUE_ID` | `0x31` | |
| `GET_STATE` | `0x50` | 72-byte reply, first 4 bytes = version |

**Bulk IN events** — every packet is a 12-byte header + payload:

```c
struct fpc_event {
    uint32_t code;     /* EVT_* */
    uint32_t len;      /* TOTAL packet length, including this header */
    uint32_t unknown;
};
```

Little-endian on `e340` (big-endian on `9201`).

Key event codes: `EVT_TLS=0x05`, `EVT_FINGER_DWN=0x06`, `EVT_IMG=0x08`.
`EVT_FINGER_DWN` is a **header-only packet (len = 12, zero payload)**.

### 3.4 TLS-PSK handshake and key derivation

1. `CMD_INIT` → device replies with an init event.
2. `CMD_GET_TLS_KEY` → sealed key blob.
3. Verify the blob:
   - magic `0x0dec0ded`
   - AAD starts with `"FPC TLS Keys"`
   - HMAC-SHA256 over `AAD || key` using `SHA256("FPC_HMAC_KEY")` must match
     the blob's signature.
4. Unseal the PSK with AES-256-CBC (no padding) using
   `SHA256("FPC_SEALING_KEY")`.
5. `CMD_TLS_INIT`, then run a TLS 1.2 **client** handshake with PSK identity
   `"Disum PSK"`. TLS records are exchanged through `CMD_TLS_DATA`.
6. `CMD_ARM` arms the sensor.

After the handshake, events arrive in **two forms**:
- plain framed bulk packets (`EVT_FINGER_DWN`, `EVT_IMG`, …), and
- events inside the decrypted TLS stream (also 12-byte framed).

A correct implementation must handle **both**. This was one of the main
bring-up bugs in the driver.

Frame payload layout for `EVT_IMG`:

```
[ 22-byte image header ][ 128×88 = 11264 pixel bytes ]   = 11286 bytes
```

### 3.5 The enclave and the BEP

The enclave exposes a root entry (`FpcBioEnrolAdd` at `0x1800013d0`) that drives
a state machine down to the image operation at `0x18001c810`. The clean-room
reimplements that operation as:

```c
cr_bep_process_1c810(result, cr_image_in, a3, a4, ctx, a6);
```

- `result[0x90]` holds the output pointer at `+0x18`.
- `a4[0]` points to `{ w, h }` (64 × 176 for the output).
- `ctx[0x40]` exposes flags and a config table.
- The control buffers are **constant per sensor**; only the pixels change.

Two static table families are referenced through
`g_cr_image_base + file_offset` (e.g. chain descriptors at `+0x159ea0`,
`+0x122980`, `+0x1598e0`), so table-consuming functions are bit-exact rather
than stubbed.

### 3.6 Function inventory and reachability

`cleanroom/tools/reachable.txt` lists every reachable function (address, vendor
symbol, size). `done.txt` lists the reimplemented ones. The invariant is:

```
done.txt == reachable.txt        # 0 missing, 0 extra
```

Current state: **355/355 functions, 169 488 bytes, 100 % of reachable `.text`**.

### 3.7 Clean-room transcription rules

These are non-negotiable for bit-exact parity:

1. **`-ffp-contract=off`** — otherwise gcc fuses `a*b + c` into an FMA and the
   rounding changes.
2. Preserve the **exact order** of floating-point operations.
3. Integer casts of out-of-range floats rely on `cvttss2si` semantics
   (`INT_MIN` on overflow/NaN). Plain `(int)` casts reproduce this on x86-64.
4. The vendor code reads **uninitialised / out-of-bounds heap memory** (e.g. the
   streaming vertical-FIR mirror branch indexes `ring + rem*w` with negative
   `rem`). Parity therefore depends on a deterministic heap:
   - `native/win32_shims.c` (`SHIM_HEAD`) and
   - `cleanroom/src/fpc_alloc.c` (`CR_HEAD`)
   both zero-fill allocations and prepend head slack. **Do not remove this.**
5. `x86-64 only` for the difftest harness (`ms_abi`); the library itself is
   portable C.

### 3.8 Validation oracles

Two independent gates:

1. **Differential test** (`cleanroom/tools/difftest.c`) — maps the vendor DLL and
   calls each vendor function and its clean-room twin on the same inputs,
   comparing results bit-for-bit. Current: **370 functions OK, 0 mismatches**.
2. **Real-data parity** — `native/fpc_recon_native --cleanroom` over the capture
   corpus: **37/37 real captures byte-identical**.

The real-data gate is essential: synthetic fixtures once hid an origin-vs-count
mix-up (`rs == cs == 0` in every fixture). When adding tests, **vary the
origins**.

### 3.9 Matcher design

NBIS `bozorth3` cannot work here: the strip yields only 2–6 minutiae per frame,
below `MIN_COMPUTABLE_BOZORTH_MINUTIAE = 10`, so every pair scores 0.

The clean-room matcher (`matcher/fpc_match.c`) instead does:

1. band-pass filtering (remove shading, keep ridges),
2. local contrast normalisation (wet/dry regions weigh equally),
3. masked, rotation-searched normalised cross-correlation (±30°, refined ±2°).

Scores are 0..1000. Empirically:

| Population | Range |
|---|---|
| Genuine, across sessions | 700–900 |
| Genuine, live sensor | 892–934 |
| Impostor | 200–450 (live: 287–411) |

Default threshold: **550**. Multi-template enrolment uses
`fpc_tpl_match_gallery` / best-of-N.

### 3.10 libfprint driver design

`fpc2040.c` is a **custom `FP_TYPE_DEVICE`**, not an `FpImageDevice`, because
libfprint's image path assumes NBIS minutiae matching.

- Capture: GUsb control + bulk transfers, TLS-PSK as above.
- Events: plain outer frames **and** decrypted inner frames, both reassembled
  with a 12-byte-header parser.
- Enrol: 5 presses, each converted to a 64×176 ridge and appended to a blob:
  ```
  [ u32 magic "FPC1" ][ u32 count ][ count × 11264 ridge bytes ]
  ```
  Stored in the `FpPrint` `fpi-data` property as `(ay)` with
  `fpi_print_set_type(FPI_PRINT_RAW)`.
- Verify: capture one probe, match against every template, take the best score,
  report `FPI_MATCH_SUCCESS` / `FPI_MATCH_FAIL`.
- Identify: same, across all enrolled prints.
- Endpoint and MPS are auto-discovered from the USB descriptors.

---

## 4. Part II — Build and run

### 4.1 Prerequisites

- Linux x86-64 (the difftest and vendor DLL are x86-64 only)
- `gcc`, `make`, `pkg-config`
- GLib / GIO, GUsb ≥ 0.4, libusb-1.0, OpenSSL ≥ 3.0, pixman
- `meson` + `ninja` (for libfprint)
- The vendor package (for the DLL, used only as a parity oracle / bootstrap)

On Arch:

```sh
sudo pacman -S base-devel meson ninja glib2 gusb libusb openssl pixman
```

### 4.2 Clean-room library + difftest

```sh
cd cleanroom
make                 # builds libfpcbep.a and difftest
make check           # runs difftest against fpc_enclave.dll
```

Expected: `370 functions ok / 0 mismatches / RESULT: PASS`.

Key flags: `-O2 -ffp-contract=off -fno-strict-aliasing`.

### 4.3 Native rehost

```sh
cd native
make                 # needs ../cleanroom/libfpcbep.a
```

Usage:

```sh
./fpc_recon_native <raw.bin> [out.raw] \
    --dll path/to/fpc_enclave.dll [--cleanroom] [--no-dllmain]
```

- Without `--cleanroom`: runs the vendor pipeline.
- With `--cleanroom`: routes `0x18001c810` to `cr_bep_process_1c810`.
- `FPC_BEP_DUMP=<prefix>` dumps the exact BEP input buffers once (used to
  build a standalone runner).

The input `.raw` file is the **EVT_IMG payload** (22-byte header + 11264
pixels). The output is a 64×176 ridge image.

### 4.4 Matcher

```sh
cd matcher
make                 # builds fpc_match_tool
./fpc_match_tool a.ridge.raw b.ridge.raw
```

The library is two files (`fpc_match.c/.h`) with no dependencies beyond
`libm`; it is compiled directly into the libfprint driver.

### 4.5 libfprint driver

Use libfprint **1.94.100**. Copy the driver sources into the tree:

```sh
cp linux-driver/src/fpc2040.c      $LIBFPRINT/libfprint/drivers/
cp linux-driver/src/bep_runner.c   $LIBFPRINT/libfprint/drivers/
cp linux-driver/include/bep_runner.h $LIBFPRINT/libfprint/drivers/
cp linux-driver/include/fpc_protocol.h $LIBFPRINT/libfprint/drivers/
cp matcher/fpc_match.c             $LIBFPRINT/libfprint/drivers/
cp matcher/fpc_match.h             $LIBFPRINT/libfprint/drivers/
```

Register the driver in `$LIBFPRINT/meson.build`:

```meson
drivers_info = {
    ...
    'fpc2040': { 'helper': ['openssl'] },
}
```

and in `$LIBFPRINT/libfprint/meson.build`:

```meson
driver_sources = {
    ...
    'fpc2040' : files(
        'drivers/fpc2040.c',
        'drivers/bep_runner.c',
        'drivers/fpc_match.c',
    ),
}
```

Configure and build:

```sh
meson setup build \
    -Ddrivers=fpc2040 \
    -Dintrospection=false \
    -Ddoc=false \
    -Dinstalled-tests=false \
    -Dudev_rules=disabled
ninja -C build
```

> **Meson ≥ 1.12 note:** `tests/meson.build` uses the old single-variable dict
> iteration. Change `foreach driver_test: drivers_tests` to
> `foreach driver_test, _unused: drivers_tests`.

Verify registration:

```sh
./build/libfprint/fprint-list-supported-devices | grep 10a5
# 10a5:a900 | Fingerprint Cards Disum (Honor / Acer)
# 10a5:e340 | Fingerprint Cards Disum (Honor / Acer)
```

### 4.6 Live test (no fprintd required)

```sh
cd build
printf '6\n' | G_MESSAGES_DEBUG=all stdbuf -oL ./examples/enroll
printf '6\n' | G_MESSAGES_DEBUG=all stdbuf -oL ./examples/verify
```

- `6` = right index.
- Use `stdbuf -oL`: the examples' stdout is block-buffered when piped.
- Enrol needs **5 presses**; verify needs **1**.
- The print is stored in `test-storage.variant` in the current directory.

Expected: `MATCH!` for the enrolled finger, `NO MATCH!` for any other finger.

The BEP backend needs two paths, overridable by environment:

```sh
FPC_RECON_BIN=/path/to/fpc_recon_native
FPC_ENCLAVE_DLL=/path/to/fpc_enclave.dll
```

Defaults point at `~/native/fpc_recon_native` and the vendor package path.

---

## 5. Troubleshooting & gotchas

| Symptom | Cause / fix |
|---|---|
| `difftest` mismatches | Missing `-ffp-contract=off`, or the deterministic-heap shims were removed. |
| `g_type_register_static_simple: instance_size <= G_MAXUINT16` | A GObject instance struct exceeded 64 KiB. Heap-allocate large buffers. |
| Enrol hangs, no events | `EVT_FINGER_DWN` is header-only; handle the outer event code directly. Also ensure decrypted TLS events are drained. |
| Device disappears (`LIBUSB_ERROR_NO_DEVICE`) | A killed process can leave the sensor mid-session; it re-enumerates. Re-open or replug. |
| No events after arming | The sensor is silent until touched — this is normal. |
| `Error loading storage` on first run | Expected: no `test-storage.variant` yet. |
| Meson `Foreach expects exactly 2 variables` | Patch the dict iteration (see §4.5). |
| `pkg-config libfprint-2` missing | libfprint is built from source here, not installed. |

---

## 6. File map

| Path | Purpose |
|---|---|
| `README.md` | Project overview and protocol summary |
| `linux-driver/README.md` | Detailed USB protocol tables |
| `linux-driver/include/fpc_protocol.h` | Protocol constants and structs |
| `linux-driver/src/fpc_disum_tool.c` | Reference capture tool (libusb) |
| `linux-driver/src/fpc2040.c` | libfprint driver (GUsb) |
| `linux-driver/src/bep_runner.c` | BEP + matcher backend |
| `matcher/` | Correlation matcher + `MATCHING.md` |
| `native/` | PE loader, Win32 shims, `fpc_recon_native` |
| `cleanroom/` | 355-function clean-room BEP, `libfpcbep.a`, difftest |
| `cleanroom/MAP.md`, `REACHABLE.md` | Function inventory and mapping |
| `TESTING.md` | Determinism and parity test details |
| `ENCLAVE_IMAGE_PIPELINE.md` | Enclave image pipeline analysis |
| `WINE_REHOST.md` | Early Wine-based rehost notes |

---

## 7. Current status & roadmap

**Done**

- USB/TLS-PSK protocol fully solved.
- Clean-room BEP: 355/355 functions, 370 difftest cases, 37/37 real frames
  byte-identical.
- Correlation matcher validated: 0 FAR / 0 FRR on live hardware.
- libfprint `fpc2040` driver: enrol, verify, identify all working live.

**Remaining**

1. **Fully standalone clean-room** — remove the vendor DLL bootstrap
   (`fpc_setup_enclave` / `FpcTaInitialize_ecall` / `fmi`) so no vendor code is
   needed at runtime.
2. **fprintd / PAM integration** — install libfprint system-wide, package udev
   rules, wire `pam_fprintd` for login and sudo.
3. **Upstreaming** — split the driver and matcher into a reviewable patch
   series for libfprint.
