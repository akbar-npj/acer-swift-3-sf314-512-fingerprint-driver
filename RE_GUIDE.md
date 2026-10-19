# FPC `10a5:e340` — Reverse-Engineering Guide (deep)

This document is the **deep reverse-engineering write-up** for the Acer Swift 3
SF314-512 fingerprint sensor: how the vendor stack was reverse-engineered, how
the clean-room reimplementation is structured, and how its correctness is
validated.

Everything here was verified against real hardware (USB `10a5:e340`,
firmware `20.26.23.27`). Do not assume behaviour from the sibling `10a5:9201`
part — it differs in endianness, TLS roles, and geometry.

> **Compilation & install live elsewhere.** How to *build* the clean-room
> library, the matcher, the native rehost, and the libfprint `fpc2040` driver —
> and how to *install* them (udev, fprintd/PAM, KDE lock-screen QML, and
> surviving distribution updates) on Debian, Fedora, and Arch — is in the
> companion document **[`CROSS_DISTRO_BUILD_GUIDE.md`](./CROSS_DISTRO_BUILD_GUIDE.md)**.
> Read that one to build/run; read this one to understand the stack.

---

## 0. TL;DR

What we reverse-engineered, and the proof it is correct:

- **USB protocol** (`CMD_*`/`EVT_*`) — fully solved; handshake and session
  flow reconstructed from captured Windows traffic.
- **TLS-PSK** — the sealed PSK is derived with `FPC_SEALING_KEY` /
  `FPC_HMAC_KEY`; the handshake is a standard TLS-PSK over the bulk pipe.
- **Enclave / BEP** — `fpc_enclave.dll` (a plain `no_sgx` x86-64 DLL) does all
  ridge reconstruction. We rehost it (native PE loader, no Wine needed) and then
  re-implement it clean-room.
- **Clean-room BEP** — 355/355 functions, 370 difftest cases, 37/37 real frames
  byte-identical to the DLL output. Fully standalone: the driver links
  `cr_bep_run_frame()`; the DLL is only an oracle, never shipped or loaded.
- **Matcher** — correlation-based (NBIS is unusable: 2–6 minutiae/frame);
  0 FAR / 0 FRR on live hardware.
- **libfprint `fpc2040` driver** — enrol / verify / identify all working live.

Live validation already achieved:

| Test | Result |
|---|---|
| Enrol right index ×5 via libfprint | 5/5 stages, print saved |
| Verify same finger | `FPI_MATCH_SUCCESS` |
| Verify different finger | `FPI_MATCH_FAIL` |
| DLL-free BEP (`cr_bep_run_frame`) | 20/20 corpus frames byte-identical |
| Enrol after removing the DLL backend | 5/5 stages, print saved |

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

## 3. Reverse engineering

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

### 3.5.1 Running the BEP without the vendor image

`cr_bep_process_1c810` takes a five-pointer graph, not just an image. To run it
with no vendor code at all, the graph is captured once and turned into a
template:

1. `FPC_BEP_SNAP=<file>` in `native/fpc_recon_native` dumps every block the
   graph reaches **at function entry** (before the BEP mutates anything):
   roots `a1..a5`, `a6`, and a recursive block list.
2. `cleanroom/tools/gen_template.py` keeps the small control blocks, drops
   every buffer ≥ 32 KiB (they are pure scratch — the BEP writes before it
   reads), copies static objects that live inside the PE image, and emits
   `cleanroom/src/fpc_bep_template.c`.
3. `cr_bep_run_frame(hdr22, pix, out)` (`cleanroom/src/fpc_bep_run.c`)
   rebuilds the graph, patches the frame, and calls the BEP.

Two things are per-frame:

| Input | Where it goes |
|---|---|
| 128×88 pixels (11264 B) | `a4[0]->data` (the pixbuf) |
| 22-byte header bytes | metadata store `a4[7]`, keys `d2..da` |

The header mapping (verified on the whole corpus):

```
d3 = hdr[0]   d5 = hdr[1]   d7 = hdr[2]   da = hdr[3]
d2 = u16 @ hdr[4]   d4 = u16 @ hdr[6]   d6 = u16 @ hdr[8]
```

Static data reached through `g_cr_image_base` is reproduced sparsely: a
`0x17d000` zeroed image with only the referenced regions copied in
(calibration blobs at `+0x117800` / `+0x12d3a0`, descriptor chains at
`+0x159ea0` / `+0x122980` / `+0x1598e0`, `+0x1229e0`, `+0xa0c80`). The blob
sizes are in **elements**, not bytes: `0x1900` floats = `0x6400` bytes.

Validation: all 20 corpus frames are byte-identical with the driver's sparse
image, and `CR_PROBE=1` (guard pages over every uncopied page) confirms the
BEP reads nothing else.

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

> **Building and installing** the clean-room library, matcher, native
> rehost, and the libfprint `fpc2040` driver — including udev, fprintd/PAM,
> KDE lock-screen QML, and update-survival hooks — is covered step-by-step
> for Debian, Fedora, and Arch in
> **[`CROSS_DISTRO_BUILD_GUIDE.md`](./CROSS_DISTRO_BUILD_GUIDE.md)**.

---

## 4. Troubleshooting & gotchas

| Symptom | Cause / fix |
|---|---|
| `difftest` mismatches | Missing `-ffp-contract=off`, or the deterministic-heap shims were removed. |
| `g_type_register_static_simple: instance_size <= G_MAXUINT16` | A GObject instance struct exceeded 64 KiB. Heap-allocate large buffers. |
| Enrol hangs, no events | `EVT_FINGER_DWN` is header-only; handle the outer event code directly. Also ensure decrypted TLS events are drained. |
| Device disappears (`LIBUSB_ERROR_NO_DEVICE`) | A killed process can leave the sensor mid-session; it re-enumerates. Re-open or replug. |
| No events after arming | The sensor is silent until touched — this is normal. |
| `Error loading storage` on first run | Expected: no `test-storage.variant` yet. |
| Fingerprint scanner "fails to load" intermittently / kernel `usb reset` for the FPC device | The kernel autosuspends the USB sensor after ~2s idle (`/sys/.../power/control = auto`); resuming it on next unlock triggers a `usb reset` that races with the libfprint driver's claim. Disable autosuspend with a udev rule — see `CROSS_DISTRO_BUILD_GUIDE.md` §5.3. |
| Meson `Foreach expects exactly 2 variables` | Patch the dict iteration — see `CROSS_DISTRO_BUILD_GUIDE.md` §4.6. |
| `pkg-config libfprint-2` missing | libfprint is built from source here, not installed. |

---

## 5. File map

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
| `cleanroom/src/fpc_bep_run.c` | `cr_bep_run_frame()` — DLL-free entry point |
| `cleanroom/src/fpc_bep_template.c` | generated graph template (do not edit) |
| `cleanroom/tools/gen_template.py` | snapshot → template generator |
| `cleanroom/tools/bep_run_test.c` | one-frame parity harness (`CR_PROBE`) |
| `cleanroom/MAP.md`, `REACHABLE.md` | Function inventory and mapping |
| `TESTING.md` | Determinism and parity test details |
| `ENCLAVE_IMAGE_PIPELINE.md` | Enclave image pipeline analysis |
| `WINE_REHOST.md` | Early Wine-based rehost notes |

---

## 6. Current status & roadmap

**Done**

- USB/TLS-PSK protocol fully solved.
- Clean-room BEP: 355/355 functions, 370 difftest cases, 37/37 real frames
  byte-identical.
- Correlation matcher validated: 0 FAR / 0 FRR on live hardware.
- libfprint `fpc2040` driver: enrol, verify, identify all working live.
- **Fully standalone clean-room BEP**: `cr_bep_run_frame()` links into the
  driver; no vendor DLL, no subprocess. 20/20 corpus frames byte-identical,
  live enrol 5/5 with the DLL-free backend.
- **System install**: `fprintd` + `pam_fprintd` wired for login/screen-lock on
  the Acer (Arch/KDE/SDDM). End-to-end `verify-match` via fprintd and a
  real fingerprint login/unlock both confirmed on the hardware.

**Remaining**

1. **Upstreaming** — split the driver and matcher into a reviewable patch
   series for libfprint.
