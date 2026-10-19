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

# 2. Native rehost of the vendor enclave (only needed to (re)generate the
#    standalone template or an oracle; the driver does not use it)
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

### 4.3.1 Standalone BEP (no DLL)

`cleanroom/src/fpc_bep_run.c` exposes `cr_bep_run_frame()`. The driver links
it directly; nothing vendor-side is needed at runtime.

```sh
cd cleanroom
make                 # builds bep_run_test too

# one frame, compared against a vendor-produced oracle
./bep_run_test frame.raw out.raw oracle.raw
# -> cr_bep_run_frame -> 0
#    PARITY OK (11264 bytes byte-identical)
```

Regenerating the template (only needed if the sensor firmware or the corpus
changes):

```sh
cd native
FPC_BEP_SNAP=/tmp/bep.snap ./fpc_recon_native frame.raw /tmp/oracle.raw \
    --dll path/to/fpc_enclave.dll
cd ../cleanroom
python3 tools/gen_template.py /tmp/bep.snap src/fpc_bep_template.c
make
```

`CR_PROBE=1 ./bep_run_test ...` runs with guard pages over every uncopied page
of the synthetic image and reports the first out-of-region read.

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
        # clean-room BEP (copy of cleanroom/src + cleanroom/include)
        'drivers/fpcbep/fpc_comp.c',
        'drivers/fpcbep/fpc_bep_run.c',
        'drivers/fpcbep/fpc_bep_template.c',
        ... one entry per cleanroom/src/*.c ...
    ),
}
```

Two more edits are required:

```meson
# parity: never let the compiler fuse mul+add into an FMA
drivers_cflags = ['-ffp-contract=off']

# let bep_runner.c find fpc_bep_template.h
deps += declare_dependency(include_directories: [
    ...
    include_directories('drivers/fpcbep'),
])
```

Copy `cleanroom/src/*.c` and `cleanroom/include/*.h` into
`$LIBFPRINT/libfprint/drivers/fpcbep/` first.

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

### 4.7 System install (fprintd / PAM)

Verified on the Acer Swift 3 (Arch Linux, KDE/SDDM, Wayland). The same driver
is also valid for the Honor `10a5:a900` part.

1. **Install the daemon** (pulls libfprint as a dependency):

   ```sh
   sudo pacman -S fprintd
   ```

2. **Replace the distro libfprint with the driver build.** The package ships
   `1.94.100` but without the `fpc2040` driver, so swap the `.so` in place.
   Also stash a *canonical* copy in a pacman-untouched location — this is what
   the auto-restore mechanism (§4.8) re-deploys after every upgrade:

   ```sh
   sudo cp -a /usr/lib/libfprint-2.so.2.0.0 /usr/lib/libfprint-2.so.2.0.0.pacman
   sudo install -m755 ~/src/libfprint-v1.94.100/build/libfprint/libfprint-2.so.2.0.0 \
                    /usr/lib/libfprint-2.so.2.0.0
   # canonical copy used by the restore hook (see §4.8):
   sudo install -Dm755 ~/src/libfprint-v1.94.100/build/libfprint/libfprint-2.so.2.0.0 \
                    /usr/local/lib/fpc2040/libfprint-2.so.2.0.0
   ```

3. **udev** (already in `linux-driver/udev/70-libfprint-2-fpc2040.rules`):

   ```sh
   sudo make -C linux-driver install-udev   # or: cp + udevadm control --reload-rules
   ```

4. **polkit** — over an SSH/headless session fprintd is denied by default. Add
   `/etc/polkit-1/rules.d/49-fprintd-user.rules` (the user below is `shaan`):

   ```js
   polkit.addRule(function(action, subject) {
       if (action.id.indexOf("net.reactivated.fprint.") === 0 &&
           subject.user === "shaan") {
           return polkit.Result.YES;
       }
   });
   ```

   `sudo systemctl restart polkit`.

5. **Enrol + verify as the user** (not root — root's prints land under `root`):

   ```sh
   fprintd-enroll -f right-index-finger   # 5 presses
   fprintd-verify -f right-index-finger   # 1 press -> "verify-match"
   ```

6. **PAM** — add `auth sufficient pam_fprintd.so` to the stacks you want
   fingerprint on. For a laptop, the lock screen and console login:

   ```sh
   # prepend to /etc/pam.d/login and /etc/pam.d/sddm (and create /etc/pam.d/kde)
   auth       sufficient   pam_fprintd.so max-tries=3 timeout=10
   ```

   `sufficient` means a fingerprint match is enough, but a failure falls through
   to the password — it cannot lock you out. Restarting `polkit`/`fprintd` is
   not required; the change takes effect immediately. Originals were saved as
   `/etc/pam.d/{login,sddm}.pre-fprintd` for rollback.

   > Note: a synthetic `pamtester`-style `PAM_PERM_DENIED` is expected when the
   > caller has no real seat/TTY (e.g. a hand-rolled test binary). The actual
   > `login`/`sddm`/`kde` path works because it runs with a proper session.

7. **Enable the daemon** so it is available after reboot (it is D-Bus
   activated, but `enable` is harmless):

   ```sh
   sudo systemctl enable fprintd
   ```

Known gap: `sudo` was intentionally left on password only so headless SSH stays
password-based; add the same `auth sufficient` line to `/etc/pam.d/sudo` to
enable fingerprint sudo.

### 4.8 Surviving `pacman -Syu` (auto-restore the driver)

A future `pacman -Syu` that upgrades `libfprint` will overwrite
`/usr/lib/libfprint-2.so.2.0.0` with the stock build and silently drop the
`fpc2040` driver. The files in `linux-driver/install/` make that self-healing:

| File | Goes to | Role |
|---|---|---|
| `restore-fpc2040-libfprint.sh` | `/usr/local/sbin/` (mode 755) | Restores the canonical `.so` into place; idempotent, safe to run by hand. |
| `99-fpc2040-libfprint.hook` | `/etc/pacman.d/hooks/` | Pacman `PostTransaction` hook: fires on any `libfprint` Upgrade/Install and calls the script. |
| `fpc2040-libfprint-restore.service` | `/etc/systemd/system/` | Oneshot at boot, same script — catches any out-of-band overwrite. |

Deploy once:

```sh
REPO=~/Projects/FingerPrintSensors/Acer\ Swift\ 3\ SF314-512   # adjust
sudo install -Dm755 "$REPO"/linux-driver/install/restore-fpc2040-libfprint.sh \
     /usr/local/sbin/restore-fpc2040-libfprint.sh
sudo install -Dm644 "$REPO"/linux-driver/install/99-fpc2040-libfprint.hook \
     /etc/pacman.d/hooks/99-fpc2040-libfprint.hook
sudo install -Dm644 "$REPO"/linux-driver/install/fpc2040-libfprint-restore.service \
     /etc/systemd/system/fpc2040-libfprint-restore.service
sudo systemctl enable fpc2040-libfprint-restore.service
```

How it behaves:

- **Resolves via the soname symlink** (`libfprint-2.so.2`), so a minor bump
  (`…2.0.0` → `…2.0.1`) is handled without editing anything.
- **Refuses to clobber on a major ABI bump** — if `libfprint-2.so.2` disappears
  (e.g. libfprint-3), it logs "needs rebuild" and exits, instead of breaking the
  system. In that case rebuild the driver against the new libfprint and refresh
  the canonical copy.
- **No-ops when the custom build is already in place** (`cmp -s` guard), and
  **backs up** whatever it replaces (`…distro.<epoch>`) so rollback is trivial.

Test it without waiting for an upgrade:

```sh
# simulate a distro overwrite, then let the hook logic fix it:
sudo cp -a /usr/lib/libfprint-2.so.2.0.0.pacman /usr/lib/libfprint-2.so.2.0.0
sudo /usr/local/sbin/restore-fpc2040-libfprint.sh   # -> "restored custom libfprint"
fprintd-verify -f right-index-finger                 # should still match
```

> Long-term "proper" fix: fork the Arch `libfprint` PKGBUILD to include the
> `fpc2040` driver, so pacman owns the file and an upgrade simply rebuilds it.
> The hook is the zero-maintenance answer until then.

### 4.9 Lock-screen auto-unlock (drop the extra "Unlock" button)

By design (KDE commit `dc6341bb`, Plasma 5.25+) `kscreenlocker` shows an
explicit **Unlock** button whenever authentication succeeds *without a password
prompt having been shown* — meant to stop passwordless accounts unlocking
silently, but it also hits fingerprint/face auth, so you get one extra click
after a good scan. The fix is a one-function edit to the lock-screen QML: make
*any* successful auth call `Qt.quit()` (auto-unlock). Failures still go through
`onFailed` → "Unlocking failed", so the "success → unlock, fail → error"
behaviour you want falls out for free.

The relevant logic in
`/usr/share/plasma/shells/org.kde.plasma.desktop/contents/lockscreen/LockScreenUi.qml`:

```js
function onSucceeded() {
    if (authenticator.hadPrompt) {
        Qt.quit();                       // password path: auto-unlock
    } else {
        mainStack.replace(..., "NoPasswordUnlock.qml", ...);  // the button
    }
}
```

`linux-driver/install/` ships everything to make this persistent:

| File | Goes to | Role |
|---|---|---|
| `patch-lockscreen.py` | run once (as root) | Reads the upstream QML, rewrites `onSucceeded()` to always `Qt.quit()`, writes the canonical patched file to `/usr/local/share/kde-lockscreen/LockScreenUi.qml`. Idempotent; refuses if the QML layout changed. |
| `restore-kde-lockscreen.sh` | `/usr/local/sbin/` (755) | Re-applies the canonical patched QML into place; idempotent, safe to run by hand. |
| `99-kde-lockscreen.hook` | `/etc/pacman.d/hooks/` | `PostTransaction` hook on `plasma-desktop` upgrades. |
| `kde-lockscreen-restore.service` | `/etc/systemd/system/` | Oneshot at boot, same script. |

Deploy once:

```sh
REPO=~/Projects/FingerPrintSensors/Acer\ Swift\ 3\ SF314-512   # adjust
# 1) generate the canonical patched QML from the installed upstream file:
sudo python3 "$REPO"/linux-driver/install/patch-lockscreen.py
# 2) install the guard files:
sudo install -Dm755 "$REPO"/linux-driver/install/restore-kde-lockscreen.sh /usr/local/sbin/
sudo install -Dm644 "$REPO"/linux-driver/install/99-kde-lockscreen.hook /etc/pacman.d/hooks/
sudo install -Dm644 "$REPO"/linux-driver/install/kde-lockscreen-restore.service /etc/systemd/system/
sudo systemctl enable kde-lockscreen-restore.service
```

Notes / safety:

- A broken QML just makes `kscreenlocker` fall back to the built-in password
  locker (you can still unlock with your password) — it will not lock you out.
- The patch is tied to the `onSucceeded()` shape; if a future `plasma-desktop`
  reworks that function, `patch-lockscreen.py` prints `PATTERN NOT FOUND` and
  you re-run it. `restore-kde-lockscreen.sh` also refuses to clobber if the
  installed QML path disappears (layout change).
- Rollback: `sudo cp -a /usr/local/share/kde-lockscreen/LockScreenUi.qml.orig
  /usr/share/plasma/shells/org.kde.plasma.desktop/contents/lockscreen/LockScreenUi.qml`.

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
| `cleanroom/src/fpc_bep_run.c` | `cr_bep_run_frame()` — DLL-free entry point |
| `cleanroom/src/fpc_bep_template.c` | generated graph template (do not edit) |
| `cleanroom/tools/gen_template.py` | snapshot → template generator |
| `cleanroom/tools/bep_run_test.c` | one-frame parity harness (`CR_PROBE`) |
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
- **Fully standalone clean-room BEP**: `cr_bep_run_frame()` links into the
  driver; no vendor DLL, no subprocess. 20/20 corpus frames byte-identical,
  live enrol 5/5 with the DLL-free backend.
- **System install**: `fprintd` + `pam_fprintd` wired for login/screen-lock on
  the Acer (Arch/KDE/SDDM). End-to-end `verify-match` via fprintd and a
  real fingerprint login/unlock both confirmed on the hardware.

**Remaining**

1. **Upstreaming** — split the driver and matcher into a reviewable patch
   series for libfprint.
