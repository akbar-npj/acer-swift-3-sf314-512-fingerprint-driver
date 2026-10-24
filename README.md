# FPC Disum Fingerprint Sensors (`10a5:e340` & `10a5:a900`) Linux Driver & Port

Unified Linux driver, reverse-engineering findings, automated build toolchain, and standalone test utility for **Fingerprint Cards AB (FPC)** sensor controllers found on Acer and Honor laptops.

### Supported Hardware:
| Vendor / Laptop Series | USB VID:PID | ASIC / Pipeline | Windows Driver Symbol (PDB) | Architecture |
| :--- | :---: | :---: | :--- | :---: |
| **Honor MagicBook X 14 & X 16 (2024)** | `10a5:a900` (Rev 0229) | FPC Disum (Galileo) | `Honor-Galileo-DPL_driver` | Match-on-Host (MoH) |
| **Acer Swift Series** (Swift Go, Swift 3 SF314-512) | `10a5:e340` | FPC2040 (Swift21) | `ACER-Swift21-DPL_driver_FPC2040_pipeline` | Match-on-Host (MoH) |

---

## 📑 Table of Contents
- [1. Quickstart: Automated Build (`build.sh`)](#1-quickstart-automated-build-buildsh)
- [2. Manual Compilation Instructions](#2-manual-compilation-instructions)
  - [Prerequisites](#prerequisites)
  - [Building with GNU Make](#building-with-gnu-make)
  - [Installing Udev Rules](#installing-udev-rules)
  - [Running the Test Tool](#running-the-test-tool)
- [3. REA MCP Reverse-Engineering Findings](#3-rea-mcp-reverse-engineering-findings)
  - [Match-on-Host Architecture](#match-on-host-architecture)
  - [Binary Comparison (Acer vs. Honor)](#binary-comparison-acer-vs-honor)
  - [Decompiled Command Dispatcher (`FUN_180018c38`)](#decompiled-command-dispatcher-fun_180018c38)
  - [Decompiled Event Parser (`FUN_180018ea8`)](#decompiled-event-parser-fun_180018ea8)
  - [Decompiled DFU Protocol (`FUN_18000f4b0`)](#decompiled-dfu-protocol-fun_18000f4b0)
  - [Image Capture Workflow & Framing](#image-capture-workflow--framing)
- [4. Integrating into libfprint & System Authentication](#4-integrating-into-libfprint--system-authentication)
- [5. Repository File Structure](#5-repository-file-structure)
- [6. License & Credits](#6-license--credits)

---

## ⭐ Headline result (2026-10-13): ridge images, on Linux, no Wine

The sensor never hands the host a ridge image — it streams a ridge-free contact
buffer. The ridge structure is produced by FPC's host-side BEP algorithm inside
`fpc_enclave.dll`. **That algorithm now runs on Linux**, driven from our own
capture tool, producing a genuine finger-specific ridge image:

```sh
# capture N taps from the real sensor, reconstruct, write PNGs + a montage
~/fpc-rehost/fpc_reconstruct.sh 5 ~/caps
```

This works via the **native rehost** ([`native/`](native/)) — a small Linux ELF
that maps the vendor DLL and runs the BEP reconstruction directly (no Wine, no
Windows, no SGX). It is byte-for-byte identical to the Wine oracle on all 27
distinct captured frames, and has been validated **end-to-end against live
hardware**. Full write-up: [`WINE_REHOST.md`](WINE_REHOST.md) ·
[`native/README.md`](native/README.md) · [`ENCLAVE_IMAGE_PIPELINE.md`](ENCLAVE_IMAGE_PIPELINE.md).

Live capture evidence: [`analysis/reconstructed/live-native/montage.png`](analysis/reconstructed/live-native/montage.png)
(three real taps → clear whorl/loop ridges).

---

## 1. Quickstart: Automated Build (`build.sh`)

The repository includes a self-contained automated build and setup script [`build.sh`](file:///home/shaanair/Projects/FingerPrintSensors/Acer%20Swift%203%20SF314-512/build.sh):

```bash
# 1. Compile the driver utility (automatically checks toolchain & headers)
./build.sh

# 2. Install udev permissions for non-root hardware access
sudo ./build.sh --install-udev

# 3. Test fingerprint capture
./fpc_disum_tool
```

### Available `build.sh` Options:
| Flag | Description |
| :--- | :--- |
| *(default)* | Validates dependencies and compiles `fpc_disum_tool`. |
| `--deps` | Automatically installs missing build packages using the system package manager (`dnf`, `apt`, `pacman`, `zypper`). |
| `--install-udev` | Copies the udev rule to `/etc/udev/rules.d/` and reloads `udevadm`. |
| `--all` | Runs dependency validation, compilation, and udev rule installation in one step. |
| `--clean` | Removes compiled binaries and captured test image frames. |
| `--help` | Displays script usage and instructions. |

---

## 2. Manual Compilation Instructions

### Prerequisites
Install development tools and `libusb-1.0` headers:

- **Fedora / RHEL / CentOS:**
  ```bash
  sudo dnf install gcc make libusb1-devel pkgconf-pkg-config
  ```
- **Ubuntu / Debian / Linux Mint:**
  ```bash
  sudo apt update && sudo apt install build-essential libusb-1.0-0-dev pkg-config
  ```
- **Arch Linux / Manjaro:**
  ```bash
  sudo pacman -S base-devel libusb pkgconf
  ```
- **openSUSE:**
  ```bash
  sudo zypper install gcc make libusb-1_0-devel pkg-config
  ```

### Building with GNU Make
```bash
cd linux-driver
make
```

### Installing Udev Rules
To communicate with either device without root (`sudo`):
```bash
sudo make install-udev
```

### Running the Test Tool
```bash
./fpc_disum_tool          # capture N frames (arg = count, default 1)
./fpc_disum_tool probe    # ask for a no-finger image, log every event
./fpc_disum_tool sweep    # sweep every command that might yield a second/reference
                          # (no-finger) image; no finger interaction required
./fpc_disum_tool calib    # read the runtime per-unit data (CMD_GET_KPI + dead-pixel
                          # report); no finger interaction required
./fpc_disum_tool calib-spi # calib + an experimental CMD_PASSTHRU_FROM_SPI probe
```

Example session output:
```
=== FPC Disum Sensor Linux Driver Utility ===
[*] Supported targets: Honor MagicBook (10a5:a900), Acer Swift (10a5:e340)
[+] Found Honor MagicBook sensor: 10a5:a900
[+] Device opened successfully!
[+] Claimed interface 0
[*] Step 1: Initializing sensor (CMD_INIT)...
[+] Sent CMD_INIT (0x01), val=0x0001, idx=0x0000, len=4
[*] Step 2: Arming sensor for finger detection (CMD_ARM)...
[+] Sent CMD_ARM (0x02), val=0x0001, idx=0x0000, len=4

[+] Sensor ready! Place your finger on the sensor (Press Ctrl+C to stop)...

=========================================
>>> [!] FINGER DETECTED ON SENSOR! <<<
=========================================
[*] Requesting image (CMD_GET_IMG)...
[+] Sent CMD_GET_IMG (0x09), val=0x0000, idx=0x0000, len=0
[*] Received image packet! Total size: 25634 bytes
[*] Saved image to honor_fingerprint_001.pgm (25600 bytes, 160x160)

--- Finger removed from sensor ---
[+] Sent CMD_ARM (0x02), val=0x0001, idx=0x0000, len=4
```
The captured image is automatically saved as a standard grayscale file (`honor_fingerprint_001.pgm` or `acer_fingerprint_001.pgm`).

---

## 3. REA MCP Reverse-Engineering Findings

Using **REA MCP** backed by **Ghidra 12.1.4**, the Windows 11 drivers (`fpc_disum.dll`) for both laptops were analyzed and cross-referenced.

### Match-on-Host Architecture

> **⚠️ CORRECTION (2026-10-13) — see [`ENCLAVE_IMAGE_PIPELINE.md`](ENCLAVE_IMAGE_PIPELINE.md) §3d/§5.**
> The earlier claim that the host receives a directly matchable ridge image is **wrong**.
> The vendor's own Windows driver was run against the real unit, its whole USB session
> captured and **decrypted**, and its `EVT_IMG` payload is byte-for-byte the *same
> ridge-free buffer* our Linux tool captures. The ridge information is only ever
> materialised inside FPC's host-side reconstruction module (`fpc_enclave.dll`), by the
> `fpc_bio_bep_sw23_*` algorithm. A capture-and-match libfprint driver therefore **cannot**
> work from `EVT_IMG` alone — it needs that reconstruction ported.
>
> **UPDATE (2026-10-13):** the per-unit calibration image the engine looks for
> (`C:\Windows\System32\WinBioPlugIns\calibrationimg.pndat`) was extracted from the live
> Windows VM and is **effectively empty** (only 55 of 52,209 bytes non-zero; the registry key
> `HKLM\SOFTWARE\FPC\WBF` does not exist). So the missing ridges are **not** a calibration
> problem — they are purely the `fpc_bio_bep_sw23_*` algorithm. See
> [`ENCLAVE_IMAGE_PIPELINE.md`](ENCLAVE_IMAGE_PIPELINE.md) §"Calibration".

FPC DISUM is Match-on-Host (MoH) in the sense that matching runs on the host CPU rather
than in sensor firmware — but on Windows that host code is split between the driver
(`fpc_disum.dll`, `FpcDisumEngine.dll`) and a **separate user-mode module**
(`fpc_enclave.dll`) that does the secure image reconstruction and template work.
Despite the name, `fpc_enclave.dll` is **not** a hardware Intel-SGX enclave — see
[`ENCLAVE_IMAGE_PIPELINE.md`](ENCLAVE_IMAGE_PIPELINE.md) §4: it is FPC's
`Prerelease_no_sgx` build, plain user-mode code with no SGX runtime dependency.

- The controller streams a **raw capacitive contact/FPN buffer** (128 × 88 = 11264 px on
  the Acer e340) — a smooth contact map with **no ridge structure**.
- Image reconstruction (`fpc_copy_buffer_into_fmi` → dead-pixel fix →
  `convert_column_wise_image` → `dfd_calibrate`) runs **inside `fpc_enclave.dll`** via the
  `fpc_bio_bep_sw23_*` family. The per-unit `calibrationimg.pndat` was extracted and found
  to be effectively empty, so the reconstruction is **algorithm-only** (raw frame + static
  variant tables).
- The USB session is a **TLS-PSK tunnel** (device = TLS server; see
  `linux-driver/README.md`), with the TLS endpoint itself inside the enclave.
- libfprint's NBIS minutiae engine is available on Linux, but it needs a ridge image to
  work on — which this sensor never provides to the host. (This is consistent with the
  general libfprint experience that small area sensors give too few minutiae.)

### Binary Comparison (Acer vs. Honor)
- **Honor `fpc_disum.dll`:** 740 procedures, `.text` size 169,984 bytes, SHA256 `7d824b7b...`
- **Acer `fpc_disum.dll`:** 741 procedures, `.text` size 171,520 bytes, SHA256 `693f92d6...`
- Both share the exact same 26 USB vendor commands and 11 interrupt events.

### Decompiled Command Dispatcher (`FUN_180018c38`)
Decompiled from `fpc_disum.dll` via REA `procedure_pseudo_code`:

```c
char * FUN_180018c38(int param_1) {
  if (param_1 < 0x21) {
    if (param_1 == 0x20) return "CMD_REFRESH_SENSOR";
    if (param_1 < 10) {
      if (param_1 == 9) return "CMD_GET_IMG";
      if (param_1 == 1) return "CMD_INIT";
      if (param_1 == 2) return "CMD_ARM";
      if (param_1 == 3) return "CMD_ABORT";
      if (param_1 == 4) return "CMD_BOOT0_REQ";
      if (param_1 == 5) return "CMD_TLS_INIT";
      if (param_1 == 6) return "CMD_TLS_DATA";
      if (param_1 == 8) return "CMD_INDICATE_S_STATE";
    } else {
      if (param_1 == 10) return "CMD_GET_DEAD_PIXELS";
      if (param_1 == 0xb) return "CMD_GET_TLS_KEY";
      if (param_1 == 0xc) return "CMD_GET_KPI";
      if (param_1 == 0xd) return "CMD_SET_TLS_KEY";
      if (param_1 == 0xe) return "CMD_FINISH_ENROLL";
      if (param_1 == 0x10) return "CMD_FUSE_DEVICE";
      if (param_1 == 0x12) return "CMD_FINGERPRINT_SESSION_OFF";
    }
  } else if (param_1 < 0x43) {
    if (param_1 == 0x42) return "CMD_PASSTHRU_INT_VALUE_OUT";
    if (param_1 == 0x30) return "CMD_GET_FW_VERSION";
    if (param_1 == 0x31) return "CMD_GET_HW_UNIQUE_ID";
    if (param_1 == 0x32) return "CMD_FLUSH_KEYS";
    if (param_1 == 0x40) return "CMD_PASSTHRU_INT_CONTROL";
    if (param_1 == 0x41) return "CMD_PASSTHRU_CS_CONTROL";
  } else {
    if (param_1 == 0x43) return "CMD_PASSTHRU_TO_SPI";
    if (param_1 == 0x44) return "CMD_PASSTHRU_FROM_SPI";
    if (param_1 == 0x45) return "CMD_PASSTHRU_INT_VALUE_IN";
    if (param_1 == 0x50) return "GET_STATE";
    if (param_1 == 0xaa) return "CMD_GET_MSOS";
  }
  return "Unknown USB CMD.";
}
```

### Decompiled Event Parser (`FUN_180018ea8`)
Decompiled from the Endpoint `0x81` interrupt callback loop via REA `procedure_pseudo_code`:

```c
char * FUN_180018ea8(int param_1) {
  if (param_1 < 7) {
    if (param_1 == 6) return "EVT_FINGER_DWN";
    if (param_1 == 1) return "EVT_HELLO";
    if (param_1 == 2) return "EVT_INIT_RESULT";
    if (param_1 == 3) return "EVT_ARM_RESULT";
    if (param_1 == 4) return "EVT_DEAD_PIXEL_REPORT";
    if (param_1 == 5) return "EVT_TLS";
  } else {
    if (param_1 == 7) return "EVT_FINGER_UP";
    if (param_1 == 8) return "EVT_IMG";
    if (param_1 == 9) return "EVT_USB_LOGS";
    if (param_1 == 10) return "EVT_TLS_KEY";
    if (param_1 == 0x20) return "EVT_REFRESH_SENSOR";
  }
  return "Unknown USB EVT.";
}
```

### Decompiled DFU Protocol (`FUN_18000f4b0`)
```c
char * FUN_18000f4b0(int param_1) {
  if (param_1 < 6) {
    if (param_1 == 5) return "DFU_GETSTATE";
    if (param_1 == 0) return "DFU_DETACH";
    if (param_1 == 1) return "DFU_DNLOAD";
    if (param_1 == 2) return "DFU_UPLOAD";
    if (param_1 == 3) return "DFU_GETSTATUS";
    if (param_1 == 4) return "DFU_CLRSTATUS";
  } else {
    if (param_1 == 6) return "DFU_ABORT";
    if (param_1 == 7) return "DFU_FPC_SETTINGS";
    if (param_1 == 8) return "DFU_FPC_KEYS";
    if (param_1 == 9) return "DFU_FPC_GET_FW_STATUS";
    if (param_1 == 10) return "DFU_FPC_BOOT0";
  }
  return "UNKNOWN";
}
```

### Image Capture Workflow & Framing
```
Host                     Sensor (10a5:e340 or 10a5:a900)
 |                               |
 |-- CMD_INIT (0x01) ----------->|
 |<-- EVT_INIT_RESULT (0x02) ----|
 |-- CMD_ARM (0x02) ------------>|
 |<-- EVT_ARM_RESULT (0x03) -----|
 |                               |  [User touches sensor]
 |<-- EVT_FINGER_DWN (0x06) -----|
 |-- CMD_GET_IMG (0x09) -------->|
 |<-- EVT_IMG (0x08) ------------|  [sub-header + raw pixel buffer, see note below]
 |                               |  [User lifts finger]
 |<-- EVT_FINGER_UP (0x07) ------|
```

The image frame within `EVT_IMG` is a small metadata sub-header followed immediately by
raw 8-bit pixel bytes. On the **Acer e340** the payload is **11286 B = 22-byte sub-header +
11264 px (128 × 88)**; the Honor part uses a different sub-header size (e.g. 34 B +
160 × 160 = 25600). The sub-header's fixed 4-byte field at offset 10 is the session/arm
token echoed from `CMD_ARM` (e.g. `11 2f 11 17` for our tool).

---

## 4. Integrating into libfprint & System Authentication

The driver [`src/fpc2040.c`](file:///home/shaanair/Projects/FingerPrintSensors/Acer%20Swift%203%20SF314-512/linux-driver/src/fpc2040.c) contains native `id_table` entries for both Honor (`10a5:a900`) and Acer (`10a5:e340`):

1. **Clone `libfprint`:**
   ```bash
   git clone https://gitlab.freedesktop.org/libfprint/libfprint.git
   cd libfprint
   ```

2. **Copy the Driver Source:**
   ```bash
   cp /path/to/linux-driver/src/fpc2040.c libfprint/drivers/
   cp /path/to/linux-driver/include/fpc_protocol.h libfprint/drivers/
   ```

3. **Register in `libfprint/meson.build`:**
   Add `'fpc2040'` to the list of drivers in `libfprint/meson.build`.

4. **Build and Install:**
   ```bash
   meson setup builddir -Ddrivers=all
   ninja -C builddir
   sudo ninja -C builddir install
   ```

5. **Restart `fprintd` and Enroll:**
   ```bash
   sudo systemctl restart fprintd
   fprintd-enroll
   ```

6. **Enable PAM Authentication:**
   - On Fedora / RHEL:
     ```bash
     sudo authselect enable-feature with-fingerprint
     ```
   - On Ubuntu / Debian:
     ```bash
     sudo pam-auth-update
     ```

---

## 5. Repository File Structure

```
├── build.sh                                # Automated build & dependency installer
├── README.md                               # Complete findings & setup guide
├── ENCLAVE_IMAGE_PIPELINE.md               # How fpc_enclave.dll turns EVT_IMG into ridges
├── WINE_REHOST.md                          # Wine rehost + native port + parity write-up
├── IDA_MCP_WORKFLOW.md                     # REA/Ghidra analysis workflow notes
├── linux-driver/
│   ├── build.sh                            # Local build script
│   ├── Makefile                            # GNU Makefile
│   ├── include/
│   │   └── fpc_protocol.h                  # Protocol constants, opcodes, structures
│   ├── src/
│   │   ├── fpc_disum_tool.c                # Standalone test CLI application
│   │   └── fpc2040.c                       # Native libfprint driver
│   └── udev/
│       └── 70-libfprint-2-fpc2040.rules    # Hardware udev permissions
├── native/                                 # Native (no-Wine) rehost of fpc_enclave.dll
│   ├── pe_loader.[ch]                      # Minimal PE32+ loader
│   ├── win32_shims.[ch]                    # ms_abi Win32 import shims + BCryptGenRandom
│   ├── fpc_recon.c                         # Driver: maps DLL, drives BEP, dumps image
│   └── README.md
└── wine-rehost/
    ├── harness.c                           # Wine harness (the correctness oracle)
    ├── fpc_reconstruct.sh                  # End-to-end: capture -> reconstruct -> PNG
    └── recon2png.py                        # 8-bit raw -> PNG
```

---

## 6. License & Credits

- Reverse-engineered using **REA** and **Ghidra 12.1.4**.
- Standalone test tool & protocol definitions: MIT License.
- `libfprint` driver implementation: LGPL-2.1-or-later.
