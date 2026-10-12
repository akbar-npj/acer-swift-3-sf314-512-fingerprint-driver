# FPC Disum Fingerprint Sensors (`10a5:e340` & `10a5:a900`) Linux Driver & Port

Unified Linux driver, reverse-engineering findings, and standalone test utility for **Fingerprint Cards AB (FPC)** sensor controllers found on Acer and Honor laptops.

### Supported Devices:
| Vendor / Laptop Series | USB VID:PID | ASIC / Pipeline | Windows Driver Project (PDB) | Architecture |
| :--- | :---: | :---: | :--- | :---: |
| **Honor MagicBook X 14 & X 16 (2024)** | `10a5:a900` (Rev 0229) | FPC Disum (Galileo) | `Honor-Galileo-DPL_driver` | Match-on-Host (MoH) |
| **Acer Swift Series** (Swift Go, SF314-512) | `10a5:e340` | FPC2040 (Swift21) | `ACER-Swift21-DPL_driver_FPC2040_pipeline` | Match-on-Host (MoH) |

---

## 📑 Table of Contents
- [1. Reverse-Engineering Findings](#1-reverse-engineering-findings)
  - [Hardware & Architecture](#hardware--architecture)
  - [Driver Comparison: Acer vs. Honor](#driver-comparison-acer-vs-honor)
  - [USB Communication Protocol](#usb-communication-protocol)
  - [Packet Framing & Endpoints](#packet-framing--endpoints)
  - [Image Capture Workflow](#image-capture-workflow)
- [2. Repository Contents](#2-repository-contents)
- [3. Compilation & Quickstart](#3-compilation--quickstart)
  - [Prerequisites](#prerequisites)
  - [Building the Standalone Tool](#building-the-standalone-tool)
  - [Installing Udev Rules](#installing-udev-rules)
  - [Testing Fingerprint Capture](#testing-fingerprint-capture)
- [4. Integrating into libfprint & System Authentication](#4-integrating-into-libfprint--system-authentication)
- [5. License & Credits](#5-license--credits)

---

## 1. Reverse-Engineering Findings

Using the **REA** binary analysis suite and **Ghidra 12.1.4**, the Windows 11 UMDF drivers for both laptops (`fpc_disum.dll`) were analyzed and cross-referenced.

### Hardware & Architecture
- **Sensor Family:** FPC DISUM pipeline (FPC2040 / Galileo sensor matrix).
- **Match-on-Host (MoH):** Unlike Match-on-Chip (MoC) hardware where biometric matching occurs within microcontroller flash, FPC DISUM operates in Match-on-Host mode:
  - The controller streams raw capacitive image frames to the host OS.
  - In standard operation (`SensorMode=1`), frames are transmitted unencrypted without requiring mandatory Intel SGX / TLS enclaves.
  - On Linux, **libfprint** natively incorporates the NIST Biometric Image Software (NBIS) minutiae extraction and matching engine (`fpi_image_device`), removing the need for any proprietary closed-source matching blobs.

### Driver Comparison: Acer vs. Honor
| Property | Acer Swift 3 / Go | Honor MagicBook X 2024 |
| :--- | :--- | :--- |
| **USB VID:PID** | `10a5:e340` | `10a5:a900` |
| **Driver Package** | `Carewe 20.26.23.27` | `FPCFingerprint 22.26.2.29` |
| **PDB Debug Path** | `ACER-Swift21-DPL_driver_FPC2040_pipeline` | `Honor-Galileo-DPL_driver` |
| **USB Protocol** | Identical 26 commands, 11 events | Identical 26 commands, 11 events |
| **Control Endpoint** | Endpoint 0 (`0x40` OUT, `0xC0` IN) | Endpoint 0 (`0x40` OUT, `0xC0` IN) |
| **Interrupt IN** | Endpoint `0x81` | Endpoint `0x81` |

### USB Communication Protocol

#### Control Transfers
All command dispatches use standard USB Control Transfers (`bmRequestType = 0x40` for Vendor OUT, `0xC0` for Vendor IN):

| Opcode | Command Name | `wValue` | `wIndex` | Description |
| :---: | :--- | :---: | :---: | :--- |
| `0x01` | `CMD_INIT` | `0x0001` | `0x0000` | Initializes the sensor controller matrix |
| `0x02` | `CMD_ARM` | `0x0001` | `0x0000` | Arms capacitive touch matrix for finger detection |
| `0x03` | `CMD_ABORT` | `0x0001` | `0x0000` | Cancels current capture or session |
| `0x04` | `CMD_BOOT0_REQ` | &mdash; | &mdash; | DFU bootloader request |
| `0x08` | `CMD_INDICATE_S_STATE` | power_state | `0x0000` | Power management sleep/wake state |
| `0x09` | `CMD_GET_IMG` | `0x0000` | `0x0000` | Triggers fingerprint frame readout |
| `0x0A` | `CMD_GET_DEAD_PIXELS` | `0x0000` | `0x0000` | Queries factory dead pixel calibration map |
| `0x12` | `CMD_FINGERPRINT_SESSION_OFF` | `0x0000` | `0x0000` | Shuts down touch detection / low power mode |
| `0x20` | `CMD_REFRESH_SENSOR` | `0x0001` | `0x0000` | Forces sensor recalibration |
| `0x30` | `CMD_GET_FW_VERSION` | `0x0000` | `0x0000` | Queries firmware version string |
| `0x31` | `CMD_GET_HW_UNIQUE_ID` | `0x0000` | `0x0000` | Queries hardware chip unique serial |
| `0x32` | `CMD_FLUSH_KEYS` | `0x0071` | `0x003a` | Flushes security key session |

#### Asynchronous Event Packets
Streamed to the host over **Endpoint `0x81` (Interrupt IN)**:

```c
struct fpc_packet_header {
    uint32_t event_id;   /* Event identifier */
    uint32_t length;     /* Total payload length in bytes */
    uint32_t status;     /* Status / sequence / return code */
};
```

| Event ID | Event Name | Description |
| :---: | :--- | :--- |
| `0x01` | `EVT_HELLO` | Device handshake greeted host on bus connection |
| `0x02` | `EVT_INIT_RESULT` | Controller matrix initialization confirmed |
| `0x03` | `EVT_ARM_RESULT` | Sensor armed and actively polling touch electrodes |
| `0x04` | `EVT_DEAD_PIXEL_REPORT`| Factory calibration data |
| `0x06` | `EVT_FINGER_DWN` | **Finger touched the sensor** |
| `0x07` | `EVT_FINGER_UP` | **Finger lifted from the sensor** |
| `0x08` | `EVT_IMG` | **Fingerprint image frame data** |
| `0x09` | `EVT_USB_LOGS` | Diagnostic logs from firmware |
| `0x20` | `EVT_REFRESH_SENSOR` | Calibration refresh notification |

### Image Capture Workflow
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
 |<-- EVT_IMG (0x08) ------------|  [34-byte metadata + raw grayscale pixel buffer]
 |                               |  [User lifts finger]
 |<-- EVT_FINGER_UP (0x07) ------|
```

The image frame within `EVT_IMG` begins with a **34-byte metadata header (`0x22`)**, followed immediately by raw 8-bit grayscale pixel bytes (`length - 34`).

---

## 2. Repository Contents

- [`linux-driver/`](file:///home/shaanair/Projects/FingerPrintSensors/Acer%20Swift%203%20SF314-512/linux-driver)
  - [`include/fpc_protocol.h`](file:///home/shaanair/Projects/FingerPrintSensors/Acer%20Swift%203%20SF314-512/linux-driver/include/fpc_protocol.h): Complete C protocol definitions, opcodes, and device IDs (`0xe340` & `0xa900`).
  - [`src/fpc_disum_tool.c`](file:///home/shaanair/Projects/FingerPrintSensors/Acer%20Swift%203%20SF314-512/linux-driver/src/fpc_disum_tool.c): Standalone CLI tester application with dual-device auto-detection.
  - [`src/fpc2040.c`](file:///home/shaanair/Projects/FingerPrintSensors/Acer%20Swift%203%20SF314-512/linux-driver/src/fpc2040.c): Native `libfprint` driver (`FpiDeviceImage`) supporting both PIDs.
  - [`udev/70-libfprint-2-fpc2040.rules`](file:///home/shaanair/Projects/FingerPrintSensors/Acer%20Swift%203%20SF314-512/linux-driver/udev/70-libfprint-2-fpc2040.rules): Udev permission rules for systemd, plugdev, and uaccess.
  - [`Makefile`](file:///home/shaanair/Projects/FingerPrintSensors/Acer%20Swift%203%20SF314-512/linux-driver/Makefile): Makefile for the standalone utility.
- [`FingerPrint_Carewe_20.26.23.27_W11x64/`](file:///home/shaanair/Projects/FingerPrintSensors/Acer%20Swift%203%20SF314-512/FingerPrint_Carewe_20.26.23.27_W11x64): Original Windows 11 driver binaries and setup INF.

---

## 3. Compilation & Quickstart

### Prerequisites
On Fedora / RHEL:
```bash
sudo dnf install gcc make libusb1-devel
```
On Ubuntu / Debian:
```bash
sudo apt install build-essential libusb-1.0-0-dev
```
On Arch Linux:
```bash
sudo pacman -S base-devel libusb
```

### Building the Standalone Tool
```bash
cd linux-driver
make
```

### Installing Udev Rules
To allow your standard user to communicate with either USB device without `sudo`:
```bash
sudo make install-udev
```

### Testing Fingerprint Capture
Run the compiled tool:
```bash
./fpc_disum_tool
```

Example output:
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

## 4. Integrating into libfprint & System Authentication

The driver [`src/fpc2040.c`](file:///home/shaanair/Projects/FingerPrintSensors/Acer%20Swift%203%20SF314-512/linux-driver/src/fpc2040.c) contains entries for both Honor (`10a5:a900`) and Acer (`10a5:e340`):

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
   Enable fingerprint login in PAM:
   ```bash
   sudo authselect enable-feature with-fingerprint
   ```
   *(On Ubuntu: `sudo pam-auth-update`)*

---

## 5. License & Credits

- Reverse-engineered with **REA** and **Ghidra**.
- Standalone test tool & protocol definitions: MIT License.
- `libfprint` driver implementation: LGPL-2.1-or-later.
