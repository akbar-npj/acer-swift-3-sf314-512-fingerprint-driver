# FPC Sensor Controller (`10a5:e340`) Linux Driver & Port

Linux driver, reverse-engineering findings, and test utility for the **Fingerprint Cards AB (FPC)** sensor controller commonly found on Acer laptops (e.g. Acer Swift Go series, Swift 21).

- **USB VID:PID:** `10a5:e340`
- **Linux Device Identification:** `Bus 001 Device 002: ID 10a5:e340 FPC Sensor Controller`
- **Controller ASIC / Family:** **FPC2040** ("Disum" pipeline)
- **Windows Driver Package:** `FingerPrint_Carewe_20.26.23.27_W11x64` (`fpc_disum.dll`)
- **Biometric Architecture:** Match-on-Host (MoH)

---

## 📑 Table of Contents
- [1. Reverse-Engineering Findings](#1-reverse-engineering-findings)
  - [Hardware & Architecture](#hardware--architecture)
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

Using the **REA** binary analysis suite and **Ghidra 12.1.4**, the Windows 11 UMDF driver [`fpc_disum.dll`](file:///home/shaanair/Projects/Acer%20Finger%20Print%20Sensor/FingerPrint_Carewe_20.26.23.27_W11x64/12b431fd-7d7e-4dd7-b87c-9ab3f9a3d01b/x64/fpc_disum.dll) was decompiled and analyzed.

### Hardware & Architecture
- **Internal Model:** The build path in the debug symbols explicitly identifies the project:  
  `C:\Jenkins\workspace\PC\DISUM\_Customer\ACER\Swift21_disum2\ACER-Swift21-DPL_driver_FPC2040_pipeline\disum_driver\out\UM_USB_no_sgx\x64\fpc_disum.pdb`
- **Sensor Type:** **FPC2040** capacitive touch sensor.
- **Match-on-Host (MoH):** Unlike Match-on-Chip (MoC) hardware where template matching occurs in on-chip flash, the FPC2040 operates in Match-on-Host mode. The sensor transmits raw capacitive image frames to the host. This is a massive advantage on Linux, because **libfprint** natively incorporates the NIST Biometric Image Software (NBIS) minutiae extraction and matching engine (`fpi_image_device`), removing the need for proprietary Windows matching blobs.

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
Host                     Sensor (10a5:e340)
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

- [`linux-driver/`](file:///home/shaanair/Projects/Acer%20Finger%20Print%20Sensor/linux-driver)
  - [`include/fpc_protocol.h`](file:///home/shaanair/Projects/Acer%20Finger%20Print%20Sensor/linux-driver/include/fpc_protocol.h): Complete C protocol definitions, opcodes, and headers.
  - [`src/fpc_disum_tool.c`](file:///home/shaanair/Projects/Acer%20Finger%20Print%20Sensor/linux-driver/src/fpc_disum_tool.c): Standalone CLI tester application using `libusb-1.0`.
  - [`src/fpc2040.c`](file:///home/shaanair/Projects/Acer%20Finger%20Print%20Sensor/linux-driver/src/fpc2040.c): Native `libfprint` driver (`FpiDeviceImage`).
  - [`udev/70-libfprint-2-fpc2040.rules`](file:///home/shaanair/Projects/Acer%20Finger%20Print%20Sensor/linux-driver/udev/70-libfprint-2-fpc2040.rules): Udev permission rules for systemd and plugdev.
  - [`Makefile`](file:///home/shaanair/Projects/Acer%20Finger%20Print%20Sensor/linux-driver/Makefile): Makefile for the standalone utility.
- [`FingerPrint_Carewe_20.26.23.27_W11x64/`](file:///home/shaanair/Projects/Acer%20Finger%20Print%20Sensor/FingerPrint_Carewe_20.26.23.27_W11x64): Original Windows 11 driver binaries and setup INF.
- [`Readme.txt`](file:///home/shaanair/Projects/Acer%20Finger%20Print%20Sensor/Readme.txt): Hardware and Windows driver notes.

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
To allow your standard user to communicate with the USB device without `sudo`:
```bash
sudo make install-udev
```

### Testing Fingerprint Capture
Run the compiled tool:
```bash
./fpc_disum_tool
```

Output:
```
=== FPC Sensor Controller (10a5:e340) Linux Driver ===
[*] Searching for USB device 10a5:e340...
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
[*] Saved image to fingerprint_001.pgm (25600 bytes, 160x160)

--- Finger removed from sensor ---
[+] Sent CMD_ARM (0x02), val=0x0001, idx=0x0000, len=4
```
The captured image is automatically saved as a standard grayscale file `fingerprint_001.pgm`.

---

## 4. Integrating into libfprint & System Authentication

The driver [`src/fpc2040.c`](file:///home/shaanair/Projects/Acer%20Finger%20Print%20Sensor/linux-driver/src/fpc2040.c) is designed to be dropped directly into `libfprint`:

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
