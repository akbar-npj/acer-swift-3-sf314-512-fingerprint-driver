# Linux Driver for FPC Fingerprint Sensor (`10a5:e340`)

This driver supports the **Fingerprint Cards AB (FPC)** sensor controller found in Acer laptops (such as Acer Swift Go series), identified by:
- **USB Vendor ID:** `0x10a5`
- **USB Product ID:** `0xe340`
- **Controller Model:** FPC2040 ("Disum")
- **Original Windows Driver:** `FingerPrint_Carewe_20.26.23.27_W11x64` (`fpc_disum.dll`)

---

## 1. Reverse-Engineered USB Protocol Summary

Using **REA** and **Ghidra 12.1.4**, the internal communication protocol in `fpc_disum.dll` was reverse-engineered:

### A. USB Control Transfers (Host to Device)
All vendor requests use `bmRequestType = 0x40` (Vendor OUT) or `0xC0` (Vendor IN):
- **`CMD_INIT` (`0x01`):** `wValue = 1, wIndex = 0, length = 4` — Sensor hardware initialization.
- **`CMD_ARM` (`0x02`):** `wValue = 1, wIndex = 0, length = 4` — Arms the sensor for touch detection.
- **`CMD_ABORT` (`0x03`):** `wValue = 1, wIndex = 0, length = 0` — Cancels ongoing capture.
- **`CMD_GET_IMG` (`0x09`):** `wValue = 0, wIndex = 0, length = 0` — Triggers fingerprint frame readout.
- **`CMD_GET_FW_VERSION` (`0x30`):** Query firmware build info.
- **`CMD_GET_HW_UNIQUE_ID` (`0x31`):** Query sensor serial number.
- **`CMD_REFRESH_SENSOR` (`0x20`):** Resets/recalibrates sensor matrix.
- **`CMD_FINGERPRINT_SESSION_OFF` (`0x12`):** Shuts down biometric session / powers down.

### B. Event Notifications (Device to Host)
Streamed asynchronously via **Endpoint `0x81` (Interrupt IN)**:
- **Packet Structure:**
  ```c
  struct fpc_packet_header {
      uint32_t event_id;   /* 1=HELLO, 2=INIT_RESULT, 3=ARM_RESULT, 6=FINGER_DWN, 7=FINGER_UP, 8=IMG, etc. */
      uint32_t length;     /* Payload size */
      uint32_t status;     /* Result code */
  };
  ```
- **Flow:**
  1. Sensor arms via `CMD_ARM`.
  2. User places finger -> sensor fires `EVT_FINGER_DWN` (`0x06`).
  3. Host sends `CMD_GET_IMG` (`0x09`).
  4. Device sends `EVT_IMG` (`0x08`):
     - First 34 bytes: metadata header (`0x22`).
     - Subsequent bytes: raw 8-bit grayscale pixel stream.
  5. User lifts finger -> sensor fires `EVT_FINGER_UP` (`0x07`).

---

## 2. Testing with Standalone Utility (`fpc_disum_tool`)

The standalone utility directly connects to the device, initializes it, arms it, detects finger placement, and captures frames into `.pgm` grayscale images.

### Compilation
```bash
cd linux-driver
make
```

### Install Udev Rules
```bash
sudo make install-udev
```

### Run
```bash
./fpc_disum_tool
```

Touch the sensor with your finger. The tool will capture the fingerprint image and save it as `fingerprint_001.pgm`.

---

## 3. Integrating into `libfprint`

The native driver [`src/fpc2040.c`](file:///home/shaanair/Projects/Acer%20Finger%20Print%20Sensor/linux-driver/src/fpc2040.c) is formatted for upstream `libfprint`:

1. Clone `libfprint`:
   ```bash
   git clone https://gitlab.freedesktop.org/libfprint/libfprint.git
   cd libfprint
   ```
2. Copy the driver files:
   ```bash
   cp /path/to/linux-driver/src/fpc2040.c libfprint/drivers/
   cp /path/to/linux-driver/include/fpc_protocol.h libfprint/drivers/
   ```
3. Add `fpc2040` to `libfprint/meson.build` under the drivers list.
4. Build and install:
   ```bash
   meson setup builddir -Ddrivers=all
   ninja -C builddir
   sudo ninja -C builddir install
   ```
5. Restart `fprintd`:
   ```bash
   sudo systemctl restart fprintd
   ```
6. Enroll your fingerprint:
   ```bash
   fprintd-enroll
   ```
