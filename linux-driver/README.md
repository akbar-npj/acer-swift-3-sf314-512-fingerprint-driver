# Linux driver / tooling for the FPC `10a5:e340` fingerprint sensor

Reverse-engineered and ported to Linux for the **Acer Swift 3 SF314-512**.

- **USB Vendor ID:** `0x10a5`
- **USB Product ID:** `0xe340` ("FPC Sensor Controller")
- **Interface string:** `FPC L:0001 FW:20262327`
- **Firmware reported by `GET_STATE`:** `20.26.23.27`
- **Original Windows driver:** `FingerPrint_Carewe_20.26.23.27_W11x64` (`fpc_disum.dll`)

Everything below was verified against the real hardware, not inferred from the
sibling `10a5:9201` part (which differs in endianness, TLS roles and geometry).

---

## 1. Reverse-engineered USB protocol

### A. Commands — vendor control transfers on endpoint 0

| `bmRequestType` | direction |
|---|---|
| `0x40` | host → device (OUT) |
| `0xc0` | device → host (IN) |

`bRequest` is one of the command codes; `wValue`/`wIndex` are command specific.

| Command | Value | Notes |
|---|---|---|
| `CMD_INIT` | `0x01` | `wValue=1`, 4-byte payload `10 2f 11 17` |
| `CMD_ARM` | `0x02` | `wValue=1`, payload `11 2f 11 17` (arm) / `12 2f 11 17` (disarm) |
| `CMD_ABORT` | `0x03` | |
| `CMD_TLS_INIT` | `0x05` | `wValue=1` |
| `CMD_TLS_DATA` | `0x06` | TLS record transport, `wValue=1`, ≤64-byte chunks |
| `CMD_INDICATE_S_STATE` | `0x08` | `wValue=0x10` |
| `CMD_GET_IMG` | `0x09` | request a frame after finger-down |
| `CMD_GET_DEAD_PIXELS` | `0x0a` | |
| `CMD_GET_TLS_KEY` | `0x0b` | returns the sealed PSK blob |
| `CMD_GET_KPI` | `0x0c` | quality/coverage metrics |
| `CMD_FINGERPRINT_SESSION_OFF` | `0x12` | |
| `CMD_REFRESH_SENSOR` | `0x20` | |
| `CMD_GET_FW_VERSION` | `0x30` | |
| `CMD_GET_HW_UNIQUE_ID` | `0x31` | |
| `GET_STATE` | `0x50` | 72-byte reply; first 4 bytes = `20.26.23.27` |

### B. Events — bulk IN endpoint `0x81` (64-byte MPS)

There is **one** endpoint, `0x81`, and it is **Bulk**, not Interrupt. Every packet
is a 12-byte little-endian header followed by a payload:

```c
struct fpc_event_hdr { uint32_t code; uint32_t len; uint32_t unknown; };
/* len = TOTAL packet length (header + payload) */
```

| Event | Value |
|---|---|
| `EVT_HELLO` | `0x01` |
| `EVT_INIT_RESULT` | `0x02` |
| `EVT_ARM_RESULT` | `0x03` |
| `EVT_DEAD_PIXEL_REPORT` | `0x04` |
| `EVT_TLS` | `0x05` (payload is a raw TLS record) |
| `EVT_FINGER_DWN` | `0x06` |
| `EVT_FINGER_UP` | `0x07` |
| `EVT_IMG` | `0x08` |
| `EVT_USB_LOGS` | `0x09` |
| `EVT_TLS_KEY` | `0x0a` |
| `EVT_REFRESH_SENSOR` | `0x20` |

### C. Session flow

1. `CMD_INDICATE_S_STATE(0x10)` → `GET_STATE` (firmware version).
2. `CMD_INIT` with magic `10 2f 11 17` → `EVT_INIT_RESULT`.
3. `CMD_GET_TLS_KEY` → sealed-PSK blob → derive PSK (see below).
4. `CMD_TLS_INIT` → **TLS-PSK handshake**. The **host is the TLS client** and the
   device is the TLS server (opposite of the `9201`). Ciphersuite is
   `TLS_PSK_WITH_AES_128_GCM_SHA256` / `..._CBC_SHA256` (mbedTLS on the device).
   Host→device TLS records go out over `CMD_TLS_DATA`; device→host records arrive
   as `EVT_TLS` bulk packets (strip the 12-byte header before feeding OpenSSL).
5. `CMD_ARM` (`11 2f 11 17`) → `EVT_FINGER_DWN` → `CMD_GET_IMG` → `EVT_IMG`.
6. Teardown: `CMD_ARM` with `12 2f 11 17`, `CMD_ABORT`,
   `CMD_FINGERPRINT_SESSION_OFF`.

> On this unit the post-handshake finger/image events arrive as **plain** framed
> packets, not wrapped in `EVT_TLS`.

### D. PSK derivation

The `CMD_GET_TLS_KEY` blob has magic `0x0dec0ded` followed by offset/length pairs
for the sealed key, the AAD (`"FPC TLS Keys"`) and the signature. To recover the
32-byte PSK:

1. Verify `HMAC-SHA256(AAD || sealed_key)` using key `sha256("FPC_HMAC_KEY")` (13 bytes).
2. Unseal with **AES-256-CBC**, key `sha256("FPC_SEALING_KEY")` (16 bytes),
   zero IV, padding disabled.

---

## 2. Image format

An `EVT_IMG` payload is a **22-byte frame header** (it embeds the capture id
`11 2f 11 17` at offset 10) followed by `128 × 88 = 11264` pixel bytes:

```
payload = 11286 bytes = 22-byte header + 128*88 pixels
```

* Layout is **row-major, 128 wide × 88 tall**, 8-bit grayscale.
* The sensor reads out in **8 column-blocks of 16 columns**, which leaves
  visible per-block fixed-pattern noise (vertical banding) in the raw data.
* The raw frame is **noise dominated**: two single captures of the same finger
  correlate only ~0.1–0.4, and two *different* fingers correlate ~0.83 — the
  frame is dominated by the sensor's fixed pattern.

### The raw frame has no ridges — reconstruction is host-side

Averaging many frames does **not** recover ridges: the averaged stack is a
smooth contact map whose radial power spectrum is monotonic (no ridge-frequency
peak). Confirmed against the vendor's own decrypted USB session — Windows
receives the *same* ridge-free `EVT_IMG` buffer. Ridge recovery is entirely the
host-side BEP algorithm inside the vendor's `fpc_enclave.dll`.

That module is a plain `no_sgx` x86-64 DLL and has been **rehosted** — first
under Wine, then natively: [`native/fpc_recon_native`](../native/) maps the DLL
and runs it directly (no Wine), byte-identical to the Wine build.
`wine-rehost/fpc_reconstruct.sh` drives the whole path (capture → inject → BEP →
reconstructed ridge image) and picks the native backend automatically. See
[`../WINE_REHOST.md`](../WINE_REHOST.md) and [`../native/README.md`](../native/README.md).

---

## 3. Building and running

```bash
cd linux-driver
make                     # needs libusb-1.0 + OpenSSL dev headers
sudo make install-udev   # optional: allow non-root access
```

Run the capture tool (the argument is the number of frames to stack):

```bash
./fpc_disum_tool 20
```

Because the device yields exactly **one frame per touch**, tap the sensor
repeatedly (place, lift, place again) to collect frames. The tool:

* initialises the sensor and completes the TLS-PSK handshake,
* arms the sensor and waits for `EVT_FINGER_DWN`,
* requests a frame, re-arms, and repeats until `N` frames are collected,
* writes every frame as `acer_fingerprint_NNN.pgm` / `.raw`, and
* writes the averaged stack as `acer_fingerprint_stack.pgm`.

Touch the sensor repeatedly while it runs; it exits once `N` frames are captured.

To turn the captured raw frames into a **usable ridge image**, run the
reconstruction wrapper (uses the native rehost, or Wine as a fallback):

```bash
~/fpc-rehost/fpc_reconstruct.sh --from acer_fingerprint_001.raw ...   # existing frames
~/fpc-rehost/fpc_reconstruct.sh 5 ~/caps                              # capture + reconstruct
```

See [`../WINE_REHOST.md`](../WINE_REHOST.md) and [`../native/README.md`](../native/README.md).

---

## 4. Integrating into `libfprint`

`src/fpc2040.c` is a **working** libfprint 1.94.100 driver, not a skeleton. It
implements the protocol above over GUsb and registers as a custom
`FP_TYPE_DEVICE` (not an image device): this sensor yields only 2–6 minutiae per
frame, so NBIS matching cannot work and the driver carries its own correlation
matcher.

### 4.1 What the driver does

| Stage | Implementation |
|---|---|
| Capture | `src/fpc2040.c` — GUsb sync control/bulk transfers, TLS-PSK via OpenSSL |
| Ridge recovery | `src/bep_runner.c` → `cr_bep_run_frame()` from `cleanroom/` |
| Matching | `src/bep_runner.c` → `matcher/fpc_match.c` (scores 0..1000, thr 550) |
| Template | 5 ridge images stored in the `FpPrint` `fpi-data` blob (`FPC1` magic) |

The BEP backend is **standalone** — it links the clean-room sources directly and
does **not** need `fpc_enclave.dll` at runtime. `cr_bep_run_frame(hdr22, pix,
out)` rebuilds the captured pointer graph from a static template and produces a
byte-identical 64×176 ridge image to the vendor DLL.

### 4.2 Building libfprint with the driver

The driver is not upstream; it is built inside a libfprint source tree.

```bash
git clone --depth 1 --branch v1.94.100 \
    https://gitlab.freedesktop.org/libfprint/libfprint.git ~/src/libfprint-v1.94.100
cd ~/src/libfprint-v1.94.100

# 1. driver entry point + clean-room BEP + matcher
mkdir -p libfprint/drivers/fpcbep
cp "$REPO"/linux-driver/src/fpc2040.c libfprint/drivers/
cp "$REPO"/linux-driver/src/bep_runner.c \
   "$REPO"/linux-driver/include/*.h libfprint/drivers/fpcbep/
cp "$REPO"/cleanroom/src/*.c "$REPO"/cleanroom/include/*.h libfprint/drivers/fpcbep/
cp "$REPO"/matcher/fpc_match.c "$REPO"/matcher/fpc_match.h libfprint/drivers/fpcbep/
```

Then in `libfprint/meson.build`:

* add `'drivers/fpc2040.c'` plus every `drivers/fpcbep/*.c` to the `'fpc2040'`
  entry of `driver_sources`,
* add `'fpc2040'` to `drivers_info`,
* add `include_directories('drivers/fpcbep')` to the driver deps,
* set `drivers_cflags = ['-ffp-contract=off']` (bit-exact float parity),
* add `helper: ['openssl']` for the driver.

Configure and build:

```bash
meson setup build -Ddrivers=fpc2040 -Dintrospection=false -Ddoc=false \
                  -Dinstalled-tests=false -Dudev_rules=disabled
ninja -C build
```

> `-ffp-contract=off` is **required**. Without it the compiler fuses
> multiply-adds and the clean-room BEP no longer reproduces the vendor output
> bit-for-bit.

### 4.3 Trying it

```bash
sudo ./build/examples/enroll   # 5 touches of the same finger
sudo ./build/examples/verify   # touch again -> FPI_MATCH_SUCCESS / _FAIL
```

Use `stdbuf -oL` when piping: `examples/*` use buffered stdout.

### 4.4 System install (fprintd / PAM)

Not packaged yet. The pieces are:

1. `ninja -C build install` (installs `libfprint-2.so` and the driver).
2. `sudo make -C linux-driver install-udev` — grants `uaccess` on `10a5:e340`
   so fprintd can open the device without root.
3. `sudo dnf install fprintd fprintd-pam` and enable the service.
4. `fprintd-enroll` / `fprintd-verify`, then add `pam_fprintd.so` to the
   relevant PAM stacks.

See `RE_AND_BUILD_GUIDE.md` §4 for the full build/validation walkthrough and
§7 for current status.
