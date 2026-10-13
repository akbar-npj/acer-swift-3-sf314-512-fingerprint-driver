# FPC e340 — Enclave image pipeline & raw-capture analysis

Reverse-engineering notes for the Acer Swift 3 (SF314-512) fingerprint sensor
`10a5:e340` (firmware 20.26.23.27).  This documents **option 2**: digging into the
vendor enclave to learn how the raw sensor image becomes a usable fingerprint
image, plus the empirical analysis of the frames we capture over USB.

Companion docs:
- `linux-driver/README.md` — verified USB/TLS protocol (commands, events, session flow, PSK).
- `linux-driver/src/fpc_disum_tool.c` — standalone CLI that arms, captures and saves frames.

---

## 1. TL;DR

- The USB `EVT_IMG` stream **is** the raw sensor image (128 × 88 = 11264 px, 22-byte
  sub-header + pixels), and the finger **is** detected (a smooth finger-shaped blob is
  visible after contrast enhancement).
- But the raw frame contains **no ridge structure** in any orientation/layout we tried.
  It is a smooth, low-contrast *contact map* (correlation length ≈ 10 px), not a ridge image.
- The enclave applies a real pipeline on top of this raw data
  (`fpc_copy_buffer_into_fmi` → dead-pixel correction → `convert_column_wise_image`
  → `dfd_calibrate`).  Reproducing it faithfully requires the device's per-unit
  calibration data, which is not part of the raw USB stream.

---

## 2. Enclave: `fpc_enclave.dll`

The DLL is **not stripped** — it carries an embedded symbol table (see §4 for the format).
Image-pipeline symbols (VA = `0x180000000 + RVA`):

| VA | symbol | role |
|----|--------|------|
| `0x18006a500` | `fpc_ta_common_init` | allocates the `bep_image`; logs `new bep image w: %d, h: %d` |
| `0x180068470` | `fpc_copy_buffer_into_fmi` | **copies the received image buffer into the image container**; logs `Bytes received %u, image_size %u` and `Recv MetaData: 0x%x ×7` |
| `0x18000c4f0` | `fpc_bep_image_new` | image container ctor |
| `0x18000c570` | `fpc_bep_image_new_moh` | image container ctor (variant); called with `(buf, 0xd2, width)` |
| `0x18004b980` | `fpc_sensor_internal_capture_image` | low-level sensor capture (SPI/register writes via `0x18004db20` / `0x18004d2d0`) |
| `0x18004c0c0` | `fpc_sensor_internal_convert_column_wise_image` | **column-wise → normal image conversion**; called from 3 sites: `0x18000b79d`, `0x18000b9c4`, `0x18000c5cb` |
| `0x18004c330` | `fpc_sensor_internal_dfd_calibrate` | DFD calibration |
| `0x18004c380` | `fpc_sensor_internal_finger_detect` | finger detection |
| `0x18004a2f0` | `fpc_image_data_create` | image-data object |
| `0x18004a590` | `fpc_image_data_create_from_buffer` | |
| `0x18004ad30` | `fpc_image_data_init_fpc_image` | |
| `0x18004b090` | `fpc_image_data_set_from_fpc_image` | |
| — | `fpc_bep_image_get_dimensions` / `_get_pixels` / `_get_size` / `_extract` / `_write_metadata` | accessors |
| — | `fpc_buffer_pixels_copy_image` / `_check_size` / `_set_size` | pixel buffer helpers |
| — | `fpc_buffer_dead_pixels_copy` / `_copy_to_buffer` / `_get_dead_pixels_buffer` | dead-pixel list |
| — | `_create_histogram_find_medians`, `get_histogram_median`, `reset_pixel_test`, `pixel_list_add_dead_pixel` | dead-pixel detection |

Relevant log strings found in `.rdata`:

```
Copying image pixels into fpc_bep_image
Bytes received %u, image_size %u
%s : Incorrect Image size (%d)
%s : Recv MetaData: 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x      <- 7 metadata fields
Type1 (all black or all white) pixels have a median value that is outside limits.
Type2 (all black or all white) pixels have a median value that is outside limits.
The number of dead pixels in the image are outside the limit.
The number of dead pixels in the finger detect zones are outside the limit.
The median value difference between the histogram with the highest value and the
  histogram with the lowest value is outside the limit.
```

### `fpc_copy_buffer_into_fmi` (`0x180068470`) — how the frame is ingested

```
call 0x18006a7f0                 ; global image context
rdi = [ctx+0x10]
cmp ecx, 8                       ; arg1 == 8  -> "image" message class
jne ...
lea rdx, "Copying image pixels into fpc_bep_image"
call 0x18000c450                 ; size of current image
lea rdx, "Bytes received %u, image_size %u"
...
; then it reads 7 format fields from the globals at 0x1801728ec..0x1801728f4
;   +0 u8, +1 u8, +2 u8, +3 u8, +4 u16, +6 u16, +8 u16
lea rdx, "%s : Recv MetaData: 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x"
...
call 0x18000c570                 ; fpc_bep_image_new_moh(buf, 0xd2, width)
```

So the host sends the pixel buffer **plus 7 metadata fields**; the enclave wraps them into
the `bep_image` and validates the size.  (The per-frame 22-byte USB sub-header is where
that metadata lives — see §3.)

### Other DLLs

- `fpc_disum.dll` — arm/calibration logic on the host side:
  `Not Calibrated`, `Testing for dead pixels`, `Bad pixel[%d]: Avg=%d, this=%d`,
  `Found %lu dead pixels`, `Do Arm Again!`, `Img quality fail, Arm Finger Again`,
  `Clr image in S5 and do arm again!`.
- `FpcDisumEngine.dll` — matching engine (`EngineAdapterCreateEnrollment`, …), not image processing.

---

## 3. Raw USB frame — what we actually receive

Captured files (21 taps) on the remote: `acer_fingerprint_001..020.raw`, `cap_1.raw`.

- Size **11286 B** = 22-byte sub-header + **11264 B** pixels (128 × 88, 1 byte/px).
- Sub-header (22 B) — **varies per frame** (counters/timestamps); fixed magic at offset 10:

```
00 02 05 05 00 04 d0 00 58 09 | 11 2f 11 17 | 00 00 00 00 00 00 00 00
<--- varying metadata --->       ^ arm magic    ^ 6 trailing zero bytes
```

  The magic `11 2f 11 17` is the same "arm/capture" magic the host sends in `CMD_ARM`.
  The first 10 bytes look like a frame counter / timestamp (bytes 8–9 change slowly:
  `0x0958` → `0x0d6a` across the session).

### Pixel analysis (21 frames averaged)

| metric | value |
|--------|-------|
| value range (avg) | 100 … 226, mean ≈ 143 |
| horizontal autocorr | lag1 ≈ 0.90, lag2 ≈ 0.79 … → correlation length ≈ 10 px |
| per-pixel temporal std | ≈ 30 (as large as the spatial signal!) |
| residual std after removing row+col means | 10.3 (single frame), 4.2 (21-frame avg) |
| ridge-band FFT energy | flat across all frames (1.27–1.38) — **no ridge band** |

The averaged image is dominated by a strong vertical gradient (dark top → bright bottom).
Per 16-column block, blocks 0–5 are nearly flat (std ≈ 5) and blocks 6–7 are bright
(means 157 / 211) — i.e. the finger mostly contacted the last two blocks.

**A CLAHE render reveals a clear, smooth finger-shaped blob** → the finger *is* on the
sensor and the protocol is correct.  There is simply no ridge detail in the raw stream.

### Layouts tried (none revealed ridges)

- row-major `88×128`, row-major `128×88`, and both transposes;
- 8 × 16-column **block de-interleave** (row-major and column-major within each block);
- horizontal / vertical 2× down-sampling (`44×128`, `88×64`, `44×64`);
- even/odd **field split** of the buffer (two halves of 5632 B each);
- high-pass, background-removed (row+col mean), unsharp, CLAHE, percentile stretch.

---

### 3b. Stationary-press capture (2026-10-13)

A second session captured **15 frames with the finger pressed firmly and held** (lift +
re-press in the same spot each time).  Result is unchanged:

- inter-frame correlation mean 0.57 (min −0.13) — the finger still shifted between presses;
- translation-registering the frames before averaging did **not** help (residual std 4.4 vs 4.0);
- **radial power spectrum is monotonic** (1/f-like, no peak at any ridge frequency —
  peak bin is DC, ~38× the mean; every ridge-scale bin is ≈1×);
- band-pass at 6 px period, frame differences, and the temporal-std map all show only
  smooth structure + horizontal/vertical FPN streaks.

So the absence of ridges is **not** a motion/averaging artefact — the raw USB frame simply
does not contain ridge structure.

### 3c. What the vendor library suggests

`fpc_disum.dll` (host-side protocol lib) shows the device has several capture paths and
references sensor OTP/calibration:

```
cac_if_image_capture / cac_if_single_capture / cac_if_multi_capture
fpc_cac_fasttap_image_capture / fpc_cac_simple_image_capture
"Initialized FID with two image buffers"  "Second image does not %s"
"Finger Coverage OK => Sending FingerDown Event"
"Img quality fail, Arm Finger Again"   "Img Expired!"
"Testing for dead pixels"   "Finger on sensor, skipping dead pixels test"
"Failed to capture dp image (%x %x)"
"Sensor %d does not support OTP"   "AFailed to identify sensor (hwid=%02X %02X)"
```

The dead-pixel test explicitly captures an image **with no finger** ("Finger on sensor,
skipping dead pixels test"), and the sensor has OTP calibration.  Both point at per-unit
baseline/FPN data that the raw `EVT_IMG` does not include.

**No-finger probe (2026-10-13):** the tool has a `probe` mode that issues, with the finger
off the sensor, `CMD_GET_DEAD_PIXELS` → `CMD_GET_IMG` → `CMD_REFRESH_SENSOR`.  Result: the
device does **not** emit a background image —
`CMD_GET_DEAD_PIXELS` returns an empty `EVT_DEAD_PIXEL_REPORT`,
`CMD_GET_IMG` returns nothing, and `CMD_REFRESH_SENSOR` returns `EVT_REFRESH_SENSOR`
(8 bytes `ec 04 31 03 40 00 b0 00`).  So a host-side baseline subtraction is not directly
possible; the calibration must come from elsewhere (OTP / enclave).

The "enclave" is **not** a hardware SGX enclave in this package — it is the vendor's
**`Prerelease_no_sgx`** software build (see §4), i.e. ordinary user-mode code.  Its internal
calibration and intermediate images are still not on the USB bus, but they *are* readable
code, so the pipeline can be reversed and ported.

### 3d. DECISIVE TEST — vendor Windows stack vs. ours (2026-10-13)

The vendor's own Windows 11 driver was run in a QEMU/KVM VM with the real
`10a5:e340` passed through, and a finger was enrolled in Windows Hello
(**enrollment succeeded**).  All USB traffic was captured with `usbmon`
(`/home/shaanair/fpwork/usbcap/uc.pcapng`, 7201 packets, device `3.2.0`).

### The vendor uses exactly our protocol
- Same command set (`bRequest` 1,2,5,6,8,9,10,11,12,80) in the same cycle
  `GET_IMG → GET_KPI(28) → GET_DEAD_PIXELS → ARM`, ~18×.
- Commands via EP0 control transfers; events via bulk IN, 12-byte framing — identical.

### The vendor image is inside the TLS-PSK session
- Every bulk packet is `EVT_TLS (0x05)` wrapping a raw TLS record; the **device is
  the TLS server** (it sends `ServerHello`).  Client records go out via
  `CMD_TLS_DATA (0x06)` control transfers.
- Session: `ServerHello` (advertises suite `0x00a8`, EMS extension `0x0017`) →
  `ServerHelloDone` → CCS → `Finished` → ~199 application-data records of 1048 B.
- `ClientKeyExchange` carries **PSK identity `"Disum PSK"`**.
- **Decrypted offline** (`/home/shaanair/fpwork/usbcap/decrypt_final.py`):
  - PSK = `AES-256-CBC-decrypt(sealed, key = sha256("FPC_SEALING_KEY\0"), IV = 0)`
    — byte-identical to `derive_psk()` in `fpc_disum_tool.c`.
  - HMAC over `aad || sealed` with `sha256("FPC_HMAC_KEY\0")` verifies
    (so `FPC_HMAC_KEY_LEN 13` / `FPC_SEALING_KEY_LEN 16` in `fpc_protocol.h`
    are **correct** — both lengths include the NUL).
  - premaster = `u16(32) || 32 zeros || u16(32) || PSK` (RFC 4279);
    master = `P_SHA256(premaster, "extended master secret" || SHA256(transcript))`.
  - **The record crypto is AES-128-GCM / SHA-256 with EMS** even though the
    `ServerHello` advertises suite `0x00a8` — the AEAD tags verify, so this is
    definitive (FPC's minimal TLS uses a nonstandard suite→crypto mapping).
  - Sequence numbers reset to 0 after `ChangeCipherSpec` (as required).

### The vendor's raw image is identical to ours
The decrypted inner stream contains **18 × `EVT_IMG` (code 8), each 11286 B =
22-byte sub-header + 11264 pixels**, plus 18 empty `EVT_DEAD_PIXEL_REPORT`.

| metric | vendor (Windows, decrypted) | ours (Linux tool) |
|--------|-----------------------------|-------------------|
| pixel mean / std | 142.4 / 31.8 | 152.8 / 40.8 |
| per-pixel temporal std | ≈ 30 | ≈ 30 |
| horizontal autocorr | 0.97, 0.93, 0.90 … (smooth) | 0.998, 0.995 … (smooth) |
| vertical autocorr | decays to 0 by lag 12 | decays to 0 by lag 15 |
| ridge periodicity | **none** | **none** |
| radial power spectrum | monotonic (1/f-like) | monotonic |

`corr(our_avg, vendor_avg) = 0.26`, `corr(best our frame, vendor_avg) = 0.65`
— consistent with a shared sensor fixed-pattern (row FPN), not shared ridges.
All 18 vendor frames look alike (same bright contact band) → the buffer is
dominated by fixed pattern, the finger contributes a smooth contact map.

**Conclusion of the decisive test:** Windows receives *exactly the same*
ridge-free buffer that we do.  The ridges are not in the USB stream, and
Windows Hello still works because the vendor's **no-SGX software pipeline**
(`fpc_enclave.dll`, §4) reconstructs the biometric image from this buffer plus
**per-unit calibration** that never appears on the bus.

---

### 3e. Second-image / reference-image avenue — tested, NEGATIVE (2026-10-13)

Hypothesis: the driver's "FID" (finger image data) can hold **two** image buffers
(`fpc_disum.dll`: *"Initialized FID with two image buffers"* / *"…one image buffer"*,
*"Failed to get pixel buffer 0/1"*, and — the `%s` is the adjacent literal — *"Second
image does not **exist**"*), so maybe a second/reference frame could reveal ridges.

Findings (all negative):

1. **The device sends exactly one image per touch.**  In the vendor's own decrypted
   session, the per-touch cycle is
   `GET_KPI(28) → GET_DEAD_PIXELS → ARM → GET_IMG`, and there is exactly **one**
   `CMD_GET_IMG` and **one** `EVT_IMG` per cycle (18 touches → 18 images).  No second
   image, no reference frame, on the wire.
2. **No no-finger image is obtainable.**  A hardware command sweep with the finger off
   (`linux-driver` `sweep` mode: `GET_KPI` → `GET_DEAD_PIXELS` → `GET_IMG` unarmed →
   `ARM` → `GET_IMG` armed → `GET_IMG` again → `GET_KPI` → `REFRESH_SENSOR`) produced
   **zero** images: `GET_DEAD_PIXELS` returns an empty `EVT_DEAD_PIXEL_REPORT`,
   `GET_IMG` returns nothing whether armed or not, and `REFRESH_SENSOR` returns the
   8-byte `ec 04 31 03 40 00 b0 00`.  So there is no background/reference buffer to
   subtract.
3. **`GET_KPI` is not image data.**  It returns a **fixed 28-byte device constant**
   (`74 3e a7 d4 ba 0b a8 c6 ba a1 dc 0f fd 51 87 18 f8 b4 c3 87 f0 73 1b 56 5f fc 1c 3e`)
   — byte-identical across two runs *and* identical to the value the Windows driver
   received.  A per-device constant, not a frame.
4. **Capture orchestration is enclave-side.**  `fpc_enclave.dll` contains
   `cac_custom_image_capture`, `cac_capture_config_default_get` and dozens of per-device
   `cac_dev_<hash>` capture configs; `fpc_disum.dll` exposes
   `fpc_cac_fasttap_image_capture` / `fpc_cac_simple_image_capture` /
   `cac_if_single_capture` / `cac_if_multi_capture`.  Any multi-capture/averaging is a
   *capture strategy* that still yields a **single** image — and the Windows driver's own
   single image is already smooth.

**Conclusion:** the "two image buffers" is a host-side FID structure that degrades
gracefully when a second image is absent (*"Second image does not exist"*); it is not an
extra data source.  This avenue does not unlock ridge data.

---

## 4. The "enclave" is NOT hardware-sealed — it is a plain `no_sgx` DLL

This corrects an earlier assumption in this document.  `fpc_enclave.dll` is **not** a
hardware Intel-SGX enclave in this package:

- The embedded PDB path says so explicitly:
  `…\out\fpc_enclave\`**`Prerelease_no_sgx`**`\x64\fpc_enclave.pdb`.
- It imports **no SGX runtime** (no `sgx_urts`/`sgx_ukey_exchange` anywhere in the
  package; imports are only Windows API sets + `bcrypt.dll`).  `fpc_disum.dll` loads it
  dynamically with `LoadLibraryExW` + `GetProcAddress("FpcTaOp_ecall")` — an "ecall"
  *naming convention*, not a real SGX ECALL.
- **The code is plaintext and we already disassembled it** (§2/§5) — an actual SGX
  enclave is encrypted at rest and only decryptable by the CPU.
- The host CPU is a **12th-gen i5-12500H, which has no SGX** (Intel dropped SGX from
  11th/12th-gen consumer parts; `/proc/cpuinfo` has no `sgx` flag), yet Windows Hello
  works — so the vendor stack runs the software path here by construction.
  (`fpc_disum.dll` still carries `FPC_SGX_STATE_*` strings for SKUs where SGX exists;
  that build is simply not the one shipped for this Acer part.)

**Consequence:** the image reconstruction
(`fpc_copy_buffer_into_fmi` → dead-pixel fix → `convert_column_wise_image` →
`dfd_calibrate`) is **ordinary user-mode x86-64 code** that can be reversed and
reimplemented on Linux, or run under Wine.  There is no hardware barrier.

**What *would* be unsealable (for reference):** a real production SGX enclave.  Its
on-disk image is CPU-encrypted into the Enclave Page Cache; the sealing key derives via
`EGETKEY` from CPU-fused secrets plus the enclave's `MRENCLAVE` measurement, so it is
bound to one CPU and one exact binary; and production enclaves are not introspectable
(only `SGX_DEBUG`-signed ones are).  That is not the situation here.

**The remaining unknown is data, not crypto:** whether the pipeline can produce ridges
from the raw buffer depends on **per-unit calibration** (OTP / `cac_dev` / dead-pixel /
DFD reference).  Where that reference lives (device OTP vs. a host-side file captured at
first use) is now an open, tractable question — see §6.

---

## 5. Reading the enclave symbol table (useful for further RE)

`fpc_enclave.dll` is unstripped.  Symbols are stored as records:

```
".text$" + <name> + 0x00 + <u32 RVA> + <u32 size>
```

PE sections (image base `0x180000000`):

| section | VA | file offset | raw size |
|---------|-----|-------------|----------|
| `.text` | `0x180001000` | `0x400` | `0x7e000` |
| `.text.un` | `0x18007f000` | `0x7e400` | `0x200` |
| `.rdata` | `0x180081000` | `0x7e800` | `0xec600` |
| `.data` | `0x18016e000` | `0x16ae00` | `0xe00` |
| `.pdata` | `0x180177000` | `0x16bc00` | `0x2a00` |

So for `.text`: `VA = 0x180000000 + RVA`, `file_offset = RVA - 0xc00`.
For `.rdata`: `file_offset = 0x7e800 + (VA - 0x180081000)`.

Quick recipes used here:

```bash
# list image-related symbols
python3 - <<'EOF'
import struct
d=open("fpc_enclave.dll","rb").read(); i=0
while True:
    j=d.find(b".text$",i)
    if j<0: break
    k=d.find(b"\x00",j); name=d[j:k].decode("latin1")
    rva,size=struct.unpack_from("<II",d,k+1)
    if 0x1000<rva<0x200000 and size<0x100000: print(hex(0x180000000+rva),name)
    i=k+1
EOF

# disassemble a function
objdump -d --start-address=0x18004b980 --stop-address=0x18004bb60 -M intel fpc_enclave.dll
```

---

## 6. Conclusion & next steps

**Option 2 result:** the enclave pipeline is understood at a structural level
(`copy → dead-pixel fix → column-wise convert → DFD calibrate`), but it is not a simple
transform we can replay: it depends on the device's stored calibration (reference / FPN /
dead-pixel data) that never appears in the raw USB stream.  So option 2 alone does not
recover ridges from these frames.

**Option 1 result (2026-10-13):** a firm, stationary press was captured (15 frames) — still
no ridges (see §3b).  The blocker is not motion; it is the raw signal itself.

**Decisive test result (2026-10-13, §3d): DONE — negative.**  The vendor Windows stack was
run against the real unit, Windows Hello enrollment succeeded, and its whole USB session
was captured and decrypted.  Windows receives the *same* 11286-byte ridge-free buffer we
do.  So the raw USB buffer is not a ridge image for anyone; the vendor reconstructs the
biometric image from it.

**Crucial correction (2026-10-13, §4): the "enclave" is NOT hardware-sealed.**  The
shipped `fpc_enclave.dll` is the **`Prerelease_no_sgx`** build (its PDB path says so), it
imports no SGX runtime, and its code is plaintext x86-64 we can read.  The host CPU
(i5-12500H) has no SGX at all, and Windows Hello still works.  So the reconstruction
pipeline is **ordinary software** — reversible and portable.

### Solution paths (ranked)

**A. Reimplement the pipeline on Linux (the real fix).**  `fpc_enclave.dll` is plain code;
reverse the four stages and port them into `fpc_disum_tool`/libfprint.  The open question
is no longer crypto but **data**: where the per-unit calibration (OTP / `cac_dev` /
dead-pixel / DFD reference) comes from.  Next concrete step: instrument the DLL (or run it
under Wine) on our captured frames and dump the intermediate `fpc_bep_image` after each
stage — that immediately shows whether ridges emerge and from what input.

**B. Run the vendor DLL under Wine (fastest to "does it even work?").**  Because it is a
`no_sgx` user-mode DLL using only standard APIs + `bcrypt`, Wine is a plausible host.  We
already own the USB/TLS transport (§3d), so the shape is: Linux captures `EVT_IMG` →
hand the buffer to `fpc_enclave.dll` under Wine via its `FpcTaOp_ecall` entry point →
get the processed image/template.  This is the quickest way to confirm feasibility.

**C. Keep the Windows VM (works today, heavy).**  QEMU/KVM + USB passthrough + the vendor
driver already gives working Windows Hello; it can back a Linux PAM module, but it is
clumsy (a VM must own the sensor).

**D. Replace the hardware.**  A USB fingerprint dongle with a libfprint-supported sensor
is the pragmatic answer if the goal is "fingerprint login on this laptop", not "this
sensor on Linux".

**Blocked/closed avenues**
  1. ~~Second-image / reference pair~~ — **tested, negative (§3e).**  The device sends one
     image per touch and no no-finger image is obtainable; the "two image buffers" is a
     host-side FID structure that degrades gracefully when the second is absent.
  2. Per-unit calibration via `CMD_PASSTHRU_*` / OTP — not exercised by the vendor driver
     in our capture; still open, but now tractable because the maths is plain code (§4).
  3. A higher-quality `SensorMode` — the Windows driver's own session used the same
     single-image mode we do.

**Bottom line:** the USB protocol is fully solved and reproducible
(`linux-driver/README.md`), and the image pipeline is *plain software*, not an SGX black
box — so a Linux port is a real engineering task, gated on recovering the per-unit
calibration, not on breaking hardware security.

Raw artefacts and the decryption toolchain live in
`/home/shaanair/fpwork/usbcap/`:
`uc.pcapng`, `parse_bulk.py`, `decrypt_tls.py`, `derive2.py`, `decrypt_final.py`,
`vendor_tls.bin`, `vendor_inner.bin`, `V_all18.png`, `BEST_sidebyside.png`,
`TSTD_montage.png`, `L_layouts_single.png`, `L_detrend_avg.png`; our own frames in
`/home/shaanair/fpwork/ourcaps/`.  Earlier artefacts: `/home/shaanair/fpwork/`
(`R_montage.png`, `D_montage.png`, `S_montage.png`, `X_montage.png`, `capture_session.log`).

---

## 7. Breakthrough (2026-10-13): the whole enclave is now named and decompiled

`fpc_enclave.dll` is **unstripped** — it embeds a `.text$<name>\0 + u32 RVA + u32 size`
symbol table.  Parsing it yields **1093 named functions** (see `fpwork/parse_enclave_syms.py`
→ `fpwork/enclave_syms.txt`).  These are the real FPC internal names (`fpc_bep_*`,
`fpc_sensor_internal_*`, `cac_dev_*`, `fpc_bio_bep_sw23_*`, `cac_*`, `otp_*`, …).

Two things then became possible:

1. **IDA** (Free 9.4 + the `ida-free-mcp` plugin) can `define_func` at the exact
   RVA/size from the symbol table and rename — so the functions Ghidra skipped (they have
   no `.pdata` unwind entries, which is why Ghidra's PE loader missed everything below
   `0x18004f0b0`) become decompilable by name.
2. **Ghidra headless with a custom script** (`fpwork/ReaCreateDecompile.java`) creates a
   function at every symbol-table RVA and decompiles it.  Result:
   **all 1093 functions decompiled to C, 0 failures**, in `fpwork/enclave_decompiled/`.

Tooling lives in `fpwork/`: `ida.py` (IDA-MCP client), `ida_dc.py` / `ida_asm.py`
(decompile/disasm by name), `ReaCreateDecompile.java`, `ghidra_headless.log`.
**Full step-by-step reproduction guide: [`IDA_MCP_WORKFLOW.md`](IDA_MCP_WORKFLOW.md).**

### The real pipeline (named functions)

```
FpcTaOp_ecall (0x180068360)                 // host TA command entry
  └─ sub_18006A2C0                          // TA opcode dispatcher
       └─ fpc_bep_capture (0x18000b870)     // capture a sub-image
       └─ fpc_bep_cal_get (0x18000b640)     // capture + CAC image processing
            ├─ cac_dev_fb3ea0eb81           // build per-device context (chip driver)
            ├─ cac_capture_config_default_get // fill capture config from device ctx
            ├─ fpc_sensor_internal_convert_column_wise_image (0x18004c0c0)
            ├─ fpc_bep_set_nbr_of_subimages
            ├─ fpc_cac_pn_image_capture      // issue capture to sensor
            ├─ cac_reg_write / cac_if_reg_*  // sensor register I/O
            └─ fpc_image_fid_get_size        // FID = frame image data
       └─ fpc_bep_image_extract (0x18000c290) → fpc_bep_image_extract_fq (0x18000c2d0)
            └─ fpc_bio_bep_sw23_* (≈80 funcs) // the actual BEP algorithm
```

- `fpc_sensor_internal_capture_image` (`0x18004b980`) is **register/command driven**
  (`FUN_18004d2d0` = write_reg/cmd, `FUN_18007e7c0`, `FUN_18004cda0`) — the raw frame is
  read back from the sensor, confirming the sensor never hands the host a ridge image.
- The ridge reconstruction is the `fpc_bio_bep_sw23_<hash>` family ("sw23" = FPC BEP
  software v2.3).  These are plain x86-64 (no SGX), now available as decompiled C.

### Calibration: what the vendor fetches at runtime vs. where it is stored

The vendor's **decrypted** Windows session (`usbcap/uc.pcapng`) used **only** these control
requests, counted over 18 touches: `CMD_INIT(1)`, `CMD_ARM(2)`, `CMD_GET_IMG(9)` ×18,
`CMD_GET_KPI(12)` ×18, `CMD_GET_DEAD_PIXELS(10)` ×18, `CMD_INDICATE_S_STATE(8)`,
`CMD_TLS_INIT(5)`, `CMD_TLS_DATA(6)`, `CMD_GET_TLS_KEY(11)`, `CMD_FINGERPRINT_SESSION_OFF(18)`.
**No `CMD_PASSTHRU_*` and no OTP traffic at all** — the passthru/SPI/OTP path is a
factory/sensor-test path, not part of normal operation.

So the only per-unit data fetched over USB at runtime is:
- `CMD_GET_KPI` → a fixed 28-byte device constant (byte-identical to ours), and
- `CMD_GET_DEAD_PIXELS` → `EVT_DEAD_PIXEL_REPORT` (ours: empty).

The per-unit calibration the Windows engine looks for is a **file**, not a registry key:
- file `C:\Windows\System32\WinBioPlugIns\calibrationimg.pndat` ("calibration image",
  `.pndat`).

Its path appears as a wide string in `FpcDisumEngine.dll` / `FpcSessionService.exe`, alongside
the API `EngineAdapterQueryCalibrationData` / `EngineAdapterSelectCalibrationFormat`.

#### Extracted 2026-10-13 — and it is (almost) EMPTY

We pulled the live `calibrationimg.pndat` out of the `win11` QEMU guest (the same VM whose
Windows Hello enrolment succeeded) by typing a `curl --upload-file` one-liner into the guest
via `virsh send-key` and receiving it on a host-side sink at `192.168.122.1:80`
(copy in `windows-calibration/`).  Result:

- `calibrationimg.pndat` = **52,209 bytes**, of which **only 55 bytes are non-zero** — the
  payload (bytes `0x24..end`) is **all zeros** apart from a 4-byte trailer `d0 9f a0 e6`.
  Layout: a 16-byte header/hash (`e4 f6 d4 ab …`), `u32 1260` at `0x10`, `u32 52173`
  (= file size − 36) at `0x1c`/`0x24`, `u32 140` at `0x28`, a `float 1.0` at `0x55`, then
  zeros.  In other words it is a **placeholder / identity calibration**, not a rich per-unit
  reference image.
- The registry key `HKLM\SOFTWARE\FPC\WBF` **does not exist** on the machine (a full
  `reg query HKLM\SOFTWARE /f fpc /k /s` found only unrelated SideBySide/WUDF hits).  The
  earlier "registry `SOFTWARE\FPC\WBF`" claim (inferred from DLL strings) was a red herring.
- `WinBioPlugIns\` contains exactly **one** `.pndat` and no other per-unit data file.

#### This overturns the "missing calibration" hypothesis

Because the calibration is effectively empty, the ridge-free raw `EVT_IMG` is **not** caused by
missing calibration.  The vendor receives the *same* ridge-free buffer (proved by the offline
decryption of `usbcap/uc.pcapng`) and still reconstructs a usable image — so the entire
ridge-recovery step is the **`fpc_bio_bep_sw23_*` algorithm itself**, running on the raw frame
plus the static per-variant tables (already inside the DLL we have; sensor variant = **1262g175**,
build string `FPCBEP: fpc_pc_1262_acer_swift21_20.26.23.27`).

### Revised conclusion

The remaining work is **purely algorithmic** (no secret blob, no hardware security):
1. reuse or port the `fpc_bio_bep_sw23_*` BEP and feed it the raw `EVT_IMG` buffer.
   - **fastest test:** rehost `fpc_enclave.dll` (plain `no_sgx` x86-64) under Wine and call
     `fpc_bep_capture` / `fpc_bep_image_extract` on a saved raw frame;
   - **portable route:** port the ≈80 `fpc_bio_bep_sw23_*` functions from the decompiled C
     (`fpwork/enclave_decompiled/`).

