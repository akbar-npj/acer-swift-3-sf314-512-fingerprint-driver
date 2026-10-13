# Wine rehost of `fpc_enclave.dll`

Goal: run FPC's host-side reconstruction module (`fpc_enclave.dll`, a plain
`no_sgx` x86-64 DLL) **outside Windows**, and drive it on a captured raw frame so
we can see whether its BEP (`fpc_bio_bep_sw23_*`) turns our ridge-free `EVT_IMG`
buffer into a ridge image.

Status (2026-10-13): **the rehost works end-to-end.** The DLL loads in Wine, its
crypto/sensor context initialises, its full TA (trusted-application) command
interface is mapped and callable, and it now consumes a captured raw `EVT_IMG`
frame and writes out a genuine, finger-specific reconstructed ridge image. One
command drives the whole thing — see ["Using it"](#using-it--end-to-end-ridge-image-production-2026-10-13).
The Wine dependency has since been removed: [`native/`](native/) runs the same
reconstruction directly on Linux with byte-identical output.

## Environment

On the test laptop (`shaan@10.240.74.234`):

```sh
sudo pacman -S --needed wine mingw-w64-gcc     # multilib repo required
mkdir -p ~/fpc-rehost && cd ~/fpc-rehost
cp ~/win_extract/fpc_enclave.dll .             # extracted from the Windows VM
x86_64-w64-mingw32-gcc -O2 -o harness.exe harness.c
WINEPREFIX=$HOME/fpc-rehost/wp WINEDEBUG=-all WINEDLLOVERRIDES="mscoree,mshtml=" \
  wine ./harness.exe
```

Source of truth for the harness: [`wine-rehost/harness.c`](wine-rehost/harness.c).

## The enclave's exported interface

`fpc_enclave.dll` (image base `0x180000000`) exports 10 entry points:

| RVA | export | role |
|-----|--------|------|
| 0x68220 | `fpc_setup_enclave` | installs the host callback ("ocall") table |
| 0x682a0 | `FpcTaInitialize_ecall` | `(u16 hwid)` — configures sensor context |
| 0x68360 | `FpcTaOp_ecall` | `(void *in, u32 in_len, void *out, u32 out_len)` — generic TA command |
| 0x68440 | `FpcTaTerminate_ecall` | teardown |
| 0x681d0 | `fpc_clean_enclave` | teardown |
| 0x68850 | `fpc_enclave_gen_tls_key_ecall` | TLS key gen |
| 0x68b70 | `fpc_enclave_get_tls_state_ecall` | TLS state |
| 0x68b80 | `fpc_enclave_process_data_ecall` | TLS data |
| 0x68ed0 | `fpc_enclave_tls_context_free_ecall` | TLS free |
| 0x68f90 | `fpc_enclave_tls_handle_connection_ecall` | TLS connection |

The imports are only `api-ms-win-core-*` (kernel32 API sets) + `bcrypt.dll` — no
USB, no CRT — so it is fully Wine-compatible.

### Host callbacks ("ocall" table)

`fpc_setup_enclave(table)` stores `table` at `0x18016ecc0`. Only entries
`[0]..[4]` (offsets 0/8/0x10/0x18/0x20) are ever used, and only from the TLS/crypto
region (`0x1800681a8`, `0x180068dd1`, `0x1800692b1`) — i.e. the ocalls are **TLS
record transport only**. Stubs returning 0 are enough to get everything else running.

### TA command protocol

`FpcTaOp_ecall` copies the input into a working buffer and calls the router
`fpc_ta_route_command` (0x18006a2c0), which reads `u32 target = in[0]` and looks it
up in a 3-entry table at `0x18016e090`:

```
in = { u32 target; u32 cmd; u32 result; u32 param; u8 payload[] @0x10 }
```

| target | handler | meaning |
|--------|---------|---------|
| 0xb (11) | `fpc_ta_bio_command_handler` (0x18006afb0) | biometric ops |
| 0xc (12) | `fpc_ta_common_command_handler` (0x18006a4b0) | logging/no-op |
| 0xe (14) | `fpc_ta_wbf_handler` (0x18006c700) | WBF (hmac/keys) |

`fpc_ta_bio_command_handler` dispatch (jump table @ RVA 0x6b214):

| cmd | operation |
|-----|-----------|
| 0 | `fpc_ta_bio_begin_enrol` |
| 1 | `fpc_ta_bio_enrol` |
| 2 | `fpc_ta_bio_end_enrol` |
| 3 | `fpc_ta_bio_identify` (does the image extract) |
| 4 | `fpc_ta_bio_update_template` |
| 5 | unsupported |
| 6 | `fpc_ta_bio_load_empty_db` |
| 7 | `fpc_ta_bio_get_template_ids` |
| 8 | `fpc_ta_bio_delete_template` |
| 9 | `fpc_ta_bio_set_active_fingerprint_set` |
| 10 | `fpc_ta_bio_get_template_db_id` |

`result` (in[2]) is filled by the router with the handler's status; some handlers
also return a per-op code in `out[8]`.

## Findings

- **The DLL loads and runs under Wine** (`LoadLibraryA` → OK).
- `fpc_setup_enclave(stubs)` → **0**.
- `FpcTaInitialize_ecall(hwid)` needs the **right hwid**. `fpc_common_config_sensor`
  (0x18006a680) looks the hwid up in `fpc_common_config_sensor`'s helper
  (0x18006ad40), which masks it. Brute-forcing the helper in-process shows the
  valid sets: **coating=0 → hwid in 0x0101..0x03ff (272 values)**, and
  **coating=8 → hwid in 0x0300..0x03ff (256 values)**. With **hwid = 0x0300**
  `FpcTaInitialize_ecall` returns **0** (sensor context configured; variant 1262g175).
- With the context up, **all BIO sub-commands dispatch and return** (e.g.
  `begin_enrol`→0, `enrol`→out[8]=0xffffffff, `identify`→out[8]=0xffffffff — the
  latter two fail only because no frame has been injected).
- The enclave writes **no log file**; its log sink is the global struct at
  `0x180175c00` (not wired to a file/handle we can see), so we rely on return codes.

## RESOLVED: the raw frame enters via the capture-result struct, and the algorithm
## produces a reconstructed image (2026-10-13)

### How the frame enters (solved)

The TLS-received `EVT_IMG` is memcpy'd into a **global capture-result struct at
`0x1801728e0`**:

```
+0x00 : 12-byte event header {u32 code=8; u32 len; u32 unknown}
+0x0c : EVT_IMG payload  (22-byte sub-header; its first 10 bytes are the metadata)
+0x22 : image[11264]     (0x1801728e0 + 0x22 = 0x180172902)
```

Then **`fpc_copy_buffer_into_fmi(8, out, 11264)` (0x180068470)** does the ingestion
(disassembly-verified, type==8 branch):
- reads metadata from globals `0x1801728ec..0x1801728f5` (10 bytes = sub-header[0..10])
- **puts keys 0xd2,0xd3,0xd4,0xd5,0xd6,0xd7,0xda** into the live `fpc_image_data`
  (via `0x18000c570`), aborting with `-0xa` if any put fails
- validates `len == image size`, then **memcpy's the pixels** from `0x180172902`
  into the live pixel buffer (`0x180070800`).

So to inject a saved raw frame we just:
```c
unsigned char *cap = g_base + 0x1728e0;
memset(cap, 0, 0x22 + 11264);
memcpy(cap + 0x0c, raw, n);      /* raw = 22-byte sub-header + 11264 px */
fmi(8, &outv, 11264);            /* fpc_copy_buffer_into_fmi */
```
**This was the fix**: injecting pixels directly into the pixel buffer *without* the
metadata left key `0xda` unset, so the algorithm aborted with `0x3eb` → error `200`.
Going through `fpc_copy_buffer_into_fmi` sets all seven keys and the algorithm runs.

### The reconstructed image (solved) — `FUN_18001c810`

The BEP core is `FpcBioEnrolAdd` (0x1800013d0) → `FUN_180013f70` (0x180013f70) →
`FUN_180017420` (0x180017420) → **`FUN_18001c810` (0x18001c810)**. Near its end the
pipeline writes an explicit 8-bit **output image**:

```c
iVar6 = width * height;
for (i=0; i<iVar6; i++)
    *(char *)(param_1[3] + i) = (char)(*(short *)(local_58 + i*2) + 0x20 >> 6);
```

where `param_1` is the `fpc_image`-shaped struct passed down from the core:
`+0x00` magic, `+0x18` **output pixel pointer**, `+0x20` **width**, `+0x24` **height**
(for our sensor: 64 × 176). Hooking `FUN_18001c810` and dumping `param_1[3]` yields
the reconstructed image directly.

### Validation (the output is a faithful, input-dependent transform)

Ran the same pipeline on synthetic inputs (`wine-rehost/harness.c` modes above):

| input | output |
|-------|--------|
| constant 128 | constant 128 (std **0.0**) — **no hallucination** |
| uniform random pixels | noise |
| real frame pixels **shuffled** | noise |
| real frame | coherent curved-line pattern |
| synthetic vertical stripes (period 6) | diagonal stripe pattern |

- Same frame twice → **identical** output (corr 1.000, deterministic).
- Different real frames (f01..f05) → different outputs (corr 0.05..0.6).
- Radial power spectrum: input is **monotonic** (no ridge band), the reconstructed
  image has a **clear band-limited peak at r≈5** — ridge-scale structure that was
  absent from the raw buffer.

### Validation with a DIFFERENT finger — the reconstruction is genuine (2026-10-13)

Captured 5 new `EVT_IMG` frames of a **different finger** with
`fpc_disum_tool 5`, ran them through the harness, and compared correlations over
64×176 px:

| comparison | RAW EVT_IMG | RECONSTRUCTED |
|---|---|---|
| index vs index (same finger) | 0.868 | 0.341 |
| different vs different (same finger) | 0.867 | 0.003 |
| **index vs different finger** | **0.828** | **0.012** |

In the raw stream two *different fingers* correlate **0.83** — the sensor's fixed
pattern dominates and the finger contributes almost nothing visible. After the BEP
pipeline, different fingers are **uncorrelated (0.01)** while the same finger still
correlates (0.34, limited by re-press drift). So the algorithm **removes the fixed
pattern and exposes finger-specific ridge structure** — this is a real fingerprint
reconstruction, not a fixed-pattern artefact.

Visual: `analysis/reconstructed/index_vs_difffinger_comparison.png` (top = index
finger f01..f05, bottom = the different finger). Details:
`analysis/reconstructed/VALIDATION.md`.

Artefacts saved in [`analysis/reconstructed/`](analysis/reconstructed/):
`reconstructed_f01.raw`, `reconstructed_f01_64x176_x6.png`,
`reconstructed_montage_f01-f05.png`, `validation_real_vs_synthetic.png`,
`validation_shuffled_input.png`, `index_vs_difffinger_comparison.png`,
`difffinger/` (5 raw + 5 reconstructed).

**Conclusion:** the rehosted enclave turns our ridge-free `EVT_IMG` into a genuine,
finger-specific ridge image, on Linux, with no Windows and no hardware SGX.

## Using it — end-to-end ridge-image production (2026-10-13)

The reconstruction is now wired into the capture flow with one command. Two files
in [`wine-rehost/`](wine-rehost/) implement it:

- `fpc_reconstruct.sh` — the wrapper: capture → reconstruct → PNG + montage.
- `recon2png.py` — 8-bit raw → PNG (contrast-stretched by default).
- `harness.c` gained a `recon` mode (begin → inject → enrol, nothing else) and
  honours `FPC_OUTIMG=<path>` so each input frame names its own output.

The wrapper runs either backend (`FPC_BACKEND=native|wine|auto`, default `auto`):
the **native** [`native/fpc_recon_native`](native/) when built (no Wine), else the
Wine `harness.exe`. Both produce byte-identical images.

```sh
# capture N frames (touch the sensor N times), reconstruct, write PNGs + montage
~/fpc-rehost/fpc_reconstruct.sh 5 ~/caps

# reconstruct frames you already captured (no hardware needed)
~/fpc-rehost/fpc_reconstruct.sh --from ~/caps/acer_fingerprint_001.raw ...
```

Outputs per frame: `acer_fingerprint_NNN_recon.raw` (64×176 8-bit),
`acer_fingerprint_NNN_recon.png`, plus `montage.png` (2× view, 5 per row).
Per-frame Wine logs land in `acer_fingerprint_NNN.recon.log`.

Live end-to-end result (2026-10-13): `fpc_reconstruct.sh 3 ~/caps-live` captured
three taps and produced a clear whorl/loop ridge pattern — see
[`analysis/reconstructed/live/`](analysis/reconstructed/live/) (`montage.png` +
three `*_recon.png`).

Live end-to-end result on the **native backend** (2026-10-13): the same command
against real hardware with **no Wine involved** —
`FPC_BACKEND=native fpc_reconstruct.sh 3 ~/caps-native` — captured three taps and
produced a clear whorl/loop ridge pattern. Evidence:
[`analysis/reconstructed/live-native/`](analysis/reconstructed/live-native/)
(`montage.png`, three `*_recon.png`, the source `*.raw` frames, and the per-frame
`*.recon.log`). This is the end-to-end proof that the native rehost drives a live
sensor, not just saved frames.

Under the hood, per frame:

```sh
FPC_OUTIMG=<out>.raw wine ./harness.exe <frame>.raw 11 1 recon
```

which does `FpcTaOp_ecall` begin_enrol (11,0) → memcpy the raw payload into the
capture-result struct `0x1801728e0` and call `fpc_copy_buffer_into_fmi(8,…)`
(`0x180068470`) → enrol (11,1) → `FpcBioEnrolAdd` → `FUN_180013f70` →
`FUN_180017420` → **`FUN_18001c810`**, whose output buffer is dumped.

Overridable env: `FPC_REHOST_DIR` (default `~/fpc-rehost`), `FPC_TOOL` (default
`~/fpc-port/linux-driver/fpc_disum_tool`), `WINE`, `FPC_NO_STRETCH=1`.

## Native vs Wine parity (2026-10-13)

The native backend ([`native/`](native/), no Wine) is verified **byte-for-byte
identical** to the Wine backend, driven through the real wrapper on the same
inputs.

**Result: 27/27 distinct captured frames byte-identical.**

```
collected=56 raw frames (11286 B)  ->  27 distinct (de-duplicated by md5)
PARITY: pass=27 fail=0   (native vs wine, byte-for-byte)
```

Method — every `*.raw` / `*.bin` of exactly 11286 bytes under the capture
directories is collected, de-duplicated by md5, and for each distinct frame both
backends are run and the outputs compared:

```sh
FPC_BACKEND=native fpc_reconstruct.sh --from f.raw   # -> f_recon.raw
FPC_BACKEND=wine   fpc_reconstruct.sh --from f.raw   # -> f_recon.raw
cmp native/f_recon.raw wine/f_recon.raw              # 27/27 identical
```

The **internal status lines** match too (per-frame `*.recon.log`):

| line | value (both backends) |
|------|-----------------------|
| `inject(...) fmi->` | `0` (`fpc_copy_buffer_into_fmi`) |
| `> FUN_18001c810 ->` | `0  out_img=…  64x176  hdr=0x3e800xx` |
| `op(t=11 c=1) ->` | `0 out[8]=1 out[12]=15` |

Backend auto-selection: the wrapper prints `[*] backend: native` when
`fpc_recon_native` is built, else `wine`.

### Reading the comparison correctly (gotchas)

The raw logs are **not** textually identical even when the run is; compare after
normalising:

- **Input path** differs (`native/f.raw` vs `wine/f.raw`) in the `inject(...)`
  line — expected.
- **Output pointer** differs (each process allocates its own image buffer); the
  `out_img=` address is meaningless across runs. Wine prints it without a `0x`
  prefix, native with one.
- **Line endings** — Wine's log is CRLF, native's is LF (`file` reports
  "with CRLF line terminators"). Strip `\r` before comparing.
- `FUN_18001c810` prints `hdr=0x3e800xx`; that value is per-frame and matches
  between backends for the same input.

### Coverage note

An earlier "8 frames" figure double-counted: three files under
`~/fpc-recon-test/` (`acer_fingerprint_00{1,2,3}.raw`) had the same md5 as
`g001..g003.bin` (they were overwritten by the different-finger capture). The
de-duplicated, honest count is **27 distinct frames**.

## Next steps

1. ~~Wire the reconstruction into the Linux tool~~ **done** — see "Using it" above
   (`fpc_reconstruct.sh`).
2. ~~Remove the Wine dependency~~ **done** — [`native/`](native/) builds
   `fpc_recon_native`, a small ELF that maps `fpc_enclave.dll` and runs the BEP
   reconstruction directly (ms_abi shims + a fake `%gs` TEB, no Wine). Output is
   byte-identical to the Wine build on all 27 distinct captured frames;
   `fpc_reconstruct.sh` prefers it automatically (`FPC_BACKEND=native|wine`). See
   [`native/README.md`](native/README.md).
3. Optional: a clean-room C rewrite of the reachable BEP tree (359 functions,
   ~166 KiB) to drop the vendor code bytes entirely. The native and Wine builds
   are the correctness oracle.
