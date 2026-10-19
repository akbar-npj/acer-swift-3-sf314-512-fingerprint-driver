# FPC `10a5:e340` — Cross-Distro Compilation & Install Guide (Debian · Fedora · Arch)

A self-contained guide to **compiling and installing** the Linux driver for the
**FPC Disum** fingerprint sensor (`10a5:e340`, Acer Swift 3 SF314-512; the
sibling `10a5:a900` Honor part is also supported by the same code). It is
organised around three distributions — **Debian/Ubuntu**, **Fedora**, and
**Arch Linux** — because the *build inputs* are identical (GCC, Meson, GLib,
GUsb, OpenSSL) but the *system install* differs (package names, library paths,
update-survival hooks).

> This guide does **not** explain how the stack was reverse-engineered. For the
> protocol, every command table, the enclave/BEP reconstruction, the clean-room
> rules, and the function inventory, read
> [`RE_GUIDE.md`](./RE_GUIDE.md). This document is the
> **distro-oriented build/install** companion.

---

## 0. TL;DR

1. The sensor speaks a vendor USB protocol over a **TLS-PSK** channel. The
   ridge image is reconstructed host-side inside a vendor DLL (`fpc_enclave.dll`)
   that has been **rehosted** (runs natively on Linux, no Windows).
2. A **clean-room** C re-implementation of that reconstruction (`cleanroom/`) is
   byte-identical to the DLL on 37/37 frames, so the driver never ships or loads
   the original bytes at runtime.
3. The driver (`linux-driver/src/fpc2040.c`) is a **libfprint 1.94.100** driver
   that links the clean-room BEP library + a correlation matcher and registers
   the `10a5:e340`/`10a5:a900` devices.
4. You compile libfprint from source **with** the driver, then swap the built
   `libfprint-2.so` into the system. **The only distro-specific parts are:
   package names, the library install path, and the update-survival hook.**

---

## 1. Hardware & software inventory

| Item | Value |
|---|---|
| USB VID:PID | `10a5:e340` (Acer) · `10a5:a900` (Honor) |
| Interface string | `FPC L:0001 FW:20262327` |
| Firmware | `20.26.23.27` |
| Sensor geometry | raw `128×88` px → reconstructed ridge `64×176` |
| Original Windows driver | `FingerPrint_Carewe_20.26.23.27_W11x64/fpc_disum.dll` |
| Reconstruction module | `fpc_enclave.dll` (no_sgx x86-64 DLL) |
| Cipher suite | `TLS_PSK_WITH_AES_128_GCM_SHA256` / `_CBC_SHA256` (mbedTLS on device) |
| TLS roles | **host = TLS client, device = TLS server** (opposite of the `9201`) |

Everything below was validated against real hardware, not inferred from the
sibling `10a5:9201` (which differs in endianness, TLS roles and geometry).

---

## 2. Reverse engineering — where to read it

This document is **compilation-only**. The full deep reverse-engineering
write-up (the protocol, TLS-PSK, the enclave/BEP reconstruction, the clean-room
rules, the validation oracles, the matcher, and the driver design) lives in a
separate document:

> **[`RE_GUIDE.md`](./RE_GUIDE.md)** —
> *FPC `10a5:e340` Reverse-Engineering Guide (deep)*

That document covers, in depth:

- Hardware/software inventory and the `10a5:e340` vs `10a5:9201` split
- The USB `CMD_*`/`EVT_*` protocol and session flow
- The TLS-PSK handshake and PSK derivation (`FPC_SEALING_KEY` /
  `FPC_HMAC_KEY`)
- The `fpc_enclave.dll` rehost (native PE loader + Wine fallback) and the
  clean-room BEP reconstruction rules
- The differential-test oracles and how byte-identical parity is proven
- The correlation matcher design and the libfprint `fpc2040` driver design

Read `RE_GUIDE.md` first if you want to *understand* the stack. This
document tells you how to *build and install* it on Debian, Fedora, and Arch.

---

## 3. Build prerequisites (per distro)

Install the toolchain and libraries **once**. The package names differ; the
rest of the build is identical.

| Need | Debian / Ubuntu | Fedora | Arch |
|---|---|---|---|
| C toolchain + make | `build-essential` | `gcc` `make` | `base-devel` |
| Meson | `meson` | `meson` | `meson` |
| Ninja | `ninja-build` | `ninja-build` | `ninja` |
| pkg-config | `pkg-config` | `pkgconf-pkg-config` | `pkgconf` |
| GLib dev | `libglib2.0-dev` | `glib2-devel` | `glib2` |
| libusb-1.0 dev | `libusb-1.0-0-dev` | `libusb1-devel` | `libusb` |
| GUsb dev | `libgusb-dev` | `libgusb-devel` | `libgusb` |
| OpenSSL dev | `libssl-dev` | `openssl-devel` | `openssl` |
| fprintd daemon | `fprintd` | `fprintd` | `fprintd` |
| PAM module | `libpam-fprintd` | `fprintd-pam` | `fprintd`¹ |
| polkit | `polkitd-pkla`² / `polkitd` | `polkit` | `polkit` |

¹ On Arch the `fprintd` package already ships `pam_fprintd.so`.
² On current Debian/Ubuntu the daemon + PAM module are in `fprintd` /
`libpam-fprintd`; a polkit rule is only needed so a **non-root** user can enroll.

One-line install:

```sh
# Debian / Ubuntu
sudo apt-get update && sudo apt-get install -y \
  build-essential meson ninja-build pkg-config \
  libglib2.0-dev libusb-1.0-0-dev libgusb-dev libssl-dev \
  fprintd libpam-fprintd

# Fedora
sudo dnf install -y \
  gcc make meson ninja-build pkgconf-pkg-config \
  glib2-devel libusb1-devel libgusb-devel openssl-devel \
  fprintd fprintd-pam

# Arch
sudo pacman -S --needed --noconfirm \
  base-devel meson ninja pkgconf \
  glib2 libusb libgusb openssl fprintd
```

> To **build libfprint from source** you need the same deps as libfprint itself
> (GLib, GUsb, OpenSSL, UDev). The packages above cover them.

---

## 4. Building the components

All commands below are **distribution-independent** (plain `make`/`meson`).
`$REPO` is the path to this repository root.

### 4.1 Clean-room library + differential test

```sh
cd "$REPO"/cleanroom
make                 # builds libfpcbep.a (50 sources) + the difftest tool
# Run the difftest against a captured frame and the DLL oracle:
"$REPO"/cleanroom/tools/cr_difftest <captured_frame.raw>
# Expect: PARITY OK — 37/37 bytes byte-identical
```

`libfpcbep.a` is what the libfprint driver links.

### 4.2 Matcher

```sh
cd "$REPO"/matcher
make                 # builds libfpc_match.a + fpc_match_tool
./fpc_match_tool a.raw b.raw    # prints score=N (coverage X% / Y%)
```

### 4.3 Native rehost (x86-64 only — no Wine)

```sh
cd "$REPO"/native
make                 # gcc, requires libfpcbep.a from §4.1
./fpc_recon_native <raw.bin> [out.raw] [--dll fpc_enclave.dll]
```

`fpc_recon_native` is the speed/CI-friendly backend; it is **not** required by
the driver (the driver links the clean-room library directly).

### 4.4 Wine rehost (fallback / oracle)

```sh
cd "$REPO"/wine-rehost
./fpc_reconstruct.sh --from <frame.raw>     # reconstruct an existing frame
./fpc_reconstruct.sh 5 ~/caps               # capture 5 frames then reconstruct
```

### 4.5 Standalone capture tool (no fprintd needed)

```sh
cd "$REPO"/linux-driver
make                                       # builds ./fpc_disum_tool
sudo ./fpc_disum_tool 20     # tap the sensor 20×; writes acer_fingerprint_NNN.pgm/.raw
```

Useful for raw capture / debugging without involving libfprint.

### 4.6 libfprint driver (Meson, `-Ddrivers=fpc2040`)

Clone libfprint, drop the driver + the two libraries in, edit `meson.build`,
build. (Same on every distro.)

```sh
git clone --depth 1 --branch v1.94.100 \
    https://gitlab.freedesktop.org/libfprint/libfprint.git ~/src/libfprint-v1.94.100
cd ~/src/libfprint-v1.94.100

# 1. driver entry point + clean-room BEP + matcher
mkdir -p libfprint/drivers/fpcbep
cp "$REPO"/linux-driver/src/fpc2040.c           libfprint/drivers/
cp "$REPO"/linux-driver/src/bep_runner.c        libfprint/drivers/fpcbep/
cp "$REPO"/linux-driver/include/*.h             libfprint/drivers/fpcbep/
cp "$REPO"/cleanroom/src/*.c                    libfprint/drivers/fpcbep/
cp "$REPO"/cleanroom/include/*.h                libfprint/drivers/fpcbep/
cp "$REPO"/matcher/fpc_match.c "$REPO"/matcher/fpc_match.h \
                                                  libfprint/drivers/fpcbep/

# 2. register the driver in the two meson.build files.

# 2a. in the top-level meson.build, add the openssl helper to drivers_info:
#     drivers_info = {
#         ...
#         'fpc2040': { 'helper': ['openssl'] },
#     }

# 2b. in libfprint/meson.build, add the driver + every fpcbep/*.c to
#     driver_sources. (Copy cleanroom/src/*.c and cleanroom/include/*.h into
#     libfprint/drivers/fpcbep/ first — step 1 above already did that.)
#
#     driver_sources = {
#         ...
#         'fpc2040' : files(
#             'drivers/fpc2040.c',
#             'drivers/bep_runner.c',
#             'drivers/fpc_match.c',
#             # clean-room BEP (one entry per cleanroom/src/*.c)
#             'drivers/fpcbep/fpc_comp.c',
#             'drivers/fpcbep/fpc_bep_run.c',
#             'drivers/fpcbep/fpc_bep_template.c',
#             ...
#         ),
#     }

# 2c. in libfprint/meson.build, two more edits:
#     # parity: never let the compiler fuse mul+add into an FMA
#     drivers_cflags = ['-ffp-contract=off']
#     # let bep_runner.c find fpc_bep_template.h
#     deps += declare_dependency(include_directories: [
#         ...
#         include_directories('drivers/fpcbep'),
#     ])

# 3. configure + build
meson setup build -Ddrivers=fpc2040 -Dintrospection=false -Ddoc=false \
                  -Dinstalled-tests=false -Dudev_rules=disabled
ninja -C build
```

> `-ffp-contract=off` is **required**: without it the compiler fuses
> multiply-adds and the clean-room BEP no longer reproduces the vendor output
> bit-for-bit.

> **Meson ≥ 1.12 note:** `tests/meson.build` uses the old single-variable dict
> iteration. Change `foreach driver_test: drivers_tests` to
> `foreach driver_test, _unused: drivers_tests`.

Verify the driver registered (both VIDs should appear):

```sh
./build/libfprint/fprint-list-supported-devices | grep 10a5
# 10a5:a900 | Fingerprint Cards Disum (Honor / Acer)
# 10a5:e340 | Fingerprint Cards Disum (Honor / Acer)
```

Try it before the system install:

```sh
sudo ./build/examples/enroll     # 5 touches of the same finger
sudo ./build/examples/verify     # touch again -> FPI_MATCH_SUCCESS / _FAIL
```

---

## 5. System install (per distro)

The build produced `~/src/libfprint-v1.94.100/build/libfprint/libfprint-2.so.2.0.0`.
You now swap it in for the distro's `libfprint-2.so.2.0.0`. **The path is the
only thing that changes per distro.**

### 5.1 Library install path matrix

| Distro | System `libfprint-2.so.2.0.0` lives at |
|---|---|
| Debian / Ubuntu | `/usr/lib/x86_64-linux-gnu/libfprint-2.so.2.0.0` |
| Fedora | `/usr/lib64/libfprint-2.so.2.0.0` |
| Arch | `/usr/lib/libfprint-2.so.2.0.0` |

```sh
# Debian / Ubuntu
sudo install -m755 ~/src/libfprint-v1.94.100/build/libfprint/libfprint-2.so.2.0.0 \
        /usr/lib/x86_64-linux-gnu/libfprint-2.so.2.0.0
sudo ldconfig

# Fedora
sudo install -m755 ~/src/libfprint-v1.94.100/build/libfprint/libfprint-2.so.2.0.0 \
        /usr/lib64/libfprint-2.so.2.0.0
sudo ldconfig

# Arch
sudo install -m755 ~/src/libfprint-v1.94.100/build/libfprint/libfprint-2.so.2.0.0 \
        /usr/lib/libfprint-2.so.2.0.0
sudo ldconfig
```

> **`ldconfig` hazard (learned the hard way):** never copy a backup of the
> stock `.so` into a directory `ldconfig` searches (e.g. `/usr/lib`). The soname
> symlink gets rewired to the stock copy and the driver silently disappears.
> Keep backups *outside* any ldconfig path (see `restore-fpc2040-libfprint.sh`
> in §7).

### 5.2 udev rule for the sensor

```sh
sudo cp "$REPO"/linux-driver/udev/70-libfprint-2-fpc2040.rules \
         /etc/udev/rules.d/70-libfprint-2-fpc2040.rules
sudo udevadm control --reload-rules
sudo udevadm trigger      # or unplug/replug the sensor
```

### 5.3 Disable USB autosuspend (prevents "scanner fails to load")

The kernel autosuspends the sensor after ~2 s idle; resuming it on next unlock
triggers a `usb reset` that races with the driver's claim and intermittently
fails to load. Pin the device on (matched by VID:PID so it survives replugs /
reboots):

```sh
cat <<'EOF' | sudo tee /etc/udev/rules.d/99-fpc-no-autosuspend.rules
ACTION=="add|change", SUBSYSTEM=="usb", ATTR{idVendor}=="10a5", ATTR{idProduct}=="e340", TEST=="power/control", ATTR{power/control}="on"
EOF
sudo udevadm control --reload-rules
# apply immediately to the live device (path may differ; find it with lsusb):
echo on | sudo tee /sys/bus/usb/devices/3-5/power/control
```

### 5.4 fprintd + PAM

Enroll and verify as your user (polkit lets a non-root user enroll on all three
distros once `fprintd` is installed):

```sh
fprintd-enroll                 # follow prompts, 5 touches of one finger
fprintd-verify                 # touch -> verify-match
```

**Make unlock instant (password *first*, fingerprint fallback).** The distro
default puts `pam_fprintd` *first*, so even a password attempt spins up the
fingerprint device (our custom driver) and waits — a 1–3 s delay. Reorder so the
password (`pam_unix`) is checked first; fingerprint stays a `sufficient`
fallback. Edit the service kscreenlocker uses (typically `/etc/pam.d/kde`; also
`/etc/pam.d/login` and `/etc/pam.d/sddm` if you want login too):

```
#%PAM-1.0
auth       requisite    pam_nologin.so
auth       sufficient   pam_unix.so try_first_pass nullok
auth       sufficient   pam_fprintd.so max-tries=3 timeout=10
auth       include      system-local-login
account    include      system-local-login
session    include      system-local-login
password   include      system-local-login
```

(The trailing `include system-local-login` is only reached when *both* password
and fingerprint fail, so `pam_faillock` still catches genuine wrong passwords;
correct passwords and successful fingerprints never touch `faillock`.)

### 5.5 KDE lock-screen QML tweaks (optional UX, desktop-specific)

If you use KDE and want (a) a successful fingerprint to auto-unlock with **no
extra button** and (b) password to submit on a single Enter, apply the QML
patches (KDE-shell paths are identical across the three distros):

```sh
sudo python3 "$REPO"/linux-driver/install/patch-lockscreen.py
sudo install -Dm755 "$REPO"/linux-driver/install/restore-kde-lockscreen.sh /usr/local/sbin/
sudo install -Dm755 "$REPO"/linux-driver/install/uninstall-kde-lockscreen.sh /usr/local/sbin/
sudo install -Dm644 "$REPO"/linux-driver/install/99-kde-lockscreen.hook /etc/pacman.d/hooks/
sudo install -Dm644 "$REPO"/linux-driver/install/kde-lockscreen-restore.service /etc/systemd/system/
sudo systemctl enable kde-lockscreen-restore.service
```

> The `99-kde-lockscreen.hook` is a **pacman** PostTransaction hook (Arch). On
> Debian/Fedora there is no equivalent hook mechanism; use the auto-restore
> service (boot) and re-run `restore-kde-lockscreen.sh` after a
> `plasma-desktop` upgrade, or wire a dpkg/post-invoke / dnf script (see §7).

---

## 6. Verify end-to-end

```sh
lsusb | grep 10a5            # sensor present
fprintd-list "$USER"         # fprintd loads the device; lists enrolled finger
# Lock the screen, unlock with a finger -> auto-unlock (no button)
# Lock the screen, type password, Enter once -> instant unlock
```

On the Acer (Arch / KDE / SDDM) this was verified live: `fprintd-verify`
returns `verify-match` and a real fingerprint login/unlock works.

---

## 7. Surviving distribution updates

A `distro -Syu` / `dnf upgrade` / `apt upgrade` that touches `libfprint` silently
restores the **stock** `.so` and drops the driver. Re-swap it.

**Arch (pacman hook — already installed by §5.5):**
`/etc/pacman.d/hooks/99-fpc2040-libfprint.hook` runs
`restore-fpc2040-libfprint.sh` on every `libfprint` transaction, and
`fpc2040-libfprint-restore.service` re-applies it at boot.

**Debian / Fedora (no pacman hook):** install the generic boot service and an
update hook:

```sh
# boot-time restore (all distros)
sudo install -Dm644 "$REPO"/linux-driver/install/fpc2040-libfprint-restore.service \
         /etc/systemd/system/
sudo systemctl enable fpc2040-libfprint-restore.service

# Debian: re-swap after any libfprint upgrade via apt
echo 'DPkg::Post-Invoke { "if [ -x /usr/local/sbin/restore-fpc2040-libfprint.sh ]; then /usr/local/sbin/restore-fpc2040-libfprint.sh; fi"; };' \
  | sudo tee /etc/apt/apt.conf.d/99-fpc2040-restore.conf

# Fedora: re-swap after any libfprint upgrade via dnf
sudo mkdir -p /etc/dnf/plugins/post-transaction-actions.d
echo 'libfprint*:any:/usr/local/sbin/restore-fpc2040-libfprint.sh' \
  | sudo tee /etc/dnf/plugins/post-transaction-actions.d/fpc2040.action
```

The restore script (`linux-driver/install/restore-fpc2040-libfprint.sh`)
keeps the **custom** `.so` outside any ldconfig path, backs up the distro
`.so` outside ldconfig, and re-installs the custom one — idempotently.

---

## 8. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `difftest` mismatches | Missing `-ffp-contract=off`; or deterministic-heap shims removed. |
| Enrol hangs, no events | `EVT_FINGER_DWN` is header-only; handle the outer event code. Drain decrypted TLS events. |
| `LIBUSB_ERROR_NO_DEVICE` | Killed process left the sensor mid-session; re-open or replug. |
| Scanner "fails to load" intermittently / kernel `usb reset` | USB autosuspend — apply §5.3. |
| Password unlock slow (1–3 s) but fingerprint instant | `pam_fprintd` first in PAM — apply §5.4. |
| Password Enter needs 2–3 presses | Focus/first-Enter bug — apply QML patch §5.5. |
| Fingerprint succeeds but an extra "Unlock" button appears | Upstream `onSucceeded` shows a button — apply QML patch §5.5. |
| Driver "vanishes" after update | Stock `.so` restored — §7. |
| Driver "vanishes" after reboot despite a backup | Backup `.so` was placed in `/usr/lib` and `ldconfig` rewired the soname — §5.1 note. |

---

## 9. File map

| Path | Role |
|---|---|
| `cleanroom/` | Clean-room BEP library (50 sources) + tools (difftest) |
| `native/` | No-Wine rehost of `fpc_enclave.dll` (`fpc_recon_native`) |
| `wine-rehost/` | Wine rehost + `fpc_reconstruct.sh` wrapper |
| `matcher/` | Correlation matcher (`libfpc_match.a`) |
| `linux-driver/src/fpc2040.c` | libfprint 1.94.100 driver |
| `linux-driver/src/bep_runner.c` | BEP + matcher glue used by the driver |
| `linux-driver/udev/` | `70-libfprint-2-fpc2040.rules` |
| `linux-driver/install/` | QML/pacman/systemd deploy scripts + uninstall |
| `RE_GUIDE.md` | Full RE deep-dive (protocol, TLS-PSK, enclave, clean-room, matcher, driver design) |

---

## 10. References

* Full RE write-up and every command table: [`RE_GUIDE.md`](./RE_GUIDE.md)
* libfprint: <https://gitlab.freedesktop.org/libfprint/libfprint>
* fprintd / PAM: <https://fprint.freedesktop.org/>
* KDE lock-screen QML: `org.kde.plasma.desktop` `contents/lockscreen/`
