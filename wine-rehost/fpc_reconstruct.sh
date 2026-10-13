#!/usr/bin/env bash
#
# fpc_reconstruct.sh - end-to-end ridge-image production for the FPC 10a5:e340.
#
#   capture (fpc_disum_tool) -> inject EVT_IMG -> fpc_copy_buffer_into_fmi
#   -> enrol (FpcBioEnrolAdd) -> FUN_18001c810 reconstruction
#      (rehosted fpc_enclave.dll) -> per-frame PNG + montage
#
# Two backends run the vendor's BEP reconstruction:
#   native  fpc_recon_native  - small ELF that maps the DLL and runs it directly
#                               (no Wine). Preferred when built.
#   wine    harness.exe       - the original Wine rehost (fallback).
# See ../WINE_REHOST.md and ../native/README.md.
#
# Usage:
#   fpc_reconstruct.sh [N] [outdir]
#       Capture N frames (touch the sensor N times), reconstruct each, write
#       <outdir>/recon_NNN.png and <outdir>/montage.png.
#
#   fpc_reconstruct.sh --from RAW [RAW...]
#       Reconstruct existing raw EVT_IMG frame(s); outputs next to each input.
#
# Env:
#   FPC_BACKEND     native | wine | auto   (default auto: native if built)
#   FPC_NATIVE      path to fpc_recon_native (default ~/fpc-native/fpc_recon_native)
#   FPC_REHOST_DIR  dir with harness.exe + fpc_enclave.dll (default ~/fpc-rehost)
#   FPC_ENCLAVE_DLL path to fpc_enclave.dll (default $FPC_REHOST_DIR/fpc_enclave.dll)
#   FPC_TOOL        capture tool (default ~/fpc-port/linux-driver/fpc_disum_tool)
#   WINE            wine binary (default: wine)
#   FPC_NO_STRETCH=1  keep raw pixel values (no contrast stretch)
#
set -euo pipefail

REHOST_DIR="${FPC_REHOST_DIR:-$HOME/fpc-rehost}"
NATIVE="${FPC_NATIVE:-$HOME/fpc-native/fpc_recon_native}"
DLL="${FPC_ENCLAVE_DLL:-$REHOST_DIR/fpc_enclave.dll}"
HARNESS="$REHOST_DIR/harness.exe"
TOOL="${FPC_TOOL:-$HOME/fpc-port/linux-driver/fpc_disum_tool}"
WINE="${WINE:-wine}"
HERE="$(cd "$(dirname "$0")" && pwd)"
RECON2PNG="$HERE/recon2png.py"

export WINEPREFIX="${WINEPREFIX:-$REHOST_DIR/wp}"
export WINEDEBUG="${WINEDEBUG:--all}"
export WINEDLLOVERRIDES="${WINEDLLOVERRIDES:-mscoree,mshtml=}"

die() { echo "error: $*" >&2; exit 1; }

# pick a backend
BACKEND="${FPC_BACKEND:-auto}"
if [ "$BACKEND" = "auto" ]; then
    if [ -x "$NATIVE" ]; then BACKEND=native; else BACKEND=wine; fi
fi
case "$BACKEND" in
    native)
        [ -x "$NATIVE" ] || die "native backend selected but $NATIVE is not executable"
        [ -f "$DLL" ]    || die "no fpc_enclave.dll at $DLL (set FPC_ENCLAVE_DLL)"
        ;;
    wine)
        [ -f "$HARNESS" ] || die "no harness.exe in $REHOST_DIR (build it: see WINE_REHOST.md)"
        [ -f "$DLL" ]     || die "no fpc_enclave.dll in $REHOST_DIR"
        command -v "$WINE" >/dev/null || die "wine not found"
        ;;
    *) die "FPC_BACKEND must be native|wine|auto (got '$BACKEND')" ;;
esac

command -v python3 >/dev/null || die "python3 not found (needed for PNG conversion)"

STRETCH=1
[ "${FPC_NO_STRETCH:-0}" = "1" ] && STRETCH=0

# Reconstruct one raw frame -> writes "$out" (.raw); stdout is the harness log.
reconstruct() {
    local raw="$1" out="$2"
    if [ "$BACKEND" = "native" ]; then
        FPC_OUTIMG="$out" "$NATIVE" "$raw" --dll "$DLL"
    else
        ( cd "$REHOST_DIR" && FPC_OUTIMG="$out" "$WINE" ./harness.exe "$raw" 11 1 recon )
    fi
}

# raw -> png
to_png() {
    local raw="$1" png="$2"
    if [ "$STRETCH" = "1" ]; then
        python3 "$RECON2PNG" "$raw" "$png"
    else
        python3 "$RECON2PNG" "$raw" "$png" --no-stretch
    fi
}

montage_pngs() {
    local out="$1"; shift
    [ "$#" -ge 1 ] || return 0
    if command -v montage >/dev/null; then
        # 2x view, up to 5 per row
        montage "$@" -tile 5x -geometry 128x352+6+6 -background black "$out" 2>/dev/null \
            && echo "[+] montage: $out"
    fi
}

echo "[*] backend: $BACKEND"

# ---- mode: reconstruct existing raw frames -------------------------------
if [ "${1:-}" = "--from" ]; then
    shift
    [ "$#" -ge 1 ] || die "--from needs at least one raw file"
    pngs=()
    for raw in "$@"; do
        [ -f "$raw" ] || die "no such file: $raw"
        raw="$(readlink -f "$raw")"
        stem="${raw%.*}"            # strip .raw/.bin/... extension
        out="${stem}_recon.raw"
        echo "=== reconstruct $raw ==="
        reconstruct "$raw" "$out" >"${stem}.recon.log" 2>&1 \
            || die "reconstruction failed on $raw (see ${stem}.recon.log)"
        [ -s "$out" ] || die "no reconstructed image for $raw (see ${stem}.recon.log)"
        to_png "$out" "${stem}_recon.png"
        pngs+=("${stem}_recon.png")
        echo "[+] ${stem}_recon.png"
    done
    if [ "${#pngs[@]}" -ge 2 ]; then
        montage_pngs "$(dirname "${pngs[0]}")/montage.png" "${pngs[@]}"
    fi
    exit 0
fi

# ---- mode: capture + reconstruct -----------------------------------------
N="${1:-3}"
case "$N" in
    ''|*[!0-9]*) die "first argument must be a frame count (got '$N')" ;;
esac
OUTDIR="${2:-$PWD/recon-$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$OUTDIR"
OUTDIR="$(cd "$OUTDIR" && pwd)"

[ -x "$TOOL" ] || die "capture tool not found/executable: $TOOL"

echo "=== capture $N frame(s) ==="
echo "    touch the sensor $N time(s) when prompted"
( cd "$OUTDIR" && "$TOOL" "$N" ) || die "capture failed (sensor present? finger tapped?)"
echo

shopt -s nullglob
raws=("$OUTDIR"/acer_fingerprint_*.raw)
shopt -u nullglob
[ "${#raws[@]}" -ge 1 ] || die "no frames captured"

echo "=== reconstruct ${#raws[@]} frame(s) ==="
pngs=()
for raw in "${raws[@]}"; do
    base="$(basename "$raw" .raw)"
    out="$OUTDIR/${base}_recon.raw"
    echo "--- $base ---"
    reconstruct "$raw" "$out" >"$OUTDIR/${base}.recon.log" 2>&1 \
        || { echo "    reconstruction failed (see ${base}.recon.log)"; continue; }
    [ -s "$out" ] || { echo "    no image produced (see ${base}.recon.log)"; continue; }
    png="$OUTDIR/${base}_recon.png"
    to_png "$out" "$png"
    pngs+=("$png")
    echo "    -> $png"
done

[ "${#pngs[@]}" -ge 1 ] || die "no reconstructed images produced"
montage_pngs "$OUTDIR/montage.png" "${pngs[@]}"

echo
echo "[+] done. Reconstructed images in $OUTDIR"
