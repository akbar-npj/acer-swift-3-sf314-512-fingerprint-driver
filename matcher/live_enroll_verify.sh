#!/bin/bash
# live_enroll_verify.sh — end-to-end fingerprint demo on the target laptop.
#
# Pipeline:  fpc_disum_tool (capture, 128x88 raw)
#          -> fpc_recon_native --cleanroom (clean-room BEP -> 64x176 ridge)
#          -> fpc_match_tool (correlation matcher, 0..1000)
#
# Usage:
#   sudo ./live_enroll_verify.sh [ENROL=5] [VERIFY=3]
#
# Phase 1 (enrol):  press the SAME finger ENROL times when prompted.
# Phase 2 (verify): press that same finger (genuine) and/or a DIFFERENT
#                   finger (impostor) VERIFY times.  Each verify press is
#                   scored against the enrol gallery; ACCEPT/REJECT is
#                   printed at the default threshold (550).
#
# Requires:  - root (libusb claims the sensor)
#            - ~/native/fpc_recon_native and ~/matcher/fpc_match_tool built
#            - a copy of the vendor fpc_enclave.dll for enclave bootstrap
#              (the --cleanroom flag only replaces the image op; setup/init
#               still run in the vendor DLL — see MATCHING.md).
set -u

# Resolve the real home: under `sudo` $HOME is /root, but our toolchain and the
# DLL live in the *invoking* user's home.  Prefer SUDO_USER's home when present.
if [ -n "${SUDO_USER:-}" ] && [ "${SUDO_USER}" != "root" ]; then
  RHOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
  [ -z "$RHOME" ] && RHOME="$HOME"
else
  RHOME="$HOME"
fi

ENROL=${1:-5}
VERIFY=${2:-3}

# Locate the vendor DLL used only to bootstrap the enclave (DllMain + init).
DLL_CANDIDATES=(
  "$RHOME/fp/FingerPrint_Carewe_20.26.23.27_W11x64/12b431fd-7d7e-4dd7-b87c-9ab3f9a3d01b/x64/fpc_enclave.dll"
  "$RHOME/FingerPrint_Carewe_20.26.23.27_W11x64/12b431fd-7d7e-4dd7-b87c-9ab3f9a3d01b/x64/fpc_enclave.dll"
  "$RHOME/fpc-rehost/fpc_enclave.dll"
)
DLL=""
for d in "${DLL_CANDIDATES[@]}"; do
  [ -f "$d" ] && DLL="$d" && break
done
if [ -z "$DLL" ]; then
  echo "[-] fpc_enclave.dll not found for enclave bootstrap (searched under $RHOME)" >&2; exit 1
fi

RECON="$RHOME/native/fpc_recon_native"
MATCH="$RHOME/matcher/fpc_match_tool"
CAP="$RHOME/fpc-port/linux-driver/fpc_disum_tool"
THRESH=550

WORK="$(mktemp -d)/fpc_live_$$"
mkdir -p "$WORK/enrol" "$WORK/verify"
trap 'echo "[*] work dir: $WORK"' EXIT

reconstruct() {  # $1=rawfile  -> writes ${1%.raw}.ridge.raw
  "$RECON" "$1" "${1%.raw}.ridge.raw" --cleanroom --dll "$DLL" >/dev/null 2>&1 \
    && [ -s "${1%.raw}.ridge.raw" ]
}

echo "=== Phase 1: ENROL ==="
echo ">>> Press the SAME finger $ENROL time(s). Ctrl+C to abort. <<<"
cd "$WORK/enrol"
"$CAP" "$ENROL" || { echo "[-] capture failed"; exit 1; }
n=0
for f in acer_fingerprint_*.raw; do reconstruct "$f" && n=$((n+1)); done
echo "[+] enrolled $n ridge images"
if [ "$n" -lt 2 ]; then echo "[-] need >=2 enrol frames"; exit 1; fi

echo
echo "=== Phase 2: VERIFY ==="
echo ">>> Press a finger $VERIFY time(s) (same finger = expect ACCEPT, different = REJECT). <<<"
cd "$WORK/verify"
"$CAP" "$VERIFY" || { echo "[-] capture failed"; exit 1; }
v=0
for f in acer_fingerprint_*.raw; do
  reconstruct "$f" || { echo "[-] recon failed for $f"; continue; }
  ridge="${f%.raw}.ridge.raw"
  best=0; bestf=""
  for e in "$WORK/enrol"/*.ridge.raw; do
    s=$("$MATCH" "$ridge" "$e" | sed -n 's/.*score=\([0-9]*\).*/\1/p')
    s=${s:-0}
    if [ "$s" -gt "$best" ]; then best=$s; bestf=$(basename "$e"); fi
  done
  v=$((v+1))
  if [ "$best" -ge "$THRESH" ]; then
    echo "  verify #$v: score=$best (vs $bestf)  => ACCEPT"
  else
    echo "  verify #$v: score=$best (vs $bestf)  => REJECT"
  fi
done
echo "[*] done.  Genuine same-finger scores are typically 600-900; impostors <=500."
