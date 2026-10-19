#!/bin/bash
#
# restore-fpc2040-libfprint.sh
#
# Re-inject the FPC2040 custom libfprint build after a package upgrade
# clobbers it. Invoked automatically by the pacman PostTransaction hook
# (99-fpc2040-libfprint.hook) on every `pacman -Syu` / `-S` / `-U` that
# touches the `libfprint` package, and also as a oneshot systemd unit at
# boot (fpc2040-libfprint-restore.service) as a belt-and-suspenders guard.
#
# Design notes:
#   * The canonical custom build lives in a pacman-untouched location
#     (/usr/local/lib/fpc2040) so this script never depends on a build
#     tree or a possibly-unmounted home directory.
#   * We restore through the soname symlink (libfprint-2.so.2), not a
#     hardcoded filename, so a minor version bump (...2.0.0 -> ...2.0.1)
#     is handled without editing this file.
#   * If the soname symlink is gone (a major ABI bump, e.g. libfprint-3),
#     we REFUSE to clobber the new library and log that a rebuild is
#     required instead of silently breaking the system.
#   * Idempotent: if the installed file is already our build, it exits
#     without touching anything, so running it by hand is always safe.

set -u

CANON_DIR="/usr/local/lib/fpc2040"
CANON="$CANON_DIR/libfprint-2.so.2.0.0"
LINK="/usr/lib/libfprint-2.so.2"

log() {
    logger -t fpc2040-libfprint -- "$*"
    echo "fpc2040-libfprint: $*" >&2
}

# 1. Canonical build present?
if [ ! -f "$CANON" ]; then
    log "canonical custom build missing at $CANON; not restoring (deploy it first)"
    exit 0
fi

# 2. Soname still present? (absence => major ABI bump => needs rebuild)
if [ ! -e "$LINK" ]; then
    log "libfprint-2 soname symlink missing (major ABI bump?). NOT clobbering; rebuild required."
    exit 0
fi

REAL="$(readlink -f "$LINK")"

# 3. Already our build? Nothing to do.
if cmp -s "$CANON" "$REAL" 2>/dev/null; then
    log "custom libfprint already in place ($REAL); no action"
    exit 0
fi

# 4. Distro overwrote us (or first deploy) — back up the current file and restore.
BACK="${REAL}.distro.$(date +%s)"
if cp -a "$REAL" "$BACK" 2>/dev/null; then
    log "backed up current libfprint -> $BACK"
else
    log "warn: could not back up $REAL (continuing)"
fi

install -m755 "$CANON" "$REAL" || { log "FAILED to install $CANON -> $REAL"; exit 1; }
ldconfig 2>/dev/null

CANON_VER="$(basename "$CANON")"
log "restored custom libfprint ($CANON_VER) -> $REAL"
exit 0
