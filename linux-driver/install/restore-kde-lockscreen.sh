#!/bin/bash
#
# restore-kde-lockscreen.sh
#
# Re-apply the patched KDE lock-screen QML after a `plasma-desktop` package
# upgrade overwrites it. Invoked automatically by the pacman PostTransaction
# hook (99-kde-lockscreen.hook) on every `pacman -Syu` / `-S` / `-U` that
# touches `plasma-desktop`, and also as a oneshot systemd unit at boot
# (kde-lockscreen-restore.service) as a belt-and-suspenders guard.
#
# What the patch does: upstream kscreenlocker shows an explicit "Unlock" button
# whenever authentication succeeds WITHOUT a password prompt having been shown
# (commit dc6341bb, Plasma 5.25+, to stop passwordless accounts silently
# unlocking). Fingerprint/face auth hits that path, so you get the extra click.
# The patched QML makes *any* successful auth call Qt.quit() and auto-unlock;
# failures still go through onFailed -> "Unlocking failed".
#
# Source of truth: the canonical patched file in a pacman-untouched location
# (/usr/local/share/kde-lockscreen). We never depend on a build tree.

set -u

CANON_DIR="/usr/local/share/kde-lockscreen"
LOCKSCREEN_DIR="/usr/share/plasma/shells/org.kde.plasma.desktop/contents/lockscreen"
TARGETS="LockScreenUi.qml MainBlock.qml"
BACKDIR="/usr/local/lib/kde-lockscreen/backups"

log() {
    logger -t kde-lockscreen -- "$*"
    echo "kde-lockscreen: $*" >&2
}

[ -d "$CANON_DIR" ] || { log "canonical dir missing at $CANON_DIR; not restoring"; exit 0; }
mkdir -p "$BACKDIR"

for name in $TARGETS; do
    TARGET="$LOCKSCREEN_DIR/$name"
    CANON="$CANON_DIR/$name"
    [ -e "$TARGET" ] || { log "$name path missing (plasma layout changed?); skipping"; continue; }
    [ -f "$CANON" ] || { log "canonical $name missing; skipping"; continue; }
    if cmp -s "$CANON" "$TARGET" 2>/dev/null; then
        log "$name already patched; no action"
        continue
    fi
    cp -a "$TARGET" "$BACKDIR/$name.distro.$(date +%s)" 2>/dev/null || true
    install -m644 "$CANON" "$TARGET"
    log "restored patched $name -> $TARGET"
done
exit 0
