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

CANON="/usr/local/share/kde-lockscreen/LockScreenUi.qml"
TARGET="/usr/share/plasma/shells/org.kde.plasma.desktop/contents/lockscreen/LockScreenUi.qml"

log() {
    logger -t kde-lockscreen -- "$*"
    echo "kde-lockscreen: $*" >&2
}

[ -f "$CANON" ] || { log "canonical patched QML missing at $CANON; not restoring"; exit 0; }
[ -e "$TARGET" ] || { log "lock-screen QML path missing (plasma layout changed?); not clobbering"; exit 0; }

if cmp -s "$CANON" "$TARGET" 2>/dev/null; then
    log "patched lock screen already in place; no action"
    exit 0
fi

cp -a "$TARGET" "${TARGET}.distro.$(date +%s)" 2>/dev/null || true
install -m644 "$CANON" "$TARGET"
log "restored patched lock-screen QML -> $TARGET"
exit 0
