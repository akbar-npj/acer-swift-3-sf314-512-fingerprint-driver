#!/bin/bash
#
# uninstall-kde-lockscreen.sh
#
# Remove the KDE lock-screen auto-unlock patch: restore the upstream QML and
# delete all deploy artifacts (pacman hook, systemd service, restore script,
# canonical/backup directory). The reverse of the §4.9 install.
#
# After running, the lock screen reverts to upstream behaviour (the explicit
# "Unlock" button after a fingerprint scan). Re-apply any time with
# patch-lockscreen.py + the deploy steps in RE_AND_BUILD_GUIDE.md §4.9.
#
# Safe to run even if parts are already gone.

set -u

TARGET="/usr/share/plasma/shells/org.kde.plasma.desktop/contents/lockscreen/LockScreenUi.qml"
ORIG="/usr/local/share/kde-lockscreen/LockScreenUi.qml.orig"
CANON_DIR="/usr/local/share/kde-lockscreen"
HOOK="/etc/pacman.d/hooks/99-kde-lockscreen.hook"
SERVICE="/etc/systemd/system/kde-lockscreen-restore.service"
RESTORE="/usr/local/sbin/restore-kde-lockscreen.sh"

log() {
    logger -t kde-lockscreen -- "$*"
    echo "kde-lockscreen: $*" >&2
}

# 1) Restore the upstream QML if we have the backup.
if [ -f "$ORIG" ]; then
    install -m644 "$ORIG" "$TARGET"
    log "restored upstream lock-screen QML from $ORIG"
elif [ -e "$TARGET" ]; then
    log "no upstream backup ($ORIG); leaving $TARGET as-is -- reinstall plasma-desktop to restore"
fi

# 2) Disable and remove the systemd service.
if [ -e "$SERVICE" ]; then
    systemctl disable --now kde-lockscreen-restore.service 2>/dev/null || true
    rm -f "$SERVICE"
    log "removed systemd service"
fi

# 3) Remove the pacman hook and the restore script.
rm -f "$HOOK" "$RESTORE"
log "removed pacman hook and restore script"

# 4) Remove the canonical/backup directory (the patch is gone).
rm -rf "$CANON_DIR"
log "removed canonical patch dir $CANON_DIR"

log "lock-screen patch uninstalled; change applies on next lock (no reboot needed)"
exit 0
