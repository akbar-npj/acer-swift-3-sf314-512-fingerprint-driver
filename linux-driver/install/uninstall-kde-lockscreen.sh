#!/bin/bash
#
# uninstall-kde-lockscreen.sh
#
# Remove the KDE lock-screen auto-unlock patch: restore the upstream QML and
# delete all deploy artifacts (pacman hook, systemd service, restore script,
# canonical/backup directory). The reverse of the §5.5 install.
#
# After running, the lock screen reverts to upstream behaviour (the explicit
# "Unlock" button after a fingerprint scan). Re-apply any time with
# patch-lockscreen.py + the deploy steps in CROSS_DISTRO_BUILD_GUIDE.md §5.5.
#
# Safe to run even if parts are already gone.

set -u

LOCKSCREEN_DIR="/usr/share/plasma/shells/org.kde.plasma.desktop/contents/lockscreen"
NAMES="LockScreenUi.qml MainBlock.qml"
CANON_DIR="/usr/local/share/kde-lockscreen"
HOOK="/etc/pacman.d/hooks/99-kde-lockscreen.hook"
SERVICE="/etc/systemd/system/kde-lockscreen-restore.service"
RESTORE="/usr/local/sbin/restore-kde-lockscreen.sh"

log() {
    logger -t kde-lockscreen -- "$*"
    echo "kde-lockscreen: $*" >&2
}

# 1) Restore the upstream QML for each patched file if we have the backup.
for name in $NAMES; do
    TARGET="$LOCKSCREEN_DIR/$name"
    ORIG="$CANON_DIR/$name.orig"
    if [ -f "$ORIG" ]; then
        install -m644 "$ORIG" "$TARGET"
        log "restored upstream $name from $ORIG"
    elif [ -e "$TARGET" ]; then
        log "no upstream backup ($ORIG); leaving $TARGET as-is -- reinstall plasma-desktop to restore"
    fi
done

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
