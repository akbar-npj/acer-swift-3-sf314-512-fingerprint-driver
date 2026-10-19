#!/usr/bin/env python3
#
# patch-lockscreen.py
#
# Generate the patched KDE lock-screen QML that makes a *successful*
# authentication auto-unlock (Qt.quit()) instead of showing the explicit
# "Unlock" button for passwordless / fingerprint / face auth.
#
# Upstream behaviour (commit dc6341bb, Plasma 5.25+): kscreenlocker shows an
# explicit button when auth succeeds without a password prompt having been
# shown -- intended to stop passwordless accounts unlocking silently, but it
# also bites fingerprint auth. The fix rewrites onSucceeded() in
# LockScreenUi.qml to always call Qt.quit().
#
# This script reads the *installed* upstream QML, rewrites the function, and
# writes the result to the canonical location used by restore-kde-lockscreen.sh
# (/usr/local/share/kde-lockscreen/LockScreenUi.qml). Run it once after a major
# plasma-desktop version bump (when the QML path/content changes), then let the
# pacman hook keep it applied.
#
# Usage:
#   sudo python3 patch-lockscreen.py [path-to-upstream-LockScreenUi.qml]
#
# It is idempotent against the upstream file and refuses to clobber if the
# onSucceeded() pattern is no longer found (i.e. the QML layout changed and the
# patch needs revisiting).

import re
import shutil
import os
import sys

DEFAULT_SRC = "/usr/share/plasma/shells/org.kde.plasma.desktop/contents/lockscreen/LockScreenUi.qml"
CANON_DIR = "/usr/local/share/kde-lockscreen"
CANON = os.path.join(CANON_DIR, "LockScreenUi.qml")

NEW = "        function onSucceeded() {\n            Qt.quit();\n        }"
PAT = re.compile(r"function onSucceeded\(\) \{.*?\n        \}", re.DOTALL)


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_SRC
    with open(src, "r", encoding="utf-8") as fh:
        text = fh.read()

    if not PAT.search(text):
        sys.exit(
            "PATTERN NOT FOUND in %s -- plasma layout changed, revisit the patch" % src
        )

    patched = PAT.sub(NEW, text, count=1)

    os.makedirs(CANON_DIR, exist_ok=True)
    # Back up the pre-patch upstream file exactly once.
    orig = os.path.join(CANON_DIR, "LockScreenUi.qml.orig")
    if not os.path.exists(orig):
        shutil.copy(src, orig)

    with open(CANON, "w", encoding="utf-8") as fh:
        fh.write(patched)

    print("wrote canonical patched QML -> %s" % CANON)
    print("rollback:  sudo cp -a %s %s" % (orig, src))


if __name__ == "__main__":
    main()
