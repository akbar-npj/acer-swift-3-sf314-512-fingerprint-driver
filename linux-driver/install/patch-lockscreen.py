#!/usr/bin/env python3
#
# patch-lockscreen.py
#
# Generate the patched KDE lock-screen QML files that make a *successful*
# authentication auto-unlock (no explicit "Unlock" button) AND make the
# password field submit on Enter/Return (not just on the ">" button).
#
# Two patches, both upstream KDE behaviours we override:
#
#   1. LockScreenUi.qml -- onSucceeded(): upstream shows an explicit "Unlock"
#      button when auth succeeds without a password prompt (commit dc6341bb,
#      Plasma 5.25+, to stop passwordless accounts unlocking silently). That
#      bites fingerprint/face auth, so we make ANY success call Qt.quit().
#
#   2. MainBlock.qml -- the password field's onAccepted() only calls
#      startLogin() when sessionManager.lockScreenUiVisible is true. That
#      property is frequently false on the lock screen, so Enter/Return is
#      silently dropped and you must click the ">" button. We drop the guard so
#      Enter behaves like the button.
#
# The script reads the *installed* upstream QMLs, rewrites both functions,
# and writes the canonical patched files to /usr/local/share/kde-lockscreen/
# (the source of truth used by restore-kde-lockscreen.sh). It is idempotent and
# refuses to clobber if a pattern is no longer found (layout changed -> revisit).
#
# Usage:
#   sudo python3 patch-lockscreen.py
#
# Rollback per file:
#   sudo cp -a /usr/local/share/kde-lockscreen/<File>.orig <installed file>

import re
import shutil
import os
import sys

CANON_DIR = "/usr/local/share/kde-lockscreen"

LOCKSCREEN_DIR = (
    "/usr/share/plasma/shells/org.kde.plasma.desktop/contents/lockscreen"
)

PATCHES = [
    (
        "LockScreenUi.qml",
        re.compile(r"function onSucceeded\(\) \{.*?\n        \}", re.DOTALL),
        "        function onSucceeded() {\n            Qt.quit();\n        }",
    ),
    (
        "MainBlock.qml",
        re.compile(
            r"onAccepted: \{\s*if \(sessionManager\.lockScreenUiVisible\) \{\s*"
            r"sessionManager\.startLogin\(\);\s*\}\s*\}",
            re.DOTALL,
        ),
        "onAccepted: {\n                sessionManager.startLogin();\n            }",
    ),
]


def main():
    any_missing = False
    os.makedirs(CANON_DIR, exist_ok=True)

    for name, pat, new in PATCHES:
        src = os.path.join(LOCKSCREEN_DIR, name)
        with open(src, "r", encoding="utf-8") as fh:
            text = fh.read()

        if not pat.search(text):
            print("PATTERN NOT FOUND in %s -- plasma layout changed, revisit" % name)
            any_missing = True
            continue

        patched = pat.sub(new, text, count=1)

        orig = os.path.join(CANON_DIR, name + ".orig")
        if not os.path.exists(orig):
            shutil.copy(src, orig)

        with open(os.path.join(CANON_DIR, name), "w", encoding="utf-8") as fh:
            fh.write(patched)
        print("wrote canonical patched %s" % name)

    if any_missing:
        sys.exit("one or more patterns not found -- check the upstream QML")

    print("rollback: sudo cp -a %s/<File>.orig %s/<File>" % (CANON_DIR, LOCKSCREEN_DIR))


if __name__ == "__main__":
    main()
