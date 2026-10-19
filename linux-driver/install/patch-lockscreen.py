#!/usr/bin/env python3
#
# patch-lockscreen.py
#
# Generate the patched KDE lock-screen QML files that make a *successful*
# authentication auto-unlock (no explicit "Unlock" button) AND make the
# password field submit reliably on Enter/Return.
#
# Three patches, all upstream KDE behaviours we override:
#
#   1. LockScreenUi.qml -- onSucceeded(): upstream shows an explicit "Unlock"
#      button when auth succeeds without a password prompt (commit dc6341bb,
#      Plasma 5.25+, to stop passwordless accounts unlocking silently). That
#      bites fingerprint/face auth, so we make ANY success call Qt.quit().
#
#   2. MainBlock.qml (submit) -- the password field's onAccepted() only calls
#      startLogin() when sessionManager.lockScreenUiVisible is true (upstream
#      guard). That property is frequently false on the lock screen, so
#      Enter/Return is silently dropped and you must click the ">" button.
#      We drop the guard. But onAccepted is *also* unreliable for the very
#      first Enter after the field gains focus (a Qt input-method timing
#      issue: the first Return can be swallowed while focus is still
#      settling). So we replace onAccepted with explicit
#      Keys.onReturnPressed / Keys.onEnterPressed handlers, which catch the
#      raw key on the focused item and fire every time -- including the first.
#
#   3. MainBlock.qml (focus) -- make sure the password box actually holds
#      active keyboard focus as soon as the lock UI becomes visible, so the
#      Enter key is delivered to it. We hook onLockScreenUiVisibleChanged and
#      forceActiveFocus() the box. (lockScreenUiVisible is bound to the root
#      MouseArea's uiVisible, which flips true on the first key press / mouse
#      move, i.e. exactly when the user starts interacting.)
#
# The script reads the *installed* upstream QMLs, rewrites the functions, and
# writes the canonical patched files to /usr/local/share/kde-lockscreen/
# (the source of truth used by restore-kde-lockscreen.sh). It is idempotent:
# each sub-patch is skipped if its replacement is already present, and it
# refuses to clobber if an expected pattern is genuinely missing (layout
# changed -> revisit).
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

# Each entry: (filename, [ (pattern, replacement, already_marker), ... ])
# - pattern        : regex matched against the source text. The leading
#                    whitespace of the line being replaced is captured in \1 so
#                    the replacement keeps the original indentation (avoids
#                    doubling indentation when the match's own indent is also
#                    preserved).
# - replacement    : what to substitute in (only the first match). Use \1 for
#                    the captured leading indentation.
# - already_marker : substring that, if present, means this change is already
#                    applied -> skip instead of erroring (idempotency)
PATCHES = [
    (
        "LockScreenUi.qml",
        [
            # Match the WHOLE function (up to the brace at the function's own
            # indentation \1) so the upstream "if (authenticator.hadPrompt)"
            # guard is fully consumed. Marker is a comment we inject, since
            # "Qt.quit();" already exists in upstream inside that guard.
            (
                re.compile(
                    r"(\s*)function onSucceeded\(\) \{(.*?)\n\1\}", re.DOTALL
                ),
                "\\1function onSucceeded() {\n"
                "\\1    // auto-unlock on any success (fingerprint/face/password)\n"
                "\\1    Qt.quit();\n"
                "\\1}",
                "// auto-unlock on any success",
            ),
        ],
    ),
    (
        "MainBlock.qml",
        [
            # (2) Remove the password field's OWN Enter handling. It only fires
            #     when the field holds active focus, and the first Enter after
            #     the lock screen appears is frequently dropped because focus
            #     has not settled yet. Submit is instead handled at the
            #     SessionManagementScreen level (sub 4) which catches
            #     Enter/Return regardless of which child currently has focus.
            #     We replace the whole block (up to its own closing brace \1)
            #     with a comment so the field stays clean.
            (
                re.compile(
                    r"(\s*)onAccepted:\s*\{(.*?)\n\1\}", re.DOTALL
                ),
                "\\1// Enter/Return submit is handled by SessionManagementScreen.Keys.onPressed",
                "Enter/Return submit is handled by SessionManagementScreen",
            ),
            # (2b) Remove the login button's Enter/Return handlers for the same
            #      reason. The button stays mouse-clickable via onClicked. We
            #      replace the two lines with a comment (unique marker) so the
            #      removal is idempotent and does not collide with the
            #      pre-existing Keys.onPressed handler on the password box.
            (
                re.compile(
                    r"(\s*)Keys\.onEnterPressed: clicked\(\)\n\s*"
                    r"Keys\.onReturnPressed: clicked\(\)",
                    re.DOTALL,
                ),
                "\\1// Enter/Return submit is handled at the SessionManagementScreen level",
                "// Enter/Return submit is handled at the SessionManagementScreen level",
            ),
            # (3) Force focus on the password box when the lock UI becomes
            #     visible, so typing lands in the field immediately.
            (
                re.compile(r"\n    function startLogin\(\) \{"),
                "\n    onLockScreenUiVisibleChanged: {\n"
                "        if (lockScreenUiVisible) {\n"
                "            passwordBox.forceActiveFocus();\n"
                "        }\n"
                "    }\n"
                "\n    function startLogin() {",
                "onLockScreenUiVisibleChanged:",
            ),
            # (4) Submit on Enter/Return at the SessionManagementScreen level.
            #     Key events bubble from the focused child (password box OR
            #     button) up to this ancestor, so a single Enter works no
            #     matter where focus is. We accept the event so it does not
            #     also reach the root MouseArea. The marker is the unique Enter
            #     condition so it does not collide with the password box's own
            #     (Left/Right) Keys.onPressed handler already in upstream.
            (
                re.compile(r"(\s*)signal passwordResult\(string password\)"),
                "\\1signal passwordResult(string password)\n"
                "\n"
                "\\1Keys.onPressed: event => {\n"
                "\\1    if (event.key === Qt.Key_Return || event.key === Qt.Key_Enter) {\n"
                "\\1        sessionManager.startLogin();\n"
                "\\1        event.accepted = true;\n"
                "\\1    }\n"
                "\\1}",
                "if (event.key === Qt.Key_Return || event.key === Qt.Key_Enter)",
            ),
        ],
    ),
]


def source_path(name):
    # Prefer the genuine upstream snapshot (.orig) as the basis for the
    # canonical, so regeneration is always deterministic and never builds on a
    # previously-patched file. Fall back to the installed file (e.g. after an
    # uninstall has restored it to upstream).
    orig = os.path.join(CANON_DIR, name + ".orig")
    if os.path.exists(orig):
        return orig
    return os.path.join(LOCKSCREEN_DIR, name)


def patch_file(name, subs):
    src = source_path(name)
    with open(src, "r", encoding="utf-8") as fh:
        text = fh.read()

    missing = False
    for pat, new, marker in subs:
        if marker and marker in text:
            # already applied -> idempotent skip
            continue
        if not pat.search(text):
            print("PATTERN NOT FOUND in %s -- plasma layout changed, revisit" % name)
            missing = True
            continue
        text = pat.sub(new, text, count=1)

    if missing:
        return False

    orig = os.path.join(CANON_DIR, name + ".orig")
    if not os.path.exists(orig):
        shutil.copy(os.path.join(LOCKSCREEN_DIR, name), orig)

    with open(os.path.join(CANON_DIR, name), "w", encoding="utf-8") as fh:
        fh.write(text)
    print("wrote canonical patched %s" % name)
    return True


def main():
    any_missing = False
    os.makedirs(CANON_DIR, exist_ok=True)

    for name, subs in PATCHES:
        if not patch_file(name, subs):
            any_missing = True

    if any_missing:
        sys.exit("one or more patterns not found -- check the upstream QML")

    print("rollback: sudo cp -a %s/<File>.orig %s/<File>" % (CANON_DIR, LOCKSCREEN_DIR))


if __name__ == "__main__":
    main()
