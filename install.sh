#!/usr/bin/env bash
# Puts `secret` on your PATH. Touches no agent config — that is `secret init`.
set -euo pipefail

ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="${SECRET_CLI_BINDIR:-$HOME/.local/bin}"

command -v python3 >/dev/null || { echo "secret needs python3"; exit 1; }
[ "$(uname -s)" = "Darwin" ] || echo "warning: the Keychain backend needs macOS"

# A window that macOS excludes from screen capture needs a real app, so build
# the Swift helper when we can. Without it `secret show` falls back to a plain
# dialog, which works but can be screenshotted.
if [ -n "${SECRET_CLI_SKIP_DIALOG:-}" ]; then
  echo "skipping the protected dialog (SECRET_CLI_SKIP_DIALOG set)"
elif command -v swiftc >/dev/null 2>&1; then
  mkdir -p "$ROOT/libexec"
  if swiftc -O -o "$ROOT/libexec/secret-dialog" "$ROOT/helper/SecretDialog.swift" 2>/dev/null \
     && "$ROOT/libexec/secret-dialog" --self-test >/dev/null 2>&1; then
    echo "built  $ROOT/libexec/secret-dialog  (secret show is not capturable)"
  else
    rm -f "$ROOT/libexec/secret-dialog"
    echo "warning: could not build the protected dialog — secret show will use a plain, screenshottable one"
  fi
else
  echo "note: no swiftc, so secret show will use a plain dialog that can be screenshotted."
  echo "      install Xcode Command Line Tools (xcode-select --install) and re-run to get the protected one."
fi

mkdir -p "$BIN"
ln -sf "$ROOT/bin/secret" "$BIN/secret"
echo "linked $BIN/secret -> $ROOT/bin/secret"

case ":$PATH:" in
  *":$BIN:"*) ;;
  *) echo; echo "add this to your shell profile:"; echo "  export PATH=\"$BIN:\$PATH\"" ;;
esac

echo
echo "next: secret init      (installs the guard hook, after showing you what changes)"
