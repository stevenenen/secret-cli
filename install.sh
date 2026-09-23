#!/usr/bin/env bash
# Puts `secret` on your PATH. Touches no agent config — that is `secret init`.
set -euo pipefail

ROOT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="${SECRET_CLI_BINDIR:-$HOME/.local/bin}"

command -v python3 >/dev/null || { echo "secret needs python3"; exit 1; }
[ "$(uname -s)" = "Darwin" ] || echo "warning: the Keychain backend needs macOS"

mkdir -p "$BIN"
ln -sf "$ROOT/bin/secret" "$BIN/secret"
echo "linked $BIN/secret -> $ROOT/bin/secret"

case ":$PATH:" in
  *":$BIN:"*) ;;
  *) echo; echo "add this to your shell profile:"; echo "  export PATH=\"$BIN:\$PATH\"" ;;
esac

echo
echo "next: secret init      (installs the guard hook, after showing you what changes)"
