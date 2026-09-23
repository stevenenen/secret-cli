#!/usr/bin/env bash
# PreToolUse hook entry point. Keeps the shell wrapper trivial so the logic
# stays in one testable place.
set -uo pipefail
_self="${BASH_SOURCE[0]}"
while [ -L "$_self" ]; do
  _dir="$(cd -P "$(dirname "$_self")" && pwd)"
  _self="$(readlink "$_self")"
  case "$_self" in /*) ;; *) _self="$_dir/$_self" ;; esac
done
ROOT="$(cd -P "$(dirname "$_self")/.." && pwd)"
exec python3 "$ROOT/lib/guard.py"
