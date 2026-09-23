# macOS Keychain backend.
#
# Every other backend only has to provide these six functions, so adding
# libsecret for Linux is a sibling file, not a rewrite.
#
# Two things matter here and are easy to get wrong:
#   * A value is never passed as a command-line argument. `security -i` reads
#     its command line from stdin, so the value stays out of the process table.
#   * A value is stored base64-encoded. Raw multi-line or binary data comes
#     back from `find-generic-password -w` as a hex string with no marker,
#     which is indistinguishable from a secret that happens to be hex.
# shellcheck shell=bash

STORE_ACCOUNT="${SECRET_CLI_ACCOUNT:-$USER}"

_kc_positional() {
  if [ -n "${SECRET_CLI_KEYCHAIN:-}" ]; then printf ' %s' "$SECRET_CLI_KEYCHAIN"; fi
}

_kc_args() {
  if [ -n "${SECRET_CLI_KEYCHAIN:-}" ]; then printf '%s' "$SECRET_CLI_KEYCHAIN"; fi
}

store_name() { printf 'macOS Keychain'; }

store_check() {
  command -v security >/dev/null 2>&1 ||
    die "the 'security' command is missing — this backend needs macOS"
  if [ -n "${SECRET_CLI_KEYCHAIN:-}" ] && [ ! -f "$SECRET_CLI_KEYCHAIN" ]; then
    die "keychain not found: $SECRET_CLI_KEYCHAIN"
  fi
}

_svc() { printf '%s%s' "$SECRET_CLI_SERVICE_PREFIX" "$1"; }

# `security -i` reads one command per line through a 4 KB buffer, so a long
# value is split across numbered items: KEY, KEY#1, KEY#2 ... Reading stops at
# the first gap, which is why an overwrite has to clear the old chain first.
SECRET_CLI_CHUNK=3000

_chunk_svc() {
  if [ "$2" -eq 0 ]; then _svc "$1"; else printf '%s#%s' "$(_svc "$1")" "$2"; fi
}

_raw_get() {
  local kc; kc="$(_kc_args)"
  if [ -n "$kc" ]; then
    security find-generic-password -a "$STORE_ACCOUNT" -s "$1" -w "$kc" 2>/dev/null
  else
    security find-generic-password -a "$STORE_ACCOUNT" -s "$1" -w 2>/dev/null
  fi
}

_raw_del() {
  local kc; kc="$(_kc_args)"
  if [ -n "$kc" ]; then
    security delete-generic-password -a "$STORE_ACCOUNT" -s "$1" "$kc" >/dev/null 2>&1
  else
    security delete-generic-password -a "$STORE_ACCOUNT" -s "$1" >/dev/null 2>&1
  fi
}

_raw_put() {
  local svc="$1" chunk="$2" line
  line="add-generic-password -a \"$STORE_ACCOUNT\" -s \"$svc\""
  line="$line -l \"$svc\" -D \"secret-cli credential\" -U -w \"$chunk\""
  line="$line$(_kc_positional)"
  printf '%s\n' "$line" | security -i >/dev/null 2>&1
}

store_has() {
  local kc; kc="$(_kc_args)"
  if [ -n "$kc" ]; then
    security find-generic-password -a "$STORE_ACCOUNT" -s "$(_svc "$1")" "$kc" >/dev/null 2>&1
  else
    security find-generic-password -a "$STORE_ACCOUNT" -s "$(_svc "$1")" >/dev/null 2>&1
  fi
}

# $1 = key. Raw value on stdin.
store_put() {
  local key="$1" b64 i=0 offset=0
  b64="$(b64enc)"
  store_del "$key"
  while [ "$offset" -lt "${#b64}" ]; do
    _raw_put "$(_chunk_svc "$key" "$i")" "${b64:$offset:$SECRET_CLI_CHUNK}" ||
      die "keychain refused to store '$key'"
    offset=$((offset + SECRET_CLI_CHUNK))
    i=$((i + 1))
  done
}

store_get() {
  local key="$1" i=0 part b64=""
  while :; do
    part="$(_raw_get "$(_chunk_svc "$key" "$i")")" || break
    [ -n "$part" ] || break
    b64="$b64$part"
    i=$((i + 1))
  done
  [ -n "$b64" ] || return 1
  printf '%s' "$b64" | b64dec
}

store_del() {
  local key="$1" i=0
  while _raw_del "$(_chunk_svc "$key" "$i")"; do
    i=$((i + 1))
  done
  return 0
}
