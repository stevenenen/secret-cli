# Shared helpers. Sourced by bin/secret.
# shellcheck shell=bash

# shellcheck disable=SC2034  # read by bin/secret, which sources this
SECRET_CLI_VERSION="0.1.0"

: "${SECRET_CLI_HOME:=${XDG_CONFIG_HOME:-$HOME/.config}/secret-cli}"
: "${SECRET_CLI_SERVICE_PREFIX:=secret-cli.}"

# Values shorter than this cannot be scrubbed out of a child's output without
# mangling unrelated text, so `run` will not redact them.
# shellcheck disable=SC2034  # read by bin/secret, which sources this
SECRET_CLI_MIN_SCRUB_LEN=6

die() { printf 'secret: %s\n' "$*" >&2; exit 1; }
warn() { printf 'secret: %s\n' "$*" >&2; }
info() { printf '%s\n' "$*"; }

ensure_home() { mkdir -p "$SECRET_CLI_HOME"; }

# A key has to be usable as an environment variable name, because that is
# exactly what `run` turns it into.
valid_key() {
  case "$1" in
    "" ) return 1 ;;
    *[!A-Za-z0-9_]* ) return 1 ;;
    [0-9]* ) return 1 ;;
    * ) return 0 ;;
  esac
}

require_key() {
  valid_key "$1" ||
    die "invalid key name '$1' — use letters, digits and underscores, not starting with a digit"
}

# base64 decode differs between BSD and GNU; settle it once.
_b64_decode_flag() {
  if printf 'aGk=' | base64 --decode >/dev/null 2>&1; then printf -- '--decode'
  else printf -- '-D'; fi
}
B64_DECODE_FLAG="$(_b64_decode_flag)"

b64enc() { base64 | tr -d '\n'; }
b64dec() { tr -d '\n' | base64 "$B64_DECODE_FLAG"; }

# Read a secret value. From a terminal it is prompted for and never echoed;
# from a pipe it is taken verbatim, minus one trailing newline.
read_value() {
  local value
  if [ -t 0 ]; then
    printf 'Value for %s (input hidden, paste then Enter): ' "$1" >&2
    IFS= read -rs value || true
    printf '\n' >&2
  else
    value="$(cat; printf x)"   # printf x guards the command substitution
    value="${value%x}"         # against stripping meaningful newlines
    value="${value%$'\n'}"     # then drop exactly one trailing newline
  fi
  printf '%s' "$value"
}
