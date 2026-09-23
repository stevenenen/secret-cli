# Host plugin: Claude Code.
#
# A host plugin provides four functions. Supporting another agent means adding
# a sibling file, not touching anything else.
# shellcheck shell=bash

CC_DIR="${CLAUDE_CONFIG_DIR:-$HOME/.claude}"
CC_SETTINGS="$CC_DIR/settings.json"
CC_HOOK="$SECRET_CLI_ROOT/hooks/secret-guard.sh"
CC_MATCHER="Bash|Read|Edit|Write|NotebookEdit|Grep|Glob"

_cc_validate() {
  [ -f "$CC_SETTINGS" ] || return 0
  python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$CC_SETTINGS" 2>/dev/null ||
    die "$CC_SETTINGS is not valid JSON — fix it first, nothing was changed"
}

_cc_installed() {
  [ -f "$CC_SETTINGS" ] || return 1
  python3 - "$CC_SETTINGS" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    raise SystemExit(1)
found = any("secret-guard" in h.get("command", "")
            for e in d.get("hooks", {}).get("PreToolUse", [])
            for h in e.get("hooks", []))
raise SystemExit(0 if found else 1)
PY
}

host_describe_install() {
  _cc_validate
  info "Claude Code"
  info ""
  if _cc_installed; then
    info "  status  already installed"
  else
    info "  status  not installed"
  fi
  info "  file    $CC_SETTINGS"
  info "  add     a PreToolUse hook running $CC_HOOK"
  info "  on      $CC_MATCHER"
  info ""
  info "  It denies any call that would read a credential out of band — the"
  info "  keychain, a dotenv file, an ssh private key, aws or kube config."
  info "  Existing hooks and settings are kept; the file is backed up first."
  info ""
  info "  Reverse it with: secret init claude-code --uninstall"
}

host_describe_uninstall() {
  _cc_validate
  info "Claude Code"
  info ""
  info "  file    $CC_SETTINGS"
  info "  remove  the PreToolUse hook running $CC_HOOK"
  info ""
  info "  Every other hook and setting is left alone."
}

_cc_backup() {
  [ -f "$CC_SETTINGS" ] || return 0
  cp "$CC_SETTINGS" "$CC_SETTINGS.bak.$(date +%Y%m%d%H%M%S)"
}

_cc_edit() {
  mkdir -p "$CC_DIR"
  [ -f "$CC_SETTINGS" ] || printf '{}\n' > "$CC_SETTINGS"
  python3 - "$CC_SETTINGS" "$CC_HOOK" "$CC_MATCHER" "$1" <<'PY'
import json, sys

settings_path, hook, matcher, action = sys.argv[1:5]

with open(settings_path) as fh:
    settings = json.load(fh)

hooks = settings.setdefault("hooks", {})
entries = hooks.setdefault("PreToolUse", [])

def is_ours(entry):
    return any("secret-guard" in h.get("command", "") for h in entry.get("hooks", []))

entries[:] = [e for e in entries if not is_ours(e)]

if action == "install":
    entries.append({
        "matcher": matcher,
        "hooks": [{
            "type": "command",
            "command": hook,
            "statusMessage": "Checking for out-of-band credential access",
        }],
    })

if not entries:
    hooks.pop("PreToolUse", None)
if not hooks:
    settings.pop("hooks", None)

with open(settings_path, "w") as fh:
    json.dump(settings, fh, indent=2)
    fh.write("\n")
PY
}

host_install() {
  _cc_validate
  _cc_backup
  _cc_edit install
  info ""
  info "Installed. Start a new Claude Code session for it to take effect."
}

host_uninstall() {
  _cc_validate
  _cc_backup
  _cc_edit uninstall
  info ""
  info "Removed."
}
