# Host plugin: Claude Code.
#
# A host plugin provides four functions. Supporting another agent means adding
# a sibling file, not touching anything else.
# shellcheck shell=bash

CC_DIR="${CLAUDE_CONFIG_DIR:-$HOME/.claude}"
CC_SETTINGS="$CC_DIR/settings.json"
CC_HOOK="$SECRET_CLI_ROOT/hooks/secret-guard.sh"
CC_MATCHER="Bash|Read|Edit|Write|NotebookEdit|Grep|Glob"
# The tools whose output can carry a credential back to the agent.
CC_POST_MATCHER="Bash|Read|Grep|WebFetch|mcp__.*"

_cc_validate() {
  [ -f "$CC_SETTINGS" ] || return 0
  python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$CC_SETTINGS" 2>/dev/null ||
    die "$CC_SETTINGS is not valid JSON — fix it first, nothing was changed"
}

# Prints which of the two hooks are installed: "both", "pre", "post" or "none".
_cc_state() {
  [ -f "$CC_SETTINGS" ] || { echo none; return; }
  python3 - "$CC_SETTINGS" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    print("none")
    raise SystemExit
def has(event):
    return any("secret-guard" in h.get("command", "")
               for e in d.get("hooks", {}).get(event, [])
               for h in e.get("hooks", []))
pre, post = has("PreToolUse"), has("PostToolUse")
print("both" if pre and post else "pre" if pre else "post" if post else "none")
PY
}

host_describe_install() {
  _cc_validate
  info "Claude Code"
  info ""
  case "$(_cc_state)" in
    both) info "  status  already installed" ;;
    none) info "  status  not installed" ;;
    *)    info "  status  partly installed — applying adds the missing hook" ;;
  esac
  info "  file    $CC_SETTINGS"
  info "  add     a PreToolUse hook running $CC_HOOK"
  info "  on      $CC_MATCHER"
  info "  add     a PostToolUse hook running $CC_HOOK"
  info "  on      $CC_POST_MATCHER"
  info ""
  info "  The first denies any call that would read a credential out of band —"
  info "  the keychain, a dotenv file, an ssh private key, aws or kube config,"
  info "  a shell's or a container's environment, a command that prints a token."
  info "  The second redacts a credential that still turns up in a tool's output"
  info "  and tells you, so you can rotate it."
  info "  Existing hooks and settings are kept; the file is backed up first."
  info ""
  info "  Reverse it with: secret init claude-code --uninstall"
}

host_describe_uninstall() {
  _cc_validate
  info "Claude Code"
  info ""
  info "  file    $CC_SETTINGS"
  info "  remove  the PreToolUse and PostToolUse hooks running $CC_HOOK"
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
  python3 - "$CC_SETTINGS" "$CC_HOOK" "$CC_MATCHER" "$CC_POST_MATCHER" "$1" <<'PY'
import json, sys

settings_path, hook, matcher, post_matcher, action = sys.argv[1:6]

with open(settings_path) as fh:
    settings = json.load(fh)

hooks = settings.setdefault("hooks", {})

def is_ours(entry):
    return any("secret-guard" in h.get("command", "") for h in entry.get("hooks", []))

wanted = {
    "PreToolUse": (matcher, "Checking for out-of-band credential access"),
    "PostToolUse": (post_matcher, "Checking the output for credentials"),
}

for event, (event_matcher, status) in wanted.items():
    entries = hooks.setdefault(event, [])
    entries[:] = [e for e in entries if not is_ours(e)]
    if action == "install":
        entries.append({
            "matcher": event_matcher,
            "hooks": [{
                "type": "command",
                "command": hook,
                "statusMessage": status,
            }],
        })
    if not entries:
        hooks.pop(event, None)

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
