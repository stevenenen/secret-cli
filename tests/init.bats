#!/usr/bin/env bats
# Behavior: installing the guard into a host agent's config, with consent.
#
# The only host implemented today is Claude Code. Everything here is written
# against the generic contract, so a second host is a new file in hosts/ and
# a copy of this spec, not a rewrite.

load test_helper

setup() {
  setup_isolated_env
  export CLAUDE_CONFIG_DIR="$TEST_TMP/dot-claude"
  mkdir -p "$CLAUDE_CONFIG_DIR"
  SETTINGS="$CLAUDE_CONFIG_DIR/settings.json"
}
teardown() { teardown_isolated_env; }

# A settings file that already has hooks from some other tool.
existing_settings() {
  cat > "$SETTINGS" <<'JSON'
{
  "model": "opus",
  "hooks": {
    "PreToolUse": [
      { "matcher": "*", "hooks": [ { "type": "command", "command": "/opt/other-tool/hook.sh" } ] }
    ],
    "Stop": [
      { "matcher": "*", "hooks": [ { "type": "command", "command": "/opt/other-tool/stop.sh" } ] }
    ]
  }
}
JSON
}

hook_count() {
  python3 -c '
import json,sys
d=json.load(open(sys.argv[1]))
n=0
for entry in d.get("hooks",{}).get("PreToolUse",[]):
    for h in entry.get("hooks",[]):
        if "secret-guard" in h.get("command",""): n+=1
print(n)' "$SETTINGS"
}

# --- discovery --------------------------------------------------------------

@test "init lists the hosts it knows how to configure" {
  run secret init --list-hosts
  assert_success
  assert_output_contains "claude-code"
}

@test "init rejects a host it does not support" {
  run secret init not-a-real-agent --yes
  assert_failure
  assert_output_contains "not-a-real-agent"
}

# --- consent ----------------------------------------------------------------

@test "init describes what it will change before touching anything" {
  existing_settings
  run secret init claude-code --dry-run
  assert_success
  assert_output_contains "settings.json"
  assert_equal "$(hook_count)" "0"
}

@test "init asks before writing and does nothing when refused" {
  existing_settings
  run bash -c 'printf "n\n" | secret init claude-code'
  assert_equal "$(hook_count)" "0"
}

@test "init proceeds when the answer is yes" {
  existing_settings
  run bash -c 'printf "y\n" | secret init claude-code'
  assert_success
  assert_equal "$(hook_count)" "1"
}

@test "init needs no answer when given --yes" {
  existing_settings
  run secret init claude-code --yes
  assert_success
  assert_equal "$(hook_count)" "1"
}

# --- merging ----------------------------------------------------------------

@test "init keeps hooks that another tool already installed" {
  existing_settings
  secret init claude-code --yes
  run grep -c "other-tool/hook.sh" "$SETTINGS"
  assert_equal "$output" "1"
  run grep -c "other-tool/stop.sh" "$SETTINGS"
  assert_equal "$output" "1"
}

@test "init keeps unrelated settings" {
  existing_settings
  secret init claude-code --yes
  run python3 -c 'import json;print(json.load(open("'"$SETTINGS"'"))["model"])'
  assert_equal "$output" "opus"
}

@test "init backs the settings file up before changing it" {
  existing_settings
  secret init claude-code --yes
  run bash -c 'ls "$CLAUDE_CONFIG_DIR"/settings.json.bak* | wc -l | tr -d " "'
  assert_equal "$output" "1"
}

@test "the backup holds the settings as they were" {
  existing_settings
  secret init claude-code --yes
  run bash -c 'cat "$CLAUDE_CONFIG_DIR"/settings.json.bak*'
  refute_output_contains "secret-guard"
}

@test "init twice leaves exactly one guard hook" {
  existing_settings
  secret init claude-code --yes
  secret init claude-code --yes
  assert_equal "$(hook_count)" "1"
}

@test "init creates a settings file when there is none" {
  run secret init claude-code --yes
  assert_success
  assert_equal "$(hook_count)" "1"
}

@test "init covers the tools that can read a file, not just Bash" {
  run secret init claude-code --yes
  run python3 -c '
import json
d=json.load(open("'"$SETTINGS"'"))
m=[e["matcher"] for e in d["hooks"]["PreToolUse"] if any("secret-guard" in h["command"] for h in e["hooks"])][0]
print(m)'
  assert_output_contains "Bash"
  assert_output_contains "Read"
  assert_output_contains "Grep"
}

# --- refusing to damage anything --------------------------------------------

@test "init refuses a settings file that is not valid json and changes nothing" {
  printf '{ this is not json' > "$SETTINGS"
  run secret init claude-code --yes
  assert_failure
  run cat "$SETTINGS"
  assert_equal "$output" "{ this is not json"
}

# --- uninstall --------------------------------------------------------------

@test "uninstall removes the guard hook" {
  existing_settings
  secret init claude-code --yes
  run secret init claude-code --uninstall --yes
  assert_success
  assert_equal "$(hook_count)" "0"
}

@test "uninstall leaves another tool's hooks alone" {
  existing_settings
  secret init claude-code --yes
  secret init claude-code --uninstall --yes
  run grep -c "other-tool/hook.sh" "$SETTINGS"
  assert_equal "$output" "1"
}

@test "uninstall on a clean settings file succeeds and changes nothing" {
  existing_settings
  run secret init claude-code --uninstall --yes
  assert_success
  assert_equal "$(hook_count)" "0"
}
