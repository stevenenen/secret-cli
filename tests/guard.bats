#!/usr/bin/env bats
# Behavior: the PreToolUse guard that stops an agent reading a credential
# out of band — straight from the keychain, or straight off disk.
#
# The guard is exercised the way the host exercises it: a hook payload on
# stdin, a decision on stdout. The corpora in tests/fixtures are the spec.

load test_helper

GUARD() { echo "$SECRET_CLI_ROOT/hooks/secret-guard.sh"; }

setup() { setup_isolated_env; }
teardown() { teardown_isolated_env; }

# Feed one fixture line to the guard; sets $output and $status.
feed() {
  run bash -c "printf '%s' '$(printf '%s' "$1" | sed "s/'/'\\\\''/g")' | \"$(GUARD)\""
}

decision() {
  printf '%s' "$1" | python3 -c 'import json,sys
try: d=json.load(sys.stdin)
except Exception: print("none"); raise SystemExit
print(d.get("hookSpecificOutput",{}).get("permissionDecision","none"))' 2>/dev/null
}

@test "every deny fixture is denied" {
  local failures=0
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    local desc; desc=$(printf '%s' "$line" | python3 -c 'import json,sys;print(json.load(sys.stdin)["desc"])')
    feed "$line"
    if [ "$(decision "$output")" != "deny" ]; then
      printf 'NOT DENIED: %s\n' "$desc" >&2
      failures=$((failures + 1))
    fi
  done < "$SECRET_CLI_ROOT/tests/fixtures/guard-deny.jsonl"
  [ "$failures" -eq 0 ]
}

@test "every allow fixture is left alone" {
  local failures=0
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    local desc; desc=$(printf '%s' "$line" | python3 -c 'import json,sys;print(json.load(sys.stdin)["desc"])')
    feed "$line"
    if [ "$(decision "$output")" = "deny" ]; then
      printf 'FALSE POSITIVE: %s\n' "$desc" >&2
      failures=$((failures + 1))
    fi
  done < "$SECRET_CLI_ROOT/tests/fixtures/guard-allow.jsonl"
  [ "$failures" -eq 0 ]
}

@test "known gaps are still gaps, and are listed in the readme" {
  # If one of these starts being caught, delete it from the fixture and from
  # the readme's Limits section — do not silently leave a stale claim.
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    feed "$line"
    [ "$(decision "$output")" != "deny" ] || {
      printf 'now caught, update the fixture and the readme: %s\n' "$line" >&2
      return 1
    }
  done < "$SECRET_CLI_ROOT/tests/fixtures/guard-known-gaps.jsonl"
  grep -q "Known gaps" "$SECRET_CLI_ROOT/README.md"
}

# --- decision shape ---------------------------------------------------------

@test "a denial explains itself without naming a value" {
  feed '{"tool_name":"Bash","tool_input":{"command":"security find-generic-password -w -s secret-cli.TOKEN"}}'
  assert_output_contains "permissionDecisionReason"
  assert_output_contains "secret run"
}

@test "an allowed call produces no decision at all" {
  feed '{"tool_name":"Bash","tool_input":{"command":"ls -la"}}'
  assert_equal "$(decision "$output")" "none"
  assert_equal "$status" "0"
}

@test "the guard exits zero even when it denies" {
  feed '{"tool_name":"Bash","tool_input":{"command":"cat .env"}}'
  assert_equal "$status" "0"
}

# --- modes ------------------------------------------------------------------

@test "warn mode allows the call but says something" {
  SECRET_CLI_GUARD_MODE=warn feed '{"tool_name":"Bash","tool_input":{"command":"cat .env"}}'
  assert_equal "$(decision "$output")" "none"
}

@test "off mode is silent" {
  SECRET_CLI_GUARD_MODE=off feed '{"tool_name":"Bash","tool_input":{"command":"cat .env"}}'
  assert_equal "$output" ""
}

@test "an unrecognized mode falls back to enforcing" {
  SECRET_CLI_GUARD_MODE=banana feed '{"tool_name":"Bash","tool_input":{"command":"cat .env"}}'
  assert_equal "$(decision "$output")" "deny"
}

# --- robustness -------------------------------------------------------------

@test "malformed input does not wedge the session" {
  run bash -c "printf 'not json at all' | \"$(GUARD)\""
  assert_equal "$status" "0"
}

@test "empty input does not wedge the session" {
  run bash -c "printf '' | \"$(GUARD)\""
  assert_equal "$status" "0"
}

@test "an unknown tool name is left alone" {
  feed '{"tool_name":"SomeFutureTool","tool_input":{"whatever":"cat .env"}}'
  assert_equal "$(decision "$output")" "none"
}

@test "a missing tool_input is left alone" {
  feed '{"tool_name":"Bash"}'
  assert_equal "$status" "0"
}

# --- audit log --------------------------------------------------------------

@test "a denial is recorded in the audit log" {
  feed '{"tool_name":"Bash","tool_input":{"command":"cat .env"}}'
  run cat "$SECRET_CLI_HOME/audit.jsonl"
  assert_output_contains "deny"
}

@test "an allowed call is not recorded" {
  feed '{"tool_name":"Bash","tool_input":{"command":"ls -la"}}'
  [ ! -s "$SECRET_CLI_HOME/audit.jsonl" ]
}

@test "the audit log never contains a secret value" {
  put_secret TOKEN "s3cr3t-value-abcdef"
  feed '{"tool_name":"Bash","tool_input":{"command":"security find-generic-password -w -s secret-cli.TOKEN"}}'
  run cat "$SECRET_CLI_HOME/audit.jsonl"
  refute_output_contains "s3cr3t-value-abcdef"
}
