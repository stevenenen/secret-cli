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

@test "a rule with its own advice says what to do instead" {
  feed '{"tool_name":"Bash","tool_input":{"command":"docker inspect web"}}'
  assert_output_contains "anchored sed"
  assert_output_contains "cmd.container-env"
}

# --- detection after the fact (PostToolUse) ---------------------------------

# A PostToolUse payload for a Bash call whose stdout is $2.
post_bash() {
  python3 -c 'import json,sys
print(json.dumps({"hook_event_name":"PostToolUse","tool_name":"Bash",
  "tool_input":{"command":sys.argv[1]},
  "tool_response":{"stdout":sys.argv[2],"stderr":"","interrupted":False,"isImage":False}}))' "$1" "$2"
}

field() {
  printf '%s' "$1" | python3 -c 'import json,sys
d=json.load(sys.stdin)
for k in sys.argv[1].split("."): d=d.get(k,{}) if isinstance(d,dict) else {}
print(json.dumps(d) if not isinstance(d,str) else d)' "$2"
}

@test "a credential in a tool's output is reported to the user" {
  feed "$(post_bash 'docker logs web' 'key AKIAIOSFODNN7EXAMPLE here')"
  assert_equal "$status" "0"
  run field "$output" systemMessage
  assert_output_contains "aws-access-key-id"
  assert_output_contains "rotate"
  assert_output_contains "docker logs web"
}

@test "the report never repeats the credential" {
  feed "$(post_bash 'docker logs web' 'key AKIAIOSFODNN7EXAMPLE here')"
  refute_output_contains "AKIAIOSFODNN7EXAMPLE"
}

@test "the agent sees the output with the credential redacted, in the same shape" {
  feed "$(post_bash 'docker logs web' 'key AKIAIOSFODNN7EXAMPLE here')"
  run field "$output" hookSpecificOutput.updatedToolOutput
  assert_output_contains "redacted:aws-access-key-id"
  assert_output_contains '"stderr"'
  assert_output_contains '"interrupted"'
}

@test "the agent is told what happened" {
  feed "$(post_bash 'docker logs web' 'key AKIAIOSFODNN7EXAMPLE here')"
  run field "$output" hookSpecificOutput.additionalContext
  assert_output_contains "rotated"
}

@test "a credential in a file the agent read is caught too" {
  feed '{"hook_event_name":"PostToolUse","tool_name":"Read","tool_input":{"file_path":"/repo/notes.md"},"tool_response":{"type":"text","file":{"filePath":"/repo/notes.md","content":"sk-ant-api03-0123456789abcdefghijklmnopqrstuvwxyz"}}}'
  assert_output_contains "anthropic-api-key"
  assert_output_contains "/repo/notes.md"
  refute_output_contains "0123456789abcdefghijklmnopqrstuvwxyz"
}

@test "a credential in the command itself is not repeated in the report" {
  feed "$(post_bash 'echo AKIAIOSFODNN7EXAMPLE' 'AKIAIOSFODNN7EXAMPLE')"
  refute_output_contains "AKIAIOSFODNN7EXAMPLE"
}

@test "clean output produces nothing" {
  feed "$(post_bash 'ls' 'README.md')"
  assert_equal "$output" ""
  [ ! -s "$SECRET_CLI_HOME/audit.jsonl" ]
}

@test "a leak is recorded in the audit log by shape, without the value" {
  feed "$(post_bash 'docker logs web' 'key AKIAIOSFODNN7EXAMPLE here')"
  run cat "$SECRET_CLI_HOME/audit.jsonl"
  assert_output_contains "leak.aws-access-key-id"
  refute_output_contains "AKIAIOSFODNN7EXAMPLE"
}

@test "warn mode reports a leak but leaves the output as it was" {
  SECRET_CLI_GUARD_MODE=warn feed "$(post_bash 'docker logs web' 'key AKIAIOSFODNN7EXAMPLE here')"
  assert_output_contains "systemMessage"
  refute_output_contains "updatedToolOutput"
}

@test "off mode does not look at output" {
  SECRET_CLI_GUARD_MODE=off feed "$(post_bash 'docker logs web' 'key AKIAIOSFODNN7EXAMPLE here')"
  assert_equal "$output" ""
}
