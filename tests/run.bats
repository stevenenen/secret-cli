#!/usr/bin/env bats
# Behavior: handing a secret to a child process without letting the value
# reach the caller's terminal — which, for an agent, is its transcript.

load test_helper

setup() {
  setup_isolated_env
  put_secret TOKEN "s3cr3t-value-abcdef"
}
teardown() { teardown_isolated_env; }

# --- injection -------------------------------------------------------------

@test "run puts the value in the child's environment under the key name" {
  run stored_value TOKEN
  assert_equal "$output" "s3cr3t-value-abcdef"
}

@test "run injects several keys at once" {
  put_secret OTHER "second-value-xyz"
  run bash -c 'secret run TOKEN OTHER --no-scrub -- sh -c '"'"'printf "%s|%s" "$TOKEN" "$OTHER"'"'"' 2>/dev/null'
  assert_equal "$output" "s3cr3t-value-abcdef|second-value-xyz"
}

@test "run does not leak the value into the calling shell" {
  secret run TOKEN -- true
  run sh -c 'printf %s "${TOKEN-unset}"'
  assert_equal "$output" "unset"
}

@test "run keeps the value out of its own command line" {
  # A sibling process must not be able to see the value via ps.
  run secret run TOKEN -- sh -c 'ps -ww -o args= -p $$ -p $PPID'
  refute_output_contains "s3cr3t-value-abcdef"
}

# --- scrubbing -------------------------------------------------------------

@test "run redacts the value when the child prints it to stdout" {
  run secret run TOKEN -- sh -c 'echo "auth=$TOKEN"'
  assert_success
  refute_output_contains "s3cr3t-value-abcdef"
  assert_output_contains "TOKEN"
}

@test "run redacts the value when the child prints it to stderr" {
  run secret run TOKEN -- sh -c 'echo "auth=$TOKEN" >&2'
  refute_output_contains "s3cr3t-value-abcdef"
}

@test "run redacts a base64 encoding of the value" {
  run secret run TOKEN -- sh -c 'printf %s "$TOKEN" | base64'
  refute_output_contains "$(printf %s 's3cr3t-value-abcdef' | base64 | tr -d '\n')"
}

@test "run redacts a percent-encoded form of the value" {
  put_secret URLY 'a b/c+d=e'
  run secret run URLY -- sh -c 'echo "q=a%20b%2Fc%2Bd%3De"'
  refute_output_contains "a%20b%2Fc%2Bd%3De"
}

@test "run redacts the value even when it appears many times on one line" {
  run secret run TOKEN -- sh -c 'echo "$TOKEN $TOKEN $TOKEN"'
  refute_output_contains "s3cr3t-value-abcdef"
}

@test "run redacts the value spread over a large stream without truncating output" {
  run secret run TOKEN -- sh -c 'for i in $(seq 1 500); do echo "line $i $TOKEN"; done'
  assert_success
  refute_output_contains "s3cr3t-value-abcdef"
  assert_output_contains "line 500"
}

@test "run leaves unrelated output untouched" {
  run secret run TOKEN -- sh -c 'echo "hello world"; echo "second line"'
  assert_equal "$output" "$(printf 'hello world\nsecond line')"
}

@test "run keeps stdout and stderr separate" {
  run bash -c 'secret run TOKEN -- sh -c "echo OUT; echo ERR >&2" 2>/dev/null'
  assert_equal "$output" "OUT"
}

# --- shape-based scrubbing (secrets that were never stored) -----------------

@test "run redacts an AWS access key id it has never seen" {
  run secret run TOKEN -- sh -c 'echo "key AKIAIOSFODNN7EXAMPLE here"'
  refute_output_contains "AKIAIOSFODNN7EXAMPLE"
}

@test "run redacts an Anthropic-style api key it has never seen" {
  run secret run TOKEN -- sh -c 'echo "sk-ant-api03-0123456789abcdefghijklmnopqrstuvwxyz"'
  refute_output_contains "sk-ant-api03-0123456789abcdefghijklmnopqrstuvwxyz"
}

@test "run redacts a JWT it has never seen" {
  jwt="eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"
  run secret run TOKEN -- sh -c "echo $jwt"
  refute_output_contains "$jwt"
}

@test "run redacts a private key block it has never seen" {
  run secret run TOKEN -- sh -c 'echo "-----BEGIN RSA PRIVATE KEY-----"'
  refute_output_contains "BEGIN RSA PRIVATE KEY"
}

@test "run does not redact ordinary text that merely looks long" {
  run secret run TOKEN -- sh -c 'echo "abcdefghijklmnopqrstuvwxyz0123456789"'
  assert_output_contains "abcdefghijklmnopqrstuvwxyz0123456789"
}

# --- exit status and streams ------------------------------------------------

@test "run propagates the child's zero exit status" {
  run secret run TOKEN -- true
  assert_equal "$status" "0"
}

@test "run propagates a non-zero child exit status" {
  run secret run TOKEN -- sh -c 'exit 42'
  assert_equal "$status" "42"
}

@test "run forwards stdin to the child" {
  run bash -c 'printf "piped-in" | secret run TOKEN -- cat'
  assert_equal "$output" "piped-in"
}

# --- argument handling ------------------------------------------------------

@test "run fails when a key is unknown and never starts the child" {
  run secret run GHOST -- sh -c 'echo should-not-run'
  assert_failure
  refute_output_contains "should-not-run"
}

@test "run fails when one of several keys is unknown" {
  run secret run TOKEN GHOST -- true
  assert_failure
  assert_output_contains "GHOST"
}

@test "run requires a -- separator" {
  run secret run TOKEN echo hi
  assert_failure
  assert_output_contains -- "--"
}

@test "run requires a command after the separator" {
  run secret run TOKEN --
  assert_failure
}

@test "run requires at least one key" {
  run secret run -- true
  assert_failure
}

@test "run reports a command that does not exist" {
  run secret run TOKEN -- definitely-not-a-real-command
  assert_failure
}

@test "no-scrub warns on stderr that output is unfiltered" {
  run bash -c 'secret run TOKEN --no-scrub -- true 2>&1 >/dev/null'
  assert_output_contains "scrub"
}

@test "no-scrub keeps the warning off stdout so pipelines stay clean" {
  run bash -c 'secret run TOKEN --no-scrub -- echo payload 2>/dev/null'
  assert_equal "$output" "payload"
}
