#!/usr/bin/env bats
# Behavior: showing a value to the person, never to the terminal.
#
# The value goes to a macOS dialog, which is outside the terminal, so it never
# enters scrollback, a pipe, or an agent's tool output. Tests swap the dialog
# for a capture command through SECRET_CLI_SHOW_CMD, which is the same seam a
# non-macOS backend would use.

load test_helper

setup() {
  setup_isolated_env
  put_secret TOKEN "s3cr3t-value-abcdef"
  export SECRET_CLI_SHOW_CMD="cat > $TEST_TMP/shown"
}
teardown() { teardown_isolated_env; }

@test "show puts the value on the display and nothing on the terminal" {
  run secret show TOKEN
  assert_success
  assert_equal "$output" ""
  assert_equal "$(cat "$TEST_TMP/shown")" "s3cr3t-value-abcdef"
}

@test "show writes nothing to stdout even when stdout is a pipe" {
  run bash -c 'secret show TOKEN | cat'
  assert_equal "$output" ""
}

@test "show never writes the value to stderr" {
  run bash -c 'secret show TOKEN 2>&1 >/dev/null'
  refute_output_contains "s3cr3t-value-abcdef"
}

@test "show tells the display which key it is showing" {
  export SECRET_CLI_SHOW_CMD="sh -c 'cat >/dev/null; printf %s \"\$SECRET_CLI_SHOW_KEY\" > $TEST_TMP/shownkey'"
  secret show TOKEN
  assert_equal "$(cat "$TEST_TMP/shownkey")" "TOKEN"
}

@test "show works for a multi-line value" {
  v=$'-----BEGIN PRIVATE KEY-----\nMIIBVgIBADAN\n-----END PRIVATE KEY-----'
  printf '%s' "$v" | secret set PRIVKEY
  secret show PRIVKEY
  assert_equal "$(cat "$TEST_TMP/shown")" "$v"
}

@test "show works for a value with quotes and backslashes" {
  v='he said "hi" \and\ left'
  printf '%s' "$v" | secret set QUOTED
  secret show QUOTED
  assert_equal "$(cat "$TEST_TMP/shown")" "$v"
}

@test "show works for an adopted key" {
  put_foreign "some.app.service" "alice" "foreign-value-123"
  secret adopt some.app.service --as FOREIGN
  secret show FOREIGN
  assert_equal "$(cat "$TEST_TMP/shown")" "foreign-value-123"
}

@test "show fails on an unknown key and displays nothing" {
  run secret show GHOST
  assert_failure
  assert_output_contains "GHOST"
  [ ! -f "$TEST_TMP/shown" ]
}

# --- the protected window ---------------------------------------------------

@test "the protected dialog self-tests clean" {
  [ -x "$SECRET_CLI_ROOT/libexec/secret-dialog" ] || skip "helper not built"
  run "$SECRET_CLI_ROOT/libexec/secret-dialog" --self-test
  assert_success
  assert_output_contains "ok"
}

@test "show reports which display it will use, without showing anything" {
  unset SECRET_CLI_SHOW_CMD
  run secret show TOKEN --how
  assert_success
  refute_output_contains "s3cr3t-value-abcdef"
  [ ! -f "$TEST_TMP/shown" ]
}

@test "show prefers the protected window when it is built" {
  [ -x "$SECRET_CLI_ROOT/libexec/secret-dialog" ] || skip "helper not built"
  unset SECRET_CLI_SHOW_CMD
  run secret show TOKEN --how
  assert_output_contains "secret-dialog"
  assert_output_contains "accessibility"
}

@test "an explicit display command wins over the built helper" {
  run secret show TOKEN --how
  assert_output_contains "SECRET_CLI_SHOW_CMD"
}

@test "install builds the protected dialog" {
  command -v swiftc >/dev/null 2>&1 || skip "no swiftc"
  rm -f "$SECRET_CLI_ROOT/libexec/secret-dialog"
  SECRET_CLI_BINDIR="$TEST_TMP/bin" "$SECRET_CLI_ROOT/install.sh" >/dev/null
  [ -x "$SECRET_CLI_ROOT/libexec/secret-dialog" ]
}

@test "install succeeds without the protected dialog" {
  run env SECRET_CLI_SKIP_DIALOG=1 SECRET_CLI_BINDIR="$TEST_TMP/bin2" "$SECRET_CLI_ROOT/install.sh"
  assert_success
}

@test "show requires a key" {
  run secret show
  assert_failure
}

@test "show refuses extra arguments rather than guessing" {
  run secret show TOKEN EXTRA
  assert_failure
}
