#!/usr/bin/env bats
# Behavior: the command surface itself.

load test_helper

setup() { setup_isolated_env; }
teardown() { teardown_isolated_env; }

@test "version prints something version-shaped" {
  run secret --version
  assert_success
  [[ "$output" =~ [0-9]+\.[0-9]+\.[0-9]+ ]]
}

@test "help names every subcommand" {
  run secret --help
  assert_success
  for cmd in set update rm list run init; do
    assert_output_contains "$cmd"
  done
}

@test "help is available as a subcommand as well as a flag" {
  run secret help
  assert_success
  assert_output_contains "usage"
  run secret --help
  assert_success
  assert_output_contains "usage"
}

@test "no arguments prints usage and fails" {
  run secret
  assert_failure
  assert_output_contains "usage"
}

@test "an unknown subcommand fails and says so" {
  run secret frobnicate
  assert_failure
  assert_output_contains "frobnicate"
}

@test "usage goes to stderr, not stdout, so it cannot pollute a pipeline" {
  run bash -c 'secret frobnicate 2>/dev/null'
  assert_equal "$output" ""
}

@test "list is machine readable enough to drive a loop" {
  put_secret ALPHA "value-alpha-x"
  put_secret BRAVO "value-bravo-x"
  run bash -c 'secret list | while read -r k; do printf "[%s]" "$k"; done'
  assert_equal "$output" "[ALPHA][BRAVO]"
}

@test "the cli works when the config directory does not exist yet" {
  rm -rf "$SECRET_CLI_HOME"
  run secret list
  assert_success
}

@test "the cli reports a clear error when the keychain is unavailable" {
  export SECRET_CLI_KEYCHAIN="$TEST_TMP/no-such.keychain-db"
  run secret list
  assert_failure
  assert_output_contains "keychain"
}

@test "no subcommand ever writes a value to the terminal" {
  put_secret TOKEN "s3cr3t-value-abcdef"
  for args in "list" "--help" "--version"; do
    run secret $args
    refute_output_contains "s3cr3t-value-abcdef"
  done
}
