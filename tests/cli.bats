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

@test "help names every subcommand and every flag" {
  # Help drifting behind the code is the failure this catches. Anything the
  # tool can do goes in this list at the same time as it goes in the code.
  run secret --help
  assert_success
  for token in set update rm list --all show adopt --as --account \
               run -- --no-scrub init --list-hosts --uninstall help --version; do
    assert_output_contains "$token"
  done
}

@test "every subcommand named in help is actually accepted" {
  for cmd in set update rm list show adopt run init; do
    run secret "$cmd"
    refute_output_contains "unknown command"
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

@test "list finds its index with no SECRET_CLI_HOME in the environment" {
  # A real install has no SECRET_CLI_HOME set, so the config location comes
  # from HOME. The helpers are separate processes; if the path is not exported
  # to them they look in the working directory and list comes back empty.
  local fake="$TEST_TMP/fakehome"
  mkdir -p "$fake"
  env -u SECRET_CLI_HOME -u XDG_CONFIG_HOME "HOME=$fake" \
    bash -c 'printf %s "a-value-here" | secret set HOMED' >/dev/null
  run env -u SECRET_CLI_HOME -u XDG_CONFIG_HOME "HOME=$fake" secret list
  assert_equal "$output" "HOMED"
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
