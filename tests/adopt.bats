#!/usr/bin/env bats
# Behavior: seeing keychain items this tool did not create, and bringing one
# under management so `run` can inject it.
#
# The rule that matters: an adopted item still belongs to whatever app created
# it. This tool may read it and forget it. It may not change it or delete it.

load test_helper

setup() {
  setup_isolated_env
  put_foreign "some.app.service" "alice" "foreign-value-123"
}
teardown() { teardown_isolated_env; }

# --- list --all -------------------------------------------------------------

@test "list --all shows an item this tool did not create" {
  run secret list --all
  assert_success
  assert_output_contains "some.app.service"
}

@test "list --all marks what it manages and what it does not" {
  put_secret MINE "managed-value-x"
  run secret list --all
  assert_output_contains "managed"
  assert_output_contains "unmanaged"
}

@test "list --all never prints a value" {
  put_secret MINE "managed-value-x"
  run secret list --all
  refute_output_contains "foreign-value-123"
  refute_output_contains "managed-value-x"
}

@test "list --all is three tab separated columns" {
  run bash -c "secret list --all | head -1 | awk -F'\t' '{print NF}'"
  assert_equal "$output" "3"
}

@test "plain list still prints bare names and nothing foreign" {
  put_secret MINE "managed-value-x"
  run secret list
  assert_equal "$output" "MINE"
}

@test "list --all puts your own keys above everything else" {
  put_secret ZZZ_MINE "managed-value-x"   # sorts last by name, first by state
  run bash -c "secret list --all | head -1 | cut -f1"
  assert_equal "$output" "managed"
}

@test "list --all works on a keychain with nothing of ours in it" {
  run secret list --all
  assert_success
  assert_output_contains "some.app.service"
}

# --- adopt ------------------------------------------------------------------

@test "an adopted item becomes usable by run, with its value intact" {
  secret adopt some.app.service --as FOREIGN
  run stored_value FOREIGN
  assert_equal "$output" "foreign-value-123"
}

@test "an adopted item appears in plain list" {
  secret adopt some.app.service --as FOREIGN
  run secret list
  assert_output_contains "FOREIGN"
}

@test "list --all calls an adopted item adopted, not unmanaged" {
  secret adopt some.app.service --as FOREIGN
  run secret list --all
  assert_output_contains "adopted"
  refute_output_contains "unmanaged"
}

@test "adopt refuses a service name that is not a valid variable name without --as" {
  run secret adopt some.app.service
  assert_failure
  assert_output_contains -- "--as"
}

@test "adopt uses the service name directly when it is already a valid name" {
  put_foreign "PLAIN_NAME" "bob" "another-value-99"
  secret adopt PLAIN_NAME
  run secret list
  assert_output_contains "PLAIN_NAME"
}

@test "adopt refuses an item that is not in the keychain" {
  run secret adopt no.such.service --as GHOST
  assert_failure
  assert_output_contains "no.such.service"
}

@test "adopt refuses to shadow a key this tool already manages" {
  put_secret TAKEN "managed-value-x"
  run secret adopt some.app.service --as TAKEN
  assert_failure
  assert_output_contains "TAKEN"
}

@test "adopting the same thing twice is refused" {
  secret adopt some.app.service --as FOREIGN
  run secret adopt some.app.service --as FOREIGN
  assert_failure
}

@test "adopt picks the right item when a service has several accounts" {
  put_foreign "shared.service" "bob" "bobs-value-1234"
  put_foreign "shared.service" "carol" "carols-value-56"
  secret adopt shared.service --account carol --as CAROL
  run stored_value CAROL
  assert_equal "$output" "carols-value-56"
}

# --- an adopted item is not ours to damage ----------------------------------

@test "rm forgets an adopted key but leaves the keychain item alone" {
  secret adopt some.app.service --as FOREIGN
  run secret rm FOREIGN
  assert_success
  run secret list
  refute_output_contains "FOREIGN"
  # The other app's credential is still there, untouched.
  run security find-generic-password -a alice -s some.app.service -w "$SECRET_CLI_KEYCHAIN"
  assert_equal "$output" "foreign-value-123"
}

@test "update refuses an adopted key rather than writing to another app's item" {
  secret adopt some.app.service --as FOREIGN
  run bash -c 'printf %s "new-value-here" | secret update FOREIGN'
  assert_failure
  assert_output_contains "adopt"
  run security find-generic-password -a alice -s some.app.service -w "$SECRET_CLI_KEYCHAIN"
  assert_equal "$output" "foreign-value-123"
}

@test "set refuses a key name already adopted" {
  secret adopt some.app.service --as FOREIGN
  run bash -c 'printf %s "some-value-xy" | secret set FOREIGN'
  assert_failure
}

@test "an adopted value is scrubbed out of command output like any other" {
  secret adopt some.app.service --as FOREIGN
  run secret run FOREIGN -- sh -c 'echo "token=$FOREIGN"'
  refute_output_contains "foreign-value-123"
}
