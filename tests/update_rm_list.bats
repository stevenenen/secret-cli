#!/usr/bin/env bats
# Behavior: changing, removing and enumerating secrets.

load test_helper

setup() { setup_isolated_env; }
teardown() { teardown_isolated_env; }

# --- update ----------------------------------------------------------------

@test "update replaces the value of an existing key" {
  put_secret TOKEN "old-value-here"
  printf '%s' "new-value-here" | secret update TOKEN
  run stored_value TOKEN
  assert_equal "$output" "new-value-here"
}

@test "update refuses an unknown key and points at set" {
  run bash -c 'printf %s "some-value" | secret update NOPE'
  assert_failure
  assert_output_contains "set"
}

@test "update never echoes the new value" {
  put_secret TOKEN "old-value-here"
  run bash -c 'printf %s "brand-new-value" | secret update TOKEN'
  assert_success
  refute_output_contains "brand-new-value"
}

@test "update refuses a value given as an argument" {
  put_secret TOKEN "old-value-here"
  run secret update TOKEN new-value-here
  assert_failure
}

@test "update rejects an empty value and leaves the old one intact" {
  put_secret TOKEN "old-value-here"
  run bash -c 'printf %s "" | secret update TOKEN'
  assert_failure
  run stored_value TOKEN
  assert_equal "$output" "old-value-here"
}

# --- rm --------------------------------------------------------------------

@test "rm deletes a key so run can no longer resolve it" {
  put_secret TOKEN "a-value-here"
  run secret rm TOKEN
  assert_success
  run secret run TOKEN -- true
  assert_failure
}

@test "rm refuses an unknown key" {
  run secret rm GHOST
  assert_failure
  assert_output_contains "GHOST"
}

@test "rm drops the key from list" {
  put_secret A "value-one-here"
  put_secret B "value-two-here"
  secret rm A
  run secret list
  refute_output_contains "A"
  assert_output_contains "B"
}

# --- list ------------------------------------------------------------------

@test "list is empty and succeeds when nothing is stored" {
  run secret list
  assert_success
  assert_equal "$output" ""
}

@test "list prints one key name per line" {
  put_secret ALPHA "value-alpha-x"
  put_secret BRAVO "value-bravo-x"
  run secret list
  assert_success
  assert_equal "$output" "$(printf 'ALPHA\nBRAVO')"
}

@test "list never prints a value" {
  put_secret TOKEN "topsecretvalue"
  run secret list
  refute_output_contains "topsecretvalue"
}

@test "list marks a key whose keychain item has vanished" {
  put_secret TOKEN "a-value-here"
  security delete-generic-password -a "$USER" -s "secret-cli.TOKEN" "$SECRET_CLI_KEYCHAIN" >/dev/null 2>&1
  run secret list
  assert_output_contains "missing"
}
