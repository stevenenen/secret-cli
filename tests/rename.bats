#!/usr/bin/env bats
# Behavior: giving a secret a different name.
#
# Naming conventions change. Renaming must move the value without it ever being
# printed, and must not leave the old name resolvable.

load test_helper

setup() {
  setup_isolated_env
  put_secret OLD_NAME "s3cr3t-value-abcdef"
}
teardown() { teardown_isolated_env; }

@test "rename moves the value to the new name" {
  secret rename OLD_NAME NEW_NAME
  run stored_value NEW_NAME
  assert_equal "$output" "s3cr3t-value-abcdef"
}

@test "the old name stops resolving" {
  secret rename OLD_NAME NEW_NAME
  run secret run OLD_NAME -- true
  assert_failure
}

@test "list shows the new name and not the old" {
  secret rename OLD_NAME NEW_NAME
  run secret list
  assert_equal "$output" "NEW_NAME"
}

@test "rename never prints the value" {
  run secret rename OLD_NAME NEW_NAME
  assert_success
  refute_output_contains "s3cr3t-value-abcdef"
}

@test "rename preserves a multi-line value across the re-chunking" {
  v=$'-----BEGIN PRIVATE KEY-----\nMIIBVgIBADAN\n-----END PRIVATE KEY-----'
  printf '%s' "$v" | secret set PRIVKEY
  secret rename PRIVKEY DEPLOY_KEY
  run stored_value DEPLOY_KEY
  assert_equal "$output" "$v"
}

@test "rename preserves a value too long for one keychain item" {
  v="$(head -c 4096 /dev/urandom | base64 | tr -d '\n' | head -c 4096)"
  printf '%s' "$v" | secret set BIG
  secret rename BIG BIGGER
  run stored_value BIGGER
  assert_equal "$output" "$v"
}

@test "rename refuses an unknown key" {
  run secret rename GHOST SOMETHING
  assert_failure
  assert_output_contains "GHOST"
}

@test "rename refuses a name that is already taken" {
  put_secret TAKEN "other-value-here"
  run secret rename OLD_NAME TAKEN
  assert_failure
  assert_output_contains "TAKEN"
}

@test "a refused rename leaves both values untouched" {
  put_secret TAKEN "other-value-here"
  run secret rename OLD_NAME TAKEN
  run stored_value OLD_NAME
  assert_equal "$output" "s3cr3t-value-abcdef"
  run stored_value TAKEN
  assert_equal "$output" "other-value-here"
}

@test "rename refuses a new name that is not a valid variable name" {
  run secret rename OLD_NAME "not-valid"
  assert_failure
}

@test "rename refuses renaming a key to itself" {
  run secret rename OLD_NAME OLD_NAME
  assert_failure
}

@test "rename needs two names" {
  run secret rename OLD_NAME
  assert_failure
}

# --- adopted keys -----------------------------------------------------------

@test "renaming an adopted key renames the mapping, not the item" {
  put_foreign "some.app.service" "alice" "foreign-value-123"
  secret adopt some.app.service --as FOREIGN
  secret rename FOREIGN VENDOR_KEY
  run stored_value VENDOR_KEY
  assert_equal "$output" "foreign-value-123"
  # Still the other app's item, under its own name.
  run security find-generic-password -a alice -s some.app.service -w "$SECRET_CLI_KEYCHAIN"
  assert_equal "$output" "foreign-value-123"
}

@test "a renamed adopted key is still adopted" {
  put_foreign "some.app.service" "alice" "foreign-value-123"
  secret adopt some.app.service --as FOREIGN
  secret rename FOREIGN VENDOR_KEY
  run secret list --all
  assert_output_contains "adopted"
  assert_output_contains "VENDOR_KEY"
}

@test "rename refuses a name already used by an adopted key" {
  put_foreign "some.app.service" "alice" "foreign-value-123"
  secret adopt some.app.service --as FOREIGN
  run secret rename OLD_NAME FOREIGN
  assert_failure
}
