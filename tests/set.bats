#!/usr/bin/env bats
# Behavior: storing a new secret.

load test_helper

setup() { setup_isolated_env; }
teardown() { teardown_isolated_env; }

@test "set stores a value that a later run can use" {
  put_secret TOKEN "abc123456"
  run secret run TOKEN -- sh -c 'test -n "$TOKEN" && echo present'
  assert_success
  assert_output_contains "present"
}

@test "set reports success naming only the key" {
  run bash -c 'printf %s "swordfish-value" | secret set TOKEN'
  assert_success
  assert_output_contains "TOKEN"
  refute_output_contains "swordfish-value"
}

@test "set refuses a value given as an argument" {
  run secret set TOKEN swordfish-value
  assert_failure
  assert_output_contains "stdin"
}

@test "set refuses to overwrite an existing key and points at update" {
  put_secret TOKEN "first-value"
  run bash -c 'printf %s "second-value" | secret set TOKEN'
  assert_failure
  assert_output_contains "update"
}

@test "a refused overwrite leaves the original value intact" {
  put_secret TOKEN "first-value"
  run bash -c 'printf %s "second-value" | secret set TOKEN' || true
  run stored_value TOKEN
  assert_equal "$output" "first-value"
}

@test "set rejects an empty value" {
  run bash -c 'printf %s "" | secret set TOKEN'
  assert_failure
  assert_output_contains "empty"
}

@test "set rejects a key name that is not a valid environment variable name" {
  for bad in "my-key" "9LIVES" "has space" "has.dot" "" "a\$b"; do
    run secret set "$bad"
    assert_failure
  done
}

@test "set accepts lowercase and underscored key names" {
  run bash -c 'printf %s "a-value-here" | secret set my_token'
  assert_success
}

@test "set warns but succeeds when the value is too short to scrub safely" {
  run bash -c 'printf %s "abc" | secret set PIN'
  assert_success
  assert_output_contains "short"
}

@test "set strips a single trailing newline from a pasted value" {
  printf 'pasted-value\n' | secret set TOKEN
  run stored_value TOKEN
  assert_equal "$output" "pasted-value"
}

@test "set preserves a value containing shell metacharacters verbatim" {
  v='p@ss w0rd $HOME `id` "q" '"'"'s'"'"' \back\ ;|&'
  printf '%s' "$v" | secret set TRICKY
  run stored_value TRICKY
  assert_equal "$output" "$v"
}

@test "set preserves a multi-line value such as a private key" {
  v=$'-----BEGIN PRIVATE KEY-----\nMIIBVgIBADAN\n-----END PRIVATE KEY-----'
  printf '%s' "$v" | secret set PRIVKEY
  run stored_value PRIVKEY
  assert_equal "$output" "$v"
}

@test "set preserves a non-ASCII value" {
  v='pässwörd-日本語-🔑'
  printf '%s' "$v" | secret set UNI
  run stored_value UNI
  assert_equal "$output" "$v"
}

@test "set preserves a 4KB value" {
  v="$(head -c 4096 /dev/urandom | base64 | tr -d '\n' | head -c 4096)"
  printf '%s' "$v" | secret set BIG
  run stored_value BIG
  assert_equal "$output" "$v"
}

@test "set requires a key name" {
  run secret set
  assert_failure
}
