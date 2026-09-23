#!/usr/bin/env bats
# Behavior: answering "is this the same secret?" without either value being
# printed.
#
# A fingerprint is salted per machine by default, because an unsalted hash of a
# low-entropy value in a transcript is itself a leak. --global drops the salt
# for the case where two machines have to agree, and says so.

load test_helper

setup() {
  setup_isolated_env
  put_secret TOKEN "s3cr3t-value-abcdef"
  put_secret OTHER "a-different-value"
  put_secret TWIN "s3cr3t-value-abcdef"
}
teardown() { teardown_isolated_env; }

fp() { secret fingerprint "$@" 2>/dev/null; }

# --- fingerprint ------------------------------------------------------------

@test "a fingerprint is stable across runs" {
  assert_equal "$(fp TOKEN)" "$(fp TOKEN)"
}

@test "different secrets get different fingerprints" {
  [ "$(fp TOKEN)" != "$(fp OTHER)" ]
}

@test "the same value under two names gets the same fingerprint" {
  assert_equal "$(fp TOKEN)" "$(fp TWIN)"
}

@test "a fingerprint never contains the value" {
  run secret fingerprint TOKEN
  refute_output_contains "s3cr3t-value-abcdef"
}

@test "a fingerprint is short enough to be obviously not the value" {
  run bash -c 'secret fingerprint TOKEN 2>/dev/null | cut -d: -f2 | tr -d "\n" | wc -c | tr -d " "'
  assert_equal "$output" "12"
}

@test "a fingerprint says which scheme it is so two kinds cannot be compared by eye" {
  run secret fingerprint TOKEN
  assert_output_contains "local:"
  run secret fingerprint TOKEN --global
  assert_output_contains "sha256:"
}

@test "the default fingerprint differs between machines" {
  # Same keychain, different config dir — so a different salt, and that is
  # the only thing that may change the answer.
  local here; here="$(fp TOKEN)"
  local there; there="$(SECRET_CLI_HOME=$TEST_TMP/other-machine secret fingerprint TOKEN 2>/dev/null)"
  [ -n "$there" ]
  [ "$here" != "$there" ]
}

@test "a global fingerprint is the same everywhere" {
  local here; here="$(fp TOKEN --global)"
  local there; there="$(SECRET_CLI_HOME=$TEST_TMP/other-machine secret fingerprint TOKEN --global 2>/dev/null)"
  [ -n "$there" ]
  assert_equal "$here" "$there"
}

@test "global warns that it is brute forceable for a weak value" {
  run bash -c 'secret fingerprint TOKEN --global 2>&1 >/dev/null'
  assert_output_contains "guess"
}

@test "fingerprint works for an adopted key" {
  put_foreign "some.app.service" "alice" "foreign-value-123"
  secret adopt some.app.service --as FOREIGN
  run secret fingerprint FOREIGN
  assert_success
  refute_output_contains "foreign-value-123"
}

@test "fingerprint fails on an unknown key" {
  run secret fingerprint GHOST
  assert_failure
}

# --- verify -----------------------------------------------------------------

@test "verify says match when the candidate is the stored value" {
  run bash -c 'printf %s "s3cr3t-value-abcdef" | secret verify TOKEN'
  assert_success
  assert_output_contains "match"
}

@test "verify fails and says so when the candidate is different" {
  run bash -c 'printf %s "not-the-same-value" | secret verify TOKEN'
  assert_failure
  assert_output_contains "no match"
}

@test "verify prints neither the candidate nor the stored value" {
  run bash -c 'printf %s "not-the-same-value" | secret verify TOKEN 2>&1'
  refute_output_contains "not-the-same-value"
  refute_output_contains "s3cr3t-value-abcdef"
}

@test "verify strips one trailing newline, like set does" {
  run bash -c 'printf "s3cr3t-value-abcdef\n" | secret verify TOKEN'
  assert_success
}

@test "verify works for an adopted key" {
  put_foreign "some.app.service" "alice" "foreign-value-123"
  secret adopt some.app.service --as FOREIGN
  run bash -c 'printf %s "foreign-value-123" | secret verify FOREIGN'
  assert_success
}

@test "verify fails on an unknown key" {
  run bash -c 'printf %s "anything-here" | secret verify GHOST'
  assert_failure
}

@test "verify rejects an empty candidate rather than calling it a mismatch" {
  run bash -c 'printf %s "" | secret verify TOKEN'
  assert_failure
  assert_output_contains "empty"
}

# --- diff -------------------------------------------------------------------

@test "diff says match for two keys holding the same value" {
  run secret diff TOKEN TWIN
  assert_success
  assert_output_contains "match"
}

@test "diff fails and says so for two different values" {
  run secret diff TOKEN OTHER
  assert_failure
  assert_output_contains "no match"
}

@test "diff prints neither value" {
  run secret diff TOKEN OTHER
  refute_output_contains "s3cr3t-value-abcdef"
  refute_output_contains "a-different-value"
}

@test "diff fails on an unknown key" {
  run secret diff TOKEN GHOST
  assert_failure
  assert_output_contains "GHOST"
}

@test "diff needs two keys" {
  run secret diff TOKEN
  assert_failure
}
