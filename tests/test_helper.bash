# Shared setup for every spec.
#
# Each test gets a throwaway keychain and a throwaway config dir, so nothing
# here can touch a real credential. Tests drive the `secret` binary and assert
# on observable behavior only — exit status, stdout, stderr, and what a later
# command can see. No test reaches into an internal function.

SECRET_CLI_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export SECRET_CLI_ROOT

setup_isolated_env() {
  TEST_TMP="$(mktemp -d "${TMPDIR:-/tmp}/secret-cli-test.XXXXXX")"
  export TEST_TMP

  TEST_KEYCHAIN="$TEST_TMP/test.keychain-db"
  security create-keychain -p testpw "$TEST_KEYCHAIN" >/dev/null 2>&1
  security unlock-keychain -p testpw "$TEST_KEYCHAIN" >/dev/null 2>&1
  security set-keychain-settings "$TEST_KEYCHAIN" >/dev/null 2>&1

  export SECRET_CLI_KEYCHAIN="$TEST_KEYCHAIN"
  export SECRET_CLI_HOME="$TEST_TMP/config"
  export PATH="$SECRET_CLI_ROOT/bin:$PATH"
}

teardown_isolated_env() {
  [ -n "${TEST_KEYCHAIN:-}" ] && security delete-keychain "$TEST_KEYCHAIN" >/dev/null 2>&1
  [ -n "${TEST_TMP:-}" ] && rm -rf "$TEST_TMP"
  return 0
}

# Store a secret the way a script would: value on stdin, never on the command line.
put_secret() {
  printf '%s' "$2" | secret set "$1" >/dev/null 2>&1
}

# Read a stored value back, for round-trip assertions. Uses --no-scrub so the
# value survives, and drops stderr so the --no-scrub warning does not land in
# $output alongside it.
stored_value() {
  secret run "$1" --no-scrub -- sh -c "printf %s \"\$$1\"" 2>/dev/null
}

# Assert a string is absent from the combined output of the last run.
refute_output_contains() {
  if [[ "$output" == *"$1"* ]]; then
    printf 'expected output NOT to contain: %s\nactual output:\n%s\n' "$1" "$output" >&2
    return 1
  fi
}

assert_output_contains() {
  if [[ "$output" != *"$1"* ]]; then
    printf 'expected output to contain: %s\nactual output:\n%s\n' "$1" "$output" >&2
    return 1
  fi
}

assert_success() {
  if [ "$status" -ne 0 ]; then
    printf 'expected exit 0, got %s\noutput:\n%s\n' "$status" "$output" >&2
    return 1
  fi
}

assert_failure() {
  if [ "$status" -eq 0 ]; then
    printf 'expected non-zero exit, got 0\noutput:\n%s\n' "$output" >&2
    return 1
  fi
}

assert_equal() {
  if [ "$1" != "$2" ]; then
    printf 'expected: %s\nactual:   %s\n' "$2" "$1" >&2
    return 1
  fi
}
