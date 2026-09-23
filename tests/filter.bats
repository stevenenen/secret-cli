#!/usr/bin/env bats
# Behavior: narrowing `list` with a filter.
#
# Three ways a filter can match, in the order results are ranked:
#   substring      tok  -> GH_TOKEN
#   initials       TIC  -> THIS_IS_COOL
#   subsequence    ghtn -> GH_TOKEN
# All case-insensitive.

load test_helper

setup() {
  setup_isolated_env
  put_secret GH_TOKEN "value-gh-token1"
  put_secret DB_PASSWORD "value-db-pass1"
  put_secret THIS_IS_COOL "value-this-cool"
}
teardown() { teardown_isolated_env; }

# --- substring --------------------------------------------------------------

@test "a filter matches part of a name" {
  run secret list tok
  assert_equal "$output" "GH_TOKEN"
}

@test "a filter ignores case in the query" {
  run secret list TOK
  assert_equal "$output" "GH_TOKEN"
}

@test "a filter matches across the underscore" {
  run secret list pass
  assert_equal "$output" "DB_PASSWORD"
}

@test "a filter can match more than one name" {
  run secret list o
  assert_output_contains "GH_TOKEN"
  assert_output_contains "THIS_IS_COOL"
}

# --- initials ---------------------------------------------------------------

@test "a filter matches the initials of the snake case parts" {
  run secret list TIC
  assert_equal "$output" "THIS_IS_COOL"
}

@test "initials matching ignores case" {
  run secret list tic
  assert_equal "$output" "THIS_IS_COOL"
}

@test "the first few initials are enough" {
  run secret list ti
  assert_output_contains "THIS_IS_COOL"
}

@test "initials do not match out of order" {
  run secret list cit
  assert_equal "$output" ""
}

# --- subsequence ------------------------------------------------------------

@test "a filter matches letters in order with gaps" {
  run secret list ghtn
  assert_equal "$output" "GH_TOKEN"
}

@test "a subsequence out of order does not match" {
  run secret list ntgh
  assert_equal "$output" ""
}

# --- ranking and shape ------------------------------------------------------

@test "a substring match is listed before a subsequence match" {
  put_secret TOOLKIT "value-toolkit1"   # 'tok' is only a subsequence of this
  run secret list tok                   # but a substring of GH_TOKEN
  assert_equal "$(printf '%s' "$output" | head -1)" "GH_TOKEN"
  assert_output_contains "TOOLKIT"
}

@test "results stay one name per line" {
  run bash -c 'secret list o | while read -r k; do printf "[%s]" "$k"; done'
  assert_output_contains "[GH_TOKEN]"
  assert_output_contains "[THIS_IS_COOL]"
}

@test "no match is empty and still succeeds" {
  run secret list zzzzz
  assert_success
  assert_equal "$output" ""
}

@test "no filter still lists everything" {
  run secret list
  assert_equal "$output" "$(printf 'DB_PASSWORD\nGH_TOKEN\nTHIS_IS_COOL')"
}

# --- with --all -------------------------------------------------------------

@test "a filter narrows list --all too" {
  put_foreign "some.app.service" "alice" "foreign-value-123"
  run secret list --all app
  assert_output_contains "some.app.service"
  refute_output_contains "GH_TOKEN"
}

@test "a filter never matches against a value" {
  run secret list "value-gh-token1"
  assert_equal "$output" ""
}
