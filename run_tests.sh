#!/usr/bin/env bash
#
# run_tests.sh -- one-step test runner for the LFE binding. Builds
# libitb3.so + the C binding archive + the Erlang backend + the LFE
# application via build.sh, then invokes `rebar3 eunit` (the test
# module is registered in rebar.config's eunit_tests — EUnit cannot
# auto-discover .lfe sources). Forwards any positional arguments
# through to rebar3.
#
# Usage:
#   ./run_tests.sh                              # full suite
#   ./run_tests.sh --test='itb-lfe-tests:version_test'

set -eu
set -o pipefail

cd "$(dirname "$0")"

./build.sh

exec rebar3 eunit "$@"
