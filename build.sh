#!/usr/bin/env bash
#
# build.sh -- one-step build for the LFE binding. Chains the Erlang
# binding's build.sh (libitb3.so + the C binding's static archive +
# the NIF shim) and then compiles the rebar3 project plus the eitb
# demonstrator; rebar3 rebuilds the Erlang application as a checkout
# dependency (_checkouts/libitb3 -> ../erlang). Prerequisites (Go, a
# C11 compiler, GNU make, Erlang/OTP 27+, rebar3) must be installed
# separately; the LFE compiler arrives as a hex dependency, so no
# system LFE install is required. See README.md "Prerequisites".
#
# The build starts by removing every artefact this binding owns, so no
# output of an earlier build can survive into this one and mask a
# breakage. The chained Erlang build.sh wipes the backend the same way,
# so the whole BEAM stack is rebuilt from tracked sources.
# ITB_SKIP_CLEAN=1 keeps both trees for fast iteration.
#
# Usage:
#   ./build.sh                       # default build (full asm stack)
#   ./build.sh --noitbasm            # opt out of ITB's SIMD asm kernels
#   CC=clang ./build.sh              # override the C compiler
#   ITB_SKIP_CLEAN=1 ./build.sh      # incremental build, no wipe

set -eu
set -o pipefail

cd "$(dirname "$0")"
SCRIPT_DIR="$(pwd)"
REPO_ROOT="$(cd ../.. && pwd)"

# Answered before the wipe below, so asking for usage never removes
# anything. Every other argument is forwarded to the Erlang build.
case "${1:-}" in
    -h|--help) echo "usage: $0 [--noitbasm]"; exit 0;;
esac

# ---------------------------------------------------------------------
# Artefact wipe.
#
# ARTEFACTS names what this binding generates. Inside a git work tree
# the list is supplemented from `git ls-files --others --ignored`, which
# enumerates exactly the paths .gitignore covers and by construction can
# never name a tracked one. Every candidate is canonicalised and refused
# unless it resolves inside this binding's own directory.
#
# _checkouts/libitb3 is a tracked symlink -- rebar3's path-dependency
# mechanism pointing at ../erlang -- and is deliberately absent from
# both lists. The Erlang backend it names is depended on, never removed
# from here: the chained build.sh below owns that tree's wipe.
# ---------------------------------------------------------------------
ARTEFACTS=(
    _build
    ebin
    .rebar3
    rebar.lock
    rebar3.crashdump
    erl_crash.dump
    '*.beam'
    'bench/*.beam'
    'eitb/*.beam'
)

# Containment is checked against the physical path, so the candidate
# and the root are canonicalised the same way even when the checkout is
# reached through a symlinked directory.
CLEAN_ROOT="$(readlink -m -- "$SCRIPT_DIR")"

rm_artefact() {
    local rel="$1" abs
    abs="$(readlink -m -- "$CLEAN_ROOT/$rel")"
    case "$abs" in
        "$CLEAN_ROOT"/?*) ;;
        *) echo "clean: '$rel' resolves outside $CLEAN_ROOT ($abs)" >&2
           exit 1 ;;
    esac
    [ -e "$abs" ] || return 0
    echo "[clean] rm -rf $abs"
    rm -rf -- "$abs"
}

clean_artefacts() {
    local entry match
    shopt -s nullglob
    for entry in "${ARTEFACTS[@]}"; do
        for match in "$CLEAN_ROOT"/$entry; do
            rm_artefact "${match#"$CLEAN_ROOT"/}"
        done
    done
    shopt -u nullglob
    # The work-tree probe silences stderr because a source tarball
    # carries no git metadata; there the ARTEFACTS list stands alone.
    if git -C "$CLEAN_ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1
    then
        while IFS= read -r entry; do
            [ -n "$entry" ] || continue
            # A dot-prefixed .md is a private note kept out of the index
            # by the global ignore file, not build output.
            case "${entry##*/}" in .*.md) continue;; esac
            rm_artefact "$entry"
        done < <(git -C "$CLEAN_ROOT" ls-files --others --ignored \
                     --exclude-standard --directory)
    fi
}

if [ "${ITB_SKIP_CLEAN:-0}" = "1" ]; then
    echo "==> ITB_SKIP_CLEAN=1 -- keeping existing build artefacts"
else
    echo "==> removing build artefacts"
    clean_artefacts
fi

../erlang/build.sh "$@"

echo "==> rebar3 compile (LFE sources via the rebar3_lfe plugin)"
rebar3 compile

# The eitb demonstrator is an LFE module outside the rebar3 source
# tree, so compile it here rather than leaving it to the launcher's
# own staleness check: after the wipe above the beam is always a
# product of this invocation.
echo "==> eitb"
erl -noshell -pa "$SCRIPT_DIR/_build/default/lib/lfe/ebin" -eval \
    "{ok, _} = lfe_comp:file(\"$SCRIPT_DIR/eitb/itb-eitb.lfe\",
                             [{outdir, \"$SCRIPT_DIR/eitb\"}, report])." \
    -run init stop

ITB_LIBITB3_PATH="$REPO_ROOT/dist/linux-amd64/libitb3.so" \
LD_LIBRARY_PATH="$REPO_ROOT/dist/linux-amd64${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
    ./eitb/eitb version

echo "==> ready: ./run_tests.sh"
