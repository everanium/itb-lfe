#!/usr/bin/env bash
#
# run_bench.sh -- micro-benchmark runner for the LFE binding. Builds
# libitb3.so + the C binding archive + the Erlang backend + the LFE
# application via build.sh, compiles the bench module with the
# hex-fetched LFE compiler, then runs the message, stream and
# stream_one_shot shapes: encrypt-message, stream-pump and
# whole-buffer stream throughput at 1 MiB / 16 MiB / 64 MiB.
#
# Usage:
#   ./run_bench.sh                        # all shapes
#   ./run_bench.sh message                # Single Message shape only
#   ./run_bench.sh stream                 # stream-pump shape only
#   ./run_bench.sh stream_one_shot        # whole-buffer stream shape only

set -eu
set -o pipefail

cd "$(dirname "$0")"

./build.sh

# Go-runtime pacing defaults for bench-scale allocation churn; the
# `:-` form respects any override set by the caller. The bench main
# applies the same caps programmatically.
export ITB_GOMEMLIMIT="${ITB_GOMEMLIMIT:-4GiB}"
export ITB_GOGC="${ITB_GOGC:-100}"

# Bench-shape defaults — match the root Go BENCH3.md pin so the
# throughput numbers are directly comparable to the shipped Go
# Encrypt3x{128,256,512}Cfg baseline. Override any of these before
# calling the script to change the shape.
export ITB_NONCE_BITS="${ITB_NONCE_BITS:-512}"
export ITB_KEY_BITS="${ITB_KEY_BITS:-1024}"
export ITB_WITH_PARALLAX="${ITB_WITH_PARALLAX:-false}"
export ITB_WITH_WRAPPER="${ITB_WITH_WRAPPER:-false}"
export ITB_INNER_HASH="${ITB_INNER_HASH:-areion512}"
export ITB_BENCH_MIN_SEC="${ITB_BENCH_MIN_SEC:-5}"

LFE_EBIN="_build/default/lib/lfe/ebin"
ITB_EBIN="_build/default/checkouts/libitb3/ebin"
APP_EBIN="_build/default/lib/libitb3_lfe/ebin"

echo "==> compiling bench module (lfe_comp from the hex lfe dep)"
erl -noshell -pa "$LFE_EBIN" -eval \
    '{ok, _} = lfe_comp:file("bench/itb-bench.lfe", [{outdir, "bench"}, report]).' \
    -run init stop

# ITB_WITH_MAC=true derives MAC/AEAD profile counterparts. When
# ITB_PROFILE is set explicitly by the caller, it wins over the
# derivation and applies to both shapes (expert override).
: "${ITB_WITH_MAC:=false}"
if [ -n "${ITB_PROFILE:-}" ]; then
    ITB_MSG_PROFILE_DEFAULT="${ITB_PROFILE}"
    ITB_STREAM_PROFILE_DEFAULT="${ITB_PROFILE}"
elif [ "${ITB_WITH_MAC}" = "true" ]; then
    ITB_MSG_PROFILE_DEFAULT="singlemsg-triple-mac-v1"
    ITB_STREAM_PROFILE_DEFAULT="streaming-aead-triple-mac-v1"
else
    ITB_MSG_PROFILE_DEFAULT="singlemsg-triple-nomac-v1"
    ITB_STREAM_PROFILE_DEFAULT="streaming-noaead-triple-v1"
fi

WHAT="${1:-all}"

run_one() {
    # The trailing shape token becomes main([Shape]).
    erl -noshell -pa "$ITB_EBIN" -pa "$APP_EBIN" -pa bench \
        -run itb-bench main "$1" -run init stop
}

case "$WHAT" in
    message)        export ITB_PROFILE="${ITB_MSG_PROFILE_DEFAULT}"
                    run_one message;;
    stream)         export ITB_PROFILE="${ITB_STREAM_PROFILE_DEFAULT}"
                    run_one stream;;
    stream_one_shot)
                    export ITB_PROFILE="${ITB_STREAM_PROFILE_DEFAULT}"
                    run_one stream_one_shot;;
    all)            export ITB_PROFILE="${ITB_MSG_PROFILE_DEFAULT}"
                    run_one message
                    export ITB_PROFILE="${ITB_STREAM_PROFILE_DEFAULT}"
                    run_one stream
                    run_one stream_one_shot;;
    *)              echo "usage: $0 [message|stream|stream_one_shot|all]" >&2
                    exit 2;;
esac
