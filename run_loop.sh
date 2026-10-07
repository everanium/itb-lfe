#!/usr/bin/env bash
#
# Fleet entry point for the loop stress harness of the LFE binding:
# compiles the utility's modules (libitb3.so, the NIF shim, the Erlang
# backend and the LFE application are assumed built by build.sh) and
# execs it with every argument passed through.
#
# Usage:
#   ./run_loop.sh --duration 2m --shape both

set -eu
set -o pipefail

cd "$(dirname "$0")"

LFE_EBIN="$PWD/_build/default/lib/lfe/ebin"
ITB_EBIN="$PWD/_build/default/checkouts/libitb3/ebin"
APP_EBIN="$PWD/_build/default/lib/libitb3_lfe/ebin"

for ebin in "$LFE_EBIN" "$ITB_EBIN" "$APP_EBIN"; do
    if [ ! -d "$ebin" ]; then
        echo "run_loop.sh: binding not built ($ebin missing); run ./build.sh first" >&2
        exit 1
    fi
done

erl -noshell -pa "$LFE_EBIN" -pa "$ITB_EBIN" -pa "$APP_EBIN" -eval \
    "[{ok, _} = lfe_comp:file(F, [{outdir, \"$PWD/loop\"}, report,
                                  warnings_as_errors])
      || F <- filelib:wildcard(\"$PWD/loop/*.lfe\")]." \
    -run init stop

exec ./loop/loop "$@"
