#!/bin/sh
# Usage: scripts/build.sh [board]
# Board names are the file stems in boards/, e.g. mikrotik-rb4011igs.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BOARD=${1:-}
TUNE=

if [ -n "$BOARD" ]; then
    CONF="$ROOT/boards/$BOARD.conf"
    if [ ! -f "$CONF" ]; then
        echo "unknown board: $BOARD" >&2
        echo "available:" >&2
        ls "$ROOT/boards" | sed 's/\.conf$//; s/^/  /' >&2
        exit 1
    fi
    TUNE=$(sed -n 's/^MIKRODOH_TUNE=//p' "$CONF" | tr -d '"')
    echo "board $BOARD, tune: ${TUNE:-none}"
fi

cmake -S "$ROOT" -B "$ROOT/build" -DCMAKE_BUILD_TYPE=Release -DMIKRODOH_TUNE="$TUNE"
cmake --build "$ROOT/build" -j "$(nproc)"
