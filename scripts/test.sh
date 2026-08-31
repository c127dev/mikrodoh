#!/bin/sh
# Builds the daemon, runs it on an unprivileged port and resolves a name
# through it over UDP and over TCP. Requires dig (bind-tools).
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PORT=${PORT:-6353}
NAME=${NAME:-google.com}

"$ROOT/scripts/build.sh" "$@"

LISTEN_ADDR=127.0.0.1 LISTEN_PORT="$PORT" "$ROOT/build/mikrodoh" &
PID=$!
trap 'kill "$PID" 2>/dev/null || true' EXIT

sleep 2

rc=0
for transport in +notcp +tcp; do
    if dig @127.0.0.1 -p "$PORT" "$transport" "$NAME" +short +timeout=5 \
        | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
        echo "PASS: resolved $NAME through the proxy ($transport)"
    else
        echo "FAIL: could not resolve $NAME ($transport)" >&2
        rc=1
    fi
done

exit "$rc"
