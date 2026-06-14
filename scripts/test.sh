#!/bin/sh
# Builds the daemon, runs it on an unprivileged port and resolves a name
# through it. Requires dig (bind-tools).
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PORT=${PORT:-6353}
NAME=${NAME:-google.com}

"$ROOT/scripts/build.sh" "$@"

LISTEN_PORT="$PORT" "$ROOT/build/mikrodoh" &
PID=$!
trap 'kill "$PID" 2>/dev/null || true' EXIT

sleep 2

if dig @127.0.0.1 -p "$PORT" "$NAME" +short +timeout=5 \
    | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
    echo "PASS: resolved $NAME through the proxy"
else
    echo "FAIL: could not resolve $NAME" >&2
    exit 1
fi
