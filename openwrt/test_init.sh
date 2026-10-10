#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Johan Alvarado
# Runs the procd init script against stubbed UCI and procd helpers.
set -eu

SRC=${MIKRODOH_SRC:-$(dirname "$0")/../..}
OUT=$(mktemp)
trap 'rm -f "$OUT"' EXIT

uci_main_enabled=1
uci_main_listen_port=5053
uci_main_doh_url=https://9.9.9.9/dns-query
uci_main_refuse_any=0
uci_main_tcp=0
FAILOVERS="https://1.1.1.1/dns-query https://8.8.8.8/dns-query"

config_load() { :; }
config_get() { eval "$1=\${uci_$2_$3:-}"; }
config_get_bool() { eval "$1=\${uci_$2_$3:-$4}"; }
config_list_foreach() { for v in $FAILOVERS; do "$3" "$v"; done; }
procd_open_instance() { echo open >> "$OUT"; }
procd_close_instance() { echo close >> "$OUT"; }
procd_set_param() { echo "set $*" >> "$OUT"; }
procd_append_param() { shift; echo "env $*" >> "$OUT"; }

. "$SRC/openwrt/mikrodoh/files/mikrodoh.init"
start_service

rc=0
expect() {
    if grep -qx "$1" "$OUT"; then echo "ok   $1"; else echo "FAIL $1"; rc=1; fi
}
expect "set command /usr/sbin/mikrodoh"
expect "env LISTEN_PORT=5053"
expect "env DOH_URL=https://9.9.9.9/dns-query"
expect "env REFUSE_ANY=0"
expect "env TCP=0"
expect "env DOH_FAILOVER_URL_1=https://1.1.1.1/dns-query"
expect "env DOH_FAILOVER_URL_2=https://8.8.8.8/dns-query"

: > "$OUT"
uci_main_enabled=0
start_service
if [ -s "$OUT" ]; then echo "FAIL disabled instance still started"; rc=1; else echo "ok   disabled instance not started"; fi

exit "$rc"
