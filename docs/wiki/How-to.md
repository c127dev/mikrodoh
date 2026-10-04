# How-to

## Use a different resolver

```bash
DOH_URL=https://9.9.9.9/dns-query
```

A resolver given by name also needs its address, because MikroDoH cannot ask
itself where the resolver is:

```bash
DOH_URL=https://cloudflare-dns.com/dns-query
DOH_BOOTSTRAP=cloudflare-dns.com=1.1.1.1,cloudflare-dns.com=1.0.0.1
```

## Add backup resolvers

```bash
DOH_URL=https://1.1.1.1/dns-query
DOH_FAILOVER_URL_1=https://9.9.9.9/dns-query
DOH_FAILOVER_URL_2=https://8.8.8.8/dns-query
```

If one fails, the next one is tried. A resolver that failed is skipped for a
while (`RESOLVER_COOLDOWN_MS`) and retried later.

## Turn on the cache

```bash
CACHE=3600
```

Answers are kept up to that many seconds. If every resolver goes down,
recently cached answers are still served (`SERVE_STALE`).

## Limit noisy clients

```bash
RATE_LIMIT_QPS=50
```

Each client (per /32 on IPv4, /56 on IPv6) gets 50 queries per second.

## Listen on one address or on IPv6

`LISTEN_ADDR` defaults to every interface. On a normal host, set it:

```bash
LISTEN_ADDR=192.168.88.1
LISTEN_ADDR=::          # IPv6 and IPv4 on one socket
```

## Run as a normal user

Started as root to bind port 53, MikroDoH can drop to another user once the
port is open:

```bash
RUN_AS_USER=nobody
```

It also locks itself down with a seccomp filter (`SANDBOX=true`, the default).

## Change settings without restarting

Put the settings in a file and point `CONFIG_FILE` at it. After editing it:

```bash
kill -HUP $(pidof mikrodoh)
```

Resolver settings (`DOH_*`, timeouts, `CHECK_CERT`, `TCP_KEEP_ALIVE`) apply
immediately. Anything else needs a restart. A broken file is logged and the
old settings stay.

## Check it is healthy

```bash
mikrodoh --health     # exit 0 = working, 1 = not
```

In a container:

```dockerfile
HEALTHCHECK --interval=30s --timeout=15s CMD ["/usr/bin/mikrodoh", "--health"]
```

On RouterOS, add a netwatch probe of type `dns` for `health.mikrodoh`, type A,
against the proxy's address.

## See what it is doing

A stats line is printed every 5 minutes, or on demand with
`kill -USR1 $(pidof mikrodoh)`:

```
[stats] served=1042 failed=3 rejected=0 dropped=0 inflight=2 tcp_conns=1 cache_hits=780 hit_rate=74%
```

## Is my router fast enough?

```bash
./scripts/crypto-bench.sh
```

It measures the encryption speed on the device. MikroDoH picks the faster
cipher on its own (`CIPHER=auto`); the bench tells you whether forcing
`CIPHER=chacha` or `CIPHER=aes` would help.
