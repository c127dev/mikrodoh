# MikroDoH

MikroDoH turns plain DNS into DNS-over-HTTPS. Adding privacy, it forwards every
question encrypted to a DoH resolver such as Cloudflare or Quad9, so your ISP
cannot read or change it.

Features:

- UDP and TCP DNS on port 53
- Several upstream resolvers with automatic failover
- An optional cache
- Optional per-client rate limiting
- A built-in health check
- Config reload without restart

## Pick your device

`boards/` holds one config per device. Start from the closest one:

| File | Device |
| --- | --- |
| `boards/mikrotik-rb4011igs.conf` | MikroTik RB4011iGS+ |
| `boards/generic-armv7.conf` | Any ARMv7 device |
| `boards/generic-arm64.conf` | Any ARM64 device |
| `boards/generic-riscv64.conf` | Any RISC-V 64 device |
| `boards/generic-x86_64.conf` | Any x86_64 PC or server |

Pass the board name to the build to get its tuning flags:

```bash
./scripts/build.sh mikrotik-rb4011igs
```

## How to:

### Use a different resolver

```bash
DOH_URL=https://9.9.9.9/dns-query
```

A resolver given by name also needs its address, because MikroDoH cannot ask
itself where the resolver is:

```bash
DOH_URL=https://cloudflare-dns.com/dns-query
DOH_BOOTSTRAP=cloudflare-dns.com=1.1.1.1,cloudflare-dns.com=1.0.0.1
```

### Add backup resolvers

```bash
DOH_URL=https://1.1.1.1/dns-query
DOH_FAILOVER_URL_1=https://9.9.9.9/dns-query
DOH_FAILOVER_URL_2=https://8.8.8.8/dns-query
```

If one fails, the next one is tried. A resolver that failed is skipped for a
while (`RESOLVER_COOLDOWN_MS`) and retried later.

### Turn on the cache

```bash
CACHE=3600
```

Answers are kept up to that many seconds. If every resolver goes down,
recently cached answers are still served (`SERVE_STALE`).

### Limit noisy clients

```bash
RATE_LIMIT_QPS=50
```

Each client (per /32 on IPv4, /56 on IPv6) gets 50 queries per second.

### Listen on one address or on IPv6

`LISTEN_ADDR` defaults to every interface. On a normal host, set it:

```bash
LISTEN_ADDR=192.168.88.1
LISTEN_ADDR=::          # IPv6 and IPv4 on one socket
```

### Run as a normal user

Started as root to bind port 53, MikroDoH can drop to another user once the
port is open:

```bash
RUN_AS_USER=nobody
```

It also locks itself down with a seccomp filter (`SANDBOX=true`, the default).

### Change settings without restarting

Put the settings in a file and point `CONFIG_FILE` at it. After editing it:

```bash
kill -HUP $(pidof mikrodoh)
```

Resolver settings (`DOH_*`, timeouts, `CHECK_CERT`, `TCP_KEEP_ALIVE`) apply
immediately. Anything else needs a restart. A broken file is logged and the
old settings stay.

### Check it is healthy

```bash
mikrodoh --health     # exit 0 = working, 1 = not
```

In a container:

```dockerfile
HEALTHCHECK --interval=30s --timeout=15s CMD ["/usr/bin/mikrodoh", "--health"]
```

On RouterOS, add a netwatch probe of type `dns` for `health.mikrodoh`, type A,
against the proxy's address.

### See what it is doing

A stats line is printed every 5 minutes, or on demand with
`kill -USR1 $(pidof mikrodoh)`:

```
[stats] served=1042 failed=3 rejected=0 dropped=0 inflight=2 tcp_conns=1 cache_hits=780 hit_rate=74%
```

### Is my router fast enough?

```bash
./scripts/crypto-bench.sh
```

It measures the encryption speed on the device. MikroDoH picks the faster
cipher on its own (`CIPHER=auto`); the bench tells you whether forcing
`CIPHER=chacha` or `CIPHER=aes` would help.

## All settings

Every setting is an environment variable (or a line in `CONFIG_FILE`). A bad
value stops startup and names the key.

| Key | Default | Meaning |
| --- | --- | --- |
| `LISTEN_ADDR` | `0.0.0.0` | Address to listen on, IPv4 or IPv6 |
| `LISTEN_PORT` | `53` | Port, UDP and TCP |
| `IPV6_V6ONLY` | `false` | On an IPv6 address, refuse IPv4 clients |
| `IP_VERSION` | `auto` | Reach the resolver over `auto`, `4` or `6` |
| `DOH_URL` | `https://1.1.1.1/dns-query` | Main resolver |
| `DOH_FAILOVER_URL_n` | unset | Backup resolvers, `n` from 1 up, no gaps |
| `DOH_BOOTSTRAP` | unset | `host=addr` pairs for resolvers given by name |
| `CIPHER` | `auto` | `auto`, `chacha` or `aes` |
| `WORKERS` | CPU cores | Worker threads |
| `UDP_READERS` | `WORKERS` | UDP reader threads |
| `MAX_INFLIGHT` | `512` | Queries in progress before new ones are dropped |
| `RATE_LIMIT_QPS` | `0` | Queries per second per client, `0` = off |
| `RATE_LIMIT_BURST` | `RATE_LIMIT_QPS` | How far a client may burst above that |
| `RATE_LIMIT_V4_PREFIX` | `32` | IPv4 prefix counted as one client |
| `RATE_LIMIT_V6_PREFIX` | `56` | IPv6 prefix counted as one client, max 64 |
| `RCVBUF_KB` | `4096` | UDP socket buffer, kB |
| `CHECK_CERT` | `true` | Verify the resolver's certificate |
| `CONNECT_TIMEOUT_MS` | `3000` | Resolver connect timeout |
| `REQUEST_TIMEOUT_MS` | `5000` | Resolver answer timeout |
| `RESOLVER_COOLDOWN_MS` | `30000` | How long a failed resolver is skipped, `0` = never |
| `WARM_INTERVAL_SEC` | `30` | Keep the resolver connection open when idle, `0` = off |
| `TCP_KEEP_ALIVE` | `0` | TCP keep-alive to the resolver, `0` = off |
| `TCP` | `true` | Also serve DNS over TCP |
| `TCP_MAX_CONNS` | `128` | Max TCP clients at once |
| `TCP_IDLE_SEC` | `10` | Close idle TCP clients after this |
| `CACHE` | `0` | Cache lifetime in seconds, `0` = off |
| `CACHE_NEGATIVE` | `60` | Cache lifetime for "not found" answers |
| `CACHE_MIN_TTL` | `0` | Raise shorter record TTLs to this |
| `CACHE_MAX_TTL` | `0` | Lower longer record TTLs to this, `0` = `CACHE` |
| `PREFETCH` | `true` | Refresh popular entries before they expire |
| `SERVE_STALE` | `86400` | Serve expired answers this long when resolvers are down |
| `STATS_INTERVAL_SEC` | `300` | Seconds between stats lines, `0` = off |
| `RUN_AS_USER` | unset | User to switch to after binding |
| `RUN_AS_GROUP` | user's group | Group to switch to |
| `CONFIG_FILE` | unset | Settings file, re-read on `SIGHUP` |
| `SANDBOX` | `true` | Lock the process down after startup |

## License

Apache License 2.0. See [LICENSE](LICENSE).
