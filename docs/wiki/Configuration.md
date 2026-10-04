# Configuration

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

## Settings file

`CONFIG_FILE` points at a file of `KEY=VALUE` lines, the same format as
`boards/*.conf`. Blank lines and `#` comments are skipped. Its keys override the
environment. `SIGHUP` re-reads it; see [[How-to]].
