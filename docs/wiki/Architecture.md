# Architecture

## Source layout

| Directory | Contents |
| --- | --- |
| `src/core/` | configuration, stats, CPU probe, privilege drop, seccomp sandbox |
| `src/dns/` | wire format parsing, cache, query coalescing, health probe |
| `src/net/` | address helpers, UDP and TCP listeners, per-client rate limiter |
| `src/upstream/` | dispatcher, DoH workers, resolver list, in-flight transfers |
| `src/main.cpp` | startup, signals, thread wiring |

## Query path

1. `UdpServer` (one `SO_REUSEPORT` socket per reader, `recvmmsg` batches) or
   `TcpServer` (RFC 7766 framing) reads a query.
2. `Dispatcher` rate-limits the source, validates the query, answers from
   `DnsCache` when it can, sheds over `MAX_INFLIGHT`, and hands the rest to a
   `DohWorker` chosen by the cache key.
3. The `DohWorker` joins an identical in-flight query (`Coalescer`) or starts
   a transfer on its `curl_multi` handle. All transfers share one HTTP/2
   connection.
4. The answer is checked against the question, cached, and written back to
   the UDP client (truncated with TC when too big) or the TCP connection.

On failure the worker tries the next resolver, skipping those in cooldown,
then falls back to a stale cache entry, then SERVFAIL.

## Threads

- UDP readers: `UDP_READERS`, default `WORKERS`
- TCP loop: one
- DoH workers: `WORKERS`, default CPU cores
- Stats thread: periodic line, `SIGUSR1` dump, `SIGHUP` reload

## Hardening

After the sockets are bound the process drops to `RUN_AS_USER`, sets
`no_new_privs` and installs a seccomp filter that fails exec, ptrace, mount,
namespace, credential, module, bpf and keyring syscalls.
