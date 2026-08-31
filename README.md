# MikroDoH

A small C++17 daemon that accepts plain UDP DNS queries and forwards them as
DNS-over-HTTPS. It targets low-end routers - the reference device is a MikroTik
RB4011iGS+ running the proxy in a RouterOS v7 container.

## Design

- **One HTTP/2 connection per event loop.** Each worker drives a `curl_multi`
  handle with `CURLPIPE_MULTIPLEX` and `CURLOPT_PIPEWAIT`, so hundreds of
  queries share a single TLS connection and no TLS handshake is repeated.
- **No thread per query.** A producer thread reads the UDP socket and shards
  queries to N workers. Concurrency is bounded by `MAX_INFLIGHT`, not by thread
  count.
- **Load shedding.** Queries above the in-flight cap are dropped instead of
  queued, so accepted queries keep bounded latency under burst.
- **Cipher selection from CPU features.** See below.
- **UDP and TCP.** A stub that gets a truncated answer retries over TCP, so
  TCP/53 has to answer. The TCP listener follows RFC 7766: two-byte length
  prefix, several queries pipelined on one connection, responses written in
  whatever order they finish, connection dropped once idle.
- **Queries are validated before they leave.** A datagram that is not a
  well-formed query, or is already a response, is dropped rather than
  forwarded or answered, so the proxy cannot be used as a reflector.
- **A failed lookup answers SERVFAIL** instead of nothing, so the client fails
  over immediately rather than waiting out its own timeout.

## Cipher selection

TLS record crypto is the throughput ceiling on CPUs without an AES engine,
because AES-GCM then runs in software. ChaCha20-Poly1305 is much faster in that
case. `CIPHER=auto` probes the CPU at startup and picks accordingly:

| CPU | Probe | Selected |
| --- | --- | --- |
| x86 with AES-NI | `CPUID.1:ECX[25]` | AES-GCM |
| x86 without AES-NI | `CPUID.1:ECX[25]` | ChaCha20-Poly1305 |
| ARMv8 with crypto extensions | `getauxval(AT_HWCAP) & HWCAP_AES` | AES-GCM |
| ARMv7 (Cortex-A15 and similar) | `getauxval(AT_HWCAP2) & HWCAP2_AES` | ChaCha20-Poly1305 |
| RISC-V, anything else | none | ChaCha20-Poly1305 |

`CIPHER=chacha` and `CIPHER=aes` override the probe. The selection is printed in
the startup banner.

## OpenSSL assembly

The record crypto belongs to OpenSSL, not to this daemon. OpenSSL carries
hand-written assembly for both AEADs and dispatches on CPU features at runtime:

| Target | ChaCha20 | Poly1305 |
| --- | --- | --- |
| ARMv7 | `chacha-armv4.pl`, NEON | `poly1305-armv4.pl`, NEON |
| ARMv8 | `chacha-armv8.pl` | `poly1305-armv8.pl` |
| x86_64 | `chacha-x86_64.pl`, SSSE3/AVX2 | `poly1305-x86_64.pl` |

Two things have to hold for a ChaCha20 build to reach those paths:

1. OpenSSL was not configured with `no-asm`. Some minimal or hardened builds
   are, and then ChaCha20 and Poly1305 fall back to portable C, which erases
   the reason to prefer them.
2. The kernel reports NEON in `AT_HWCAP`. OpenSSL reads it into
   `OPENSSL_armcap` at startup and picks the NEON code paths from it.

`scripts/crypto-bench.sh` checks both and measures the two AEADs on the device:

```bash
./scripts/crypto-bench.sh
OPENSSL_armcap=0 ./scripts/crypto-bench.sh   # same run with ARM asm disabled
```

Its numbers are the ground truth for `CIPHER`; the CPU probe is only a
prediction of them.

## Configuration

Every key is read from the environment. `boards/` holds ready-made sets, one per
supported device, in `--env-file` format.

| Key | Default | Meaning |
| --- | --- | --- |
| `LISTEN_ADDR` | `0.0.0.0` | Address to bind |
| `LISTEN_PORT` | `53` | Port to bind, UDP and TCP |
| `DOH_URL` | `https://1.1.1.1/dns-query` | Upstream DoH resolver |
| `CIPHER` | `auto` | `auto`, `chacha` or `aes` |
| `WORKERS` | CPU cores | Event-loop threads; track cores, not query volume |
| `MAX_INFLIGHT` | `512` | In-flight cap before queries are shed |
| `RCVBUF_KB` | `4096` | UDP receive/send buffer, in kB |
| `CHECK_CERT` | `true` | Verify the resolver's certificate |
| `CONNECT_TIMEOUT_MS` | `3000` | Upstream connect timeout |
| `REQUEST_TIMEOUT_MS` | `5000` | Upstream request timeout |
| `TCP_KEEP_ALIVE` | `0` | Keep-alive interval on the upstream connection, `0` disables |
| `TCP` | `true` | Serve DNS over TCP as well as UDP |
| `TCP_MAX_CONNS` | `128` | Accepted TCP connections; further ones are closed at once |
| `TCP_IDLE_SEC` | `10` | Close a TCP connection after this long with no query |
| `CACHE` | `0` | Response TTL in seconds, `0` disables the cache |

`LISTEN_ADDR` defaults to every interface because the reference deployment is a
container with its own network namespace. On a host, set it.

### Boards

| File | Device |
| --- | --- |
| `boards/mikrotik-rb4011igs.conf` | MikroTik RB4011iGS+ (AL21400, 4x Cortex-A15) |
| `boards/generic-armv7.conf` | Any ARMv7-A device |
| `boards/generic-arm64.conf` | Any ARMv8-A device |
| `boards/generic-riscv64.conf` | Any RV64GC device |
| `boards/generic-x86_64.conf` | Any x86_64 host |

Board files also carry keys the daemon ignores: `MIKRODOH_TUNE`, the compiler
flags `scripts/build.sh` passes to cmake, plus `MIKRODOH_PLATFORM` and
`MIKRODOH_VARIANT`, which name the image a board gets built into.

Adding a device means copying the closest generic file, measuring, and pinning
the values that differ.

## Build

```bash
./scripts/build.sh                        # host defaults
./scripts/build.sh mikrotik-rb4011igs     # with that board's tuning flags
```

Needs cmake, a C++17 compiler and libcurl headers. The binary lands in
`build/mikrodoh`.

## Run

```bash
set -a; . ./boards/generic-x86_64.conf; set +a
./build/mikrodoh
```

End-to-end check, builds and resolves a name through the proxy on port 6353:

```bash
./scripts/test.sh
```

## License

Apache License 2.0. See [LICENSE](LICENSE).
