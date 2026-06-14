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

## Configuration

Every key is read from the environment. `boards/` holds ready-made sets, one per
supported device, in `--env-file` format.

| Key | Default | Meaning |
| --- | --- | --- |
| `LISTEN_PORT` | `53` | UDP port to bind |
| `DOH_URL` | `https://1.1.1.1/dns-query` | Upstream DoH resolver |
| `CIPHER` | `auto` | `auto`, `chacha` or `aes` |
| `WORKERS` | CPU cores | Event-loop threads; track cores, not query volume |
| `MAX_INFLIGHT` | `512` | In-flight cap before queries are shed |
| `RCVBUF_KB` | `4096` | UDP receive/send buffer, in kB |
| `CHECK_CERT` | `true` | Verify the resolver's certificate |
| `TCP_KEEP_ALIVE` | `0` | TCP keep-alive interval in seconds, `0` disables |
| `CACHE` | `0` | Response TTL in seconds, `0` disables the cache |

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
