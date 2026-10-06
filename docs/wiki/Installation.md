# Installation

## From source

Needs CMake 3.10+, a C++17 compiler and libcurl built with HTTP/2.

```bash
./scripts/build.sh                      # portable build
./scripts/build.sh mikrotik-rb4011igs   # with board tuning, see boards/
```

The binary lands in `build/mikrodoh`. For routers with little flash, build it
size-optimised (`-Os`, LTO, section GC, stripped):

```bash
cmake -S . -B build -DMIKRODOH_SMALL=ON
cmake --build build -j"$(nproc)"
```

## Smoke test

```bash
./scripts/test.sh
```

Starts the daemon on port 6353 and resolves a name over UDP and TCP. Needs
`dig`.

## Container

The image is built from the `container` branch. Load the tarball for your
architecture and run it with the settings as environment variables:

```bash
podman load -i mikrodoh-amd64.tar
podman run -d --name mikrodoh -p 53:53/udp -p 53:53/tcp \
    -e DOH_URL=https://9.9.9.9/dns-query -e CACHE=300 mikrodoh
```

## OpenWrt

See [OpenWrt](OpenWrt.md).
