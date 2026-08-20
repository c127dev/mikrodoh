# MikroDoH container build

This branch carries the container recipe and the workflow that builds it. The
source lives on `main`.

`main` is source only and triggers nothing. Start `build.yml` from the Actions
tab with this branch selected, or over HTTP with a fine-grained token holding
Actions read and write:

```bash
curl -X POST \
    -H "Accept: application/vnd.github+json" \
    -H "Authorization: Bearer $GH_TOKEN" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    https://api.github.com/repos/c127dev/mikrodoh/actions/workflows/build.yml/dispatches \
    -d '{"ref":"container"}'
```

It checks out `main` for the source and this branch for the `Dockerfile`, then
publishes `linux/amd64`, `linux/arm64`, `linux/arm/v7` and `linux/riscv64` to
GHCR. The ref above picks the workflow, never the source.

Pushing to this branch starts a run that skips every job. That run exists only
to keep the workflow registered, since a dispatch cannot reach a workflow GitHub
has never indexed.

## Tags

| Tag | Contents |
| --- | --- |
| `latest` | Last stable release |
| `edge` | Last pre-release, that is, any push that did not change `VERSION` |
| `v<version>` | A stable release |
| `v<version>-pre.<run>` | A pre-release |
| `sha-<short>` | The commit of `main` it was built from |

`VERSION` on `main` decides which of the two a run produces. See the `main`
README for that rule.

Every release, stable or not, carries `mikrodoh-amd64.tar.gz`,
`mikrodoh-arm64.tar.gz` and `mikrodoh-armv7.tar.gz` as assets, for devices that
cannot pull from a registry.

## Local build

Run from a checkout of `main`, with this `Dockerfile` passed by path:

```bash
podman build -f ../container/Dockerfile -t mikrodoh .
podman build -f ../container/Dockerfile \
    --build-arg MIKRODOH_TUNE="-mcpu=cortex-a15 -mfpu=neon-vfpv4 -mfloat-abi=hard" \
    --platform linux/arm/v7 -t mikrodoh:rb4011 .
```

`MIKRODOH_TUNE` is per-SoC, so the published images are built without it. Build
locally when you want the tuning flags from a `boards/*.conf` baked in.

## Run

```bash
podman run -d --name mikrodoh \
    --env-file boards/generic-x86_64.conf \
    -p 5353:53/udp \
    ghcr.io/c127dev/mikrodoh:latest
```

Board files ship on `main` under `boards/`. Keys the daemon does not read, such
as `MIKRODOH_TUNE`, are ignored.

## RouterOS v7

Needs the `container` package, `mode=container` in `/system/device-mode`, and a
writable `root-dir` such as a USB or NVMe partition.

```
/interface/veth/add name=veth-doh address=172.17.0.2/24 gateway=172.17.0.1
/interface/bridge/add name=containers
/interface/bridge/port/add bridge=containers interface=veth-doh
/ip/address/add address=172.17.0.1/24 interface=containers

# The host goes in registry-url, not in remote-image. RouterOS prepends it.
/container/config/set registry-url=https://ghcr.io tmpdir=usb1/pull

/container/envs/add name=mikrodoh key=CIPHER value=auto
/container/envs/add name=mikrodoh key=WORKERS value=4
/container/envs/add name=mikrodoh key=CACHE value=60

/container/add remote-image=c127dev/mikrodoh:latest \
    interface=veth-doh envlist=mikrodoh root-dir=usb1/mikrodoh logging=yes
/container/start 0
```

Then point the router's resolver at the container and let clients use the
router:

```
/ip/dns/set servers=172.17.0.2
```

An offline device takes the image as a file instead. Download
`mikrodoh-armv7.tar.gz` from a release, `gunzip` it, upload it to the router:

```
/container/add file=mikrodoh-armv7.tar interface=veth-doh envlist=mikrodoh \
    root-dir=usb1/mikrodoh
```

## License

Apache License 2.0, same as `main`.
