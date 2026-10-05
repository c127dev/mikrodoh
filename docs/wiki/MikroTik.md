# MikroTik

RouterOS 7 runs MikroDoH as a container. The `container` package must be
installed and enabled (`/system/device-mode/update container=yes`).

## Network

```
/interface/veth/add name=veth-doh address=172.17.0.2/24 gateway=172.17.0.1
/interface/bridge/add name=containers
/ip/address/add address=172.17.0.1/24 interface=containers
/interface/bridge/port/add bridge=containers interface=veth-doh
```

## Container

Upload `mikrodoh-armv7.tar` (or `-arm64`) to the router, then:

```
/container/envs/add list=doh key=DOH_URL value=https://1.1.1.1/dns-query
/container/envs/add list=doh key=CACHE value=300
/container/add file=mikrodoh-armv7.tar interface=veth-doh envlist=doh \
    start-on-boot=yes logging=yes
/container/start [find interface=veth-doh]
```

## Point RouterOS at it

```
/ip/dns/set servers=172.17.0.2 allow-remote-requests=yes
```

## Health check

```
/tool/netwatch/add type=dns host=172.17.0.2 record-type=A \
    dns-server=172.17.0.2 name=health.mikrodoh
```

`boards/mikrotik-rb4011igs.conf` holds the compiler tuning for the RB4011.
