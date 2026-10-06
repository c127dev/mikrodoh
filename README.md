# MikroDoH

A small DNS-over-HTTPS proxy for routers. It answers plain DNS on UDP and TCP
and forwards every question, encrypted, to a DoH resolver such as Cloudflare
or Quad9, so your ISP cannot read or change it.

- UDP and TCP DNS, IPv4 and IPv6
- Several resolvers with automatic failover
- Cache with prefetch and serve-stale
- Per-client rate limiting
- Health check, live reload on `SIGHUP`
- Drops privileges and runs under a seccomp filter
- Runs on MikroTik (container), OpenWrt (package) and any Linux box

## Quick start

```bash
./scripts/build.sh
sudo LISTEN_ADDR=127.0.0.1 CACHE=300 ./build/mikrodoh
dig @127.0.0.1 example.com
```

Settings are environment variables, for example:

```bash
DOH_URL=https://9.9.9.9/dns-query
DOH_FAILOVER_URL_1=https://1.1.1.1/dns-query
```

## Documentation

The [wiki](docs/wiki/Home.md) covers everything else:

- [Installation](docs/wiki/Installation.md)
- [Configuration](docs/wiki/Configuration.md)
- [How-to](docs/wiki/How-to.md)
- [OpenWrt](docs/wiki/OpenWrt.md)
- [MikroTik](docs/wiki/MikroTik.md)
- [Architecture](docs/wiki/Architecture.md)

## License

Apache License 2.0. See [LICENSE](LICENSE).
