# MikroDoH wiki

MikroDoH is a small DNS-over-HTTPS proxy for routers. It answers plain DNS on
UDP and TCP and forwards each question, encrypted, to a DoH resolver.

## Pages

- [Installation](Installation.md) - build from source, container, OpenWrt package
- [Configuration](Configuration.md) - every setting and its default
- [How-to](How-to.md) - resolvers, failover, cache, rate limits, health checks
- [OpenWrt](OpenWrt.md) - package build, UCI options, dnsmasq integration
- [MikroTik](MikroTik.md) - running it as a RouterOS container
- [Architecture](Architecture.md) - source layout and how a query flows
