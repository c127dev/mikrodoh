# OpenWrt

`openwrt/mikrodoh/` is an OpenWrt package: a Makefile, a procd init script and
a UCI config.

## Build the package

Inside an OpenWrt buildroot or SDK:

```bash
cp -r /path/to/mikrodoh/openwrt/mikrodoh /path/to/mikrodoh/openwrt/luci-app-mikrodoh package/
make menuconfig    # Network > IP Addresses and Names > mikrodoh
                   # Libraries > libcurl > HTTP/2 support (LIBCURL_NGHTTP2)
make package/mikrodoh/compile -j"$(nproc)"
make package/luci-app-mikrodoh/compile -j"$(nproc)"   # optional web UI
```

The package lands under `bin/packages/<arch>/base/`: an `.apk` on OpenWrt 25.12
and later, an `.ipk` on 24.10 and earlier. The same Makefile builds both. Without HTTP/2 in libcurl
every query opens its own TLS connection.

## Install

OpenWrt 25.12 and later (apk):

```bash
apk add --allow-untrusted mikrodoh-*.apk
```

OpenWrt 24.10 and earlier (opkg):

```bash
opkg update
opkg install mikrodoh_*.ipk
```

Both pull `libcurl`, `libnghttp2` and `libstdcpp` from the official feeds.
Tested on x86-64 24.10.3 and 25.12.3.

## Configure

`/etc/config/mikrodoh`:

```
config mikrodoh 'main'
	option enabled '1'
	option listen_addr '127.0.0.1'
	option listen_port '5053'
	option doh_url 'https://1.1.1.1/dns-query'
	list doh_failover_url 'https://9.9.9.9/dns-query'
	option cache '300'
	option run_as_user 'nobody'
```

Every key from [Configuration](Configuration.md) is accepted in lower case (`rate_limit_qps`,
`serve_stale`, ...). `doh_failover_url` is a list and becomes
`DOH_FAILOVER_URL_1`, `_2`, ... in order.

```bash
uci set mikrodoh.main.rate_limit_qps=50
uci commit mikrodoh
/etc/init.d/mikrodoh reload
```

`reload_config` also works, except for the first change after a fresh install:
it only reacts to config files that existed when it last ran. Use
`/etc/init.d/mikrodoh reload` or reboot once.

## LuCI

`openwrt/luci-app-mikrodoh/` adds a page under Services > MikroDoH with the
service status and tabs for the listener, resolvers, cache and limits. Build it
next to the daemon (it needs the `luci` feed) and install both:

```bash
apk add --allow-untrusted mikrodoh-*.apk luci-app-mikrodoh-*.apk
```

Save & Apply restarts the daemon with the new settings.

## Use it from dnsmasq

dnsmasq keeps port 53 and forwards to MikroDoH:

```bash
uci add_list dhcp.@dnsmasq[0].server='127.0.0.1#5053'
uci set dhcp.@dnsmasq[0].noresolv='1'
uci commit dhcp
/etc/init.d/dnsmasq restart
```

Local names (`lan`, DHCP leases) still come from dnsmasq.
