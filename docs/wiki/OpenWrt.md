# OpenWrt

`openwrt/mikrodoh/` is an OpenWrt package: a Makefile, a procd init script and
a UCI config.

## Build the package

Inside an OpenWrt buildroot or SDK:

```bash
cp -r /path/to/mikrodoh/openwrt/mikrodoh package/
make menuconfig    # Network > IP Addresses and Names > mikrodoh
                   # Libraries > libcurl > HTTP/2 support (LIBCURL_NGHTTP2)
make package/mikrodoh/compile -j"$(nproc)"
```

The ipk/apk lands under `bin/packages/<arch>/base/`. Without HTTP/2 in libcurl
every query opens its own TLS connection.

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

Every key from [[Configuration]] is accepted in lower case (`rate_limit_qps`,
`serve_stale`, ...). `doh_failover_url` is a list and becomes
`DOH_FAILOVER_URL_1`, `_2`, ... in order.

```bash
uci set mikrodoh.main.rate_limit_qps=50
uci commit mikrodoh
/etc/init.d/mikrodoh reload
```

## Use it from dnsmasq

dnsmasq keeps port 53 and forwards to MikroDoH:

```bash
uci add_list dhcp.@dnsmasq[0].server='127.0.0.1#5053'
uci set dhcp.@dnsmasq[0].noresolv='1'
uci commit dhcp
/etc/init.d/dnsmasq restart
```

Local names (`lan`, DHCP leases) still come from dnsmasq.
