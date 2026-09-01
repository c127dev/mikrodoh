#pragma once

#include <iosfwd>
#include <string>
#include <vector>

enum class CipherPref { Auto, ChaCha, Aes };

// Address family used to reach the upstream resolver.
enum class IpVersion { Any, V4, V6 };

struct Config {
    std::string listen_addr        = "0.0.0.0";
    int         listen_port        = 53;
    // First entry is DOH_URL, the rest are the DOH_FAILOVER_URL_n in order. A
    // query walks the list until one resolver answers.
    std::vector<std::string> doh_urls = {"https://1.1.1.1/dns-query"};
    int         workers            = 0;
    bool        check_cert         = true;
    int         tcp_keep_alive     = 0;
    int         cache_ttl          = 0;
    long        max_inflight       = 512;
    int         rcvbuf_kb          = 4096;
    int         connect_timeout_ms = 3000;
    int         request_timeout_ms = 5000;
    CipherPref  cipher             = CipherPref::Auto;
    IpVersion   ip_version         = IpVersion::Any;

    // Only consulted for an IPv6 bind. False means the same socket also serves
    // IPv4 clients, which arrive as ::ffff:a.b.c.d.
    bool ipv6_v6only = false;

    bool tcp_enabled  = true;
    int  tcp_max_conns = 128;
    int  tcp_idle_sec  = 10;

    // Resolved from `cipher` and, for Auto, the CPU AES probe.
    bool prefer_chacha = false;

    static Config from_env();
    void print(std::ostream& os) const;
};
