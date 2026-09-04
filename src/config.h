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
    // How long a resolver is skipped after it fails. Doubles per consecutive
    // failure up to 16x, and is cleared by the next success. 0 disables the
    // memory, so every query pays a dead resolver's timeout again.
    int         resolver_cooldown_ms = 30000;
    CipherPref  cipher             = CipherPref::Auto;
    IpVersion   ip_version         = IpVersion::Any;

    // Only consulted for an IPv6 bind. False means the same socket also serves
    // IPv4 clients, which arrive as ::ffff:a.b.c.d.
    bool ipv6_v6only = false;

    // Empty leaves the process as it started. Set it when the daemon binds a
    // privileged port as root: the switch happens once the sockets are up.
    std::string run_as_user;
    std::string run_as_group;

    // Seconds between stats log lines. 0 turns the periodic line off; a
    // SIGUSR1 dump still works.
    int stats_interval_sec = 300;

    bool tcp_enabled  = true;
    int  tcp_max_conns = 128;
    int  tcp_idle_sec  = 10;

    // Resolved from `cipher` and, for Auto, the CPU AES probe.
    bool prefer_chacha = false;

    static Config from_env();
    void print(std::ostream& os) const;
};
