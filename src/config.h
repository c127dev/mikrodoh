#pragma once

#include <iosfwd>
#include <string>

enum class CipherPref { Auto, ChaCha, Aes };

struct Config {
    int         listen_port    = 53;
    std::string doh_url        = "https://1.1.1.1/dns-query";
    int         workers        = 0;
    bool        check_cert     = true;
    int         tcp_keep_alive = 0;
    int         cache_ttl      = 0;
    long        max_inflight   = 512;
    int         rcvbuf_kb      = 4096;
    CipherPref  cipher         = CipherPref::Auto;

    // Resolved from `cipher` and, for Auto, the CPU AES probe.
    bool        prefer_chacha  = false;

    static Config from_env();
    void print(std::ostream& os) const;
};
