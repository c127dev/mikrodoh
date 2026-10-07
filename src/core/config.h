// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Johan Alvarado

#pragma once

#include <iosfwd>
#include <string>
#include <vector>

enum class CipherPref { Auto, ChaCha, Aes };

enum class IpVersion { Any, V4, V6 };

struct Config {
    // Listeners
    std::string listen_addr   = "0.0.0.0";
    int         listen_port   = 53;
    bool        ipv6_v6only   = false;
    int         udp_readers   = 0;
    int         rcvbuf_kb     = 4096;
    bool        tcp_enabled   = true;
    int         tcp_max_conns = 128;
    int         tcp_idle_sec  = 10;

    // Upstream
    std::vector<std::string> doh_urls = {"https://1.1.1.1/dns-query"};
    // A hostname resolver needs a bootstrap address: getaddrinfo would loop
    // back to this daemon when it is the box's resolver.
    std::vector<std::string> resolve_entries;
    int        workers              = 0;
    bool       check_cert           = true;
    int        tcp_keep_alive       = 0;
    int        connect_timeout_ms   = 3000;
    int        request_timeout_ms   = 5000;
    int        resolver_cooldown_ms = 30000;
    int        warm_interval_sec    = 30;
    CipherPref cipher               = CipherPref::Auto;
    IpVersion  ip_version           = IpVersion::Any;
    bool       prefer_chacha        = false;

    // Cache
    int  cache_ttl          = 0;
    int  cache_negative_ttl = 60;
    int  cache_min_ttl      = 0;
    int  cache_max_ttl      = 0;
    bool prefetch           = true;
    int  serve_stale        = 86400;

    // Load control
    bool refuse_any           = true;
    long max_inflight         = 512;
    long rate_limit_qps       = 0;
    long rate_limit_burst     = 0;  // 0 means "same as qps"
    int  rate_limit_v4_prefix = 32;
    int  rate_limit_v6_prefix = 56;

    // Process
    std::string run_as_user;
    std::string run_as_group;
    bool        sandbox            = true;
    int         stats_interval_sec = 300;
    std::string config_file;
    std::string load_error;

    static Config from_env();
    void print(std::ostream& os) const;

    bool resolvers_reachable(std::ostream& err) const;
};
