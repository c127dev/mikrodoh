#pragma once

#include <cstddef>
#include <cstdint>
#include <ctime>
#include <list>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

class DnsCache {
public:
    explicit DnsCache(int ttl_seconds, std::size_t max_entries = 10000);

    bool enabled() const { return ttl_ > 0; }

    // The header flags, the question, and whether the query carried an OPT
    // record and its DO bit. The rest of the OPT record is left out, so a DNS
    // cookie that changes per query does not change the key. Empty when not
    // cacheable.
    static std::string key_of(const std::uint8_t* packet, std::size_t len);

    // `out` has every record TTL lowered by the time the entry has spent here.
    bool lookup(const std::string& key, std::vector<std::uint8_t>& out) const;
    // The entry lives for the lowest record TTL in `response`, capped by the
    // configured TTL. `ttl_override` above zero caps it further and never
    // extends it. A response whose lowest TTL is zero is not stored.
    void store(const std::string& key, const std::vector<std::uint8_t>& response,
               int ttl_override = 0);

private:
    struct Entry {
        std::vector<std::uint8_t>        response;
        std::time_t                      stored;
        std::time_t                      expires;
        std::list<std::string>::iterator order;
    };

    int         ttl_;
    std::size_t max_entries_;
    // A lookup reorders `order_`, so both paths take the lock exclusively.
    mutable std::mutex                     mutex_;
    // Most recently used key first.
    mutable std::list<std::string>         order_;
    std::unordered_map<std::string, Entry> entries_;
};
