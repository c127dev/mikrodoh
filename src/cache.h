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

    // Query bytes minus the 2-byte transaction ID. Empty when not cacheable.
    static std::string key_of(const std::uint8_t* packet, std::size_t len);

    bool lookup(const std::string& key, std::vector<std::uint8_t>& out) const;
    // `ttl_override` above zero shortens this entry's lifetime; it is clamped
    // to the configured TTL and never extends it.
    void store(const std::string& key, const std::vector<std::uint8_t>& response,
               int ttl_override = 0);

private:
    struct Entry {
        std::vector<std::uint8_t>        response;
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
