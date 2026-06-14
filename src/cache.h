#pragma once

#include <cstddef>
#include <cstdint>
#include <ctime>
#include <shared_mutex>
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
    void store(const std::string& key, const std::vector<std::uint8_t>& response);

private:
    struct Entry {
        std::vector<std::uint8_t> response;
        std::time_t               expires;
    };

    int                                    ttl_;
    std::size_t                            max_entries_;
    mutable std::shared_mutex              mutex_;
    std::unordered_map<std::string, Entry> entries_;
};
