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
    // `stale_seconds` keeps an entry that long past its expiry for
    // lookup_stale(); 0 drops it at expiry.
    // Record TTLs in a stored answer are clamped to [min_ttl, max_ttl]; a
    // max_ttl of 0 leaves the upper end at `ttl_seconds`.
    explicit DnsCache(int ttl_seconds, std::size_t max_entries = 10000,
                      int stale_seconds = 0, int min_ttl = 0, int max_ttl = 0);

    // RFC 8767 section 4: the TTL on a stale answer.
    static constexpr std::uint32_t kStaleTtl = 30;

    bool enabled() const { return ttl_ > 0; }

    // The header flags, the question, and whether the query carried an OPT
    // record and its DO bit. The rest of the OPT record is left out, so a DNS
    // cookie that changes per query does not change the key. Empty when not
    // cacheable.
    static std::string key_of(const std::uint8_t* packet, std::size_t len);

    // `out` has every record TTL lowered by the time the entry has spent here.
    bool lookup(const std::string& key, std::vector<std::uint8_t>& out) const;
    // An entry past its expiry but within the stale window, with every record
    // TTL set to kStaleTtl. For when no resolver answers.
    bool lookup_stale(const std::string& key, std::vector<std::uint8_t>& out) const;
    // The record TTLs are clamped first. The entry then lives for the lowest
    // of them, capped by the configured TTL. `ttl_override` above zero caps it
    // further and never extends it. A response whose lowest TTL is still zero
    // is not stored.
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
    int         stale_;
    int         min_ttl_;
    int         max_ttl_;
    // A lookup reorders `order_`, so both paths take the lock exclusively.
    mutable std::mutex                     mutex_;
    // Most recently used key first.
    mutable std::list<std::string>         order_;
    std::unordered_map<std::string, Entry> entries_;
};
