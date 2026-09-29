// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Johan Alvarado

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
    explicit DnsCache(int ttl_seconds, std::size_t max_entries = 10000,
                      int stale_seconds = 0, int min_ttl = 0, int max_ttl = 0);

    static constexpr std::uint32_t kStaleTtl = 30;

    bool enabled() const { return ttl_ > 0; }

    // Leaves out the OPT record body, so a per-query DNS cookie does not
    // change the key.
    static std::string key_of(const std::uint8_t* packet, std::size_t len);

    bool lookup(const std::string& key, std::vector<std::uint8_t>& out,
                bool* refresh = nullptr) const;
    bool lookup_stale(const std::string& key, std::vector<std::uint8_t>& out) const;
    void store(const std::string& key, const std::vector<std::uint8_t>& response,
               int ttl_override = 0);

private:
    struct Entry {
        std::vector<std::uint8_t>        response;
        std::time_t                      stored;
        std::time_t                      expires;
        std::list<std::string>::iterator order;
        mutable unsigned                 hits      = 0;
        mutable bool                     refreshed = false;
    };

    int         ttl_;
    std::size_t max_entries_;
    int         stale_;
    int         min_ttl_;
    int         max_ttl_;
    mutable std::mutex                     mutex_;
    mutable std::list<std::string>         order_;
    std::unordered_map<std::string, Entry> entries_;
};
