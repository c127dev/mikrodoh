#include "cache.h"

#include <mutex>

DnsCache::DnsCache(int ttl_seconds, std::size_t max_entries)
    : ttl_(ttl_seconds), max_entries_(max_entries) {}

std::string DnsCache::key_of(const std::uint8_t* packet, std::size_t len) {
    if (len <= 2) return {};
    return std::string(reinterpret_cast<const char*>(packet) + 2, len - 2);
}

bool DnsCache::lookup(const std::string& key, std::vector<std::uint8_t>& out) const {
    if (!enabled() || key.empty()) return false;

    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = entries_.find(key);
    if (it == entries_.end() || std::time(nullptr) >= it->second.expires) return false;

    // The caller overwrites the first two bytes with the client's transaction ID.
    if (it->second.response.size() < 2) return false;

    out = it->second.response;
    return true;
}

void DnsCache::store(const std::string& key, const std::vector<std::uint8_t>& response) {
    if (!enabled() || key.empty()) return;

    std::unique_lock<std::shared_mutex> lock(mutex_);
    if (entries_.size() > max_entries_) entries_.clear();
    entries_[key] = Entry{response, std::time(nullptr) + ttl_};
}
