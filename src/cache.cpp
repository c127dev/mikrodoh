#include "cache.h"

DnsCache::DnsCache(int ttl_seconds, std::size_t max_entries)
    : ttl_(ttl_seconds), max_entries_(max_entries) {}

std::string DnsCache::key_of(const std::uint8_t* packet, std::size_t len) {
    if (len <= 2) return {};
    return std::string(reinterpret_cast<const char*>(packet) + 2, len - 2);
}

bool DnsCache::lookup(const std::string& key, std::vector<std::uint8_t>& out) const {
    if (!enabled() || key.empty()) return false;

    std::lock_guard<std::mutex> lock(mutex_);
    auto it = entries_.find(key);
    if (it == entries_.end() || std::time(nullptr) >= it->second.expires) return false;

    // The caller overwrites the first two bytes with the client's transaction ID.
    if (it->second.response.size() < 2) return false;

    order_.splice(order_.begin(), order_, it->second.order);
    out = it->second.response;
    return true;
}

void DnsCache::store(const std::string& key, const std::vector<std::uint8_t>& response,
                     int ttl_override) {
    if (!enabled() || key.empty()) return;

    int ttl = ttl_;
    if (ttl_override > 0 && ttl_override < ttl) ttl = ttl_override;

    std::time_t expires = std::time(nullptr) + ttl;

    std::lock_guard<std::mutex> lock(mutex_);
    auto it = entries_.find(key);
    if (it != entries_.end()) {
        it->second.response = response;
        it->second.expires  = expires;
        order_.splice(order_.begin(), order_, it->second.order);
        return;
    }

    if (max_entries_ == 0) return;
    while (entries_.size() >= max_entries_) {
        entries_.erase(order_.back());
        order_.pop_back();
    }

    order_.push_front(key);
    entries_.emplace(key, Entry{response, expires, order_.begin()});
}
