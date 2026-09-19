#include "cache.h"

#include "dns.h"

DnsCache::DnsCache(int ttl_seconds, std::size_t max_entries, int stale_seconds)
    : ttl_(ttl_seconds), max_entries_(max_entries), stale_(stale_seconds > 0 ? stale_seconds : 0) {}

std::string DnsCache::key_of(const std::uint8_t* packet, std::size_t len) {
    std::size_t end = dns::question_end(packet, len);
    if (end == 0) return {};

    dns::UdpLimit limit = dns::udp_limit(packet, len);

    std::string key;
    key.reserve(3 + end - dns::kHeaderLen);
    key.push_back(static_cast<char>(packet[2]));
    key.push_back(static_cast<char>(packet[3]));
    key.push_back(static_cast<char>((limit.edns ? 1 : 0) | (limit.dnssec_ok ? 2 : 0)));
    key.append(reinterpret_cast<const char*>(packet) + dns::kHeaderLen, end - dns::kHeaderLen);
    return key;
}

bool DnsCache::lookup(const std::string& key, std::vector<std::uint8_t>& out) const {
    if (!enabled() || key.empty()) return false;

    std::lock_guard<std::mutex> lock(mutex_);
    auto it = entries_.find(key);
    std::time_t now = std::time(nullptr);
    if (it == entries_.end() || now >= it->second.expires) return false;

    // The caller overwrites the first two bytes with the client's transaction ID.
    if (it->second.response.size() < 2) return false;

    order_.splice(order_.begin(), order_, it->second.order);
    out = it->second.response;
    if (now > it->second.stored)
        dns::age_ttls(out.data(), out.size(), static_cast<std::uint32_t>(now - it->second.stored));
    return true;
}

bool DnsCache::lookup_stale(const std::string& key, std::vector<std::uint8_t>& out) const {
    if (!enabled() || stale_ == 0 || key.empty()) return false;

    std::lock_guard<std::mutex> lock(mutex_);
    auto it = entries_.find(key);
    std::time_t now = std::time(nullptr);
    if (it == entries_.end() || now < it->second.expires ||
        now >= it->second.expires + stale_)
        return false;

    if (it->second.response.size() < 2) return false;

    out = it->second.response;
    dns::set_ttls(out.data(), out.size(), kStaleTtl);
    return true;
}

void DnsCache::store(const std::string& key, const std::vector<std::uint8_t>& response,
                     int ttl_override) {
    if (!enabled() || key.empty()) return;

    int ttl = ttl_;
    if (ttl_override > 0 && ttl_override < ttl) ttl = ttl_override;

    long lowest = dns::min_ttl(response.data(), response.size());
    if (lowest == 0) return;
    if (lowest > 0 && lowest < ttl) ttl = static_cast<int>(lowest);

    std::time_t now     = std::time(nullptr);
    std::time_t expires = now + ttl;

    std::lock_guard<std::mutex> lock(mutex_);
    auto it = entries_.find(key);
    if (it != entries_.end()) {
        it->second.response = response;
        it->second.stored   = now;
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
    entries_.emplace(key, Entry{response, now, expires, order_.begin()});
}
