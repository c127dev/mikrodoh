#include "ratelimit.h"

#include <algorithm>
#include <chrono>
#include <cstring>

namespace {

constexpr std::size_t kShards          = 16;
constexpr std::size_t kBucketsPerShard = 4096;

std::uint64_t now_ms() {
    using namespace std::chrono;
    return static_cast<std::uint64_t>(
        duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count());
}

std::uint64_t mask_of(int bits) {
    if (bits <= 0) return 0;
    if (bits >= 64) return ~std::uint64_t(0);
    return ~std::uint64_t(0) << (64 - bits);
}

// One 64-bit key for both families. IPv4 lands in the IPv4-mapped range
// (::ffff:a.b.c.d), which is where an IPv4 client arriving on the dual-stack
// socket already is, so the two spellings of one address share a bucket and no
// routable IPv6 prefix can collide with them.
std::uint64_t key_of(const sockaddr_storage& addr, int v4_prefix, int v6_prefix) {
    if (addr.ss_family == AF_INET) {
        const auto&   in4 = reinterpret_cast<const sockaddr_in&>(addr);
        std::uint32_t a   = ntohl(in4.sin_addr.s_addr);
        std::uint32_t m   = v4_prefix >= 32 ? ~std::uint32_t(0)
                          : v4_prefix <= 0  ? 0
                                            : ~std::uint32_t(0) << (32 - v4_prefix);
        return 0x0000FFFF00000000ull | (a & m);
    }

    if (addr.ss_family == AF_INET6) {
        const auto&   in6 = reinterpret_cast<const sockaddr_in6&>(addr);
        const auto*   b   = in6.sin6_addr.s6_addr;
        std::uint64_t hi  = 0;
        for (int i = 0; i < 8; i++) hi = hi << 8 | b[i];

        // ::ffff:a.b.c.d from the dual-stack socket: the same client as the
        // AF_INET case above, so it has to produce the same key.
        static const std::uint8_t kMapped[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF};
        if (std::memcmp(b, kMapped, sizeof(kMapped)) == 0) {
            std::uint32_t a = static_cast<std::uint32_t>(b[12]) << 24 |
                              static_cast<std::uint32_t>(b[13]) << 16 |
                              static_cast<std::uint32_t>(b[14]) << 8 |
                              static_cast<std::uint32_t>(b[15]);
            std::uint32_t m = v4_prefix >= 32 ? ~std::uint32_t(0)
                            : v4_prefix <= 0  ? 0
                                              : ~std::uint32_t(0) << (32 - v4_prefix);
            return 0x0000FFFF00000000ull | (a & m);
        }

        return hi & mask_of(v6_prefix);
    }

    return 0;
}

}  // namespace

RateLimiter::RateLimiter(long qps, long burst, int v4_prefix, int v6_prefix)
    : qps_(static_cast<double>(qps)),
      burst_(static_cast<double>(burst > 0 ? burst : qps)),
      v4_prefix_(std::clamp(v4_prefix, 0, 32)),
      v6_prefix_(std::clamp(v6_prefix, 0, 64)),
      shards_(qps > 0 ? kShards : 0) {}

void RateLimiter::sweep(Shard& shard, std::uint64_t now) {
    // A bucket that has had time to refill carries no state worth keeping.
    std::uint64_t idle_ms = static_cast<std::uint64_t>(burst_ / qps_ * 1000.0) + 1000;

    for (auto it = shard.buckets.begin(); it != shard.buckets.end();) {
        if (now - it->second.last >= idle_ms) it = shard.buckets.erase(it);
        else                                  ++it;
    }
}

bool RateLimiter::allow(const sockaddr_storage& addr) {
    if (!enabled()) return true;

    std::uint64_t key = key_of(addr, v4_prefix_, v6_prefix_);
    std::uint64_t now = now_ms();

    // Multiplied by a large odd constant: the low bits of a key are the host
    // part, which is zero once the prefix mask has been applied.
    Shard& shard = shards_[(key * 0x9E3779B97F4A7C15ull) >> 60 & (kShards - 1)];

    std::lock_guard<std::mutex> lock(shard.mutex);

    auto it = shard.buckets.find(key);
    if (it == shard.buckets.end()) {
        if (shard.buckets.size() >= kBucketsPerShard) {
            sweep(shard, now);
            // Still full: every bucket is active, so the table is too small
            // for the client population. Let the query through rather than
            // turning a sizing problem into an outage; the global in-flight
            // cap is still there.
            if (shard.buckets.size() >= kBucketsPerShard) return true;
        }
        it = shard.buckets.emplace(key, Bucket{burst_, now}).first;
    }

    Bucket& b = it->second;

    double elapsed = static_cast<double>(now - b.last) / 1000.0;
    if (elapsed > 0) {
        b.tokens = std::min(burst_, b.tokens + elapsed * qps_);
        b.last   = now;
    }

    if (b.tokens < 1.0) return false;

    b.tokens -= 1.0;
    return true;
}
