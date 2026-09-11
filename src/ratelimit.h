#pragma once

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <unordered_map>
#include <vector>

#include <netinet/in.h>
#include <sys/socket.h>

// Token bucket per source prefix, so one loud or spoofed source cannot spend
// the global in-flight budget that every other client shares.
//
// Clients are grouped by prefix rather than by address: a single host is one
// bucket, and an IPv6 host that rotates its address every query still lands in
// the bucket of the /56 it was delegated.
class RateLimiter {
public:
    // `qps` is the sustained rate per prefix and `burst` the bucket depth.
    // qps <= 0 disables the limiter and allow() always succeeds.
    //
    // Prefix lengths are capped at 32 for IPv4 and 64 for IPv6, which is all
    // the key holds.
    RateLimiter(long qps, long burst, int v4_prefix, int v6_prefix);

    bool enabled() const { return qps_ > 0; }

    // One token for one query. False means the source is over its rate.
    bool allow(const sockaddr_storage& addr);

private:
    struct Bucket {
        double        tokens = 0;
        std::uint64_t last   = 0;  // steady clock, milliseconds
    };

    struct Shard {
        std::mutex                               mutex;
        std::unordered_map<std::uint64_t, Bucket> buckets;
    };

    // An entry is dropped once it has been idle long enough to have refilled,
    // because a full bucket is indistinguishable from one that never existed.
    void sweep(Shard& shard, std::uint64_t now);

    double qps_;
    double burst_;
    int    v4_prefix_;
    int    v6_prefix_;

    // Sharded so the UDP readers and the TCP loop do not serialise on one
    // mutex. Sized at construction and never resized, so no lock is needed to
    // pick a shard.
    std::vector<Shard> shards_;
};
