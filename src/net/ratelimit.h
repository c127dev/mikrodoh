// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Johan Alvarado

#pragma once

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <unordered_map>
#include <vector>

#include <netinet/in.h>
#include <sys/socket.h>

class RateLimiter {
public:
    RateLimiter(long qps, long burst, int v4_prefix, int v6_prefix);

    bool enabled() const { return qps_ > 0; }

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

    void sweep(Shard& shard, std::uint64_t now);

    double qps_;
    double burst_;
    int    v4_prefix_;
    int    v6_prefix_;

    std::vector<Shard> shards_;
};
