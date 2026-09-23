#pragma once

#include <atomic>
#include <memory>
#include <vector>

#include "config.h"
#include "ratelimit.h"
#include "stats.h"
#include "transfer.h"

class DnsCache;
class DohWorker;

// The path every query takes once it has been read off a socket, whichever
// transport read it: validate, answer from cache, shed, or hand to a worker.
class Dispatcher {
public:
    Dispatcher(const Config& cfg, DnsCache& cache, Stats& stats,
               std::vector<std::unique_ptr<DohWorker>>& workers);

    // Takes ownership. `t` must already carry its payload and reply target.
    void dispatch(std::unique_ptr<Transfer> t);

private:
    // Hands `t` to the worker that owns its cache key.
    void submit(std::unique_ptr<Transfer> t);
    // Refreshes the cache entry `t` was just answered from.
    void prefetch(std::unique_ptr<Transfer> t);

    const Config& cfg_;
    DnsCache&     cache_;
    Stats&        stats_;

    std::vector<std::unique_ptr<DohWorker>>& workers_;
    std::atomic<unsigned>                    next_{0};

    RateLimiter limiter_;
};
