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

class Dispatcher {
public:
    Dispatcher(const Config& cfg, DnsCache& cache, Stats& stats,
               std::vector<std::unique_ptr<DohWorker>>& workers);

    void dispatch(std::unique_ptr<Transfer> t);

private:
    void submit(std::unique_ptr<Transfer> t);
    void prefetch(std::unique_ptr<Transfer> t);

    const Config& cfg_;
    DnsCache&     cache_;
    Stats&        stats_;

    std::vector<std::unique_ptr<DohWorker>>& workers_;
    std::atomic<unsigned>                    next_{0};

    RateLimiter limiter_;
};
