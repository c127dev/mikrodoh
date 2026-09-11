#include "dispatch.h"

#include "cache.h"
#include "dns.h"
#include "doh_worker.h"

#include <iostream>

Dispatcher::Dispatcher(const Config& cfg, DnsCache& cache, Stats& stats,
                       std::vector<std::unique_ptr<DohWorker>>& workers)
    : cfg_(cfg),
      cache_(cache),
      stats_(stats),
      workers_(workers),
      limiter_(cfg.rate_limit_qps, cfg.rate_limit_burst, cfg.rate_limit_v4_prefix,
               cfg.rate_limit_v6_prefix) {}

void Dispatcher::dispatch(std::unique_ptr<Transfer> t) {
    const std::uint8_t* msg = t->payload.data();
    const std::size_t   len = t->payload.size();

    // Answering a malformed datagram, or one that is already a response, is
    // what turns a resolver into a reflector. Drop it.
    if (!dns::query_valid(msg, len)) {
        stats_.rejected++;
        return;
    }

    // Per-source budget before anything else is spent on the query, cache hits
    // included: the point is to cap what one source can make this daemon send,
    // not only what it can make it fetch.
    if (!limiter_.allow(t->client_addr)) {
        unsigned long throttled = ++stats_.throttled;
        if ((throttled & 0x3FF) == 0)
            std::cerr << "[rate] throttled " << throttled << " queries ("
                      << cfg_.rate_limit_qps << " qps per prefix)\n";

        std::vector<std::uint8_t> fail =
            dns::make_error(msg, len, dns::kRcodeServFail);
        if (!fail.empty()) t->reply(fail.data(), fail.size());
        return;
    }

    if (cache_.enabled()) {
        t->cache_key = DnsCache::key_of(msg, len);

        std::vector<std::uint8_t> cached;
        if (cache_.lookup(t->cache_key, cached)) {
            cached[0] = msg[0];  // the client's transaction ID, not the cached one
            cached[1] = msg[1];
            t->reply(cached.data(), cached.size());
            stats_.served++;
            stats_.cache_hits++;
            return;
        }
    }

    // Shed instead of queueing without bound: accepted queries keep their
    // latency and the box degrades gracefully under burst.
    if (stats_.inflight.load(std::memory_order_relaxed) >= cfg_.max_inflight) {
        unsigned long dropped = ++stats_.dropped;
        if ((dropped & 0x3FF) == 0)
            std::cerr << "[shed] dropped " << dropped << " queries (in-flight cap "
                      << cfg_.max_inflight << ")\n";

        // Say no now: a silent drop makes a UDP client wait out its own timeout
        // and leaves a TCP connection open until the idle sweep, which holds a
        // slot the cap is meant to free.
        std::vector<std::uint8_t> fail =
            dns::make_error(msg, len, dns::kRcodeServFail);
        if (!fail.empty()) t->reply(fail.data(), fail.size());
        return;
    }

    stats_.inflight++;
    if (t->conn) t->conn->inflight++;

    unsigned slot = next_.fetch_add(1, std::memory_order_relaxed);
    workers_[slot % workers_.size()]->submit(t.release());
}
