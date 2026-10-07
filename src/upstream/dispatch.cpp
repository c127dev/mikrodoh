// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Johan Alvarado

#include "upstream/dispatch.h"

#include "dns/cache.h"
#include "dns/dns.h"
#include "dns/health.h"
#include "upstream/doh_worker.h"

#include <functional>
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

    // Charge every datagram, cache hits included.
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

    if (t->query_truncated) {
        stats_.oversized++;

        std::vector<std::uint8_t> fail =
            dns::make_error(msg, len, dns::kRcodeFormErr);
        if (!fail.empty()) t->reply(fail.data(), fail.size());
        return;
    }

    // Answering malformed datagrams or responses makes a reflector.
    if (!dns::query_valid(msg, len)) {
        stats_.rejected++;
        return;
    }

    if (cfg_.refuse_any && dns::is_any(msg, len)) {
        std::vector<std::uint8_t> reply = dns::any_reply(msg, len);
        if (!reply.empty()) t->reply(reply.data(), reply.size());
        stats_.served++;
        return;
    }

    if (health::is_probe(msg, len)) {
        t->health_query = std::move(t->payload);
        t->payload      = health::upstream_request(msg, len);
    } else {
        t->cache_key = DnsCache::key_of(msg, len);

        std::vector<std::uint8_t> cached;
        bool                      refresh = false;
        if (cache_.lookup(t->cache_key, cached, cfg_.prefetch ? &refresh : nullptr)) {
            cached[0] = msg[0];  // the client's transaction ID, not the cached one
            cached[1] = msg[1];
            t->reply(cached.data(), cached.size());
            stats_.served++;
            stats_.cache_hits++;
            if (refresh) prefetch(std::move(t));
            return;
        }
    }

    if (stats_.inflight.load(std::memory_order_relaxed) >= cfg_.max_inflight) {
        unsigned long dropped = ++stats_.dropped;
        if ((dropped & 0x3FF) == 0)
            std::cerr << "[shed] dropped " << dropped << " queries (in-flight cap "
                      << cfg_.max_inflight << ")\n";

        std::vector<std::uint8_t> fail =
            dns::make_error(msg, len, dns::kRcodeServFail);
        if (!fail.empty()) t->reply(fail.data(), fail.size());
        return;
    }

    dns::sanitize_edns(t->payload);

    stats_.inflight++;
    if (t->conn) t->conn->inflight++;
    submit(std::move(t));
}

void Dispatcher::submit(std::unique_ptr<Transfer> t) {
    std::size_t slot = t->cache_key.empty()
                           ? next_.fetch_add(1, std::memory_order_relaxed)
                           : std::hash<std::string>{}(t->cache_key);
    workers_[slot % workers_.size()]->submit(t.release());
}

void Dispatcher::prefetch(std::unique_ptr<Transfer> t) {
    if (stats_.inflight.load(std::memory_order_relaxed) >= cfg_.max_inflight / 2) return;

    auto p       = std::make_unique<Transfer>();
    p->prefetch  = true;
    p->payload   = std::move(t->payload);
    p->cache_key = std::move(t->cache_key);
    dns::sanitize_edns(p->payload);

    stats_.prefetched++;
    submit(std::move(p));
}
