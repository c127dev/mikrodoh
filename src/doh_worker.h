#pragma once

#include <atomic>
#include <chrono>
#include <cstddef>
#include <mutex>
#include <unordered_set>
#include <vector>

#include <curl/curl.h>

#include "config.h"
#include "stats.h"
#include "transfer.h"

class DnsCache;

// A curl_multi event loop. Every query it owns is multiplexed onto a single
// HTTP/2 connection, so concurrency is capped by Config::max_inflight rather
// than by thread count.
class DohWorker {
public:
    DohWorker(const Config& cfg, DnsCache& cache, Stats& stats);
    ~DohWorker();

    DohWorker(const DohWorker&)            = delete;
    DohWorker& operator=(const DohWorker&) = delete;

    // Producer side: takes ownership of `t` and wakes the loop.
    void submit(Transfer* t);

    void run(const std::atomic<bool>& stop);

private:
    void        configure(CURL* handle) const;
    CURL*       acquire();
    void        release(CURL* handle);
    void        start(Transfer* t);
    void        reap();
    void        drain();
    void        finish(Transfer* t, bool ok);
    std::size_t pick_url(std::size_t from) const;
    void        mark_down(std::size_t url);
    void        mark_up(std::size_t url);

    const Config& cfg_;
    DnsCache&     cache_;
    Stats&        stats_;

    CURLM*             multi_   = nullptr;
    struct curl_slist* headers_ = nullptr;

    // What this loop has learnt about each entry of Config::doh_urls. It is
    // per-worker and needs no locking: a dead resolver is found again by every
    // worker at most once per cooldown.
    struct Resolver {
        std::chrono::steady_clock::time_point down_until{};
        unsigned                              fails = 0;
    };
    std::vector<Resolver> health_;

    std::mutex             inbox_mutex_;
    std::vector<Transfer*> inbox_;
    std::vector<CURL*>     idle_;

    // The handles currently in multi_. curl cannot be asked what it is still
    // carrying, and shutdown has to answer and free every one of them.
    std::unordered_set<CURL*> active_;

    // Set once the loop has left: a failed transfer is answered rather than
    // retried against the next resolver.
    bool draining_ = false;
};
