#pragma once

#include <atomic>
#include <chrono>
#include <cstddef>
#include <mutex>
#include <unordered_set>
#include <vector>

#include <curl/curl.h>

#include "coalesce.h"
#include "config.h"
#include "stats.h"
#include "transfer.h"
#include "upstream.h"

class DnsCache;

class DohWorker {
public:
    DohWorker(const Config& cfg, DnsCache& cache, Stats& stats, UpstreamSource& upstream);
    ~DohWorker();

    DohWorker(const DohWorker&)            = delete;
    DohWorker& operator=(const DohWorker&) = delete;

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
    void        answer(Transfer* t, const std::vector<std::uint8_t>* response);
    std::size_t pick_url(const Transfer* t) const;
    void        mark_down(const Transfer* t);
    void        mark_up(const Transfer* t);
    void        refresh_upstream();
    void        keep_warm();

    const Config& cfg_;
    DnsCache&     cache_;
    Stats&        stats_;

    CURLM*             multi_   = nullptr;
    struct curl_slist* headers_ = nullptr;

    UpstreamSource&                 source_;
    std::shared_ptr<const Upstream> up_;
    unsigned                        up_generation_ = 0;

    struct Resolver {
        std::chrono::steady_clock::time_point down_until{};
        unsigned                              fails = 0;
    };
    std::vector<Resolver> health_;

    std::mutex             inbox_mutex_;
    std::vector<Transfer*> inbox_;
    std::vector<CURL*>     idle_;

    std::unordered_set<CURL*> active_;

    Coalescer coalescer_;

    std::chrono::steady_clock::time_point last_start_ = std::chrono::steady_clock::now();

    bool draining_ = false;
};
