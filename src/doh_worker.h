#pragma once

#include <atomic>
#include <mutex>
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
    void  configure(CURL* handle) const;
    CURL* acquire();
    void  release(CURL* handle);
    void  start(Transfer* t);
    void  reap();
    void  finish(Transfer* t, bool ok);

    const Config& cfg_;
    DnsCache&     cache_;
    Stats&        stats_;

    CURLM*             multi_   = nullptr;
    struct curl_slist* headers_ = nullptr;

    std::mutex             inbox_mutex_;
    std::vector<Transfer*> inbox_;
    std::vector<CURL*>     idle_;
};
