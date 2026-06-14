#pragma once

#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

#include <curl/curl.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "config.h"
#include "stats.h"

class DnsCache;

// One outstanding DoH request. Lives from start() to CURLMSG_DONE.
struct Transfer {
    sockaddr_in               client_addr{};
    socklen_t                 addr_len = 0;
    std::vector<std::uint8_t> payload;
    std::vector<std::uint8_t> response;
    std::string               cache_key;
};

// A curl_multi event loop. Every query it owns is multiplexed onto a single
// HTTP/2 connection, so concurrency is capped by Config::max_inflight rather
// than by thread count.
class DohWorker {
public:
    DohWorker(const Config& cfg, DnsCache& cache, Stats& stats, int udp_socket);
    ~DohWorker();

    DohWorker(const DohWorker&)            = delete;
    DohWorker& operator=(const DohWorker&) = delete;

    // Producer side: takes ownership of `t` and wakes the loop.
    void submit(Transfer* t);

    void run(const std::atomic<bool>& stop);

private:
    void  configure(CURL* handle) const;
    CURL* acquire();
    void  start(Transfer* t);
    void  reap();

    const Config& cfg_;
    DnsCache&     cache_;
    Stats&        stats_;
    int           udp_socket_;

    CURLM*             multi_   = nullptr;
    struct curl_slist* headers_ = nullptr;

    std::mutex             inbox_mutex_;
    std::vector<Transfer*> inbox_;
    std::vector<CURL*>     idle_;
};
