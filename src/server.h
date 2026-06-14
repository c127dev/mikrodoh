#pragma once

#include <atomic>
#include <memory>
#include <vector>

#include "config.h"
#include "stats.h"

class DnsCache;
class DohWorker;

// Producer: reads UDP queries, answers from cache when it can, otherwise
// round-robins them onto the workers.
class UdpServer {
public:
    UdpServer(const Config& cfg, DnsCache& cache, Stats& stats);
    ~UdpServer();

    UdpServer(const UdpServer&)            = delete;
    UdpServer& operator=(const UdpServer&) = delete;

    bool open();
    int  fd() const { return fd_; }

    void run(std::vector<std::unique_ptr<DohWorker>>& workers,
             const std::atomic<bool>&                 stop);

private:
    const Config& cfg_;
    DnsCache&     cache_;
    Stats&        stats_;
    int           fd_ = -1;
};
