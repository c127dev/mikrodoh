#include <atomic>
#include <csignal>
#include <iostream>
#include <memory>
#include <thread>
#include <vector>

#include <curl/curl.h>

#include "cache.h"
#include "config.h"
#include "doh_worker.h"
#include "server.h"
#include "stats.h"

namespace {

std::atomic<bool> g_stop{false};

void on_signal(int) { g_stop.store(true); }

}  // namespace

int main() {
    curl_global_init(CURL_GLOBAL_DEFAULT);

    const Config cfg = Config::from_env();

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGPIPE, SIG_IGN);

    DnsCache  cache(cfg.cache_ttl);
    Stats     stats;
    UdpServer server(cfg, cache, stats);

    if (!server.open()) {
        curl_global_cleanup();
        return 1;
    }

    cfg.print(std::cout);

    std::vector<std::unique_ptr<DohWorker>> workers;
    std::vector<std::thread>                threads;
    workers.reserve(static_cast<std::size_t>(cfg.workers));

    for (int i = 0; i < cfg.workers; ++i)
        workers.push_back(std::make_unique<DohWorker>(cfg, cache, stats, server.fd()));
    for (auto& worker : workers)
        threads.emplace_back([w = worker.get()] { w->run(g_stop); });

    server.run(workers, g_stop);

    for (auto& thread : threads)
        if (thread.joinable()) thread.join();

    curl_global_cleanup();
    return 0;
}
