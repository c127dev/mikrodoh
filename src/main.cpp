#include <atomic>
#include <chrono>
#include <csignal>
#include <iostream>
#include <memory>
#include <thread>
#include <vector>

#include <curl/curl.h>

#include "cache.h"
#include "config.h"
#include "dispatch.h"
#include "doh_worker.h"
#include "server.h"
#include "stats.h"
#include "tcp_server.h"

namespace {

std::atomic<bool> g_stop{false};
std::atomic<bool> g_dump{false};

void on_signal(int) { g_stop.store(true); }

// Only a flag: the dump itself writes to stdout, which is not async-signal
// safe. The stats thread picks it up.
void on_dump(int) { g_dump.store(true); }

// Sleeps in short slices so SIGUSR1 and shutdown are noticed promptly.
void stats_loop(const Config& cfg, const Stats& stats) {
    constexpr auto kTick = std::chrono::milliseconds(200);
    auto next = std::chrono::steady_clock::now() +
                std::chrono::seconds(cfg.stats_interval_sec);

    while (!g_stop.load()) {
        std::this_thread::sleep_for(kTick);

        bool due = cfg.stats_interval_sec > 0 &&
                   std::chrono::steady_clock::now() >= next;
        if (due) next += std::chrono::seconds(cfg.stats_interval_sec);

        if (due || g_dump.exchange(false)) stats.print(std::cout);
    }
}

}  // namespace

int main() {
    curl_global_init(CURL_GLOBAL_DEFAULT);

    const Config cfg = Config::from_env();

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGUSR1, on_dump);

    DnsCache cache(cfg.cache_ttl);
    Stats    stats;

    std::vector<std::unique_ptr<DohWorker>> workers;
    workers.reserve(static_cast<std::size_t>(cfg.workers));
    for (int i = 0; i < cfg.workers; ++i)
        workers.push_back(std::make_unique<DohWorker>(cfg, cache, stats));

    Dispatcher dispatcher(cfg, cache, stats, workers);

    UdpServer udp(cfg, dispatcher);
    if (!udp.open()) {
        curl_global_cleanup();
        return 1;
    }

    TcpServer tcp(cfg, dispatcher, stats);
    if (cfg.tcp_enabled && !tcp.open()) {
        curl_global_cleanup();
        return 1;
    }

    cfg.print(std::cout);

    std::vector<std::thread> threads;
    for (auto& worker : workers)
        threads.emplace_back([w = worker.get()] { w->run(g_stop); });

    if (cfg.tcp_enabled)
        threads.emplace_back([&tcp] { tcp.run(g_stop); });

    threads.emplace_back([&cfg, &stats] { stats_loop(cfg, stats); });

    udp.run(g_stop);

    for (auto& thread : threads)
        if (thread.joinable()) thread.join();

    curl_global_cleanup();
    return 0;
}
