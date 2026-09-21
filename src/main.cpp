#include <atomic>
#include <chrono>
#include <csignal>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include <curl/curl.h>

#include "cache.h"
#include "config.h"
#include "dispatch.h"
#include "doh_worker.h"
#include "health.h"
#include "privs.h"
#include "sandbox.h"
#include "server.h"
#include "stats.h"
#include "tcp_server.h"
#include "upstream.h"

namespace {

std::atomic<bool> g_stop{false};
std::atomic<bool> g_dump{false};
std::atomic<bool> g_reload{false};

void on_signal(int) { g_stop.store(true); }

// Only a flag: the dump itself writes to stdout, which is not async-signal
// safe. The stats thread picks it up.
void on_dump(int) { g_dump.store(true); }
void on_reload(int) { g_reload.store(true); }

// Re-reads CONFIG_FILE and the environment, and swaps in the resolver
// settings. The cache and the open upstream connections are kept. A
// configuration that would fail at startup is refused and the old one stays.
void reload(UpstreamSource& upstream) {
    Config next = Config::from_env();
    if (!next.load_error.empty()) {
        std::cerr << "reload: " << next.load_error << ", keeping the old configuration\n";
        return;
    }
    if (!next.resolvers_reachable(std::cerr)) {
        std::cerr << "reload: keeping the old configuration\n";
        return;
    }

    upstream.set(std::make_shared<const Upstream>(next));

    std::string line = "reload: " + std::to_string(next.doh_urls.size()) + " resolver(s),";
    for (const std::string& url : next.doh_urls) line += " " + url;
    std::cout << line << "\n" << std::flush;
}

// Sleeps in short slices so SIGUSR1 and shutdown are noticed promptly.
void stats_loop(const Config& cfg, const Stats& stats, UpstreamSource& upstream) {
    constexpr auto kTick = std::chrono::milliseconds(200);
    auto next = std::chrono::steady_clock::now() +
                std::chrono::seconds(cfg.stats_interval_sec);

    while (!g_stop.load()) {
        std::this_thread::sleep_for(kTick);

        bool due = cfg.stats_interval_sec > 0 &&
                   std::chrono::steady_clock::now() >= next;
        if (due) next += std::chrono::seconds(cfg.stats_interval_sec);

        if (due || g_dump.exchange(false)) stats.print(std::cout);
        if (g_reload.exchange(false)) reload(upstream);
    }
}

}  // namespace

int main(int argc, char** argv) {
    if (argc == 2 && std::string(argv[1]) == "--health")
        return health::run_probe(Config::from_env());

    curl_global_init(CURL_GLOBAL_DEFAULT);

    const Config cfg = Config::from_env();
    if (!cfg.load_error.empty()) {
        std::cerr << "Invalid configuration: " << cfg.load_error << "\n";
        curl_global_cleanup();
        return 1;
    }

    // Before any socket: a resolver this daemon cannot reach without asking
    // itself never answers, and the failure looks like a network outage.
    if (!cfg.resolvers_reachable(std::cerr)) {
        curl_global_cleanup();
        return 1;
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGUSR1, on_dump);
    signal(SIGHUP, on_reload);

    DnsCache cache(cfg.cache_ttl, 10000, cfg.serve_stale, cfg.cache_min_ttl, cfg.cache_max_ttl);
    Stats    stats;

    UpstreamSource upstream(std::make_shared<const Upstream>(cfg));

    std::vector<std::unique_ptr<DohWorker>> workers;
    workers.reserve(static_cast<std::size_t>(cfg.workers));
    for (int i = 0; i < cfg.workers; ++i)
        workers.push_back(std::make_unique<DohWorker>(cfg, cache, stats, upstream));

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

    // After the binds, so a privileged port still works, and before any
    // worker thread exists to inherit the old credentials.
    if (!drop_privileges(cfg.run_as_user, cfg.run_as_group)) {
        curl_global_cleanup();
        return 1;
    }

    if (cfg.sandbox && !enter_sandbox()) {
        curl_global_cleanup();
        return 1;
    }

    cfg.print(std::cout);

    std::vector<std::thread> threads;
    for (auto& worker : workers)
        threads.emplace_back([w = worker.get()] { w->run(g_stop); });

    if (cfg.tcp_enabled)
        threads.emplace_back([&tcp] { tcp.run(g_stop); });

    threads.emplace_back([&cfg, &stats, &upstream] { stats_loop(cfg, stats, upstream); });

    // Reader 0 runs on this thread, so main still blocks until shutdown.
    for (std::size_t i = 1; i < udp.readers(); ++i)
        threads.emplace_back([&udp, i] { udp.run(i, g_stop); });

    udp.run(0, g_stop);

    for (auto& thread : threads)
        if (thread.joinable()) thread.join();

    curl_global_cleanup();
    return 0;
}
