#pragma once

#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

struct Config;
struct curl_slist;

// The settings a SIGHUP can change without a restart: which resolvers are
// asked and how. A transfer keeps the snapshot it started with, so a reload
// never changes the list under a query that is walking it.
struct Upstream {
    explicit Upstream(const Config& cfg);
    ~Upstream();

    Upstream(const Upstream&)            = delete;
    Upstream& operator=(const Upstream&) = delete;

    std::vector<std::string> urls;
    // Config::resolve_entries as a curl list, null when every resolver is an
    // IP literal.
    curl_slist* resolve = nullptr;

    int  connect_timeout_ms;
    int  request_timeout_ms;
    int  cooldown_ms;
    bool check_cert;
    int  tcp_keep_alive;
};

// The current snapshot, swapped by a reload and polled by every worker loop.
class UpstreamSource {
public:
    explicit UpstreamSource(std::shared_ptr<const Upstream> initial);

    std::shared_ptr<const Upstream> get() const;
    void                            set(std::shared_ptr<const Upstream> next);

    // Bumped by every set(), so a loop can tell cheaply whether to get().
    unsigned generation() const { return generation_.load(std::memory_order_acquire); }

private:
    mutable std::mutex              mutex_;
    std::shared_ptr<const Upstream> current_;
    std::atomic<unsigned>           generation_{0};
};
