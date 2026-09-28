#pragma once

#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

struct Config;
struct curl_slist;

struct Upstream {
    explicit Upstream(const Config& cfg);
    ~Upstream();

    Upstream(const Upstream&)            = delete;
    Upstream& operator=(const Upstream&) = delete;

    std::vector<std::string> urls;
    curl_slist* resolve = nullptr;

    int  connect_timeout_ms;
    int  request_timeout_ms;
    int  cooldown_ms;
    bool check_cert;
    int  tcp_keep_alive;
};

class UpstreamSource {
public:
    explicit UpstreamSource(std::shared_ptr<const Upstream> initial);

    std::shared_ptr<const Upstream> get() const;
    void                            set(std::shared_ptr<const Upstream> next);

    unsigned generation() const { return generation_.load(std::memory_order_acquire); }

private:
    mutable std::mutex              mutex_;
    std::shared_ptr<const Upstream> current_;
    std::atomic<unsigned>           generation_{0};
};
