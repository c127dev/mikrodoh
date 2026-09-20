#include "upstream.h"

#include "config.h"

#include <curl/curl.h>

Upstream::Upstream(const Config& cfg)
    : urls(cfg.doh_urls),
      connect_timeout_ms(cfg.connect_timeout_ms),
      request_timeout_ms(cfg.request_timeout_ms),
      cooldown_ms(cfg.resolver_cooldown_ms),
      check_cert(cfg.check_cert),
      tcp_keep_alive(cfg.tcp_keep_alive) {
    for (const std::string& entry : cfg.resolve_entries)
        resolve = curl_slist_append(resolve, entry.c_str());
}

Upstream::~Upstream() { curl_slist_free_all(resolve); }

UpstreamSource::UpstreamSource(std::shared_ptr<const Upstream> initial)
    : current_(std::move(initial)) {}

std::shared_ptr<const Upstream> UpstreamSource::get() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return current_;
}

void UpstreamSource::set(std::shared_ptr<const Upstream> next) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        current_ = std::move(next);
    }
    generation_.fetch_add(1, std::memory_order_release);
}
