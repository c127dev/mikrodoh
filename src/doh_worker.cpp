#include "doh_worker.h"

#include "cache.h"
#include "dns.h"
#include "health.h"

#include <iostream>
#include <string>

namespace {

size_t write_callback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t bytes = size * nmemb;
    auto*  out   = static_cast<std::vector<std::uint8_t>*>(userp);
    auto*  in    = static_cast<std::uint8_t*>(contents);
    out->insert(out->end(), in, in + bytes);
    return bytes;
}

// An idle handle keeps its connection warm, but one per completed transfer
// would grow the pool to MAX_INFLIGHT and hold that many sockets open.
constexpr std::size_t kMaxIdleHandles = 64;

// How long shutdown waits for in-flight transfers before failing them.
constexpr int kDrainTimeoutMs = 2000;

}  // namespace

DohWorker::DohWorker(const Config& cfg, DnsCache& cache, Stats& stats,
                     UpstreamSource& upstream)
    : cfg_(cfg), cache_(cache), stats_(stats), source_(upstream) {
    refresh_upstream();

    multi_ = curl_multi_init();
    curl_multi_setopt(multi_, CURLMOPT_PIPELINING, CURLPIPE_MULTIPLEX);
    curl_multi_setopt(multi_, CURLMOPT_MAX_CONCURRENT_STREAMS, 1000L);

    headers_ = curl_slist_append(headers_, "Content-Type: application/dns-message");
    headers_ = curl_slist_append(headers_, "Accept: application/dns-message");
}

DohWorker::~DohWorker() {
    for (CURL* h : idle_) curl_easy_cleanup(h);
    curl_slist_free_all(headers_);
    curl_multi_cleanup(multi_);

    for (Transfer* t : inbox_) delete t;
}

void DohWorker::configure(CURL* handle) const {
    // The URL, timeouts and bootstrap addresses are not set here: a pooled
    // handle outlives a reload, so start() sets them per transfer.
    curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(handle, CURLOPT_HTTPHEADER, headers_);
    curl_easy_setopt(handle, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2TLS);

    // Wait for the existing multiplexed connection instead of opening another,
    // which is what keeps every stream on one HTTP/2 connection.
    curl_easy_setopt(handle, CURLOPT_PIPEWAIT, 1L);

    if (cfg_.ip_version != IpVersion::Any)
        curl_easy_setopt(handle, CURLOPT_IPRESOLVE,
                         cfg_.ip_version == IpVersion::V6 ? CURL_IPRESOLVE_V6
                                                          : CURL_IPRESOLVE_V4);

    if (cfg_.prefer_chacha) {
        curl_easy_setopt(handle, CURLOPT_TLS13_CIPHERS, "TLS_CHACHA20_POLY1305_SHA256");
        curl_easy_setopt(handle, CURLOPT_SSL_CIPHER_LIST,
                         "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305");
    }
}

CURL* DohWorker::acquire() {
    if (!idle_.empty()) {
        CURL* handle = idle_.back();
        idle_.pop_back();
        return handle;
    }

    CURL* handle = curl_easy_init();
    if (handle) configure(handle);
    return handle;
}

void DohWorker::release(CURL* handle) {
    if (idle_.size() < kMaxIdleHandles) {
        idle_.push_back(handle);
        return;
    }
    curl_easy_cleanup(handle);
}

void DohWorker::refresh_upstream() {
    up_generation_ = source_.generation();
    up_            = source_.get();
    health_.assign(up_->urls.size(), Resolver{});
}

std::size_t DohWorker::pick_url(const Transfer* t) const {
    if (t->up != up_) return t->url;

    std::size_t n   = up_->urls.size();
    auto        now = std::chrono::steady_clock::now();

    for (std::size_t i = t->url; i < n; i++)
        if (health_[i].down_until <= now) return i;

    // Everything left is in cooldown. Send the query to the next one anyway
    // rather than fail it outright: that request is also the probe that ends
    // the cooldown.
    return t->url;
}

void DohWorker::mark_down(const Transfer* t) {
    if (t->up != up_ || up_->cooldown_ms <= 0) return;

    Resolver& r = health_[t->url];
    if (r.fails < 4) r.fails++;  // the backoff caps at 16x the base cooldown

    auto cooldown = std::chrono::milliseconds(
        static_cast<long long>(up_->cooldown_ms) << (r.fails - 1));
    r.down_until = std::chrono::steady_clock::now() + cooldown;

    std::cerr << "resolver " << up_->urls[t->url] << " marked down for "
              << cooldown.count() << "ms\n";
}

void DohWorker::mark_up(const Transfer* t) {
    if (t->up != up_) return;

    Resolver& r = health_[t->url];
    if (r.fails == 0) return;

    r.fails      = 0;
    r.down_until = {};
    std::cerr << "resolver " << up_->urls[t->url] << " is answering again\n";
}

void DohWorker::start(Transfer* t) {
    if (!t->up) t->up = up_;
    last_start_ = std::chrono::steady_clock::now();

    const Upstream& up = *t->up;
    if (t->url >= up.urls.size()) {
        finish(t, false);
        return;
    }
    t->url = pick_url(t);

    CURL* handle = acquire();
    if (!handle) {
        finish(t, false);
        return;
    }

    t->response.clear();
    curl_easy_setopt(handle, CURLOPT_URL, up.urls[t->url].c_str());

    // A resolver named by hostname is reached through this, not getaddrinfo:
    // that lookup would be sent to whatever the box's resolver is, which is
    // this daemon, and never complete. The list lives as long as `t->up`.
    curl_easy_setopt(handle, CURLOPT_RESOLVE, up.resolve);

    // Without these a stalled transfer holds its in-flight slot forever, and
    // enough of them pin MAX_INFLIGHT with no recovery.
    curl_easy_setopt(handle, CURLOPT_TIMEOUT_MS, static_cast<long>(up.request_timeout_ms));
    curl_easy_setopt(handle, CURLOPT_CONNECTTIMEOUT_MS,
                     static_cast<long>(up.connect_timeout_ms));

    curl_easy_setopt(handle, CURLOPT_SSL_VERIFYPEER, up.check_cert ? 1L : 0L);
    curl_easy_setopt(handle, CURLOPT_SSL_VERIFYHOST, up.check_cert ? 2L : 0L);

    long keep_alive = up.tcp_keep_alive;
    curl_easy_setopt(handle, CURLOPT_TCP_KEEPALIVE, keep_alive > 0 ? 1L : 0L);
    if (keep_alive > 0) {
        curl_easy_setopt(handle, CURLOPT_TCP_KEEPIDLE, keep_alive);
        curl_easy_setopt(handle, CURLOPT_TCP_KEEPINTVL, keep_alive);
    }

    curl_easy_setopt(handle, CURLOPT_POSTFIELDS, t->payload.data());
    curl_easy_setopt(handle, CURLOPT_POSTFIELDSIZE, static_cast<long>(t->payload.size()));
    curl_easy_setopt(handle, CURLOPT_WRITEDATA, &t->response);
    curl_easy_setopt(handle, CURLOPT_PRIVATE, t);
    curl_multi_add_handle(multi_, handle);
    active_.insert(handle);
}

void DohWorker::finish(Transfer* t, bool ok) {
    if (t->warm) {
        delete t;
        return;
    }

    std::vector<Transfer*> followers = coalescer_.release(t);

    if (ok) {
        // An HTTP 200 only means the resolver answered. SERVFAIL and REFUSED
        // are transient or policy-driven, so they are not cached at all; a
        // negative answer is cached for a shorter time than a real one.
        std::uint8_t rc = dns::rcode(t->response.data(), t->response.size());
        if (rc == dns::kRcodeNoError || rc == dns::kRcodeNxDomain) {
            bool negative = rc == dns::kRcodeNxDomain ||
                            !dns::has_answers(t->response.data(), t->response.size());
            // CACHE_NEGATIVE=0 keeps negative answers out of the cache.
            if (!negative)
                cache_.store(t->cache_key, t->response);
            else if (cfg_.cache_negative_ttl > 0)
                cache_.store(t->cache_key, t->response, cfg_.cache_negative_ttl);
        }
    }

    const std::vector<std::uint8_t>* response = ok ? &t->response : nullptr;

    // Every resolver failed. An expired answer keeps the LAN resolving through
    // an uplink outage, where SERVFAIL would not.
    std::vector<std::uint8_t> stale;
    if (!ok && cache_.lookup_stale(t->cache_key, stale)) {
        response = &stale;
        stats_.stale += 1 + followers.size();
    }
    for (Transfer* f : followers) {
        stats_.coalesced++;
        answer(f, response);
    }
    answer(t, response);
}

// Replies to `t` with `response` under its own transaction ID, or SERVFAIL
// when `response` is null, then frees it.
void DohWorker::answer(Transfer* t, const std::vector<std::uint8_t>* response) {
    if (!t->health_query.empty()) {
        bool healthy = response &&
                       dns::rcode(response->data(), response->size()) == dns::kRcodeNoError;
        std::vector<std::uint8_t> out =
            health::answer(t->health_query.data(), t->health_query.size(), healthy);
        if (!out.empty()) t->reply(out.data(), out.size());
        healthy ? stats_.served++ : stats_.failed++;
    } else if (response && response->size() >= 2 && t->payload.size() >= 2) {
        std::vector<std::uint8_t> out = *response;
        out[0] = t->payload[0];
        out[1] = t->payload[1];
        t->reply(out.data(), out.size());
        stats_.served++;
    } else {
        // Say so rather than staying silent: a client with no answer waits out
        // its own timeout before trying anything else.
        std::vector<std::uint8_t> fail = dns::make_error(
            t->payload.data(), t->payload.size(), dns::kRcodeServFail);
        if (!fail.empty()) t->reply(fail.data(), fail.size());
        stats_.failed++;
    }

    if (t->conn) t->conn->inflight--;
    delete t;
    stats_.inflight--;
}

void DohWorker::reap() {
    CURLMsg* msg     = nullptr;
    int      pending = 0;

    while ((msg = curl_multi_info_read(multi_, &pending))) {
        if (msg->msg != CURLMSG_DONE) continue;

        CURL*     handle = msg->easy_handle;
        Transfer* t      = nullptr;
        curl_easy_getinfo(handle, CURLINFO_PRIVATE, &t);

        long http_code = 0;
        curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &http_code);

        bool transferred = msg->data.result == CURLE_OK && http_code == 200;

        // An answer that does not match the question is not an answer: without
        // this the body is relayed to the client whatever it holds.
        bool ok = transferred &&
                  dns::response_matches(t->payload.data(), t->payload.size(),
                                        t->response.data(), t->response.size());

        if (!ok)
            std::cerr << "DoH transfer failed on " << t->up->urls[t->url]
                      << ": "
                      << (transferred ? "answer does not match the query"
                                      : curl_easy_strerror(msg->data.result))
                      << " (HTTP " << http_code << ")\n";

        curl_multi_remove_handle(multi_, handle);
        active_.erase(handle);
        release(handle);

        ok ? mark_up(t) : mark_down(t);

        if (!ok && !draining_ && !t->warm && t->url + 1 < t->up->urls.size()) {
            t->url++;
            start(t);
            continue;
        }

        finish(t, ok);
    }
}

void DohWorker::keep_warm() {
    if (cfg_.warm_interval_sec <= 0 || !active_.empty()) return;

    auto now = std::chrono::steady_clock::now();
    if (now - last_start_ < std::chrono::seconds(cfg_.warm_interval_sec)) return;

    // `. IN NS`: small, always answerable, and not cached here.
    auto* t    = new Transfer;
    t->warm    = true;
    t->payload = {0, 0, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1};
    start(t);
}

void DohWorker::submit(Transfer* t) {
    {
        std::lock_guard<std::mutex> lock(inbox_mutex_);
        inbox_.push_back(t);
    }
    curl_multi_wakeup(multi_);
}

void DohWorker::drain() {
    draining_ = true;

    // Whatever was submitted but never started has no request in flight to wait
    // for, so it is answered outright.
    std::vector<Transfer*> queued;
    {
        std::lock_guard<std::mutex> lock(inbox_mutex_);
        queued.swap(inbox_);
    }
    for (Transfer* t : queued) finish(t, false);

    // Give the transfers already on the wire a bounded window to land. Their
    // own REQUEST_TIMEOUT_MS may be longer than an operator will wait for the
    // process to exit.
    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::milliseconds(kDrainTimeoutMs);

    int still_running = 0;
    do {
        curl_multi_perform(multi_, &still_running);
        reap();
        if (active_.empty()) break;
        curl_multi_poll(multi_, nullptr, 0, 50, nullptr);
    } while (std::chrono::steady_clock::now() < deadline);

    // One write: every worker drains at once and a streamed line interleaves.
    if (!active_.empty())
        std::cerr << "shutdown: failing " + std::to_string(active_.size()) +
                         " transfer(s) still in flight\n";

    // Answering these is the only way their clients hear anything, and removing
    // the handle is the only way the Transfer behind it is freed.
    for (CURL* handle : active_) {
        Transfer* t = nullptr;
        curl_easy_getinfo(handle, CURLINFO_PRIVATE, &t);

        curl_multi_remove_handle(multi_, handle);
        curl_easy_cleanup(handle);

        if (t) finish(t, false);
    }
    active_.clear();
}

void DohWorker::run(const std::atomic<bool>& stop) {
    int                    still_running = 0;
    std::vector<Transfer*> batch;

    while (!stop.load(std::memory_order_relaxed)) {
        if (source_.generation() != up_generation_) refresh_upstream();

        {
            std::lock_guard<std::mutex> lock(inbox_mutex_);
            batch.swap(inbox_);
        }
        for (Transfer* t : batch)
            if (!coalescer_.join(t)) start(t);
        batch.clear();

        keep_warm();

        curl_multi_perform(multi_, &still_running);
        reap();

        curl_multi_poll(multi_, nullptr, 0, 200, nullptr);
    }

    drain();
}
