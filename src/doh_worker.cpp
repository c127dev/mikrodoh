#include "doh_worker.h"

#include "cache.h"
#include "dns.h"

#include <iostream>

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

}  // namespace

DohWorker::DohWorker(const Config& cfg, DnsCache& cache, Stats& stats)
    : cfg_(cfg), cache_(cache), stats_(stats) {
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
    // The URL is not set here: a pooled handle can be reused for a different
    // resolver, so start() sets it per transfer.
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

    // Without these a stalled transfer holds its in-flight slot forever, and
    // enough of them pin MAX_INFLIGHT with no recovery.
    curl_easy_setopt(handle, CURLOPT_TIMEOUT_MS,
                     static_cast<long>(cfg_.request_timeout_ms));
    curl_easy_setopt(handle, CURLOPT_CONNECTTIMEOUT_MS,
                     static_cast<long>(cfg_.connect_timeout_ms));

    if (cfg_.prefer_chacha) {
        curl_easy_setopt(handle, CURLOPT_TLS13_CIPHERS, "TLS_CHACHA20_POLY1305_SHA256");
        curl_easy_setopt(handle, CURLOPT_SSL_CIPHER_LIST,
                         "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305");
    }

    if (!cfg_.check_cert) {
        curl_easy_setopt(handle, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(handle, CURLOPT_SSL_VERIFYHOST, 0L);
    }

    if (cfg_.tcp_keep_alive > 0) {
        long secs = cfg_.tcp_keep_alive;
        curl_easy_setopt(handle, CURLOPT_TCP_KEEPALIVE, 1L);
        curl_easy_setopt(handle, CURLOPT_TCP_KEEPIDLE, secs);
        curl_easy_setopt(handle, CURLOPT_TCP_KEEPINTVL, secs);
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

void DohWorker::start(Transfer* t) {
    if (t->attempt >= cfg_.doh_urls.size()) {
        finish(t, false);
        return;
    }

    CURL* handle = acquire();
    if (!handle) {
        finish(t, false);
        return;
    }

    t->response.clear();
    curl_easy_setopt(handle, CURLOPT_URL, cfg_.doh_urls[t->attempt].c_str());
    curl_easy_setopt(handle, CURLOPT_POSTFIELDS, t->payload.data());
    curl_easy_setopt(handle, CURLOPT_POSTFIELDSIZE, static_cast<long>(t->payload.size()));
    curl_easy_setopt(handle, CURLOPT_WRITEDATA, &t->response);
    curl_easy_setopt(handle, CURLOPT_PRIVATE, t);
    curl_multi_add_handle(multi_, handle);
}

void DohWorker::finish(Transfer* t, bool ok) {
    if (ok) {
        t->reply(t->response.data(), t->response.size());
        stats_.served++;
        cache_.store(t->cache_key, t->response);
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

        bool ok = msg->data.result == CURLE_OK && http_code == 200 &&
                  t->response.size() >= dns::kHeaderLen;

        if (!ok)
            std::cerr << "DoH transfer failed on " << cfg_.doh_urls[t->attempt]
                      << ": " << curl_easy_strerror(msg->data.result)
                      << " (HTTP " << http_code << ")\n";

        curl_multi_remove_handle(multi_, handle);
        release(handle);

        if (!ok && t->attempt + 1 < cfg_.doh_urls.size()) {
            t->attempt++;
            start(t);
            continue;
        }

        finish(t, ok);
    }
}

void DohWorker::submit(Transfer* t) {
    {
        std::lock_guard<std::mutex> lock(inbox_mutex_);
        inbox_.push_back(t);
    }
    curl_multi_wakeup(multi_);
}

void DohWorker::run(const std::atomic<bool>& stop) {
    int                    still_running = 0;
    std::vector<Transfer*> batch;

    while (!stop.load(std::memory_order_relaxed)) {
        {
            std::lock_guard<std::mutex> lock(inbox_mutex_);
            batch.swap(inbox_);
        }
        for (Transfer* t : batch) start(t);
        batch.clear();

        curl_multi_perform(multi_, &still_running);
        reap();

        curl_multi_poll(multi_, nullptr, 0, 200, nullptr);
    }

    curl_multi_perform(multi_, &still_running);
    reap();
}
