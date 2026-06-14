#include "doh_worker.h"

#include "cache.h"

#include <iostream>

namespace {

size_t write_callback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t bytes = size * nmemb;
    auto*  out   = static_cast<std::vector<std::uint8_t>*>(userp);
    auto*  in    = static_cast<std::uint8_t*>(contents);
    out->insert(out->end(), in, in + bytes);
    return bytes;
}

}  // namespace

DohWorker::DohWorker(const Config& cfg, DnsCache& cache, Stats& stats, int udp_socket)
    : cfg_(cfg), cache_(cache), stats_(stats), udp_socket_(udp_socket) {
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
    curl_easy_setopt(handle, CURLOPT_URL, cfg_.doh_url.c_str());
    curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(handle, CURLOPT_HTTPHEADER, headers_);
    curl_easy_setopt(handle, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2TLS);

    // Wait for the existing multiplexed connection instead of opening another,
    // which is what keeps every stream on one HTTP/2 connection.
    curl_easy_setopt(handle, CURLOPT_PIPEWAIT, 1L);

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

void DohWorker::start(Transfer* t) {
    CURL* handle = acquire();
    if (!handle) {
        stats_.inflight--;
        delete t;
        return;
    }

    curl_easy_setopt(handle, CURLOPT_POSTFIELDS, t->payload.data());
    curl_easy_setopt(handle, CURLOPT_POSTFIELDSIZE, static_cast<long>(t->payload.size()));
    curl_easy_setopt(handle, CURLOPT_WRITEDATA, &t->response);
    curl_easy_setopt(handle, CURLOPT_PRIVATE, t);
    curl_multi_add_handle(multi_, handle);
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

        if (msg->data.result == CURLE_OK && http_code == 200 && !t->response.empty()) {
            sendto(udp_socket_, t->response.data(), t->response.size(), 0,
                   reinterpret_cast<sockaddr*>(&t->client_addr), t->addr_len);
            stats_.served++;
            cache_.store(t->cache_key, t->response);
        } else if (msg->data.result != CURLE_OK) {
            std::cerr << "DoH transfer failed: "
                      << curl_easy_strerror(msg->data.result) << "\n";
        }

        curl_multi_remove_handle(multi_, handle);
        idle_.push_back(handle);  // keeps the handle's connection warm
        delete t;
        stats_.inflight--;
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
