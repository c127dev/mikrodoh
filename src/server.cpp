#include "server.h"

#include "cache.h"
#include "doh_worker.h"

#include <cstring>
#include <iostream>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

namespace {

// Generous enough for EDNS0 payloads.
constexpr std::size_t kMaxDnsPacket = 4096;

constexpr int kRecvTimeoutMs = 200;

}  // namespace

UdpServer::UdpServer(const Config& cfg, DnsCache& cache, Stats& stats)
    : cfg_(cfg), cache_(cache), stats_(stats) {}

UdpServer::~UdpServer() {
    if (fd_ >= 0) close(fd_);
}

bool UdpServer::open() {
    fd_ = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd_ < 0) {
        std::cerr << "Failed to create socket\n";
        return false;
    }

    int bufbytes = cfg_.rcvbuf_kb * 1024;
    setsockopt(fd_, SOL_SOCKET, SO_RCVBUF, &bufbytes, sizeof(bufbytes));
    setsockopt(fd_, SOL_SOCKET, SO_SNDBUF, &bufbytes, sizeof(bufbytes));

    // Without a timeout recvfrom() blocks forever and the process ignores
    // SIGINT/SIGTERM until the next query arrives.
    struct timeval timeout {
        0, kRecvTimeoutMs * 1000
    };
    setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    sockaddr_in addr{};
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(static_cast<uint16_t>(cfg_.listen_port));

    if (bind(fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        std::cerr << "Failed to bind to port " << cfg_.listen_port << "\n";
        close(fd_);
        fd_ = -1;
        return false;
    }

    return true;
}

void UdpServer::run(std::vector<std::unique_ptr<DohWorker>>& workers,
                    const std::atomic<bool>&                 stop) {
    std::uint8_t              buffer[kMaxDnsPacket];
    std::vector<std::uint8_t> cached;
    unsigned                  next = 0;

    while (!stop.load(std::memory_order_relaxed)) {
        sockaddr_in client{};
        socklen_t   client_len = sizeof(client);

        ssize_t len = recvfrom(fd_, buffer, sizeof(buffer), 0,
                               reinterpret_cast<sockaddr*>(&client), &client_len);
        if (len <= 0) continue;

        std::string key = cache_.enabled()
                              ? DnsCache::key_of(buffer, static_cast<std::size_t>(len))
                              : std::string();

        if (cache_.lookup(key, cached)) {
            cached[0] = buffer[0];  // the client's transaction ID, not the cached one
            cached[1] = buffer[1];
            sendto(fd_, cached.data(), cached.size(), 0,
                   reinterpret_cast<sockaddr*>(&client), client_len);
            stats_.served++;
            continue;
        }

        // Shed instead of queueing without bound: accepted queries keep their
        // latency and the box degrades gracefully under burst.
        if (stats_.inflight.load(std::memory_order_relaxed) >= cfg_.max_inflight) {
            unsigned long dropped = ++stats_.dropped;
            if ((dropped & 0x3FF) == 0)
                std::cerr << "[shed] dropped " << dropped << " queries (in-flight cap "
                          << cfg_.max_inflight << ")\n";
            continue;
        }

        auto* t        = new Transfer();
        t->client_addr = client;
        t->addr_len    = client_len;
        t->payload.assign(buffer, buffer + len);
        t->cache_key = key;

        stats_.inflight++;
        workers[next++ % workers.size()]->submit(t);
    }
}
