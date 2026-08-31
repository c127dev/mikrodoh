#include "server.h"

#include "dispatch.h"
#include "transfer.h"

#include <cstring>
#include <iostream>
#include <memory>

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

UdpServer::UdpServer(const Config& cfg, Dispatcher& dispatcher)
    : cfg_(cfg), dispatcher_(dispatcher) {}

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
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(static_cast<uint16_t>(cfg_.listen_port));

    if (inet_pton(AF_INET, cfg_.listen_addr.c_str(), &addr.sin_addr) != 1) {
        std::cerr << "Bad LISTEN_ADDR: " << cfg_.listen_addr << "\n";
        close(fd_);
        fd_ = -1;
        return false;
    }

    if (bind(fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        std::cerr << "Failed to bind to UDP " << cfg_.listen_addr << ":"
                  << cfg_.listen_port << "\n";
        close(fd_);
        fd_ = -1;
        return false;
    }

    return true;
}

void UdpServer::run(const std::atomic<bool>& stop) {
    std::uint8_t buffer[kMaxDnsPacket];

    while (!stop.load(std::memory_order_relaxed)) {
        sockaddr_storage client{};
        socklen_t        client_len = sizeof(client);

        ssize_t len = recvfrom(fd_, buffer, sizeof(buffer), 0,
                               reinterpret_cast<sockaddr*>(&client), &client_len);
        if (len <= 0) continue;

        auto t         = std::make_unique<Transfer>();
        t->udp_fd      = fd_;
        t->client_addr = client;
        t->addr_len    = client_len;
        t->payload.assign(buffer, buffer + len);

        dispatcher_.dispatch(std::move(t));
    }
}
