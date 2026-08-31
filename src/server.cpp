#include "server.h"

#include "dispatch.h"
#include "net.h"
#include "transfer.h"

#include <iostream>
#include <memory>

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
    sockaddr_storage addr{};
    socklen_t        addr_len = 0;
    if (!parse_bind_addr(cfg_.listen_addr, cfg_.listen_port, addr, addr_len)) {
        std::cerr << "Bad LISTEN_ADDR: " << cfg_.listen_addr << "\n";
        return false;
    }

    fd_ = socket(addr.ss_family, SOCK_DGRAM, 0);
    if (fd_ < 0) {
        std::cerr << "Failed to create socket\n";
        return false;
    }

    apply_v6only(fd_, addr, cfg_.ipv6_v6only);

    int bufbytes = cfg_.rcvbuf_kb * 1024;
    setsockopt(fd_, SOL_SOCKET, SO_RCVBUF, &bufbytes, sizeof(bufbytes));
    setsockopt(fd_, SOL_SOCKET, SO_SNDBUF, &bufbytes, sizeof(bufbytes));

    // Without a timeout recvfrom() blocks forever and the process ignores
    // SIGINT/SIGTERM until the next query arrives.
    struct timeval timeout {
        0, kRecvTimeoutMs * 1000
    };
    setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    if (bind(fd_, reinterpret_cast<sockaddr*>(&addr), addr_len) < 0) {
        std::cerr << "Failed to bind to UDP "
                  << join_host_port(cfg_.listen_addr, cfg_.listen_port) << "\n";
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
