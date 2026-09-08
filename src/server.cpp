#include "server.h"

#include "dispatch.h"
#include "net.h"
#include "transfer.h"

#include <cstring>
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

// Datagrams read per recvmmsg() call. The buffers are per reader thread, so
// this costs kBatch * kMaxDnsPacket bytes each.
constexpr unsigned kBatch = 16;

}  // namespace

UdpServer::UdpServer(const Config& cfg, Dispatcher& dispatcher)
    : cfg_(cfg), dispatcher_(dispatcher) {}

UdpServer::~UdpServer() {
    for (int fd : fds_)
        if (fd >= 0) close(fd);
}

int UdpServer::open_one(const sockaddr_storage& addr, socklen_t addr_len,
                        bool reuseport) {
    int fd = socket(addr.ss_family, SOCK_DGRAM, 0);
    if (fd < 0) {
        std::cerr << "Failed to create socket\n";
        return -1;
    }

    apply_v6only(fd, addr, cfg_.ipv6_v6only);

    // Every reader binds the same address, and the kernel hashes each client
    // flow onto one of them.
    if (reuseport) {
        int on = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on)) < 0) {
            std::cerr << "SO_REUSEPORT is unavailable, cannot run more than one "
                      << "UDP reader\n";
            close(fd);
            return -1;
        }
    }

    int bufbytes = cfg_.rcvbuf_kb * 1024;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufbytes, sizeof(bufbytes));
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bufbytes, sizeof(bufbytes));

    // Without a timeout the receive blocks forever and the process ignores
    // SIGINT/SIGTERM until the next query arrives.
    struct timeval timeout {
        0, kRecvTimeoutMs * 1000
    };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    if (bind(fd, reinterpret_cast<const sockaddr*>(&addr), addr_len) < 0) {
        std::cerr << "Failed to bind to UDP "
                  << join_host_port(cfg_.listen_addr, cfg_.listen_port) << "\n";
        close(fd);
        return -1;
    }

    return fd;
}

bool UdpServer::open() {
    sockaddr_storage addr{};
    socklen_t        addr_len = 0;
    if (!parse_bind_addr(cfg_.listen_addr, cfg_.listen_port, addr, addr_len)) {
        std::cerr << "Bad LISTEN_ADDR: " << cfg_.listen_addr << "\n";
        return false;
    }

    int readers = cfg_.udp_readers > 0 ? cfg_.udp_readers : 1;

    for (int i = 0; i < readers; i++) {
        int fd = open_one(addr, addr_len, readers > 1);
        if (fd < 0) {
            for (int have : fds_) close(have);
            fds_.clear();
            return false;
        }
        fds_.push_back(fd);
    }

    return true;
}

void UdpServer::run(std::size_t index, const std::atomic<bool>& stop) {
    const int fd = fds_[index];

    std::vector<std::uint8_t>    buffers(kBatch * kMaxDnsPacket);
    std::vector<mmsghdr>         msgs(kBatch);
    std::vector<iovec>           iovs(kBatch);
    std::vector<sockaddr_storage> clients(kBatch);

    while (!stop.load(std::memory_order_relaxed)) {
        for (unsigned i = 0; i < kBatch; i++) {
            iovs[i].iov_base = buffers.data() + i * kMaxDnsPacket;
            iovs[i].iov_len  = kMaxDnsPacket;

            std::memset(&msgs[i], 0, sizeof(msgs[i]));
            msgs[i].msg_hdr.msg_name    = &clients[i];
            msgs[i].msg_hdr.msg_namelen = sizeof(sockaddr_storage);
            msgs[i].msg_hdr.msg_iov     = &iovs[i];
            msgs[i].msg_hdr.msg_iovlen  = 1;
        }

        // MSG_WAITFORONE returns as soon as the first datagram is in, so a
        // single query is not held back waiting for the batch to fill. The
        // SO_RCVTIMEO above bounds that first wait.
        int got = recvmmsg(fd, msgs.data(), kBatch, MSG_WAITFORONE, nullptr);
        if (got <= 0) continue;

        for (int i = 0; i < got; i++) {
            unsigned len = msgs[i].msg_len;
            if (len == 0) continue;

            auto t         = std::make_unique<Transfer>();
            t->udp_fd      = fd;
            t->client_addr = clients[i];
            t->addr_len    = msgs[i].msg_hdr.msg_namelen;

            const std::uint8_t* data = buffers.data() + i * kMaxDnsPacket;
            t->payload.assign(data, data + len);

            dispatcher_.dispatch(std::move(t));
        }
    }
}
