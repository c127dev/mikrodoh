#include "tcp_server.h"

#include "dispatch.h"
#include "net.h"
#include "transfer.h"

#include <cerrno>
#include <ctime>
#include <iostream>

#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

namespace {

constexpr int         kBacklog     = 64;
constexpr int         kPollTimeout = 100;
constexpr std::size_t kReadChunk   = 4096;

// RFC 1035 section 4.2.2: every message on a TCP connection is preceded by its
// length as a two-byte big-endian field.
constexpr std::size_t kLenPrefix = 2;

bool set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    return flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

}  // namespace

TcpServer::TcpServer(const Config& cfg, Dispatcher& dispatcher, Stats& stats)
    : cfg_(cfg), dispatcher_(dispatcher), stats_(stats) {}

TcpServer::~TcpServer() {
    if (fd_ >= 0) close(fd_);
}

bool TcpServer::open() {
    sockaddr_storage addr{};
    socklen_t        addr_len = 0;
    if (!parse_bind_addr(cfg_.listen_addr, cfg_.listen_port, addr, addr_len)) {
        std::cerr << "Bad LISTEN_ADDR: " << cfg_.listen_addr << "\n";
        return false;
    }

    fd_ = socket(addr.ss_family, SOCK_STREAM, 0);
    if (fd_ < 0) {
        std::cerr << "Failed to create TCP socket\n";
        return false;
    }

    int one = 1;
    setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    apply_v6only(fd_, addr, cfg_.ipv6_v6only);

    if (bind(fd_, reinterpret_cast<sockaddr*>(&addr), addr_len) < 0 ||
        listen(fd_, kBacklog) < 0) {
        std::cerr << "Failed to bind to TCP "
                  << join_host_port(cfg_.listen_addr, cfg_.listen_port) << "\n";
        close(fd_);
        fd_ = -1;
        return false;
    }

    set_nonblocking(fd_);
    return true;
}

void TcpServer::accept_one() {
    int cfd = accept(fd_, nullptr, nullptr);
    if (cfd < 0) return;

    // Over the cap the connection is refused immediately rather than left in
    // the backlog, so a client learns to fall back instead of hanging.
    if (slots_.size() >= static_cast<std::size_t>(cfg_.tcp_max_conns)) {
        close(cfd);
        return;
    }

    set_nonblocking(cfd);

    int one = 1;
    setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    Slot slot;
    slot.conn                = std::make_shared<TcpConn>(cfd);
    slot.conn->last_activity = std::time(nullptr);
    slots_.push_back(std::move(slot));
    stats_.tcp_conns++;
}

bool TcpServer::read_and_dispatch(Slot& slot) {
    TcpConn& conn = *slot.conn;

    std::size_t base = conn.in.size();
    conn.in.resize(base + kReadChunk);
    ssize_t n = recv(conn.fd(), conn.in.data() + base, kReadChunk, 0);
    conn.in.resize(base + (n > 0 ? static_cast<std::size_t>(n) : 0));

    if (n == 0) {
        // Client is done sending. Answers already in flight still have to go
        // out, so the connection closes only once they have.
        slot.reading_done = true;
    } else if (n < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) return false;
    } else {
        conn.last_activity = std::time(nullptr);
    }

    std::size_t pos = 0;
    while (conn.in.size() - pos >= kLenPrefix) {
        std::size_t msg_len = static_cast<std::size_t>(conn.in[pos]) << 8 |
                              static_cast<std::size_t>(conn.in[pos + 1]);

        // A zero-length message is not a DNS message and nothing can be
        // parsed after it, so the connection is not recoverable.
        if (msg_len == 0) return false;

        if (conn.in.size() - pos < kLenPrefix + msg_len) break;

        const std::uint8_t* msg = conn.in.data() + pos + kLenPrefix;

        auto t     = std::make_unique<Transfer>();
        t->conn    = slot.conn;
        t->payload.assign(msg, msg + msg_len);
        dispatcher_.dispatch(std::move(t));

        pos += kLenPrefix + msg_len;
    }

    if (pos > 0) conn.in.erase(conn.in.begin(), conn.in.begin() + static_cast<std::ptrdiff_t>(pos));

    return true;
}

void TcpServer::reap_idle() {
    std::time_t now = std::time(nullptr);

    for (auto it = slots_.begin(); it != slots_.end();) {
        TcpConn& conn = *it->conn;

        bool idle = now - conn.last_activity >= cfg_.tcp_idle_sec;
        bool done = conn.inflight <= 0 && !conn.want_write();

        if (conn.failed() || ((it->reading_done || idle) && done)) {
            stats_.tcp_conns--;
            it = slots_.erase(it);
            continue;
        }
        ++it;
    }
}

void TcpServer::run(const std::atomic<bool>& stop) {
    std::vector<pollfd> pfds;

    while (!stop.load(std::memory_order_relaxed)) {
        pfds.clear();
        pfds.push_back(pollfd{fd_, POLLIN, 0});

        for (Slot& slot : slots_) {
            short events = slot.reading_done ? 0 : POLLIN;
            if (slot.conn->want_write()) events |= POLLOUT;
            pfds.push_back(pollfd{slot.conn->fd(), events, 0});
        }

        // The timeout also bounds how long a write that could not complete
        // waits for its POLLOUT interest to be registered, and it is what
        // drives the idle sweep on a quiet listener.
        if (poll(pfds.data(), pfds.size(), kPollTimeout) < 0 && errno != EINTR) break;

        if (pfds[0].revents & POLLIN) accept_one();

        for (std::size_t i = 0; i < slots_.size(); ++i) {
            // accept_one() appended to slots_ after pfds was built.
            if (i + 1 >= pfds.size()) break;

            short revents = pfds[i + 1].revents;
            Slot& slot    = slots_[i];

            if (revents & POLLOUT) {
                if (!slot.conn->flush()) slot.conn->mark_failed();
            }

            if (revents & (POLLIN | POLLHUP | POLLERR)) {
                if (!read_and_dispatch(slot)) slot.conn->mark_failed();
            }
        }

        reap_idle();
    }
}
