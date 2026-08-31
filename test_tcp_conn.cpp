#include "harness.h"

#include "tcp_conn.h"

#include <cerrno>
#include <cstring>
#include <vector>

#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

namespace {

// A connected pair standing in for an accepted client: `conn` owns one end,
// the test reads the other.
struct Pair {
    int     peer = -1;
    TcpConn conn;

    explicit Pair(int fds[2]) : peer(fds[0]), conn(fds[1]) {}
    ~Pair() {
        if (peer >= 0) close(peer);
    }
};

bool make_pair(int fds[2], bool nonblocking) {
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) return false;
    if (nonblocking) {
        for (int i = 0; i < 2; ++i) {
            int flags = fcntl(fds[i], F_GETFL, 0);
            fcntl(fds[i], F_SETFL, flags | O_NONBLOCK);
        }
    }
    return true;
}

std::vector<std::uint8_t> body(std::size_t n, std::uint8_t fill = 0xAB) {
    return std::vector<std::uint8_t>(n, fill);
}

}  // namespace

TEST(send_message_prefixes_the_two_byte_length) {
    int fds[2];
    CHECK(make_pair(fds, false));
    Pair p(fds);

    std::vector<std::uint8_t> msg = body(5, 0x42);
    p.conn.send_message(msg.data(), msg.size());

    std::uint8_t buf[16] = {};
    ssize_t      n       = recv(p.peer, buf, sizeof(buf), 0);

    CHECK(n == 7);
    CHECK(buf[0] == 0 && buf[1] == 5);
    CHECK(std::memcmp(buf + 2, msg.data(), msg.size()) == 0);
}

TEST(the_length_prefix_is_big_endian) {
    int fds[2];
    CHECK(make_pair(fds, false));
    Pair p(fds);

    std::vector<std::uint8_t> msg = body(0x0102);
    p.conn.send_message(msg.data(), msg.size());

    std::uint8_t prefix[2] = {};
    CHECK(recv(p.peer, prefix, 2, 0) == 2);
    CHECK(prefix[0] == 0x01 && prefix[1] == 0x02);
}

TEST(two_messages_are_framed_back_to_back) {
    int fds[2];
    CHECK(make_pair(fds, false));
    Pair p(fds);

    std::vector<std::uint8_t> a = body(3, 0x11);
    std::vector<std::uint8_t> b = body(2, 0x22);
    p.conn.send_message(a.data(), a.size());
    p.conn.send_message(b.data(), b.size());

    std::uint8_t buf[32] = {};
    ssize_t      n       = recv(p.peer, buf, sizeof(buf), 0);

    CHECK(n == 9);
    CHECK(buf[0] == 0 && buf[1] == 3);
    CHECK(buf[5] == 0 && buf[6] == 2);
}

TEST(a_message_over_65535_bytes_is_refused_rather_than_truncated) {
    int fds[2];
    CHECK(make_pair(fds, true));
    Pair p(fds);

    std::vector<std::uint8_t> msg = body(70000);
    p.conn.send_message(msg.data(), msg.size());

    CHECK(!p.conn.want_write());

    std::uint8_t buf[8] = {};
    CHECK(recv(p.peer, buf, sizeof(buf), 0) < 0);
    CHECK(errno == EAGAIN || errno == EWOULDBLOCK);
}

TEST(a_write_the_socket_cannot_take_is_buffered_and_flushed_later) {
    int fds[2];
    CHECK(make_pair(fds, true));
    Pair p(fds);

    // Fill the socket buffer, which takes several maximum-size messages.
    std::vector<std::uint8_t> msg = body(65535);
    for (int i = 0; i < 64 && !p.conn.want_write(); ++i)
        p.conn.send_message(msg.data(), msg.size());

    CHECK(p.conn.want_write());
    CHECK(!p.conn.failed());

    // Drain the reader until the buffered remainder has all gone out.
    std::vector<std::uint8_t> sink(65536);
    for (int i = 0; i < 4096 && p.conn.want_write(); ++i) {
        while (recv(p.peer, sink.data(), sink.size(), 0) > 0) {
        }
        CHECK(p.conn.flush());
    }

    CHECK(!p.conn.want_write());
    CHECK(!p.conn.failed());
}

TEST(a_closed_peer_marks_the_connection_failed) {
    int fds[2];
    CHECK(make_pair(fds, false));
    Pair p(fds);

    close(p.peer);
    p.peer = -1;

    // The first write may land in the socket buffer; the second sees EPIPE.
    std::vector<std::uint8_t> msg = body(16);
    for (int i = 0; i < 8 && !p.conn.failed(); ++i)
        p.conn.send_message(msg.data(), msg.size());

    CHECK(p.conn.failed());
}

TEST(nothing_is_written_after_a_failure) {
    int fds[2];
    CHECK(make_pair(fds, false));
    Pair p(fds);

    p.conn.mark_failed();
    CHECK(p.conn.failed());

    std::vector<std::uint8_t> msg = body(4);
    p.conn.send_message(msg.data(), msg.size());

    CHECK(!p.conn.want_write());
    CHECK(!p.conn.flush());
}
