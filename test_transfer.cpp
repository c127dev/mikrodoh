// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Johan Alvarado

#include "harness.h"

#include "dns/dns.h"
#include "upstream/transfer.h"

#include <chrono>
#include <vector>

#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

namespace {

struct Pair {
    int fds[2] = {-1, -1};

    Pair() {
        socketpair(AF_UNIX, SOCK_DGRAM, 0, fds);
        fcntl(fds[1], F_SETFL, fcntl(fds[1], F_GETFL) | O_NONBLOCK);
    }
    ~Pair() {
        close(fds[0]);
        close(fds[1]);
    }

    std::size_t drain() {
        std::size_t                n = 0;
        std::vector<std::uint8_t> buf(dns::kMaxMessage);
        while (recv(fds[0], buf.data(), buf.size(), MSG_DONTWAIT) > 0) n++;
        return n;
    }
};

}  // namespace

TEST(a_udp_reply_reaches_the_client) {
    Pair     p;
    Transfer t;
    t.udp_fd = p.fds[1];

    std::vector<std::uint8_t> msg(64, 0xAB);
    t.reply(msg.data(), msg.size());
    CHECK(p.drain() == 1);
}

TEST(a_reply_on_a_full_socket_gives_up_without_blocking) {
    Pair p;
    std::vector<std::uint8_t> fill(512, 0);
    while (send(p.fds[1], fill.data(), fill.size(), MSG_DONTWAIT) > 0) {}

    Transfer t;
    t.udp_fd = p.fds[1];

    auto start = std::chrono::steady_clock::now();
    t.reply(fill.data(), fill.size());
    CHECK(std::chrono::steady_clock::now() - start < std::chrono::milliseconds(100));

    p.drain();
    t.reply(fill.data(), fill.size());
    CHECK(p.drain() == 1);
}
