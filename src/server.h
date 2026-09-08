#pragma once

#include <atomic>
#include <cstddef>
#include <vector>

#include <sys/socket.h>

#include "config.h"
#include "stats.h"

class Dispatcher;

// Producer: reads UDP queries and hands them to the dispatcher.
//
// One socket per reader thread, all bound to the same address with
// SO_REUSEPORT so the kernel spreads client flows across them, and each read
// pulls a batch of datagrams with recvmmsg(). A single reader on one socket was
// the query-rate ceiling on a multi-core board.
class UdpServer {
public:
    UdpServer(const Config& cfg, Dispatcher& dispatcher);
    ~UdpServer();

    UdpServer(const UdpServer&)            = delete;
    UdpServer& operator=(const UdpServer&) = delete;

    bool open();

    std::size_t readers() const { return fds_.size(); }

    // Reads from socket `index` until `stop`. One call per reader thread.
    void run(std::size_t index, const std::atomic<bool>& stop);

private:
    int open_one(const sockaddr_storage& addr, socklen_t addr_len,
                 bool reuseport);

    const Config&    cfg_;
    Dispatcher&      dispatcher_;
    std::vector<int> fds_;
};
