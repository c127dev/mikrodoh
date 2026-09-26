#pragma once

#include <atomic>
#include <cstddef>
#include <vector>

#include <sys/socket.h>

#include "config.h"
#include "stats.h"

class Dispatcher;

class UdpServer {
public:
    UdpServer(const Config& cfg, Dispatcher& dispatcher);
    ~UdpServer();

    UdpServer(const UdpServer&)            = delete;
    UdpServer& operator=(const UdpServer&) = delete;

    bool open();

    std::size_t readers() const { return fds_.size(); }

    void run(std::size_t index, const std::atomic<bool>& stop);

private:
    int open_one(const sockaddr_storage& addr, socklen_t addr_len,
                 bool reuseport);

    const Config&    cfg_;
    Dispatcher&      dispatcher_;
    std::vector<int> fds_;
};
