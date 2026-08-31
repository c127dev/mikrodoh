#pragma once

#include <atomic>

#include "config.h"
#include "stats.h"

class Dispatcher;

// Producer: reads UDP queries off one socket and hands them to the dispatcher.
class UdpServer {
public:
    UdpServer(const Config& cfg, Dispatcher& dispatcher);
    ~UdpServer();

    UdpServer(const UdpServer&)            = delete;
    UdpServer& operator=(const UdpServer&) = delete;

    bool open();
    int  fd() const { return fd_; }

    void run(const std::atomic<bool>& stop);

private:
    const Config& cfg_;
    Dispatcher&   dispatcher_;
    int           fd_ = -1;
};
