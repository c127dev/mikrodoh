#pragma once

#include <atomic>
#include <memory>
#include <vector>

#include "config.h"
#include "stats.h"
#include "tcp_conn.h"

class Dispatcher;

// DNS over TCP, per RFC 7766: two-byte length prefix, several queries
// pipelined on one connection, responses written in whatever order they
// finish, and the connection kept open until it goes idle.
class TcpServer {
public:
    TcpServer(const Config& cfg, Dispatcher& dispatcher, Stats& stats);
    ~TcpServer();

    TcpServer(const TcpServer&)            = delete;
    TcpServer& operator=(const TcpServer&) = delete;

    bool open();
    void run(const std::atomic<bool>& stop);

private:
    struct Slot {
        std::shared_ptr<TcpConn> conn;
        bool                     reading_done = false;
    };

    void accept_one();
    bool read_and_dispatch(Slot& slot);
    void reap_idle();

    const Config& cfg_;
    Dispatcher&   dispatcher_;
    Stats&        stats_;

    int               fd_ = -1;
    std::vector<Slot> slots_;
};
