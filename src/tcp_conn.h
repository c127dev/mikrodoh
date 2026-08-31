#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <mutex>
#include <vector>

// One accepted TCP connection. The accept loop owns the read side; workers
// finishing a transfer call send_message() from their own threads, so the
// write side is behind a mutex.
//
// Held by shared_ptr: a connection the loop has dropped stays alive until the
// last in-flight transfer that still points at it is done, which is what keeps
// the descriptor valid without the loop having to track transfers.
class TcpConn {
public:
    explicit TcpConn(int fd);
    ~TcpConn();

    TcpConn(const TcpConn&)            = delete;
    TcpConn& operator=(const TcpConn&) = delete;

    int fd() const { return fd_; }

    // Worker side. Prefixes the RFC 1035 two-byte length, appends to the out
    // buffer and writes what it can without blocking. Leftovers are flushed by
    // the loop once it polls for POLLOUT.
    void send_message(const std::uint8_t* data, std::size_t len);

    // Loop side. False means the connection is finished and must be dropped.
    bool flush();
    bool want_write() const;
    bool failed() const;
    void mark_failed();

    // Read buffer and idle clock: loop-side only, no lock. `inflight` is
    // raised by the dispatcher and lowered by whichever worker finishes, so it
    // is the one field the loop shares.
    std::vector<std::uint8_t> in;
    std::time_t               last_activity = 0;
    std::atomic<long>         inflight{0};

private:
    bool write_locked();

    int                       fd_;
    mutable std::mutex        mutex_;
    std::vector<std::uint8_t> out_;
    std::size_t               out_pos_ = 0;
    bool                      failed_  = false;
};
