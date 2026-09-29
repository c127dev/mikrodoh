// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Johan Alvarado

#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <vector>

#include <netinet/in.h>
#include <sys/socket.h>

std::uint64_t tcp_now_ms();

bool tcp_conn_idle(std::uint64_t now_ms, std::uint64_t last_ms, int idle_sec);

// Held by shared_ptr: a dropped connection stays alive until the last
// in-flight transfer pointing at it finishes.
class TcpConn {
public:
    explicit TcpConn(int fd);
    ~TcpConn();

    TcpConn(const TcpConn&)            = delete;
    TcpConn& operator=(const TcpConn&) = delete;

    int fd() const { return fd_; }

    void send_message(const std::uint8_t* data, std::size_t len);

    bool flush();
    bool want_write() const;
    bool failed() const;
    void mark_failed();

    std::vector<std::uint8_t> in;
    std::uint64_t             last_activity = 0;
    sockaddr_storage          peer{};
    std::atomic<long>         inflight{0};

private:
    bool write_locked();

    int                       fd_;
    mutable std::mutex        mutex_;
    std::vector<std::uint8_t> out_;
    std::size_t               out_pos_ = 0;
    bool                      failed_  = false;
};
