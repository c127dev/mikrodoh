// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Johan Alvarado

#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include <netinet/in.h>
#include <sys/socket.h>

#include "net/tcp_conn.h"
#include "upstream/upstream.h"

// `conn` set means the reply goes over TCP, otherwise to `udp_fd`.
struct Transfer {
    std::vector<std::uint8_t> payload;
    std::vector<std::uint8_t> response;
    std::string               cache_key;

    std::shared_ptr<const Upstream> up;

    std::size_t url = 0;

    bool query_truncated = false;

    std::vector<std::uint8_t> health_query;

    bool warm = false;

    bool prefetch = false;

    int                      udp_fd = -1;
    sockaddr_storage         client_addr{};
    socklen_t                addr_len = 0;
    std::shared_ptr<TcpConn> conn;

    void reply(const std::uint8_t* data, std::size_t len) const;
};
