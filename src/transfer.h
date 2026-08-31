#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include <netinet/in.h>
#include <sys/socket.h>

#include "tcp_conn.h"

// One outstanding DoH request. Lives from DohWorker::start() to CURLMSG_DONE.
//
// The reply target is whichever of the two sides is set: a UDP socket plus the
// client address, or a TCP connection. `conn` being non-null selects TCP.
struct Transfer {
    std::vector<std::uint8_t> payload;
    std::vector<std::uint8_t> response;
    std::string               cache_key;

    int                      udp_fd = -1;
    sockaddr_storage         client_addr{};
    socklen_t                addr_len = 0;
    std::shared_ptr<TcpConn> conn;

    void reply(const std::uint8_t* data, std::size_t len) const;
};
