#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include <netinet/in.h>
#include <sys/socket.h>

#include "tcp_conn.h"
#include "upstream.h"

// One outstanding DoH request. Lives from DohWorker::start() to CURLMSG_DONE.
//
// The reply target is whichever of the two sides is set: a UDP socket plus the
// client address, or a TCP connection. `conn` being non-null selects TCP.
struct Transfer {
    std::vector<std::uint8_t> payload;
    std::vector<std::uint8_t> response;
    std::string               cache_key;

    // The resolver list this query walks, fixed when it is first started.
    std::shared_ptr<const Upstream> up;

    // Index into `up->urls`: the resolver this attempt uses. Bumped past
    // each failure, and past any resolver in cooldown, until the list runs out.
    std::size_t url = 0;

    // The datagram was larger than the read buffer, so `payload` holds only
    // its first bytes. Nothing but an error can be built from a query whose
    // tail was never read.
    bool query_truncated = false;

    // A health probe: `payload` is the upstream stand-in and this is the
    // client's query, which the reply is built from. Empty otherwise.
    std::vector<std::uint8_t> health_query;

    int                      udp_fd = -1;
    sockaddr_storage         client_addr{};
    socklen_t                addr_len = 0;
    std::shared_ptr<TcpConn> conn;

    void reply(const std::uint8_t* data, std::size_t len) const;
};
