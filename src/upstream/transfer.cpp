// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Johan Alvarado

#include "upstream/transfer.h"

#include "dns/dns.h"

#include <cerrno>

#include <sys/socket.h>

void Transfer::reply(const std::uint8_t* data, std::size_t len) const {
    if (conn) {
        conn->send_message(data, len);
        return;
    }

    if (udp_fd < 0) return;

    std::vector<std::uint8_t> cut;
    if (len > dns::kMinUdpPayload) {
        dns::UdpLimit limit = dns::udp_limit(payload.data(), payload.size());
        if (len > limit.bytes) {
            cut = dns::truncate(data, len, limit);
            if (cut.empty()) return;

            data = cut.data();
            len  = cut.size();
        }
    }

    // A full socket buffer is transient: retry a few times before dropping.
    for (int attempt = 0; attempt < 3; attempt++) {
        if (sendto(udp_fd, data, len, MSG_NOSIGNAL,
                   reinterpret_cast<const sockaddr*>(&client_addr), addr_len) >= 0)
            return;
        if (errno != EAGAIN && errno != EWOULDBLOCK && errno != ENOBUFS && errno != EINTR)
            return;
    }
}
