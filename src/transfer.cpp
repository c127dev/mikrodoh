#include "transfer.h"

#include "dns.h"

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

    sendto(udp_fd, data, len, MSG_NOSIGNAL,
           reinterpret_cast<const sockaddr*>(&client_addr), addr_len);
}
