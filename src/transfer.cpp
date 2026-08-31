#include "transfer.h"

#include <sys/socket.h>

void Transfer::reply(const std::uint8_t* data, std::size_t len) const {
    if (conn) {
        conn->send_message(data, len);
        return;
    }

    if (udp_fd < 0) return;
    sendto(udp_fd, data, len, MSG_NOSIGNAL,
           reinterpret_cast<const sockaddr*>(&client_addr), addr_len);
}
