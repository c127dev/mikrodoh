#include "net.h"

#include <cstring>
#include <string>

#include <netdb.h>
#include <unistd.h>

bool parse_bind_addr(const std::string& addr, int port, sockaddr_storage& out,
                     socklen_t& len) {
    std::string host = addr;
    if (host.size() >= 2 && host.front() == '[' && host.back() == ']')
        host = host.substr(1, host.size() - 2);

    addrinfo hints{};
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    // A literal only: a name here would make the bind depend on resolution,
    // which is the service this daemon is trying to provide.
    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV | AI_PASSIVE;

    std::string service = std::to_string(port);

    addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), service.c_str(), &hints, &res) != 0 || !res)
        return false;

    std::memset(&out, 0, sizeof(out));
    std::memcpy(&out, res->ai_addr, res->ai_addrlen);
    len = res->ai_addrlen;

    freeaddrinfo(res);
    return true;
}

void apply_v6only(int fd, const sockaddr_storage& addr, bool v6only) {
    if (addr.ss_family != AF_INET6) return;

    int on = v6only ? 1 : 0;
    setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on));
}

std::string join_host_port(const std::string& addr, int port) {
    bool bare_v6 = addr.find(':') != std::string::npos && addr.front() != '[';
    std::string host = bare_v6 ? "[" + addr + "]" : addr;
    return host + ":" + std::to_string(port);
}
