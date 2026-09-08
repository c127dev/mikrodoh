#include "net.h"

#include <cstdlib>
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

bool is_ip_literal(const std::string& host) {
    std::string h = host;
    if (h.size() >= 2 && h.front() == '[' && h.back() == ']')
        h = h.substr(1, h.size() - 2);
    if (h.empty()) return false;

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_flags  = AI_NUMERICHOST;

    addrinfo* res = nullptr;
    if (getaddrinfo(h.c_str(), nullptr, &hints, &res) != 0) return false;

    freeaddrinfo(res);
    return true;
}

bool split_url_authority(const std::string& url, std::string& host, int& port) {
    std::string::size_type start = url.find("://");
    start = start == std::string::npos ? 0 : start + 3;

    // The authority ends at the path, the query or the fragment.
    std::string::size_type end = url.find_first_of("/?#", start);
    std::string authority = url.substr(start, end - start);

    // Credentials are not used by this daemon, but they precede the host.
    std::string::size_type at = authority.rfind('@');
    if (at != std::string::npos) authority = authority.substr(at + 1);
    if (authority.empty()) return false;

    port = 443;

    std::string::size_type colon;
    if (authority.front() == '[') {
        std::string::size_type close = authority.find(']');
        if (close == std::string::npos) return false;
        host  = authority.substr(1, close - 1);
        colon = authority.find(':', close);
    } else {
        colon = authority.find(':');
        host  = authority.substr(0, colon);
    }
    if (host.empty()) return false;

    if (colon != std::string::npos) {
        std::string p = authority.substr(colon + 1);
        if (p.empty() || p.find_first_not_of("0123456789") != std::string::npos)
            return false;
        port = std::atoi(p.c_str());
        if (port < 1 || port > 65535) return false;
    }

    return true;
}

std::string join_host_port(const std::string& addr, int port) {
    bool bare_v6 = addr.find(':') != std::string::npos && addr.front() != '[';
    std::string host = bare_v6 ? "[" + addr + "]" : addr;
    return host + ":" + std::to_string(port);
}
