#include "health.h"

#include "config.h"
#include "dns.h"
#include "net.h"

#include <iostream>
#include <string>

#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

namespace health {

namespace {

// health.mikrodoh. in wire format.
const std::uint8_t kName[] = {6, 'h', 'e', 'a', 'l', 't', 'h', 8, 'm', 'i', 'k',
                              'r', 'o', 'd', 'o', 'h', 0};

constexpr std::uint16_t kTypeA  = 1;
constexpr std::uint16_t kTypeNs = 2;

// Long enough for REQUEST_TIMEOUT_MS on every resolver in a short list.
constexpr int kProbeTimeoutMs = 10000;

std::uint8_t lower(std::uint8_t c) {
    return c >= 'A' && c <= 'Z' ? static_cast<std::uint8_t>(c + 32) : c;
}

std::uint16_t qtype(const std::uint8_t* query, std::size_t len) {
    std::size_t end = dns::question_end(query, len);
    if (end == 0) return 0;
    return static_cast<std::uint16_t>(query[end - 4] << 8 | query[end - 3]);
}

}  // namespace

bool is_probe(const std::uint8_t* query, std::size_t len) {
    std::size_t end = dns::question_end(query, len);
    if (end != dns::kHeaderLen + sizeof(kName) + 4) return false;

    for (std::size_t i = 0; i < sizeof(kName); i++)
        if (lower(query[dns::kHeaderLen + i]) != kName[i]) return false;
    return true;
}

std::vector<std::uint8_t> upstream_request(const std::uint8_t* query, std::size_t len) {
    if (len < 2) return {};
    return {query[0], query[1], 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0,
            0,  // root
            0, kTypeNs, 0, 1};
}

std::vector<std::uint8_t> answer(const std::uint8_t* query, std::size_t len, bool healthy) {
    std::vector<std::uint8_t> out = dns::make_error(
        query, len, healthy ? dns::kRcodeNoError : dns::kRcodeServFail);
    if (!healthy || out.size() <= dns::kHeaderLen || qtype(query, len) != kTypeA) return out;

    out[7] = 1;  // ANCOUNT
    out.insert(out.end(), {0xC0, 12,         // the question's name
                           0, kTypeA, 0, 1,  // A IN
                           0, 0, 0, 0,       // TTL: never cached downstream
                           0, 4, 127, 0, 0, 1});
    return out;
}

namespace {

// A connected UDP socket to the listener, or -1. A wildcard bind is reached
// on loopback; a dual-stack one on IPv4 too, for a host without ::1.
int connect_listener(const Config& cfg) {
    std::vector<std::string> targets{cfg.listen_addr};
    if (cfg.listen_addr == "0.0.0.0") targets = {"127.0.0.1"};
    if (cfg.listen_addr == "::" || cfg.listen_addr == "[::]") targets = {"::1", "127.0.0.1"};

    for (const std::string& addr : targets) {
        sockaddr_storage to{};
        socklen_t        to_len = 0;
        if (!parse_bind_addr(addr, cfg.listen_port, to, to_len)) continue;

        int fd = socket(to.ss_family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        if (fd < 0) continue;
        if (connect(fd, reinterpret_cast<const sockaddr*>(&to), to_len) == 0) return fd;
        close(fd);
    }

    std::cerr << "health: cannot reach " << join_host_port(cfg.listen_addr, cfg.listen_port)
              << "\n";
    return -1;
}
}  // namespace

int run_probe(const Config& cfg) {
    int fd = connect_listener(cfg);
    if (fd < 0) return 1;

    std::vector<std::uint8_t> q{0x4D, 0x44, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0};
    q.insert(q.end(), kName, kName + sizeof(kName));
    q.insert(q.end(), {0, kTypeA, 0, 1});

    std::uint8_t buf[512];
    ssize_t      n = -1;
    if (send(fd, q.data(), q.size(), 0) == static_cast<ssize_t>(q.size())) {
        pollfd p{fd, POLLIN, 0};
        if (poll(&p, 1, kProbeTimeoutMs) == 1) n = recv(fd, buf, sizeof(buf), 0);
    }
    close(fd);

    if (n < static_cast<ssize_t>(dns::kHeaderLen) || buf[0] != q[0] || buf[1] != q[1]) {
        std::cerr << "health: no answer\n";
        return 1;
    }

    std::uint8_t rc = dns::rcode(buf, static_cast<std::size_t>(n));
    if (rc != dns::kRcodeNoError) {
        std::cerr << "health: no resolver answered (rcode " << static_cast<int>(rc) << ")\n";
        return 1;
    }

    std::cout << "healthy\n";
    return 0;
}

}  // namespace health
