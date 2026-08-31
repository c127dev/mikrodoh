#pragma once

#include <string>

#include <netinet/in.h>
#include <sys/socket.h>

// Turns LISTEN_ADDR into a bindable address. Accepts an IPv4 literal, an IPv6
// literal with or without brackets, and an IPv6 scope suffix ("fe80::1%eth0").
bool parse_bind_addr(const std::string& addr, int port, sockaddr_storage& out,
                     socklen_t& len);

// On an IPv6 socket, decides whether the bind also covers IPv4 clients, which
// reach it as ::ffff:a.b.c.d. No effect on an IPv4 socket.
void apply_v6only(int fd, const sockaddr_storage& addr, bool v6only);

// "1.2.3.4:53" or "[::]:53", for the banner and bind errors.
std::string join_host_port(const std::string& addr, int port);
