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

// True when `host` is an IPv4 or IPv6 literal, so reaching it needs no
// resolution. Brackets around an IPv6 literal are accepted.
bool is_ip_literal(const std::string& host);

// The authority of an https:// URL. `host` is returned without brackets and
// `port` defaults to 443. False when the URL has no host or a bad port.
bool split_url_authority(const std::string& url, std::string& host, int& port);
