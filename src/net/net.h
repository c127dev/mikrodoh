// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Johan Alvarado

#pragma once

#include <string>

#include <netinet/in.h>
#include <sys/socket.h>

bool parse_bind_addr(const std::string& addr, int port, sockaddr_storage& out,
                     socklen_t& len);

void apply_v6only(int fd, const sockaddr_storage& addr, bool v6only);

std::string join_host_port(const std::string& addr, int port);

bool is_ip_literal(const std::string& host);

bool split_url_authority(const std::string& url, std::string& host, int& port);
