// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Johan Alvarado

#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

struct Config;

namespace health {
bool is_probe(const std::uint8_t* query, std::size_t len);

std::vector<std::uint8_t> upstream_request(const std::uint8_t* query, std::size_t len);

std::vector<std::uint8_t> answer(const std::uint8_t* query, std::size_t len, bool healthy);

int run_probe(const Config& cfg);

}  // namespace health
