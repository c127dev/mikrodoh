#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

struct Config;

// A query for `health.mikrodoh.` is not forwarded as asked. The daemon sends
// the resolvers a query for the root NS set instead, bypassing the cache, and
// answers NOERROR when one of them answers it, SERVFAIL when none does. For A
// the answer carries 127.0.0.1, which is what RouterOS netwatch type=dns and
// a container HEALTHCHECK look for.
namespace health {

// True for a query whose question is health.mikrodoh., in any case.
bool is_probe(const std::uint8_t* query, std::size_t len);

// The upstream request standing in for `query`: `. IN NS` with its
// transaction ID.
std::vector<std::uint8_t> upstream_request(const std::uint8_t* query, std::size_t len);

// The reply to `query`. Empty when the query has no usable header.
std::vector<std::uint8_t> answer(const std::uint8_t* query, std::size_t len, bool healthy);

// `mikrodoh --health`: queries the local listener and returns the process exit
// code, 0 when it answers NOERROR.
int run_probe(const Config& cfg);

}  // namespace health
