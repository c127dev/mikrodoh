#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace dns {

constexpr std::size_t kHeaderLen  = 12;
constexpr std::size_t kMaxMessage = 65535;

// Offset just past the first question, or 0 when the question is malformed or
// runs off the end of the message.
std::size_t question_end(const std::uint8_t* msg, std::size_t len);

// True for a message this proxy will forward: a full header, QR=0, opcode
// QUERY, QDCOUNT 1 and a well-formed question.
bool query_valid(const std::uint8_t* msg, std::size_t len);

// True when `resp` is a response to `query`: QR set, the same transaction ID
// and opcode, QDCOUNT 1 and the same question. The name is compared without
// regard to case, so a resolver that echoes 0x20-encoded labels still matches.
bool response_matches(const std::uint8_t* query, std::size_t qlen,
                      const std::uint8_t* resp, std::size_t rlen);

// A response to `query` carrying `rcode`, with the question echoed back and no
// records. Empty when the query has no usable header.
std::vector<std::uint8_t> make_error(const std::uint8_t* query, std::size_t len,
                                     std::uint8_t rcode);

constexpr std::uint8_t kRcodeServFail = 2;
constexpr std::uint8_t kRcodeRefused  = 5;

}  // namespace dns
