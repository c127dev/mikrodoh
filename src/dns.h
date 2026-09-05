#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace dns {

constexpr std::size_t kHeaderLen  = 12;
constexpr std::size_t kMaxMessage = 65535;

// The most a client is assumed to take over UDP when it advertises nothing.
constexpr std::size_t kMinUdpPayload = 512;

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

// What a client will accept over UDP.
struct UdpLimit {
    std::size_t bytes = kMinUdpPayload;
    bool        edns  = false;  // the query carried an OPT record
};

// The payload size advertised by the query's OPT record, clamped to
// [512, 65535]. Without an OPT record the limit is the 512 bytes of RFC 1035.
UdpLimit udp_limit(const std::uint8_t* query, std::size_t len);

// `resp` cut to fit a UDP limit: header and question only, TC set and every
// record dropped, so the stub retries over TCP. An OPT record is put back when
// `edns` is set, since a reply to an EDNS query has to carry one. Empty when
// `resp` has no usable header.
std::vector<std::uint8_t> truncate(const std::uint8_t* resp, std::size_t len,
                                   const UdpLimit& limit);

constexpr std::uint8_t kRcodeServFail = 2;
constexpr std::uint8_t kRcodeRefused  = 5;

}  // namespace dns
