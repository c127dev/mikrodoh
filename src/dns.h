#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace dns {
constexpr std::size_t kHeaderLen  = 12;
constexpr std::size_t kMaxMessage = 65535;

constexpr std::size_t kMinUdpPayload = 512;

std::size_t question_end(const std::uint8_t* msg, std::size_t len);

bool query_valid(const std::uint8_t* msg, std::size_t len);

bool response_matches(const std::uint8_t* query, std::size_t qlen,
                      const std::uint8_t* resp, std::size_t rlen);

std::vector<std::uint8_t> make_error(const std::uint8_t* query, std::size_t len,
                                     std::uint8_t rcode);

struct UdpLimit {
    std::size_t bytes = kMinUdpPayload;
    bool        edns  = false;  // the query carried an OPT record
    bool        dnssec_ok = false;  // the OPT record's DO bit
};

UdpLimit udp_limit(const std::uint8_t* query, std::size_t len);

std::vector<std::uint8_t> truncate(const std::uint8_t* resp, std::size_t len,
                                   const UdpLimit& limit);

constexpr std::uint8_t kRcodeNoError  = 0;
constexpr std::uint8_t kRcodeFormErr  = 1;
constexpr std::uint8_t kRcodeServFail = 2;
constexpr std::uint8_t kRcodeNxDomain = 3;
constexpr std::uint8_t kRcodeRefused  = 5;

std::uint8_t rcode(const std::uint8_t* msg, std::size_t len);

bool has_answers(const std::uint8_t* msg, std::size_t len);

void sanitize_edns(std::vector<std::uint8_t>& query);

long min_ttl(const std::uint8_t* msg, std::size_t len);

void age_ttls(std::uint8_t* msg, std::size_t len, std::uint32_t elapsed);

void clamp_ttls(std::uint8_t* msg, std::size_t len, std::uint32_t min, std::uint32_t max);

void set_ttls(std::uint8_t* msg, std::size_t len, std::uint32_t ttl);

}  // namespace dns
