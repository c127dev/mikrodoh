#include "dns.h"

#include <cstring>

namespace dns {

namespace {

constexpr std::uint8_t kLabelMask   = 0xC0;  // top two bits mark a pointer
constexpr std::size_t  kMaxNameLen  = 255;
constexpr std::uint8_t kOpcodeQuery = 0;

std::uint16_t read16(const std::uint8_t* p) {
    return static_cast<std::uint16_t>((p[0] << 8) | p[1]);
}

// Safe to run over a whole name: a label length is at most 63 and so never
// falls in the 'A'-'Z' range this folds.
std::uint8_t lower(std::uint8_t c) {
    return c >= 'A' && c <= 'Z' ? static_cast<std::uint8_t>(c + 32) : c;
}

}  // namespace

std::size_t question_end(const std::uint8_t* msg, std::size_t len) {
    if (len < kHeaderLen) return 0;

    std::size_t pos  = kHeaderLen;
    std::size_t name = 0;

    while (pos < len) {
        std::uint8_t label = msg[pos];

        // A question is never compressed, so a pointer here is malformed.
        if ((label & kLabelMask) != 0) return 0;

        if (label == 0) {
            pos++;
            // QTYPE and QCLASS follow the root label.
            return pos + 4 <= len ? pos + 4 : 0;
        }

        name += static_cast<std::size_t>(label) + 1;
        if (name > kMaxNameLen) return 0;

        pos += static_cast<std::size_t>(label) + 1;
    }

    return 0;
}

bool query_valid(const std::uint8_t* msg, std::size_t len) {
    if (len < kHeaderLen || len > kMaxMessage) return false;

    if (msg[2] & 0x80) return false;  // QR: already a response

    std::uint8_t opcode = static_cast<std::uint8_t>((msg[2] >> 3) & 0x0F);
    if (opcode != kOpcodeQuery) return false;

    if (read16(msg + 4) != 1) return false;  // QDCOUNT

    return question_end(msg, len) != 0;
}

bool response_matches(const std::uint8_t* query, std::size_t qlen,
                      const std::uint8_t* resp, std::size_t rlen) {
    if (qlen < kHeaderLen || rlen < kHeaderLen || rlen > kMaxMessage) return false;

    if (query[0] != resp[0] || query[1] != resp[1]) return false;  // transaction ID

    if ((resp[2] & 0x80) == 0) return false;                 // QR: not a response
    if (((query[2] ^ resp[2]) & 0x78) != 0) return false;    // opcode

    if (read16(resp + 4) != 1) return false;  // QDCOUNT

    std::size_t q_end = question_end(query, qlen);
    std::size_t r_end = question_end(resp, rlen);
    if (q_end == 0 || r_end == 0 || q_end != r_end) return false;

    // QTYPE and QCLASS are binary, the name is not: a resolver may echo the
    // labels in a different case than they were sent.
    std::size_t name_end = q_end - 4;
    for (std::size_t i = kHeaderLen; i < name_end; i++)
        if (lower(query[i]) != lower(resp[i])) return false;

    return std::memcmp(query + name_end, resp + name_end, 4) == 0;
}

std::vector<std::uint8_t> make_error(const std::uint8_t* query, std::size_t len,
                                     std::uint8_t rcode) {
    if (len < kHeaderLen) return {};

    // Echo the question when it parses; a malformed one is dropped and QDCOUNT
    // zeroed, so the reply stays self-consistent.
    std::size_t end = question_end(query, len);
    std::size_t out_len = end != 0 ? end : kHeaderLen;

    std::vector<std::uint8_t> out(query, query + out_len);

    out[2] = static_cast<std::uint8_t>((query[2] & 0x79) | 0x80);  // keep opcode+RD, set QR
    out[3] = static_cast<std::uint8_t>(0x80 | (rcode & 0x0F));     // RA + rcode

    std::uint16_t qdcount = end != 0 ? 1 : 0;
    out[4] = static_cast<std::uint8_t>(qdcount >> 8);
    out[5] = static_cast<std::uint8_t>(qdcount & 0xFF);
    std::memset(out.data() + 6, 0, 6);  // ANCOUNT, NSCOUNT, ARCOUNT

    return out;
}

}  // namespace dns
