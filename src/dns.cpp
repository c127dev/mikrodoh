#include "dns.h"

#include <cstring>

namespace dns {

namespace {

constexpr std::uint8_t  kLabelMask   = 0xC0;  // top two bits mark a pointer
constexpr std::size_t   kMaxNameLen  = 255;
constexpr std::uint8_t  kOpcodeQuery = 0;
constexpr std::uint16_t kTypeOpt     = 41;

// Type, class, TTL and RDLENGTH, the fixed part of a record after its name.
constexpr std::size_t kRrFixedLen = 10;

std::uint16_t read16(const std::uint8_t* p) {
    return static_cast<std::uint16_t>((p[0] << 8) | p[1]);
}

void write16(std::uint8_t* p, std::uint16_t v) {
    p[0] = static_cast<std::uint8_t>(v >> 8);
    p[1] = static_cast<std::uint8_t>(v & 0xFF);
}

// Offset just past the name at `pos`, or 0 when it is malformed. Unlike a
// question, a name here may be a compression pointer, which is two bytes and
// ends the name; the target is never followed because nothing needs it.
std::size_t name_end(const std::uint8_t* msg, std::size_t len, std::size_t pos) {
    std::size_t name = 0;

    while (pos < len) {
        std::uint8_t label = msg[pos];

        if ((label & kLabelMask) == kLabelMask) return pos + 2 <= len ? pos + 2 : 0;
        if ((label & kLabelMask) != 0) return 0;
        if (label == 0) return pos + 1;

        name += static_cast<std::size_t>(label) + 1;
        if (name > kMaxNameLen) return 0;

        pos += static_cast<std::size_t>(label) + 1;
    }

    return 0;
}

// Offset just past the record at `pos`, or 0 when it is malformed. `type` and
// `fixed` report the record's type and the offset of its fixed part.
std::size_t rr_end(const std::uint8_t* msg, std::size_t len, std::size_t pos,
                   std::uint16_t& type, std::size_t& fixed) {
    fixed = name_end(msg, len, pos);
    if (fixed == 0 || fixed + kRrFixedLen > len) return 0;

    type = read16(msg + fixed);

    std::size_t end = fixed + kRrFixedLen + read16(msg + fixed + 8);  // RDLENGTH
    return end <= len ? end : 0;
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

UdpLimit udp_limit(const std::uint8_t* query, std::size_t len) {
    UdpLimit limit;

    std::size_t pos = question_end(query, len);
    if (pos == 0) return limit;

    // A query normally carries the OPT record alone, but the answer and
    // authority sections are counted rather than assumed empty.
    std::size_t records = static_cast<std::size_t>(read16(query + 6)) +
                          read16(query + 8) + read16(query + 10);

    for (std::size_t i = 0; i < records; i++) {
        std::uint16_t type  = 0;
        std::size_t   fixed = 0;

        std::size_t end = rr_end(query, len, pos, type, fixed);
        if (end == 0) return limit;

        if (type == kTypeOpt) {
            // OPT stores the sender's payload size in the CLASS field.
            std::size_t advertised = read16(query + fixed + 2);
            limit.edns  = true;
            limit.bytes = advertised < kMinUdpPayload ? kMinUdpPayload : advertised;
            return limit;
        }

        pos = end;
    }

    return limit;
}

std::vector<std::uint8_t> truncate(const std::uint8_t* resp, std::size_t len,
                                   const UdpLimit& limit) {
    if (len < kHeaderLen) return {};

    // Cutting the message at a record boundary would still need the client to
    // retry, so nothing is kept: the header and the question carry TC, which is
    // the whole point of the reply.
    std::size_t end     = question_end(resp, len);
    std::size_t out_len = end != 0 ? end : kHeaderLen;

    std::vector<std::uint8_t> out(resp, resp + out_len);

    out[2] = static_cast<std::uint8_t>(out[2] | 0x02);  // TC

    write16(out.data() + 4, end != 0 ? 1 : 0);  // QDCOUNT
    std::memset(out.data() + 6, 0, 6);          // ANCOUNT, NSCOUNT, ARCOUNT

    // A reply to an EDNS query needs an OPT record of its own. It advertises
    // what the client offered, which is what this proxy is willing to send.
    if (limit.edns && out_len + 1 + kRrFixedLen <= limit.bytes) {
        out.push_back(0);  // root name
        std::size_t opt = out.size();
        out.resize(opt + kRrFixedLen, 0);

        write16(out.data() + opt, kTypeOpt);
        write16(out.data() + opt + 2,
                static_cast<std::uint16_t>(limit.bytes > kMaxMessage ? kMaxMessage
                                                                     : limit.bytes));
        // TTL (extended rcode, version, flags) and RDLENGTH stay zero.

        write16(out.data() + 10, 1);  // ARCOUNT
    }

    return out;
}

}  // namespace dns
