#include "harness.h"

#include "dns.h"

#include <cstring>
#include <string>
#include <vector>

namespace {

// A minimal well-formed query for `name`, QTYPE A, QCLASS IN.
std::vector<std::uint8_t> query(const std::string& name, std::uint16_t txid = 0x1234,
                                std::uint16_t flags = 0x0100, std::uint16_t qdcount = 1) {
    std::vector<std::uint8_t> q{
        static_cast<std::uint8_t>(txid >> 8),    static_cast<std::uint8_t>(txid & 0xFF),
        static_cast<std::uint8_t>(flags >> 8),   static_cast<std::uint8_t>(flags & 0xFF),
        static_cast<std::uint8_t>(qdcount >> 8), static_cast<std::uint8_t>(qdcount & 0xFF),
        0, 0, 0, 0, 0, 0};

    std::size_t start = 0;
    while (start <= name.size()) {
        std::size_t dot   = name.find('.', start);
        std::size_t label = (dot == std::string::npos ? name.size() : dot) - start;
        q.push_back(static_cast<std::uint8_t>(label));
        q.insert(q.end(), name.begin() + static_cast<std::ptrdiff_t>(start),
                 name.begin() + static_cast<std::ptrdiff_t>(start + label));
        if (dot == std::string::npos) break;
        start = dot + 1;
    }
    q.push_back(0);

    q.insert(q.end(), {0, 1, 0, 1});  // QTYPE A, QCLASS IN
    return q;
}

}  // namespace

TEST(question_end_points_past_qtype_and_qclass) {
    std::vector<std::uint8_t> q = query("example.com");
    // 12 header + 13 name + 4 = 29, which is the whole message.
    CHECK(dns::question_end(q.data(), q.size()) == q.size());
}

TEST(question_end_rejects_a_truncated_name) {
    std::vector<std::uint8_t> q = query("example.com");
    q.resize(20);
    CHECK(dns::question_end(q.data(), q.size()) == 0);
}

TEST(question_end_rejects_a_missing_qtype) {
    std::vector<std::uint8_t> q = query("example.com");
    q.resize(q.size() - 1);
    CHECK(dns::question_end(q.data(), q.size()) == 0);
}

TEST(question_end_rejects_a_compression_pointer) {
    std::vector<std::uint8_t> q = query("example.com");
    q[12] = 0xC0;  // a pointer where a label length belongs
    CHECK(dns::question_end(q.data(), q.size()) == 0);
}

TEST(question_end_rejects_a_header_with_no_question) {
    std::vector<std::uint8_t> q = query("example.com");
    q.resize(dns::kHeaderLen);
    CHECK(dns::question_end(q.data(), q.size()) == 0);
}

TEST(query_valid_accepts_an_ordinary_query) {
    std::vector<std::uint8_t> q = query("example.com");
    CHECK(dns::query_valid(q.data(), q.size()));
}

TEST(query_valid_rejects_a_short_message) {
    std::vector<std::uint8_t> q{0xde, 0xad};
    CHECK(!dns::query_valid(q.data(), q.size()));
}

TEST(query_valid_rejects_a_response) {
    std::vector<std::uint8_t> q = query("example.com", 0x1234, 0x8180);
    CHECK(!dns::query_valid(q.data(), q.size()));
}

TEST(query_valid_rejects_a_non_query_opcode) {
    // Opcode 5, UPDATE.
    std::vector<std::uint8_t> q = query("example.com", 0x1234, 0x2800);
    CHECK(!dns::query_valid(q.data(), q.size()));
}

TEST(query_valid_rejects_qdcount_other_than_one) {
    std::vector<std::uint8_t> zero = query("example.com", 0x1234, 0x0100, 0);
    std::vector<std::uint8_t> two  = query("example.com", 0x1234, 0x0100, 2);
    CHECK(!dns::query_valid(zero.data(), zero.size()));
    CHECK(!dns::query_valid(two.data(), two.size()));
}

TEST(query_valid_rejects_a_name_over_255_bytes) {
    std::string name;
    for (int i = 0; i < 30; ++i) name += "abcdefghij.";  // 330 bytes of labels
    name += "com";

    std::vector<std::uint8_t> q = query(name);
    CHECK(!dns::query_valid(q.data(), q.size()));
}

TEST(make_error_echoes_the_question_and_sets_the_rcode) {
    std::vector<std::uint8_t> q = query("example.com", 0xBEEF);
    std::vector<std::uint8_t> r =
        dns::make_error(q.data(), q.size(), dns::kRcodeServFail);

    CHECK(r.size() == q.size());
    CHECK(r[0] == 0xBE && r[1] == 0xEF);        // transaction ID preserved
    CHECK((r[2] & 0x80) != 0);                  // QR set
    CHECK((r[2] & 0x01) != 0);                  // RD copied from the query
    CHECK((r[3] & 0x0F) == dns::kRcodeServFail);
    CHECK((r[3] & 0x80) != 0);                  // RA set
    CHECK(r[4] == 0 && r[5] == 1);              // QDCOUNT 1
    CHECK(std::memcmp(r.data() + 6, "\0\0\0\0\0\0", 6) == 0);
    CHECK(std::memcmp(r.data() + 12, q.data() + 12, q.size() - 12) == 0);
}

TEST(make_error_drops_a_malformed_question) {
    std::vector<std::uint8_t> q = query("example.com");
    q.resize(20);  // name runs off the end

    std::vector<std::uint8_t> r =
        dns::make_error(q.data(), q.size(), dns::kRcodeServFail);

    CHECK(r.size() == dns::kHeaderLen);
    CHECK(r[4] == 0 && r[5] == 0);  // QDCOUNT zeroed to match
}

TEST(make_error_returns_nothing_without_a_header) {
    std::vector<std::uint8_t> q{0x00, 0x01, 0x02};
    CHECK(dns::make_error(q.data(), q.size(), dns::kRcodeServFail).empty());
}
