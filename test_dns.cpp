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

namespace {

// The query turned into the answer the resolver would send back: QR and RA set,
// one answer record appended.
std::vector<std::uint8_t> answer_to(std::vector<std::uint8_t> q) {
    q[2] = static_cast<std::uint8_t>(q[2] | 0x80);
    q[3] = static_cast<std::uint8_t>(q[3] | 0x80);
    q[7] = 1;  // ANCOUNT
    q.insert(q.end(), {0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34});
    return q;
}

}  // namespace

TEST(response_matches_accepts_the_answer_to_the_query) {
    std::vector<std::uint8_t> q = query("example.com", 0xBEEF);
    std::vector<std::uint8_t> r = answer_to(q);
    CHECK(dns::response_matches(q.data(), q.size(), r.data(), r.size()));
}

TEST(response_matches_ignores_the_case_of_the_echoed_name) {
    std::vector<std::uint8_t> q = query("example.com");
    std::vector<std::uint8_t> r = answer_to(q);
    r[13] = 'E';  // first byte of the "example" label
    CHECK(dns::response_matches(q.data(), q.size(), r.data(), r.size()));
}

TEST(response_matches_rejects_a_different_transaction_id) {
    std::vector<std::uint8_t> q = query("example.com", 0xBEEF);
    std::vector<std::uint8_t> r = answer_to(query("example.com", 0xBEF0));
    CHECK(!dns::response_matches(q.data(), q.size(), r.data(), r.size()));
}

TEST(response_matches_rejects_a_different_question) {
    std::vector<std::uint8_t> q = query("example.com");
    std::vector<std::uint8_t> r = answer_to(query("example.org"));
    CHECK(!dns::response_matches(q.data(), q.size(), r.data(), r.size()));
}

TEST(response_matches_rejects_a_different_qtype) {
    std::vector<std::uint8_t> q = query("example.com");
    std::vector<std::uint8_t> r = answer_to(q);
    r[q.size() - 3] = 28;  // QTYPE AAAA
    CHECK(!dns::response_matches(q.data(), q.size(), r.data(), r.size()));
}

TEST(response_matches_rejects_a_message_with_qr_clear) {
    std::vector<std::uint8_t> q = query("example.com");
    std::vector<std::uint8_t> r = answer_to(q);
    r[2] = static_cast<std::uint8_t>(r[2] & 0x7F);
    CHECK(!dns::response_matches(q.data(), q.size(), r.data(), r.size()));
}

TEST(response_matches_rejects_a_header_only_body) {
    std::vector<std::uint8_t> q = query("example.com");
    std::vector<std::uint8_t> r = answer_to(q);
    r.resize(dns::kHeaderLen);
    CHECK(!dns::response_matches(q.data(), q.size(), r.data(), r.size()));
}

TEST(response_matches_rejects_a_truncated_question) {
    std::vector<std::uint8_t> q = query("example.com");
    std::vector<std::uint8_t> r = answer_to(q);
    r.resize(q.size() - 1);
    CHECK(!dns::response_matches(q.data(), q.size(), r.data(), r.size()));
}

namespace {

// The query with an OPT record appended, as a resolver client sends it.
std::vector<std::uint8_t> with_opt(std::vector<std::uint8_t> q, std::uint16_t payload,
                                   std::uint16_t rdlen = 0) {
    q[11] = 1;  // ARCOUNT
    q.insert(q.end(), {0,                                        // root name
                       0, 41,                                    // TYPE OPT
                       static_cast<std::uint8_t>(payload >> 8),  // CLASS: payload size
                       static_cast<std::uint8_t>(payload & 0xFF),
                       0, 0, 0, 0,                               // TTL
                       static_cast<std::uint8_t>(rdlen >> 8),
                       static_cast<std::uint8_t>(rdlen & 0xFF)});
    q.insert(q.end(), rdlen, 0);  // an option this proxy does not read
    return q;
}

// An answer to `q` padded past `len` bytes, which is what forces truncation.
std::vector<std::uint8_t> big_answer_to(const std::vector<std::uint8_t>& q,
                                        std::size_t len) {
    std::vector<std::uint8_t> r = answer_to(q);
    r.resize(len, 0xAA);
    return r;
}

}  // namespace

TEST(udp_limit_is_512_without_an_opt_record) {
    std::vector<std::uint8_t> q = query("example.com");
    dns::UdpLimit             l = dns::udp_limit(q.data(), q.size());

    CHECK(l.bytes == dns::kMinUdpPayload);
    CHECK(!l.edns);
}

TEST(udp_limit_reads_the_advertised_payload_size) {
    std::vector<std::uint8_t> q = with_opt(query("example.com"), 1232);
    dns::UdpLimit             l = dns::udp_limit(q.data(), q.size());

    CHECK(l.bytes == 1232);
    CHECK(l.edns);
}

TEST(udp_limit_clamps_an_advertised_size_below_512) {
    std::vector<std::uint8_t> q = with_opt(query("example.com"), 300);
    dns::UdpLimit             l = dns::udp_limit(q.data(), q.size());

    CHECK(l.bytes == dns::kMinUdpPayload);
    CHECK(l.edns);
}

TEST(udp_limit_skips_a_record_before_the_opt) {
    // An OPT that is not the first record in the additional section: the walk
    // has to step over the one in front of it by its RDLENGTH.
    std::vector<std::uint8_t> q = query("example.com");
    q.insert(q.end(), {0, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 10, 0, 0, 1});  // an A record
    q = with_opt(std::move(q), 4096);
    q[11] = 2;  // ARCOUNT, both records

    dns::UdpLimit l = dns::udp_limit(q.data(), q.size());
    CHECK(l.bytes == 4096);
    CHECK(l.edns);
}

TEST(udp_limit_reads_an_opt_carrying_options) {
    // A DNS cookie or padding sits in the OPT's RDATA; the size is still in the
    // CLASS field in front of it.
    std::vector<std::uint8_t> q = with_opt(query("example.com"), 1232, 12);
    dns::UdpLimit             l = dns::udp_limit(q.data(), q.size());

    CHECK(l.bytes == 1232);
    CHECK(l.edns);
}

TEST(udp_limit_falls_back_on_a_record_running_off_the_end) {
    std::vector<std::uint8_t> q = with_opt(query("example.com"), 1232);
    q.resize(q.size() - 4);  // the OPT is cut short

    dns::UdpLimit l = dns::udp_limit(q.data(), q.size());
    CHECK(l.bytes == dns::kMinUdpPayload);
    CHECK(!l.edns);
}

TEST(udp_limit_falls_back_on_a_malformed_question) {
    std::vector<std::uint8_t> q{0x00, 0x01, 0x02};
    dns::UdpLimit             l = dns::udp_limit(q.data(), q.size());

    CHECK(l.bytes == dns::kMinUdpPayload);
    CHECK(!l.edns);
}

TEST(truncate_cuts_to_the_question_and_sets_tc) {
    std::vector<std::uint8_t> q = query("example.com", 0xBEEF);
    std::vector<std::uint8_t> r = big_answer_to(q, 2000);

    dns::UdpLimit             l = dns::udp_limit(q.data(), q.size());
    std::vector<std::uint8_t> t = dns::truncate(r.data(), r.size(), l);

    CHECK(t.size() == q.size());                // header and question only
    CHECK(t.size() <= l.bytes);
    CHECK(t[0] == 0xBE && t[1] == 0xEF);        // transaction ID preserved
    CHECK((t[2] & 0x02) != 0);                  // TC set
    CHECK((t[2] & 0x80) != 0);                  // still a response
    CHECK(t[4] == 0 && t[5] == 1);              // QDCOUNT 1
    CHECK(std::memcmp(t.data() + 6, "\0\0\0\0\0\0", 6) == 0);  // no records
    CHECK(std::memcmp(t.data() + 12, q.data() + 12, q.size() - 12) == 0);
}

TEST(truncate_answers_the_query_it_was_cut_from) {
    // A stub that validates the reply has to accept it, or the TC never gets
    // read and the retry never happens.
    std::vector<std::uint8_t> q = with_opt(query("example.com", 0xBEEF), 1232);
    std::vector<std::uint8_t> r = big_answer_to(q, 2000);

    dns::UdpLimit             l = dns::udp_limit(q.data(), q.size());
    std::vector<std::uint8_t> t = dns::truncate(r.data(), r.size(), l);

    CHECK(dns::response_matches(q.data(), q.size(), t.data(), t.size()));
}

TEST(truncate_puts_an_opt_record_back_for_an_edns_query) {
    std::vector<std::uint8_t> q = with_opt(query("example.com"), 1232);
    std::vector<std::uint8_t> r = big_answer_to(q, 2000);

    dns::UdpLimit             l = dns::udp_limit(q.data(), q.size());
    std::vector<std::uint8_t> t = dns::truncate(r.data(), r.size(), l);

    CHECK(t[10] == 0 && t[11] == 1);  // ARCOUNT 1

    std::size_t opt = dns::question_end(t.data(), t.size());
    CHECK(opt != 0);
    CHECK(t.size() == opt + 11);      // root name plus the fixed part
    CHECK(t[opt] == 0);               // root name
    CHECK(t[opt + 1] == 0 && t[opt + 2] == 41);           // TYPE OPT
    CHECK(t[opt + 3] == 0x04 && t[opt + 4] == 0xD0);      // CLASS: 1232
    CHECK(std::memcmp(t.data() + opt + 5, "\0\0\0\0\0\0", 6) == 0);  // TTL, RDLENGTH
}

TEST(truncate_omits_the_opt_record_for_a_bare_query) {
    std::vector<std::uint8_t> q = query("example.com");
    std::vector<std::uint8_t> r = big_answer_to(q, 2000);

    dns::UdpLimit             l = dns::udp_limit(q.data(), q.size());
    std::vector<std::uint8_t> t = dns::truncate(r.data(), r.size(), l);

    CHECK(t.size() == q.size());
    CHECK(t[10] == 0 && t[11] == 0);  // ARCOUNT stays 0
}

TEST(truncate_zeroes_qdcount_on_a_malformed_question) {
    std::vector<std::uint8_t> r = answer_to(query("example.com"));
    r.resize(20);  // the name runs off the end

    dns::UdpLimit             l;
    std::vector<std::uint8_t> t = dns::truncate(r.data(), r.size(), l);

    CHECK(t.size() == dns::kHeaderLen);
    CHECK((t[2] & 0x02) != 0);      // TC still set
    CHECK(t[4] == 0 && t[5] == 0);  // QDCOUNT zeroed to match
}

TEST(truncate_returns_nothing_without_a_header) {
    std::vector<std::uint8_t> r{0x00, 0x01, 0x02};
    dns::UdpLimit             l;
    CHECK(dns::truncate(r.data(), r.size(), l).empty());
}
