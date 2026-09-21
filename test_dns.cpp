#include "harness.h"

#include "dns.h"

#include <algorithm>
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

TEST(udp_limit_reads_the_do_bit) {
    std::vector<std::uint8_t> q = with_opt(query("example.com"), 1232);
    CHECK(!dns::udp_limit(q.data(), q.size()).dnssec_ok);

    q[q.size() - 4] = 0x80;  // TTL flags, high byte
    CHECK(dns::udp_limit(q.data(), q.size()).dnssec_ok);
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

TEST(rcode_reads_the_low_nibble) {
    std::vector<std::uint8_t> r = answer_to(query("example.com"));
    r[3] = static_cast<std::uint8_t>((r[3] & 0xF0) | dns::kRcodeNxDomain);
    CHECK(dns::rcode(r.data(), r.size()) == dns::kRcodeNxDomain);

    r[3] = static_cast<std::uint8_t>(0x80 | dns::kRcodeNoError);
    CHECK(dns::rcode(r.data(), r.size()) == dns::kRcodeNoError);
}

TEST(rcode_of_a_headerless_message_is_servfail) {
    std::vector<std::uint8_t> r{0x00, 0x01};
    CHECK(dns::rcode(r.data(), r.size()) == dns::kRcodeServFail);
}

TEST(has_answers_follows_ancount) {
    std::vector<std::uint8_t> r = answer_to(query("example.com"));
    r[6] = 0;
    r[7] = 0;
    CHECK(!dns::has_answers(r.data(), r.size()));

    r[7] = 1;
    CHECK(dns::has_answers(r.data(), r.size()));

    r[6] = 1;
    r[7] = 0;
    CHECK(dns::has_answers(r.data(), r.size()));
}

TEST(has_answers_is_false_without_a_header) {
    std::vector<std::uint8_t> r{0x00, 0x01, 0x02};
    CHECK(!dns::has_answers(r.data(), r.size()));
}

namespace {

std::vector<std::uint8_t> with_a(std::vector<std::uint8_t> r, std::uint32_t ttl) {
    r[7] = static_cast<std::uint8_t>(r[7] + 1);  // ANCOUNT
    r.insert(r.end(), {0xC0, 12, 0, 1, 0, 1,
                       static_cast<std::uint8_t>(ttl >> 24), static_cast<std::uint8_t>(ttl >> 16),
                       static_cast<std::uint8_t>(ttl >> 8), static_cast<std::uint8_t>(ttl),
                       0, 4, 192, 0, 2, 1});
    return r;
}

}  // namespace

TEST(min_ttl_is_the_lowest_record_ttl) {
    std::vector<std::uint8_t> r = with_a(with_a(query("example.com", 1, 0x8180), 300), 60);
    CHECK(dns::min_ttl(r.data(), r.size()) == 60);
}

TEST(min_ttl_is_minus_one_without_records) {
    std::vector<std::uint8_t> r = query("example.com", 1, 0x8180);
    CHECK(dns::min_ttl(r.data(), r.size()) == -1);
}

TEST(min_ttl_ignores_the_opt_record) {
    std::vector<std::uint8_t> r = with_a(query("example.com", 1, 0x8180), 300);
    r = with_opt(std::move(r), 1232);
    CHECK(dns::min_ttl(r.data(), r.size()) == 300);
}

TEST(min_ttl_treats_a_top_bit_ttl_as_zero) {
    std::vector<std::uint8_t> r = with_a(query("example.com", 1, 0x8180), 0x80000000u);
    CHECK(dns::min_ttl(r.data(), r.size()) == 0);
}

TEST(age_ttls_lowers_every_ttl_and_stops_at_zero) {
    std::vector<std::uint8_t> r = with_a(with_a(query("example.com", 1, 0x8180), 300), 5);
    dns::age_ttls(r.data(), r.size(), 10);
    CHECK(dns::min_ttl(r.data(), r.size()) == 0);

    std::vector<std::uint8_t> s = with_a(query("example.com", 1, 0x8180), 300);
    dns::age_ttls(s.data(), s.size(), 10);
    CHECK(dns::min_ttl(s.data(), s.size()) == 290);
}

namespace {

// `q` with an OPT record whose RDATA is `options`.
std::vector<std::uint8_t> with_options(std::vector<std::uint8_t> q,
                                       const std::vector<std::uint8_t>& options) {
    q = with_opt(std::move(q), 1232, static_cast<std::uint16_t>(options.size()));
    std::copy(options.begin(), options.end(), q.end() - static_cast<std::ptrdiff_t>(options.size()));
    return q;
}

// The OPT RDATA of a message built by with_options, after sanitize_edns.
std::vector<std::uint8_t> opt_rdata(const std::vector<std::uint8_t>& q, std::size_t opt_at) {
    std::size_t rdlen = static_cast<std::size_t>(q[opt_at + 9] << 8 | q[opt_at + 10]);
    return std::vector<std::uint8_t>(q.begin() + static_cast<std::ptrdiff_t>(opt_at + 11),
                                     q.begin() + static_cast<std::ptrdiff_t>(opt_at + 11 + rdlen));
}

const std::vector<std::uint8_t> kEcs{0, 8, 0, 7, 0, 1, 24, 0, 192, 0, 2};
const std::vector<std::uint8_t> kCookie{0, 10, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8};

}  // namespace

TEST(sanitize_edns_strips_client_subnet) {
    std::vector<std::uint8_t> q      = with_options(query("example.com"), kEcs);
    std::size_t               opt_at = query("example.com").size();

    dns::sanitize_edns(q);

    std::vector<std::uint8_t> rdata = opt_rdata(q, opt_at);
    CHECK(rdata.size() >= 4);
    CHECK(rdata[0] == 0 && rdata[1] == 12);  // padding is all that is left
    CHECK(opt_at + 11 + rdata.size() == q.size());
}

TEST(sanitize_edns_keeps_other_options) {
    std::vector<std::uint8_t> opts = kEcs;
    opts.insert(opts.end(), kCookie.begin(), kCookie.end());
    std::vector<std::uint8_t> q      = with_options(query("example.com"), opts);
    std::size_t               opt_at = query("example.com").size();

    dns::sanitize_edns(q);

    std::vector<std::uint8_t> rdata = opt_rdata(q, opt_at);
    CHECK(std::equal(kCookie.begin(), kCookie.end(), rdata.begin()));
}

TEST(sanitize_edns_pads_to_a_multiple_of_128) {
    std::vector<std::uint8_t> q = with_options(query("example.com"), kEcs);
    dns::sanitize_edns(q);
    CHECK(q.size() % 128 == 0);

    std::vector<std::uint8_t> r = with_opt(query("example.com"), 1232);
    dns::sanitize_edns(r);
    CHECK(r.size() == 128);
    CHECK(dns::query_valid(r.data(), r.size()));
    CHECK(dns::udp_limit(r.data(), r.size()).bytes == 1232);
}

TEST(sanitize_edns_replaces_existing_padding) {
    std::vector<std::uint8_t> q = with_options(query("example.com"), {0, 12, 0, 200});
    q.insert(q.end(), 200, 0);
    q[q.size() - 200 - 6] = 204 >> 8;  // RDLENGTH covers the padding bytes
    q[q.size() - 200 - 5] = 204 & 0xFF;

    dns::sanitize_edns(q);
    CHECK(q.size() == 128);
}

TEST(sanitize_edns_leaves_a_query_without_opt_alone) {
    std::vector<std::uint8_t> q    = query("example.com");
    std::vector<std::uint8_t> copy = q;
    dns::sanitize_edns(q);
    CHECK(q == copy);
}

TEST(sanitize_edns_leaves_a_malformed_option_alone) {
    std::vector<std::uint8_t> q    = with_options(query("example.com"), {0, 8, 0, 9, 0});
    std::vector<std::uint8_t> copy = q;
    dns::sanitize_edns(q);
    CHECK(q == copy);
}

TEST(set_ttls_sets_every_ttl_but_opt) {
    std::vector<std::uint8_t> r = with_a(with_a(query("example.com", 1, 0x8180), 300), 5);
    r = with_opt(std::move(r), 1232);
    dns::set_ttls(r.data(), r.size(), 30);
    CHECK(dns::min_ttl(r.data(), r.size()) == 30);
    CHECK(r[r.size() - 6] == 0 && r[r.size() - 3] == 0);  // OPT TTL untouched
}

TEST(clamp_ttls_raises_and_lowers_every_ttl_but_opt) {
    std::vector<std::uint8_t> r = with_a(with_a(query("example.com", 1, 0x8180), 5), 90000);
    r = with_opt(std::move(r), 1232);
    dns::clamp_ttls(r.data(), r.size(), 60, 3600);

    CHECK(dns::min_ttl(r.data(), r.size()) == 60);
    dns::set_ttls(r.data(), r.size(), 7200);
    dns::clamp_ttls(r.data(), r.size(), 60, 3600);
    CHECK(dns::min_ttl(r.data(), r.size()) == 3600);
    CHECK(r[r.size() - 6] == 0 && r[r.size() - 3] == 0);  // OPT TTL untouched
}

namespace {

// with_options() with the DO bit, EDNS version and extended RCODE set in the
// OPT TTL, and CD and AD set in the header.
std::vector<std::uint8_t> dnssec_query(const std::vector<std::uint8_t>& options) {
    std::vector<std::uint8_t> q = with_options(query("example.com"), options);
    std::size_t               opt_at = query("example.com").size();

    q[3] = static_cast<std::uint8_t>(q[3] | 0x30);  // AD, CD
    q[opt_at + 5] = 0x00;                           // extended RCODE
    q[opt_at + 6] = 0x00;                           // version
    q[opt_at + 7] = 0x80;                           // DO
    return q;
}

}  // namespace

TEST(sanitize_edns_keeps_the_do_bit) {
    std::vector<std::uint8_t> q = dnssec_query(kEcs);
    CHECK(dns::udp_limit(q.data(), q.size()).dnssec_ok);

    dns::sanitize_edns(q);
    CHECK(dns::udp_limit(q.data(), q.size()).dnssec_ok);
}

TEST(sanitize_edns_keeps_the_header_flags) {
    std::vector<std::uint8_t> q    = dnssec_query(kEcs);
    std::vector<std::uint8_t> copy = q;

    dns::sanitize_edns(q);
    CHECK(std::equal(copy.begin(), copy.begin() + 10, q.begin()));  // up to ARCOUNT
    CHECK(q[3] & 0x10);                                             // CD
}

TEST(sanitize_edns_keeps_the_rest_of_the_opt_record) {
    std::vector<std::uint8_t> q      = dnssec_query(kEcs);
    std::size_t               opt_at = query("example.com").size();
    std::vector<std::uint8_t> fixed(q.begin() + static_cast<std::ptrdiff_t>(opt_at),
                                    q.begin() + static_cast<std::ptrdiff_t>(opt_at + 9));

    dns::sanitize_edns(q);
    // Owner, TYPE, CLASS (payload size) and TTL (extended RCODE, version, DO).
    CHECK(std::equal(fixed.begin(), fixed.end(), q.begin() + static_cast<std::ptrdiff_t>(opt_at)));
}

TEST(sanitize_edns_keeps_the_do_bit_without_ecs) {
    std::vector<std::uint8_t> q = dnssec_query(kCookie);
    dns::sanitize_edns(q);
    CHECK(dns::udp_limit(q.data(), q.size()).dnssec_ok);
    CHECK(q[3] & 0x10);
}
