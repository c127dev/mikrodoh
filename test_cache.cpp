#include "harness.h"

#include "cache.h"

#include <chrono>
#include <initializer_list>
#include <string>
#include <thread>
#include <vector>

namespace {

std::vector<std::uint8_t> bytes(std::initializer_list<int> v) {
    std::vector<std::uint8_t> out;
    for (int b : v) out.push_back(static_cast<std::uint8_t>(b));
    return out;
}

// A query for example.com, QTYPE A, QCLASS IN, with RD set.
std::vector<std::uint8_t> query(int txid) {
    return bytes({txid >> 8, txid & 0xFF, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0,
                                         7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
                                         0, 1, 0, 1});
}

// `q` with an OPT record carrying a DNS cookie option.
std::vector<std::uint8_t> with_cookie(std::vector<std::uint8_t> q, int cookie, bool dnssec_ok = false) {
    q[11] = 1;  // ARCOUNT
    std::vector<std::uint8_t> opt = bytes({0, 0, 41, 0x04, 0xD0, 0, 0, dnssec_ok ? 0x80 : 0, 0,
                                           0, 12, 0, 10, 0, 8});
    q.insert(q.end(), opt.begin(), opt.end());
    q.insert(q.end(), 8, static_cast<std::uint8_t>(cookie));
    return q;
}

std::string key(const std::vector<std::uint8_t>& q) { return DnsCache::key_of(q.data(), q.size()); }

}  // namespace

TEST(key_of_ignores_the_transaction_id) {
    CHECK(!key(query(0x1122)).empty());
    CHECK(key(query(0x1122)) == key(query(0x3344)));
}

TEST(key_of_ignores_the_dns_cookie) {
    CHECK(key(with_cookie(query(1), 0xAA)) == key(with_cookie(query(2), 0xBB)));
}

TEST(key_of_separates_different_questions) {
    std::vector<std::uint8_t> b = query(1);
    b[b.size() - 3] = 28;  // QTYPE AAAA
    CHECK(key(query(1)) != key(b));
}

TEST(key_of_separates_edns_from_plain_queries) {
    CHECK(key(query(1)) != key(with_cookie(query(1), 0xAA)));
}

TEST(key_of_separates_the_do_bit) {
    CHECK(key(with_cookie(query(1), 0xAA)) != key(with_cookie(query(1), 0xAA, true)));
}

TEST(key_of_separates_header_flags) {
    std::vector<std::uint8_t> b = query(1);
    b[3] = 0x10;  // CD
    CHECK(key(query(1)) != key(b));
}

TEST(key_of_is_empty_for_a_malformed_question) {
    std::vector<std::uint8_t> q = query(1);
    q.resize(20);
    CHECK(key(q).empty());
}

TEST(a_zero_ttl_disables_the_cache) {
    DnsCache cache(0);
    CHECK(!cache.enabled());

    cache.store("k", bytes({0, 0, 1}));

    std::vector<std::uint8_t> out;
    CHECK(!cache.lookup("k", out));
}

TEST(store_then_lookup_returns_the_response) {
    DnsCache cache(60);
    CHECK(cache.enabled());

    std::vector<std::uint8_t> response = bytes({0x00, 0x00, 0x81, 0x80, 0x2A});
    cache.store("k", response);

    std::vector<std::uint8_t> out;
    CHECK(cache.lookup("k", out));
    CHECK(out == response);
}

TEST(lookup_misses_on_an_unknown_key) {
    DnsCache                  cache(60);
    std::vector<std::uint8_t> out;
    CHECK(!cache.lookup("absent", out));
}

TEST(an_empty_key_is_never_stored_or_found) {
    DnsCache cache(60);
    cache.store("", bytes({1, 2, 3}));

    std::vector<std::uint8_t> out;
    CHECK(!cache.lookup("", out));
}

TEST(a_response_shorter_than_a_transaction_id_is_not_returned) {
    // The caller overwrites the first two bytes, so a one-byte entry cannot be
    // served without reading past the end.
    DnsCache cache(60);
    cache.store("k", bytes({0x7F}));

    std::vector<std::uint8_t> out;
    CHECK(!cache.lookup("k", out));
}

TEST(overflow_keeps_the_most_recent_entries) {
    DnsCache cache(60, 4);

    for (int i = 0; i < 16; ++i) cache.store("key" + std::to_string(i), bytes({0, 0, 1}));

    std::vector<std::uint8_t> out;
    for (int i = 0; i < 12; ++i) CHECK(!cache.lookup("key" + std::to_string(i), out));
    for (int i = 12; i < 16; ++i) CHECK(cache.lookup("key" + std::to_string(i), out));
}

TEST(overflow_evicts_the_least_recently_used_entry) {
    DnsCache cache(60, 2);
    cache.store("a", bytes({0, 0, 1}));
    cache.store("b", bytes({0, 0, 2}));

    std::vector<std::uint8_t> out;
    CHECK(cache.lookup("a", out));

    cache.store("c", bytes({0, 0, 3}));

    CHECK(cache.lookup("a", out));
    CHECK(!cache.lookup("b", out));
    CHECK(cache.lookup("c", out));
}

TEST(restoring_a_key_replaces_it_without_evicting) {
    DnsCache cache(60, 2);
    cache.store("a", bytes({0, 0, 1}));
    cache.store("b", bytes({0, 0, 2}));
    cache.store("a", bytes({0, 0, 9}));

    std::vector<std::uint8_t> out;
    CHECK(cache.lookup("b", out));
    CHECK(cache.lookup("a", out));
    CHECK(out == bytes({0, 0, 9}));
}

TEST(a_shorter_ttl_override_expires_early) {
    DnsCache cache(3600);
    cache.store("k", bytes({0, 0, 1}), 1);

    std::vector<std::uint8_t> out;
    CHECK(cache.lookup("k", out));

    std::this_thread::sleep_for(std::chrono::milliseconds(1100));
    CHECK(!cache.lookup("k", out));
}

TEST(a_ttl_override_never_extends_the_configured_ttl) {
    DnsCache cache(1);
    cache.store("k", bytes({0, 0, 1}), 3600);

    std::this_thread::sleep_for(std::chrono::milliseconds(1100));

    std::vector<std::uint8_t> out;
    CHECK(!cache.lookup("k", out));
}

TEST(a_ttl_override_of_zero_uses_the_configured_ttl) {
    DnsCache cache(60);
    cache.store("k", bytes({0, 0, 1}), 0);

    std::vector<std::uint8_t> out;
    CHECK(cache.lookup("k", out));
}
