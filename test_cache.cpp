#include "harness.h"

#include "cache.h"

#include <initializer_list>
#include <string>
#include <vector>

namespace {

std::vector<std::uint8_t> bytes(std::initializer_list<int> v) {
    std::vector<std::uint8_t> out;
    for (int b : v) out.push_back(static_cast<std::uint8_t>(b));
    return out;
}

}  // namespace

TEST(key_of_ignores_the_transaction_id) {
    std::vector<std::uint8_t> a = bytes({0x11, 0x22, 0x01, 0x00, 0xAA});
    std::vector<std::uint8_t> b = bytes({0x33, 0x44, 0x01, 0x00, 0xAA});

    CHECK(DnsCache::key_of(a.data(), a.size()) == DnsCache::key_of(b.data(), b.size()));
}

TEST(key_of_separates_different_questions) {
    std::vector<std::uint8_t> a = bytes({0x11, 0x22, 0x01, 0x00, 0xAA});
    std::vector<std::uint8_t> b = bytes({0x11, 0x22, 0x01, 0x00, 0xBB});

    CHECK(DnsCache::key_of(a.data(), a.size()) != DnsCache::key_of(b.data(), b.size()));
}

TEST(key_of_is_empty_for_a_message_of_two_bytes_or_less) {
    std::vector<std::uint8_t> a = bytes({0x11, 0x22});
    CHECK(DnsCache::key_of(a.data(), a.size()).empty());
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

TEST(overflow_drops_entries) {
    DnsCache cache(60, 4);

    for (int i = 0; i < 16; ++i) cache.store("key" + std::to_string(i), bytes({0, 0, 1}));

    int found = 0;
    for (int i = 0; i < 16; ++i) {
        std::vector<std::uint8_t> out;
        if (cache.lookup("key" + std::to_string(i), out)) found++;
    }

    CHECK(found > 0);
    CHECK(found <= 16);
}
