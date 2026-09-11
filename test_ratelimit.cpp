#include "harness.h"

#include "ratelimit.h"

#include <chrono>
#include <string>
#include <thread>

#include <arpa/inet.h>

namespace {

sockaddr_storage v4(const char* text) {
    sockaddr_storage addr{};
    auto&            in4 = reinterpret_cast<sockaddr_in&>(addr);
    in4.sin_family       = AF_INET;
    inet_pton(AF_INET, text, &in4.sin_addr);
    return addr;
}

sockaddr_storage v6(const char* text) {
    sockaddr_storage addr{};
    auto&            in6 = reinterpret_cast<sockaddr_in6&>(addr);
    in6.sin6_family      = AF_INET6;
    inet_pton(AF_INET6, text, &in6.sin6_addr);
    return addr;
}

// How many of `n` queries from one address the limiter lets through.
int allowed(RateLimiter& limiter, const sockaddr_storage& addr, int n) {
    int ok = 0;
    for (int i = 0; i < n; i++) ok += limiter.allow(addr) ? 1 : 0;
    return ok;
}

}  // namespace

TEST(a_zero_rate_disables_the_limiter) {
    RateLimiter limiter(0, 0, 32, 56);

    CHECK(!limiter.enabled());
    CHECK(allowed(limiter, v4("10.0.0.1"), 1000) == 1000);
}

TEST(a_source_is_cut_off_at_its_burst) {
    RateLimiter limiter(10, 5, 32, 56);

    CHECK(limiter.enabled());
    CHECK(allowed(limiter, v4("10.0.0.1"), 100) == 5);
}

TEST(an_omitted_burst_is_the_rate) {
    RateLimiter limiter(7, 0, 32, 56);

    CHECK(allowed(limiter, v4("10.0.0.1"), 100) == 7);
}

TEST(one_loud_source_does_not_spend_another_clients_budget) {
    RateLimiter limiter(10, 5, 32, 56);

    CHECK(allowed(limiter, v4("10.0.0.1"), 100) == 5);
    CHECK(allowed(limiter, v4("10.0.0.2"), 5) == 5);
}

TEST(a_bucket_refills_over_time) {
    // 20 qps is a token every 50ms: slow enough that draining the bucket
    // cannot mint one along the way, whatever the machine is doing.
    RateLimiter limiter(20, 5, 32, 56);
    CHECK(allowed(limiter, v4("10.0.0.1"), 100) == 5);

    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // Four tokens' worth of time, and a slow machine only ever refills
    // further, which the burst bounds above.
    int after = allowed(limiter, v4("10.0.0.1"), 100);
    CHECK(after >= 1);
    CHECK(after <= 5);
}

TEST(refill_does_not_exceed_the_burst) {
    RateLimiter limiter(20, 3, 32, 56);
    CHECK(allowed(limiter, v4("10.0.0.1"), 10) == 3);

    // Ten tokens' worth of time into a bucket three deep.
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    CHECK(allowed(limiter, v4("10.0.0.1"), 100) == 3);
}

TEST(addresses_in_one_v4_prefix_share_a_bucket) {
    RateLimiter limiter(10, 5, 24, 56);

    CHECK(allowed(limiter, v4("10.0.0.1"), 5) == 5);
    CHECK(allowed(limiter, v4("10.0.0.9"), 1) == 0);   // same /24
    CHECK(allowed(limiter, v4("10.0.1.9"), 1) == 1);   // next /24
}

TEST(a_v4_mapped_address_is_the_same_client_as_the_v4_one) {
    // The dual-stack socket hands IPv4 clients over as ::ffff:a.b.c.d, so the
    // two spellings have to land in one bucket or the limit doubles.
    RateLimiter limiter(10, 5, 32, 56);

    CHECK(allowed(limiter, v4("10.0.0.1"), 5) == 5);
    CHECK(allowed(limiter, v6("::ffff:10.0.0.1"), 1) == 0);
}

TEST(addresses_in_one_v6_prefix_share_a_bucket) {
    RateLimiter limiter(10, 5, 32, 56);

    CHECK(allowed(limiter, v6("2001:db8:0:1::1"), 5) == 5);
    CHECK(allowed(limiter, v6("2001:db8:0:1:ffff::9"), 1) == 0);  // same /56
    CHECK(allowed(limiter, v6("2001:db8:0:200::1"), 1) == 1);     // next /56
}

TEST(a_v6_prefix_longer_than_the_key_is_capped_not_wrapped) {
    // The key holds 64 bits. /128 has to behave as /64 rather than mask to
    // nothing and put every client in one bucket.
    RateLimiter limiter(10, 5, 32, 128);

    CHECK(allowed(limiter, v6("2001:db8::1"), 5) == 5);
    CHECK(allowed(limiter, v6("2001:db8::2"), 1) == 0);       // same /64
    CHECK(allowed(limiter, v6("2001:db8:0:1::1"), 1) == 1);   // next /64
}

TEST(a_zero_prefix_puts_every_client_in_one_bucket) {
    RateLimiter limiter(10, 5, 0, 0);

    CHECK(allowed(limiter, v4("10.0.0.1"), 5) == 5);
    CHECK(allowed(limiter, v4("203.0.113.7"), 1) == 0);
}

TEST(many_distinct_sources_are_each_limited) {
    // Enough sources to spread over every shard: each keeps its own budget,
    // and none is handed a free pass by another shard's traffic.
    RateLimiter limiter(10, 2, 32, 56);

    for (int i = 0; i < 2000; i++) {
        std::string addr = "10.1." + std::to_string(i / 256) + "." + std::to_string(i % 256);
        CHECK(allowed(limiter, v4(addr.c_str()), 5) == 2);
    }
}

TEST(a_v4_and_a_v6_client_do_not_collide) {
    RateLimiter limiter(10, 5, 32, 64);

    // 0.0.255.255 masked to /64 is where an IPv4-mapped key lives, so a v6
    // address there must not eat the v4 client's bucket.
    CHECK(allowed(limiter, v4("0.0.0.0"), 5) == 5);
    CHECK(allowed(limiter, v6("::ffff:0.0.0.0"), 1) == 0);  // the same client
    CHECK(allowed(limiter, v6("2001:db8::1"), 1) == 1);
}

TEST(an_unknown_address_family_is_not_a_free_pass) {
    // A transfer whose client address was never filled in still has to be
    // charged to something rather than bypass the limiter.
    sockaddr_storage unset{};
    RateLimiter      limiter(10, 5, 32, 56);

    CHECK(allowed(limiter, unset, 100) == 5);
}
