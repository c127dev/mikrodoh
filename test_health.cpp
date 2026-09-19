#include "harness.h"

#include "dns.h"
#include "health.h"

#include <cstring>
#include <string>
#include <vector>

namespace {

std::vector<std::uint8_t> query(const std::string& name, std::uint16_t qtype) {
    std::vector<std::uint8_t> q{0xAB, 0xCD, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0};

    std::size_t label = 0;
    for (std::size_t i = 0; i <= name.size(); ++i) {
        if (i == name.size() || name[i] == '.') {
            q.push_back(static_cast<std::uint8_t>(i - label));
            for (std::size_t j = label; j < i; ++j) q.push_back(static_cast<std::uint8_t>(name[j]));
            label = i + 1;
        }
    }
    q.push_back(0);
    q.insert(q.end(), {0, static_cast<std::uint8_t>(qtype), 0, 1});
    return q;
}

}  // namespace

TEST(the_health_name_is_a_probe_in_any_case) {
    std::vector<std::uint8_t> a = query("health.mikrodoh", 1);
    std::vector<std::uint8_t> b = query("HeAlTh.MIKRODOH", 1);
    CHECK(health::is_probe(a.data(), a.size()));
    CHECK(health::is_probe(b.data(), b.size()));
}

TEST(other_names_are_not_probes) {
    std::vector<std::uint8_t> a = query("health.mikrodoh.com", 1);
    std::vector<std::uint8_t> b = query("example.com", 1);
    std::vector<std::uint8_t> c = query("mikrodoh", 1);
    CHECK(!health::is_probe(a.data(), a.size()));
    CHECK(!health::is_probe(b.data(), b.size()));
    CHECK(!health::is_probe(c.data(), c.size()));
}

TEST(the_upstream_request_is_a_root_ns_query_with_the_same_id) {
    std::vector<std::uint8_t> q = query("health.mikrodoh", 1);
    std::vector<std::uint8_t> u = health::upstream_request(q.data(), q.size());

    CHECK(dns::query_valid(u.data(), u.size()));
    CHECK(u[0] == 0xAB && u[1] == 0xCD);
    CHECK(u[12] == 0);                   // root
    CHECK(u[13] == 0 && u[14] == 2);     // NS
}

TEST(a_healthy_a_answer_carries_loopback) {
    std::vector<std::uint8_t> q = query("health.mikrodoh", 1);
    std::vector<std::uint8_t> r = health::answer(q.data(), q.size(), true);

    CHECK(dns::response_matches(q.data(), q.size(), r.data(), r.size()));
    CHECK(dns::rcode(r.data(), r.size()) == dns::kRcodeNoError);
    CHECK(dns::has_answers(r.data(), r.size()));
    CHECK(dns::min_ttl(r.data(), r.size()) == 0);

    const std::uint8_t loopback[] = {127, 0, 0, 1};
    CHECK(std::memcmp(r.data() + r.size() - 4, loopback, 4) == 0);
}

TEST(a_healthy_answer_to_another_type_has_no_records) {
    std::vector<std::uint8_t> q = query("health.mikrodoh", 28);
    std::vector<std::uint8_t> r = health::answer(q.data(), q.size(), true);

    CHECK(dns::rcode(r.data(), r.size()) == dns::kRcodeNoError);
    CHECK(!dns::has_answers(r.data(), r.size()));
}

TEST(an_unhealthy_answer_is_servfail) {
    std::vector<std::uint8_t> q = query("health.mikrodoh", 1);
    std::vector<std::uint8_t> r = health::answer(q.data(), q.size(), false);

    CHECK(dns::response_matches(q.data(), q.size(), r.data(), r.size()));
    CHECK(dns::rcode(r.data(), r.size()) == dns::kRcodeServFail);
    CHECK(!dns::has_answers(r.data(), r.size()));
}
