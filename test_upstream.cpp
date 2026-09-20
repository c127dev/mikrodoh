#include "harness.h"

#include "config.h"
#include "upstream.h"

#include <memory>

TEST(an_upstream_snapshot_copies_the_resolver_settings) {
    Config cfg;
    cfg.doh_urls           = {"https://dns.example/dns-query", "https://1.0.0.1/dns-query"};
    cfg.resolve_entries    = {"dns.example:443:192.0.2.1"};
    cfg.connect_timeout_ms = 111;
    cfg.request_timeout_ms = 222;

    Upstream up(cfg);
    CHECK(up.urls == cfg.doh_urls);
    CHECK(up.resolve != nullptr);
    CHECK(up.connect_timeout_ms == 111);
    CHECK(up.request_timeout_ms == 222);
}

TEST(no_bootstrap_entries_leave_the_resolve_list_empty) {
    Config   cfg;
    Upstream up(cfg);
    CHECK(up.resolve == nullptr);
}

TEST(set_swaps_the_snapshot_and_bumps_the_generation) {
    Config a;
    Config b;
    b.doh_urls = {"https://1.0.0.1/dns-query"};

    UpstreamSource source(std::make_shared<const Upstream>(a));
    unsigned       before = source.generation();

    std::shared_ptr<const Upstream> old = source.get();
    source.set(std::make_shared<const Upstream>(b));

    CHECK(source.generation() != before);
    CHECK(source.get()->urls.front() == "https://1.0.0.1/dns-query");
    CHECK(old->urls.front() == "https://1.1.1.1/dns-query");  // still alive for its holders
}
