#include "harness.h"

#include "config.h"

#include <sstream>

#include <cstdlib>
#include <string>

namespace {

// Every key Config reads, so one case cannot leak settings into the next.
const char* kKeys[] = {"LISTEN_ADDR",   "LISTEN_PORT",        "PORT",
                       "DOH_URL",       "WORKERS",            "CHECK_CERT",
                       "TCP_KEEP_ALIVE", "CACHE",             "RCVBUF_KB",
                       "MAX_INFLIGHT",  "CIPHER",             "CONNECT_TIMEOUT_MS",
                       "REQUEST_TIMEOUT_MS", "TCP",           "TCP_MAX_CONNS",
                       "TCP_IDLE_SEC", "RESOLVER_COOLDOWN_MS",
                       "DOH_BOOTSTRAP", "UDP_READERS"};

// DOH_FAILOVER_URL_1.. are read until the first gap, so clear a few extra.
const int kMaxFailoverKeys = 4;

void clear_env() {
    for (const char* k : kKeys) unsetenv(k);
    for (int i = 1; i <= kMaxFailoverKeys; i++)
        unsetenv(("DOH_FAILOVER_URL_" + std::to_string(i)).c_str());
}

void set(const char* k, const char* v) { setenv(k, v, 1); }

}  // namespace

TEST(defaults_apply_when_nothing_is_set) {
    clear_env();
    Config c = Config::from_env();

    CHECK(c.listen_addr == "0.0.0.0");
    CHECK(c.listen_port == 53);
    CHECK(c.doh_urls.size() == 1);
    CHECK(c.doh_urls.front() == "https://1.1.1.1/dns-query");
    CHECK(c.check_cert);
    CHECK(c.cache_ttl == 0);
    CHECK(c.max_inflight == 512);
    CHECK(c.tcp_enabled);
    CHECK(c.tcp_max_conns == 128);
    CHECK(c.tcp_idle_sec == 10);
    CHECK(c.connect_timeout_ms == 3000);
    CHECK(c.request_timeout_ms == 5000);
    CHECK(c.resolver_cooldown_ms == 30000);
}

TEST(workers_defaults_to_at_least_one) {
    clear_env();
    CHECK(Config::from_env().workers >= 1);

    // A nonsense value falls back rather than starting zero threads.
    set("WORKERS", "0");
    CHECK(Config::from_env().workers >= 1);

    set("WORKERS", "-4");
    CHECK(Config::from_env().workers >= 1);
}

TEST(udp_readers_defaults_to_the_worker_count) {
    clear_env();
    set("WORKERS", "3");
    CHECK(Config::from_env().udp_readers == 3);

    // A nonsense value falls back rather than binding no socket at all.
    set("UDP_READERS", "0");
    CHECK(Config::from_env().udp_readers == 3);

    set("UDP_READERS", "-2");
    CHECK(Config::from_env().udp_readers == 3);
}

TEST(udp_readers_can_be_set_apart_from_the_worker_count) {
    clear_env();
    set("WORKERS", "4");
    set("UDP_READERS", "1");
    CHECK(Config::from_env().udp_readers == 1);

    set("UDP_READERS", "8");
    CHECK(Config::from_env().udp_readers == 8);
}

TEST(listen_port_falls_back_to_the_older_port_key) {
    clear_env();
    set("PORT", "5353");
    CHECK(Config::from_env().listen_port == 5353);

    // LISTEN_PORT wins when both are set.
    set("LISTEN_PORT", "6353");
    CHECK(Config::from_env().listen_port == 6353);
}

TEST(booleans_accept_the_usual_spellings) {
    clear_env();

    for (const char* yes : {"1", "true", "TRUE", "yes", "on"}) {
        set("CHECK_CERT", yes);
        CHECK(Config::from_env().check_cert);
    }

    for (const char* no : {"0", "false", "no", "off", "anything else"}) {
        set("CHECK_CERT", no);
        CHECK(!Config::from_env().check_cert);
    }
}

TEST(an_empty_value_is_treated_as_unset) {
    clear_env();
    set("DOH_URL", "");
    CHECK(Config::from_env().doh_urls.front() == "https://1.1.1.1/dns-query");
}

TEST(max_inflight_never_drops_below_one) {
    clear_env();
    set("MAX_INFLIGHT", "0");
    CHECK(Config::from_env().max_inflight == 1);

    set("MAX_INFLIGHT", "-9");
    CHECK(Config::from_env().max_inflight == 1);
}

TEST(cipher_chacha_is_selected_whatever_the_cpu_is) {
    clear_env();
    set("CIPHER", "chacha");
    CHECK(Config::from_env().prefer_chacha);

    set("CIPHER", "chacha20");
    CHECK(Config::from_env().prefer_chacha);
}

TEST(cipher_aes_overrides_the_cpu_probe) {
    clear_env();
    set("CIPHER", "aes");
    CHECK(!Config::from_env().prefer_chacha);

    set("CIPHER", "aes-gcm");
    CHECK(!Config::from_env().prefer_chacha);
}

TEST(an_unknown_cipher_falls_back_to_auto) {
    clear_env();
    set("CIPHER", "twofish");
    CHECK(Config::from_env().cipher == CipherPref::Auto);
}

TEST(tcp_can_be_turned_off) {
    clear_env();
    set("TCP", "false");
    CHECK(!Config::from_env().tcp_enabled);
}

TEST(doh_url_replaces_the_whole_resolver_list) {
    clear_env();
    set("DOH_URL", "https://dns.example/dns-query");

    Config c = Config::from_env();
    CHECK(c.doh_urls.size() == 1);
    CHECK(c.doh_urls.front() == "https://dns.example/dns-query");
}

TEST(failover_urls_are_appended_in_order) {
    clear_env();
    set("DOH_FAILOVER_URL_1", "https://a.example/dns-query");
    set("DOH_FAILOVER_URL_2", "https://b.example/dns-query");

    Config c = Config::from_env();
    CHECK(c.doh_urls.size() == 3);
    CHECK(c.doh_urls[0] == "https://1.1.1.1/dns-query");
    CHECK(c.doh_urls[1] == "https://a.example/dns-query");
    CHECK(c.doh_urls[2] == "https://b.example/dns-query");
}

TEST(the_failover_list_stops_at_the_first_gap) {
    clear_env();
    set("DOH_FAILOVER_URL_2", "https://b.example/dns-query");

    Config c = Config::from_env();
    CHECK(c.doh_urls.size() == 1);
}

TEST(a_negative_resolver_cooldown_turns_the_tracking_off) {
    clear_env();
    set("RESOLVER_COOLDOWN_MS", "-1");
    CHECK(Config::from_env().resolver_cooldown_ms == 0);

    set("RESOLVER_COOLDOWN_MS", "5000");
    CHECK(Config::from_env().resolver_cooldown_ms == 5000);
}

TEST(no_bootstrap_is_needed_for_an_ip_literal_resolver) {
    clear_env();
    std::ostringstream err;

    Config c = Config::from_env();
    CHECK(c.resolve_entries.empty());
    CHECK(c.resolvers_reachable(err));
}

TEST(a_hostname_resolver_without_a_bootstrap_address_is_refused) {
    clear_env();
    set("DOH_URL", "https://dns.example/dns-query");
    std::ostringstream err;

    CHECK(!Config::from_env().resolvers_reachable(err));
    CHECK(err.str().find("dns.example") != std::string::npos);
}

TEST(a_bootstrap_address_makes_a_hostname_resolver_reachable) {
    clear_env();
    set("DOH_URL", "https://dns.example/dns-query");
    set("DOH_BOOTSTRAP", "dns.example=9.9.9.9");
    std::ostringstream err;

    Config c = Config::from_env();
    CHECK(c.resolve_entries.size() == 1);
    CHECK(c.resolve_entries[0] == "dns.example:443:9.9.9.9");
    CHECK(c.resolvers_reachable(err));
}

TEST(repeating_a_bootstrap_host_gives_it_several_addresses) {
    clear_env();
    set("DOH_URL", "https://dns.example:8443/dns-query");
    set("DOH_BOOTSTRAP", "dns.example=9.9.9.9, dns.example=1.1.1.1");

    Config c = Config::from_env();
    CHECK(c.resolve_entries.size() == 1);
    CHECK(c.resolve_entries[0] == "dns.example:8443:9.9.9.9,1.1.1.1");
}

TEST(a_bootstrap_entry_for_an_unused_host_is_ignored) {
    clear_env();
    set("DOH_BOOTSTRAP", "other.example=9.9.9.9");
    CHECK(Config::from_env().resolve_entries.empty());
}

TEST(every_failover_resolver_needs_its_own_bootstrap_address) {
    clear_env();
    set("DOH_FAILOVER_URL_1", "https://a.example/dns-query");
    set("DOH_FAILOVER_URL_2", "https://b.example/dns-query");
    set("DOH_BOOTSTRAP", "a.example=9.9.9.9");
    std::ostringstream err;

    Config c = Config::from_env();
    CHECK(c.resolve_entries.size() == 1);
    CHECK(!c.resolvers_reachable(err));
    CHECK(err.str().find("b.example") != std::string::npos);

    set("DOH_BOOTSTRAP", "a.example=9.9.9.9,b.example=8.8.8.8");
    CHECK(Config::from_env().resolvers_reachable(err));
}

TEST(malformed_bootstrap_items_are_skipped) {
    clear_env();
    set("DOH_URL", "https://dns.example/dns-query");
    set("DOH_BOOTSTRAP", "garbage,=9.9.9.9,dns.example=,,dns.example=9.9.9.9");

    Config c = Config::from_env();
    CHECK(c.resolve_entries.size() == 1);
    CHECK(c.resolve_entries[0] == "dns.example:443:9.9.9.9");
}
