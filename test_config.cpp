#include "harness.h"

#include "config.h"

#include <sstream>

#include <cstdlib>
#include <cstdio>
#include <fstream>
#include <string>

#include <unistd.h>

namespace {

// Every key Config reads, so one case cannot leak settings into the next.
const char* kKeys[] = {"LISTEN_ADDR",   "LISTEN_PORT",        "PORT",
                       "DOH_URL",       "WORKERS",            "CHECK_CERT",
                       "TCP_KEEP_ALIVE", "CACHE",             "RCVBUF_KB",
                       "MAX_INFLIGHT",  "CIPHER",             "CONNECT_TIMEOUT_MS",
                       "REQUEST_TIMEOUT_MS", "TCP",           "TCP_MAX_CONNS",
                       "TCP_IDLE_SEC", "RESOLVER_COOLDOWN_MS",
                       "DOH_BOOTSTRAP", "UDP_READERS",
                       "RATE_LIMIT_QPS", "RATE_LIMIT_BURST",
                       "RATE_LIMIT_V4_PREFIX", "RATE_LIMIT_V6_PREFIX",
                       "CONFIG_FILE", "CACHE_NEGATIVE", "SERVE_STALE",
                       "STATS_INTERVAL_SEC", "IP_VERSION", "SANDBOX",
                       "IPV6_V6ONLY", "CACHE_MIN_TTL", "CACHE_MAX_TTL"};

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

    // 0 means one per CPU rather than zero threads.
    set("WORKERS", "0");
    CHECK(Config::from_env().workers >= 1);

    set("WORKERS", "-4");
    CHECK(!Config::from_env().load_error.empty());
}

TEST(udp_readers_defaults_to_the_worker_count) {
    clear_env();
    set("WORKERS", "3");
    CHECK(Config::from_env().udp_readers == 3);

    // 0 means the worker count rather than binding no socket at all.
    set("UDP_READERS", "0");
    CHECK(Config::from_env().udp_readers == 3);

    set("UDP_READERS", "-2");
    CHECK(!Config::from_env().load_error.empty());
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

    for (const char* no : {"0", "false", "no", "off"}) {
        set("CHECK_CERT", no);
        CHECK(!Config::from_env().check_cert);
    }

    set("CHECK_CERT", "anything else");
    CHECK(!Config::from_env().load_error.empty());
}

TEST(an_empty_value_is_treated_as_unset) {
    clear_env();
    set("DOH_URL", "");
    CHECK(Config::from_env().doh_urls.front() == "https://1.1.1.1/dns-query");
}

TEST(max_inflight_below_one_is_rejected) {
    clear_env();
    set("MAX_INFLIGHT", "0");
    CHECK(!Config::from_env().load_error.empty());

    set("MAX_INFLIGHT", "-9");
    CHECK(!Config::from_env().load_error.empty());
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

TEST(a_negative_resolver_cooldown_is_rejected) {
    clear_env();
    set("RESOLVER_COOLDOWN_MS", "-1");
    CHECK(!Config::from_env().load_error.empty());

    set("RESOLVER_COOLDOWN_MS", "0");
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

TEST(the_rate_limit_is_off_unless_a_rate_is_set) {
    clear_env();
    Config c = Config::from_env();

    CHECK(c.rate_limit_qps == 0);
    CHECK(c.rate_limit_burst == 0);
    CHECK(c.rate_limit_v4_prefix == 32);
    CHECK(c.rate_limit_v6_prefix == 56);
}

TEST(rate_limit_keys_are_read) {
    clear_env();
    set("RATE_LIMIT_QPS", "50");
    set("RATE_LIMIT_BURST", "120");
    set("RATE_LIMIT_V4_PREFIX", "24");
    set("RATE_LIMIT_V6_PREFIX", "48");

    Config c = Config::from_env();
    CHECK(c.rate_limit_qps == 50);
    CHECK(c.rate_limit_burst == 120);
    CHECK(c.rate_limit_v4_prefix == 24);
    CHECK(c.rate_limit_v6_prefix == 48);
}

TEST(a_negative_rate_limit_is_read_as_off) {
    clear_env();
    set("RATE_LIMIT_QPS", "-1");
    set("RATE_LIMIT_BURST", "-5");

    Config c = Config::from_env();
    CHECK(c.rate_limit_qps == 0);
    CHECK(c.rate_limit_burst == 0);
}

namespace {

std::string write_file(const std::string& body) {
    char path[] = "/tmp/mikrodoh-config-XXXXXX";
    int  fd     = mkstemp(path);
    if (fd >= 0) close(fd);
    std::ofstream(path) << body;
    return path;
}

}  // namespace

TEST(config_file_keys_override_the_environment) {
    clear_env();
    set("LISTEN_PORT", "5353");
    set("DOH_URL", "https://9.9.9.9/dns-query");

    std::string path = write_file("# a board file\n"
                                  "\n"
                                  "DOH_URL=https://1.0.0.1/dns-query\n"
                                  "export CACHE=\"120\"\n"
                                  "  TCP = 'false'\n");
    set("CONFIG_FILE", path.c_str());

    Config c = Config::from_env();
    std::remove(path.c_str());

    CHECK(c.load_error.empty());
    CHECK(c.config_file == path);
    CHECK(c.doh_urls.front() == "https://1.0.0.1/dns-query");
    CHECK(c.cache_ttl == 120);
    CHECK(!c.tcp_enabled);
    CHECK(c.listen_port == 5353);  // not in the file, so the environment's
}

TEST(an_unreadable_config_file_is_an_error) {
    clear_env();
    set("CONFIG_FILE", "/nonexistent/mikrodoh.conf");
    CHECK(!Config::from_env().load_error.empty());
}

TEST(without_a_config_file_there_is_no_error) {
    clear_env();
    Config c = Config::from_env();
    CHECK(c.load_error.empty());
    CHECK(c.config_file.empty());
}

TEST(a_valid_environment_has_no_error) {
    clear_env();
    set("LISTEN_PORT", "5353");
    set("CACHE", "300");
    set("TCP", "off");
    set("CIPHER", "aes");
    set("IP_VERSION", "ipv6");
    CHECK(Config::from_env().load_error.empty());
}

TEST(garbage_in_a_number_is_rejected) {
    for (const char* bad : {"abc", "12abc", "1.5", " ", "99999999999999999999"}) {
        clear_env();
        set("CONNECT_TIMEOUT_MS", bad);
        Config c = Config::from_env();
        CHECK(!c.load_error.empty());
        CHECK(c.connect_timeout_ms == 3000);  // the default is kept
    }
}

TEST(a_number_out_of_range_is_rejected) {
    const char* cases[][2] = {{"LISTEN_PORT", "0"},       {"LISTEN_PORT", "65536"},
                              {"RCVBUF_KB", "-1"},        {"REQUEST_TIMEOUT_MS", "0"},
                              {"CACHE_NEGATIVE", "-5"},   {"SERVE_STALE", "-1"},
                              {"RATE_LIMIT_V4_PREFIX", "33"}, {"RATE_LIMIT_V6_PREFIX", "129"},
                              {"TCP_IDLE_SEC", "0"},      {"STATS_INTERVAL_SEC", "-1"}};
    for (auto& kv : cases) {
        clear_env();
        set(kv[0], kv[1]);
        CHECK(Config::from_env().load_error.find(kv[0]) != std::string::npos);
    }
}

TEST(an_unknown_cipher_or_ip_version_is_rejected) {
    clear_env();
    set("CIPHER", "rc4");
    CHECK(!Config::from_env().load_error.empty());

    clear_env();
    set("IP_VERSION", "5");
    CHECK(!Config::from_env().load_error.empty());
}

TEST(every_bad_key_is_reported) {
    clear_env();
    set("WORKERS", "x");
    set("TCP", "maybe");
    std::string err = Config::from_env().load_error;
    CHECK(err.find("WORKERS") != std::string::npos);
    CHECK(err.find("TCP") != std::string::npos);
}

TEST(cache_ttl_clamp_keys_are_read_and_checked) {
    clear_env();
    set("CACHE_MIN_TTL", "30");
    set("CACHE_MAX_TTL", "3600");
    Config c = Config::from_env();
    CHECK(c.load_error.empty());
    CHECK(c.cache_min_ttl == 30);
    CHECK(c.cache_max_ttl == 3600);

    set("CACHE_MIN_TTL", "7200");
    CHECK(Config::from_env().load_error.find("CACHE_MIN_TTL") != std::string::npos);
}
