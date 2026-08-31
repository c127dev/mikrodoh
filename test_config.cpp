#include "harness.h"

#include "config.h"

#include <cstdlib>

namespace {

// Every key Config reads, so one case cannot leak settings into the next.
const char* kKeys[] = {"LISTEN_ADDR",   "LISTEN_PORT",        "PORT",
                       "DOH_URL",       "WORKERS",            "CHECK_CERT",
                       "TCP_KEEP_ALIVE", "CACHE",             "RCVBUF_KB",
                       "MAX_INFLIGHT",  "CIPHER",             "CONNECT_TIMEOUT_MS",
                       "REQUEST_TIMEOUT_MS", "TCP",           "TCP_MAX_CONNS",
                       "TCP_IDLE_SEC"};

void clear_env() {
    for (const char* k : kKeys) unsetenv(k);
}

void set(const char* k, const char* v) { setenv(k, v, 1); }

}  // namespace

TEST(defaults_apply_when_nothing_is_set) {
    clear_env();
    Config c = Config::from_env();

    CHECK(c.listen_addr == "0.0.0.0");
    CHECK(c.listen_port == 53);
    CHECK(c.doh_url == "https://1.1.1.1/dns-query");
    CHECK(c.check_cert);
    CHECK(c.cache_ttl == 0);
    CHECK(c.max_inflight == 512);
    CHECK(c.tcp_enabled);
    CHECK(c.tcp_max_conns == 128);
    CHECK(c.tcp_idle_sec == 10);
    CHECK(c.connect_timeout_ms == 3000);
    CHECK(c.request_timeout_ms == 5000);
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
    CHECK(Config::from_env().doh_url == "https://1.1.1.1/dns-query");
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
