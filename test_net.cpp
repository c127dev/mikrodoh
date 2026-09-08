#include "harness.h"

#include "net.h"

#include <string>

TEST(ip_literals_are_recognised) {
    CHECK(is_ip_literal("1.1.1.1"));
    CHECK(is_ip_literal("2606:4700:4700::1111"));
    CHECK(is_ip_literal("[2606:4700:4700::1111]"));

    CHECK(!is_ip_literal("dns.example"));
    CHECK(!is_ip_literal(""));
    CHECK(!is_ip_literal("1.1.1.1.1"));
}

TEST(a_url_authority_defaults_to_port_443) {
    std::string host;
    int         port = 0;

    CHECK(split_url_authority("https://dns.example/dns-query", host, port));
    CHECK(host == "dns.example");
    CHECK(port == 443);
}

TEST(a_url_port_is_taken_from_the_authority) {
    std::string host;
    int         port = 0;

    CHECK(split_url_authority("https://dns.example:8443/dns-query", host, port));
    CHECK(host == "dns.example");
    CHECK(port == 8443);
}

TEST(an_ipv6_url_host_comes_back_without_brackets) {
    std::string host;
    int         port = 0;

    CHECK(split_url_authority("https://[2606:4700::1111]/dns-query", host, port));
    CHECK(host == "2606:4700::1111");
    CHECK(port == 443);

    CHECK(split_url_authority("https://[2606:4700::1111]:8443/dns-query", host, port));
    CHECK(host == "2606:4700::1111");
    CHECK(port == 8443);
}

TEST(a_url_authority_ends_at_the_path_query_or_fragment) {
    std::string host;
    int         port = 0;

    for (const char* url : {"https://dns.example", "https://dns.example/",
                            "https://dns.example?x=1", "https://dns.example#f"}) {
        CHECK(split_url_authority(url, host, port));
        CHECK(host == "dns.example");
    }
}

TEST(url_credentials_are_not_mistaken_for_the_host) {
    std::string host;
    int         port = 0;

    CHECK(split_url_authority("https://user:pass@dns.example:8443/q", host, port));
    CHECK(host == "dns.example");
    CHECK(port == 8443);
}

TEST(a_url_with_no_host_or_a_bad_port_is_rejected) {
    std::string host;
    int         port = 0;

    CHECK(!split_url_authority("https:///dns-query", host, port));
    CHECK(!split_url_authority("", host, port));
    CHECK(!split_url_authority("https://dns.example:/q", host, port));
    CHECK(!split_url_authority("https://dns.example:https/q", host, port));
    CHECK(!split_url_authority("https://dns.example:70000/q", host, port));
    CHECK(!split_url_authority("https://[2606:4700::1111/q", host, port));
}
