#include "config.h"

#include "cpu.h"
#include "net.h"

#include <cctype>
#include <cstddef>
#include <cstdlib>
#include <string>
#include <ostream>
#include <thread>

namespace {

std::string lower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

std::string env_str(const char* name, const std::string& fallback) {
    const char* v = std::getenv(name);
    return v && *v ? std::string(v) : fallback;
}

long env_long(const char* name, long fallback) {
    const char* v = std::getenv(name);
    return v && *v ? std::atol(v) : fallback;
}

int env_int(const char* name, int fallback) {
    return static_cast<int>(env_long(name, fallback));
}

bool env_bool(const char* name, bool fallback) {
    const char* v = std::getenv(name);
    if (!v || !*v) return fallback;
    std::string s = lower(v);
    return s == "1" || s == "true" || s == "yes" || s == "on";
}

const char* cipher_name(CipherPref p) {
    switch (p) {
        case CipherPref::ChaCha: return "chacha";
        case CipherPref::Aes:    return "aes";
        default:                 return "auto";
    }
}

const char* ip_version_name(IpVersion v) {
    switch (v) {
        case IpVersion::V4: return "ipv4";
        case IpVersion::V6: return "ipv6";
        default:            return "auto";
    }
}

}  // namespace

Config Config::from_env() {
    Config c;

    c.listen_addr = env_str("LISTEN_ADDR", c.listen_addr);
    c.listen_port = env_int("LISTEN_PORT", env_int("PORT", c.listen_port));
    c.doh_urls.assign(1, env_str("DOH_URL", c.doh_urls.front()));
    for (int i = 1;; i++) {
        std::string key = "DOH_FAILOVER_URL_" + std::to_string(i);
        std::string url = env_str(key.c_str(), "");
        if (url.empty()) break;  // the list ends at the first gap
        c.doh_urls.push_back(url);
    }

    c.workers = env_int("WORKERS", 0);
    if (c.workers < 1) {
        unsigned hc = std::thread::hardware_concurrency();
        c.workers = hc > 0 ? static_cast<int>(hc) : 4;
    }

    c.check_cert     = env_bool("CHECK_CERT", c.check_cert);
    c.tcp_keep_alive = env_int("TCP_KEEP_ALIVE", c.tcp_keep_alive);
    c.cache_ttl      = env_int("CACHE", c.cache_ttl);
    c.rcvbuf_kb      = env_int("RCVBUF_KB", c.rcvbuf_kb);

    c.connect_timeout_ms = env_int("CONNECT_TIMEOUT_MS", c.connect_timeout_ms);
    c.request_timeout_ms = env_int("REQUEST_TIMEOUT_MS", c.request_timeout_ms);

    c.run_as_user  = env_str("RUN_AS_USER", c.run_as_user);
    c.run_as_group = env_str("RUN_AS_GROUP", c.run_as_group);

    c.stats_interval_sec = env_int("STATS_INTERVAL_SEC", c.stats_interval_sec);
    if (c.stats_interval_sec < 0) c.stats_interval_sec = 0;

    c.tcp_enabled   = env_bool("TCP", c.tcp_enabled);
    c.tcp_max_conns = env_int("TCP_MAX_CONNS", c.tcp_max_conns);
    c.tcp_idle_sec  = env_int("TCP_IDLE_SEC", c.tcp_idle_sec);

    c.max_inflight = env_long("MAX_INFLIGHT", c.max_inflight);
    if (c.max_inflight < 1) c.max_inflight = 1;

    c.ipv6_v6only = env_bool("IPV6_V6ONLY", c.ipv6_v6only);

    std::string ipv = lower(env_str("IP_VERSION", "auto"));
    if (ipv == "4" || ipv == "ipv4") c.ip_version = IpVersion::V4;
    else if (ipv == "6" || ipv == "ipv6") c.ip_version = IpVersion::V6;
    else c.ip_version = IpVersion::Any;

    std::string pref = lower(env_str("CIPHER", "auto"));
    if (pref == "chacha" || pref == "chacha20") c.cipher = CipherPref::ChaCha;
    else if (pref == "aes" || pref == "aes-gcm") c.cipher = CipherPref::Aes;
    else c.cipher = CipherPref::Auto;

    // Without an AES engine the TLS record layer runs AES-GCM in software,
    // which is the DoH throughput ceiling on such CPUs. ChaCha20-Poly1305 is
    // faster there, so Auto selects it.
    c.prefer_chacha = c.cipher == CipherPref::ChaCha ||
                      (c.cipher == CipherPref::Auto && !cpu::has_aes());

    return c;
}

void Config::print(std::ostream& os) const {
    os << "MikroDoH listening on " << join_host_port(listen_addr, listen_port)
       << " UDP" << (tcp_enabled ? "+TCP" : "") << "\n"
       << "Resolver      : " << doh_urls.front() << " ("
       << ip_version_name(ip_version) << ")\n";

    for (std::size_t i = 1; i < doh_urls.size(); i++)
        os << "Failover " << i << "    : " << doh_urls[i] << "\n";

    os << "Event loops   : " << workers << "\n"
       << "Max in-flight : " << max_inflight << "\n"
       << "Timeouts      : " << connect_timeout_ms << "ms connect, "
       << request_timeout_ms << "ms request\n"
       << "Check cert    : " << (check_cert ? "true" : "false") << "\n"
       << "TCP keep-alive: " << tcp_keep_alive << "s\n"
       << "Cache TTL     : " << cache_ttl << "s\n"
       << "TCP           : " << (tcp_enabled ? "on" : "off") << ", max "
       << tcp_max_conns << " conns, " << tcp_idle_sec << "s idle\n"
       << "Run as        : "
       << (run_as_user.empty() ? std::string("unchanged")
                               : run_as_user + (run_as_group.empty()
                                                    ? ""
                                                    : ":" + run_as_group))
       << "\n"
       << "Stats line    : "
       << (stats_interval_sec > 0 ? std::to_string(stats_interval_sec) + "s"
                                  : std::string("off, SIGUSR1 only"))
       << "\n"
       << "IPv6 bind     : " << (ipv6_v6only ? "v6only" : "dual stack") << "\n"
       << "CPU           : " << cpu::arch()
       << (cpu::has_aes() ? " (AES engine)" : " (no AES engine)") << "\n"
       << "Cipher        : " << cipher_name(cipher) << " -> "
       << (prefer_chacha ? "ChaCha20-Poly1305" : "AES-GCM") << "\n";

    // stdout is a pipe under a container runtime, so without this the banner
    // sits in the buffer until the process exits.
    os.flush();
}
