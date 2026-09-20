#include "config.h"

#include "cpu.h"
#include "net.h"

#include <cctype>
#include <cerrno>
#include <cstddef>
#include <cstdlib>
#include <fstream>
#include <string>
#include <ostream>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

namespace {

std::string lower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

// CONFIG_FILE's entries while from_env() runs. Only one thread loads the
// configuration at a time: main at startup, then the stats thread on SIGHUP.
const std::unordered_map<std::string, std::string>* g_file = nullptr;

// What was wrong with the values read during the same from_env() call.
std::vector<std::string>* g_errors = nullptr;

void reject(const char* name, const char* value, const std::string& why) {
    if (g_errors) g_errors->push_back(std::string(name) + "=" + value + ": " + why);
}

// A key from CONFIG_FILE wins over the same key in the environment.
const char* lookup(const char* name) {
    if (g_file) {
        auto it = g_file->find(name);
        if (it != g_file->end()) return it->second.c_str();
    }
    return std::getenv(name);
}

std::string env_str(const char* name, const std::string& fallback) {
    const char* v = lookup(name);
    return v && *v ? std::string(v) : fallback;
}

// A whole decimal integer within [min, max]. Anything else is rejected and
// `fallback` returned, so the caller still has a usable value to report with.
long env_long(const char* name, long fallback, long min, long max) {
    const char* v = lookup(name);
    if (!v || !*v) return fallback;

    char* end = nullptr;
    errno     = 0;
    long n    = std::strtol(v, &end, 10);
    if (end == v || *end != '\0' || errno == ERANGE) {
        reject(name, v, "not an integer");
        return fallback;
    }
    if (n < min || n > max) {
        reject(name, v, "out of range " + std::to_string(min) + ".." + std::to_string(max));
        return fallback;
    }
    return n;
}

int env_int(const char* name, int fallback, int min, int max) {
    return static_cast<int>(env_long(name, fallback, min, max));
}

bool env_bool(const char* name, bool fallback) {
    const char* v = lookup(name);
    if (!v || !*v) return fallback;

    std::string s = lower(v);
    if (s == "1" || s == "true" || s == "yes" || s == "on") return true;
    if (s == "0" || s == "false" || s == "no" || s == "off") return false;

    reject(name, v, "not a boolean");
    return fallback;
}

std::string trim(const std::string& s) {
    std::size_t b = s.find_first_not_of(" \t");
    if (b == std::string::npos) return "";
    return s.substr(b, s.find_last_not_of(" \t") - b + 1);
}

// KEY=VALUE lines, the format of boards/*.conf: blank lines and # comments
// skipped, an optional "export " and one pair of surrounding quotes removed.
bool read_config_file(const std::string& path,
                      std::unordered_map<std::string, std::string>& out) {
    std::ifstream in(path);
    if (!in) return false;

    std::string line;
    while (std::getline(in, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;
        if (line.compare(0, 7, "export ") == 0) line = trim(line.substr(7));

        std::size_t eq = line.find('=');
        if (eq == std::string::npos || eq == 0) continue;

        std::string value = trim(line.substr(eq + 1));
        if (value.size() >= 2 && (value[0] == '"' || value[0] == '\'') &&
            value.back() == value[0])
            value = value.substr(1, value.size() - 2);

        out[trim(line.substr(0, eq))] = value;
    }
    return true;
}

// "dns.example=1.1.1.1,dns.example=1.0.0.1,other=2606:4700::1111" into
// host -> the addresses given for it, in the order they appear.
std::vector<std::pair<std::string, std::vector<std::string>>> parse_bootstrap(
    const std::string& spec) {
    std::vector<std::pair<std::string, std::vector<std::string>>> out;

    for (std::size_t pos = 0; pos <= spec.size();) {
        std::size_t comma = spec.find(',', pos);
        std::string item  = trim(spec.substr(pos, comma - pos));
        pos = comma == std::string::npos ? spec.size() + 1 : comma + 1;

        std::size_t eq = item.find('=');
        if (eq == std::string::npos) continue;

        std::string host = trim(item.substr(0, eq));
        std::string addr = trim(item.substr(eq + 1));
        if (host.empty() || addr.empty()) continue;

        auto it = out.begin();
        for (; it != out.end(); ++it)
            if (it->first == host) break;

        if (it == out.end()) out.push_back({host, {addr}});
        else it->second.push_back(addr);
    }

    return out;
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

    std::vector<std::string> errors;
    g_errors = &errors;

    std::unordered_map<std::string, std::string> file;
    const char* path = std::getenv("CONFIG_FILE");
    if (path && *path) {
        c.config_file = path;
        if (read_config_file(c.config_file, file)) g_file = &file;
        else c.load_error = "cannot read CONFIG_FILE " + c.config_file;
    }

    c.listen_addr = env_str("LISTEN_ADDR", c.listen_addr);
    c.listen_port = env_int("LISTEN_PORT", env_int("PORT", c.listen_port, 1, 65535), 1, 65535);
    c.doh_urls.assign(1, env_str("DOH_URL", c.doh_urls.front()));
    for (int i = 1;; i++) {
        std::string key = "DOH_FAILOVER_URL_" + std::to_string(i);
        std::string url = env_str(key.c_str(), "");
        if (url.empty()) break;  // the list ends at the first gap
        c.doh_urls.push_back(url);
    }

    // An entry is only useful for a host this daemon actually talks to, so the
    // curl form is built per resolver URL: the port comes from the URL.
    for (const auto& entry : parse_bootstrap(env_str("DOH_BOOTSTRAP", ""))) {
        for (const std::string& url : c.doh_urls) {
            std::string host;
            int         port = 0;
            if (!split_url_authority(url, host, port)) continue;
            if (host != entry.first) continue;

            std::string line = host + ":" + std::to_string(port) + ":";
            for (std::size_t i = 0; i < entry.second.size(); i++)
                line += (i ? "," : "") + entry.second[i];

            // The same host can appear on two URLs with different ports, and
            // each of those needs its own entry.
            bool seen = false;
            for (const std::string& have : c.resolve_entries)
                seen = seen || have == line;
            if (!seen) c.resolve_entries.push_back(line);
        }
    }

    c.workers = env_int("WORKERS", 0, 0, 1024);
    if (c.workers < 1) {
        unsigned hc = std::thread::hardware_concurrency();
        c.workers = hc > 0 ? static_cast<int>(hc) : 4;
    }

    c.udp_readers = env_int("UDP_READERS", 0, 0, 1024);
    if (c.udp_readers < 1) c.udp_readers = c.workers;

    c.check_cert     = env_bool("CHECK_CERT", c.check_cert);
    c.tcp_keep_alive = env_int("TCP_KEEP_ALIVE", c.tcp_keep_alive, 0, 86400);
    c.cache_ttl      = env_int("CACHE", c.cache_ttl, 0, 604800);

    c.cache_negative_ttl = env_int("CACHE_NEGATIVE", c.cache_negative_ttl, 0, 86400);
    c.serve_stale = env_int("SERVE_STALE", c.serve_stale, 0, 604800);

    c.rcvbuf_kb      = env_int("RCVBUF_KB", c.rcvbuf_kb, 1, 1048576);

    c.connect_timeout_ms = env_int("CONNECT_TIMEOUT_MS", c.connect_timeout_ms, 1, 600000);
    c.request_timeout_ms = env_int("REQUEST_TIMEOUT_MS", c.request_timeout_ms, 1, 600000);

    c.resolver_cooldown_ms = env_int("RESOLVER_COOLDOWN_MS", c.resolver_cooldown_ms, 0, 3600000);

    c.run_as_user  = env_str("RUN_AS_USER", c.run_as_user);
    c.run_as_group = env_str("RUN_AS_GROUP", c.run_as_group);
    c.sandbox      = env_bool("SANDBOX", c.sandbox);

    c.stats_interval_sec = env_int("STATS_INTERVAL_SEC", c.stats_interval_sec, 0, 86400);

    c.tcp_enabled   = env_bool("TCP", c.tcp_enabled);
    c.tcp_max_conns = env_int("TCP_MAX_CONNS", c.tcp_max_conns, 1, 65535);
    c.tcp_idle_sec  = env_int("TCP_IDLE_SEC", c.tcp_idle_sec, 1, 3600);

    c.max_inflight = env_long("MAX_INFLIGHT", c.max_inflight, 1, 1000000);

    c.rate_limit_qps   = env_long("RATE_LIMIT_QPS", c.rate_limit_qps, 0, 10000000);
    c.rate_limit_burst = env_long("RATE_LIMIT_BURST", c.rate_limit_burst, 0, 10000000);
    c.rate_limit_v4_prefix = env_int("RATE_LIMIT_V4_PREFIX", c.rate_limit_v4_prefix, 0, 32);
    c.rate_limit_v6_prefix = env_int("RATE_LIMIT_V6_PREFIX", c.rate_limit_v6_prefix, 0, 128);

    c.ipv6_v6only = env_bool("IPV6_V6ONLY", c.ipv6_v6only);

    std::string ipv = lower(env_str("IP_VERSION", "auto"));
    if (ipv == "4" || ipv == "ipv4") c.ip_version = IpVersion::V4;
    else if (ipv == "6" || ipv == "ipv6") c.ip_version = IpVersion::V6;
    else if (ipv == "auto" || ipv == "any") c.ip_version = IpVersion::Any;
    else reject("IP_VERSION", ipv.c_str(), "not one of auto, ipv4, ipv6");

    std::string pref = lower(env_str("CIPHER", "auto"));
    if (pref == "chacha" || pref == "chacha20") c.cipher = CipherPref::ChaCha;
    else if (pref == "aes" || pref == "aes-gcm") c.cipher = CipherPref::Aes;
    else if (pref == "auto") c.cipher = CipherPref::Auto;
    else reject("CIPHER", pref.c_str(), "not one of auto, chacha, aes");

    // Without an AES engine the TLS record layer runs AES-GCM in software,
    // which is the DoH throughput ceiling on such CPUs. ChaCha20-Poly1305 is
    // faster there, so Auto selects it.
    c.prefer_chacha = c.cipher == CipherPref::ChaCha ||
                      (c.cipher == CipherPref::Auto && !cpu::has_aes());

    g_file   = nullptr;
    g_errors = nullptr;

    for (const std::string& e : errors)
        c.load_error += (c.load_error.empty() ? "" : "; ") + e;
    return c;
}

bool Config::resolvers_reachable(std::ostream& err) const {
    bool ok = true;

    for (const std::string& url : doh_urls) {
        std::string host;
        int         port = 0;

        if (!split_url_authority(url, host, port)) {
            err << "DoH URL has no host: " << url << "\n";
            ok = false;
            continue;
        }

        if (is_ip_literal(host)) continue;

        std::string prefix = host + ":" + std::to_string(port) + ":";
        bool        bootstrapped = false;
        for (const std::string& entry : resolve_entries)
            bootstrapped = bootstrapped || entry.compare(0, prefix.size(), prefix) == 0;

        if (bootstrapped) continue;

        err << "resolver " << url << " is named by hostname and has no "
            << "bootstrap address. Resolving it needs a resolver, which is "
            << "this daemon. Use an IP literal, or set DOH_BOOTSTRAP="
            << host << "=<address>.\n";
        ok = false;
    }

    return ok;
}

void Config::print(std::ostream& os) const {
    os << "MikroDoH listening on " << join_host_port(listen_addr, listen_port)
       << " UDP" << (tcp_enabled ? "+TCP" : "") << "\n"
       << (config_file.empty() ? std::string() : "Config file   : " + config_file + "\n")
       << "Resolver      : " << doh_urls.front() << " ("
       << ip_version_name(ip_version) << ")\n";

    for (std::size_t i = 1; i < doh_urls.size(); i++)
        os << "Failover " << i << "    : " << doh_urls[i] << "\n";

    for (const std::string& entry : resolve_entries)
        os << "Bootstrap     : " << entry << "\n";

    os << "Event loops   : " << workers << "\n"
       << "UDP readers   : " << udp_readers << "\n"
       << "Max in-flight : " << max_inflight << "\n"
       << "Rate limit    : "
       << (rate_limit_qps > 0
               ? std::to_string(rate_limit_qps) + " qps, burst " +
                     std::to_string(rate_limit_burst > 0 ? rate_limit_burst
                                                         : rate_limit_qps) +
                     ", per /" + std::to_string(rate_limit_v4_prefix) + " v4 and /" +
                     std::to_string(rate_limit_v6_prefix) + " v6"
               : std::string("off"))
       << "\n"
       << "Timeouts      : " << connect_timeout_ms << "ms connect, "
       << request_timeout_ms << "ms request\n"
       << "Cooldown      : "
       << (resolver_cooldown_ms > 0 ? std::to_string(resolver_cooldown_ms) + "ms"
                                    : std::string("off"))
       << "\n"
       << "Check cert    : " << (check_cert ? "true" : "false") << "\n"
       << "TCP keep-alive: " << tcp_keep_alive << "s\n"
       << "Cache TTL     : " << cache_ttl << "s\n"
       << "Cache neg TTL : " << cache_negative_ttl << "s\n"
       << "Serve stale   : "
       << (serve_stale > 0 ? std::to_string(serve_stale) + "s" : std::string("off")) << "\n"
       << "TCP           : " << (tcp_enabled ? "on" : "off") << ", max "
       << tcp_max_conns << " conns, " << tcp_idle_sec << "s idle\n"
       << "Run as        : "
       << (run_as_user.empty() ? std::string("unchanged")
                               : run_as_user + (run_as_group.empty()
                                                    ? ""
                                                    : ":" + run_as_group))
       << "\n"
       << "Sandbox       : " << (sandbox ? "on" : "off") << "\n"
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
