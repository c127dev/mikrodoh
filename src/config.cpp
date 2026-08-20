#include "config.h"

#include "cpu.h"

#include <cctype>
#include <cstdlib>
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

}  // namespace

Config Config::from_env() {
    Config c;

    c.listen_port = env_int("LISTEN_PORT", env_int("PORT", c.listen_port));
    c.doh_url     = env_str("DOH_URL", c.doh_url);

    c.workers = env_int("WORKERS", 0);
    if (c.workers < 1) {
        unsigned hc = std::thread::hardware_concurrency();
        c.workers = hc > 0 ? static_cast<int>(hc) : 4;
    }

    c.check_cert     = env_bool("CHECK_CERT", c.check_cert);
    c.tcp_keep_alive = env_int("TCP_KEEP_ALIVE", c.tcp_keep_alive);
    c.cache_ttl      = env_int("CACHE", c.cache_ttl);
    c.rcvbuf_kb      = env_int("RCVBUF_KB", c.rcvbuf_kb);

    c.max_inflight = env_long("MAX_INFLIGHT", c.max_inflight);
    if (c.max_inflight < 1) c.max_inflight = 1;

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
    os << "MikroDoH listening on UDP port " << listen_port << "\n"
       << "Resolver      : " << doh_url << "\n"
       << "Event loops   : " << workers << "\n"
       << "Max in-flight : " << max_inflight << "\n"
       << "Check cert    : " << (check_cert ? "true" : "false") << "\n"
       << "TCP keep-alive: " << tcp_keep_alive << "s\n"
       << "Cache TTL     : " << cache_ttl << "s\n"
       << "CPU           : " << cpu::arch()
       << (cpu::has_aes() ? " (AES engine)" : " (no AES engine)") << "\n"
       << "Cipher        : " << cipher_name(cipher) << " -> "
       << (prefer_chacha ? "ChaCha20-Poly1305" : "AES-GCM") << "\n";

    // stdout is a pipe under a container runtime, so without this the banner
    // sits in the buffer until the process exits.
    os.flush();
}
