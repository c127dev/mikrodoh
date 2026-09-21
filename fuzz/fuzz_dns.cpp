// libFuzzer entry point for the code that parses bytes off the wire. Every
// function in dns.h, the cache key and the health probe get the input, and
// the invariants their callers rely on are checked.

#include "cache.h"
#include "dns.h"
#include "health.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <vector>

namespace {

void require(bool ok) {
    if (!ok) std::abort();
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    // The first byte picks a split, so one input also serves as a query and a
    // response to it.
    std::size_t split = size ? data[0] % (size + 1) : 0;
    const std::uint8_t* q    = data;
    std::size_t         qlen = split;
    const std::uint8_t* r    = data + split;
    std::size_t         rlen = size - split;

    for (auto [msg, len] : {std::pair{data, size}, std::pair{q, qlen}, std::pair{r, rlen}}) {
        // A copy of exactly `len` bytes, so ASan sees any read past the end.
        std::vector<std::uint8_t> m(msg, msg + len);
        const std::uint8_t*       p = m.data();

        std::size_t end = dns::question_end(p, len);
        require(end == 0 || (end > dns::kHeaderLen && end <= len));

        bool valid = dns::query_valid(p, len);
        require(!valid || end != 0);

        dns::UdpLimit limit = dns::udp_limit(p, len);
        require(limit.bytes >= dns::kMinUdpPayload && limit.bytes <= dns::kMaxMessage);

        dns::rcode(p, len);
        dns::has_answers(p, len);

        long ttl = dns::min_ttl(p, len);
        require(ttl >= -1 && ttl <= 0x7FFFFFFF);

        std::vector<std::uint8_t> err = dns::make_error(p, len, dns::kRcodeServFail);
        require(err.empty() == (len < dns::kHeaderLen));
        if (valid) require(dns::response_matches(p, len, err.data(), err.size()));

        std::vector<std::uint8_t> cut = dns::truncate(p, len, limit);
        require(cut.empty() == (len < dns::kHeaderLen));

        std::vector<std::uint8_t> aged(m);
        dns::age_ttls(aged.data(), aged.size(), 100);
        require(aged.size() == len);
        long aged_ttl = dns::min_ttl(aged.data(), aged.size());
        require(ttl < 0 || aged_ttl == (ttl > 100 ? ttl - 100 : 0));

        std::vector<std::uint8_t> set(m);
        dns::set_ttls(set.data(), set.size(), 30);
        require(ttl < 0 || dns::min_ttl(set.data(), set.size()) == 30);

        std::vector<std::uint8_t> clamped(m);
        dns::clamp_ttls(clamped.data(), clamped.size(), 60, 3600);
        long clamped_ttl = dns::min_ttl(clamped.data(), clamped.size());
        require(ttl < 0 || (clamped_ttl >= 60 && clamped_ttl <= 3600));

        std::vector<std::uint8_t> clean(m);
        dns::sanitize_edns(clean);
        if (valid) {
            require(dns::query_valid(clean.data(), clean.size()));
            require(dns::udp_limit(clean.data(), clean.size()).bytes == limit.bytes);
            // DNSSEC passthrough: DO in the OPT record, CD and the rest of
            // the header ahead of the counts.
            require(dns::udp_limit(clean.data(), clean.size()).dnssec_ok == limit.dnssec_ok);
            require(std::equal(m.begin(), m.begin() + 10, clean.begin()));
            if (clean != m) require(clean.size() % 128 == 0);
        }

        std::string key = DnsCache::key_of(p, len);
        require(key.empty() == (end == 0));

        if (health::is_probe(p, len)) {
            require(!health::answer(p, len, true).empty());
            require(!health::upstream_request(p, len).empty());
        }
    }

    std::vector<std::uint8_t> qc(q, q + qlen);
    std::vector<std::uint8_t> rc(r, r + rlen);
    dns::response_matches(qc.data(), qlen, rc.data(), rlen);

    return 0;
}
