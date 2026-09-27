#include "stats.h"

#include <ostream>

void Stats::print(std::ostream& os) const {
    unsigned long ok   = served.load(std::memory_order_relaxed);
    unsigned long hits = cache_hits.load(std::memory_order_relaxed);

    os << "[stats] served=" << ok
       << " failed=" << failed.load(std::memory_order_relaxed)
       << " rejected=" << rejected.load(std::memory_order_relaxed)
       << " dropped=" << dropped.load(std::memory_order_relaxed)
       << " throttled=" << throttled.load(std::memory_order_relaxed)
       << " oversized=" << oversized.load(std::memory_order_relaxed)
       << " inflight=" << inflight.load(std::memory_order_relaxed)
       << " tcp_conns=" << tcp_conns.load(std::memory_order_relaxed)
       << " cache_hits=" << hits
       << " prefetched=" << prefetched.load(std::memory_order_relaxed)
       << " stale=" << stale.load(std::memory_order_relaxed)
       << " coalesced=" << coalesced.load(std::memory_order_relaxed) << " hit_rate=";

    if (ok == 0) os << "n/a";
    else         os << (hits * 100 / ok) << "%";

    os << "\n" << std::flush;
}
