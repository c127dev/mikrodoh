#include "stats.h"

#include <ostream>

void Stats::print(std::ostream& os) const {
    unsigned long ok   = served.load(std::memory_order_relaxed);
    unsigned long hits = cache_hits.load(std::memory_order_relaxed);

    os << "[stats] served=" << ok
       << " failed=" << failed.load(std::memory_order_relaxed)
       << " rejected=" << rejected.load(std::memory_order_relaxed)
       << " dropped=" << dropped.load(std::memory_order_relaxed)
       << " inflight=" << inflight.load(std::memory_order_relaxed)
       << " tcp_conns=" << tcp_conns.load(std::memory_order_relaxed)
       << " cache_hits=" << hits << " hit_rate=";

    if (ok == 0) os << "n/a";
    else         os << (hits * 100 / ok) << "%";

    // stdout is a pipe under a container runtime, so the line would otherwise
    // sit in the buffer until the process exits.
    os << "\n" << std::flush;
}
