#pragma once

#include <atomic>
#include <iosfwd>

struct Stats {
    std::atomic<long>          inflight{0};
    std::atomic<unsigned long> dropped{0};
    std::atomic<unsigned long> served{0};
    std::atomic<unsigned long> failed{0};
    std::atomic<unsigned long> rejected{0};
    std::atomic<unsigned long> throttled{0};
    std::atomic<unsigned long> oversized{0};
    std::atomic<unsigned long> cache_hits{0};
    std::atomic<unsigned long> stale{0};
    std::atomic<unsigned long> prefetched{0};
    std::atomic<unsigned long> coalesced{0};
    std::atomic<long>          tcp_conns{0};

    void print(std::ostream& os) const;
};
