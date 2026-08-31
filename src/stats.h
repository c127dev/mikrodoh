#pragma once

#include <atomic>

struct Stats {
    std::atomic<long>          inflight{0};
    std::atomic<unsigned long> dropped{0};
    std::atomic<unsigned long> served{0};
    std::atomic<unsigned long> failed{0};
    std::atomic<unsigned long> rejected{0};
    std::atomic<unsigned long> cache_hits{0};
    std::atomic<long>          tcp_conns{0};
};
