#pragma once

#include <atomic>

struct Stats {
    std::atomic<long>          inflight{0};
    std::atomic<unsigned long> dropped{0};
    std::atomic<unsigned long> served{0};
};
