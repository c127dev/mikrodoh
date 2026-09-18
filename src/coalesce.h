#pragma once

#include <string>
#include <unordered_map>
#include <vector>

struct Transfer;

// Queries waiting on an identical one already sent upstream. Keyed by the
// cache key, so a follower accepts exactly the answer the cache would give it.
// Owned by one worker loop and not locked.
class Coalescer {
public:
    // True when a transfer with the same key is pending: `t` is attached to it
    // and must not be started. Otherwise `t` becomes the pending one for its
    // key, unless the key is empty.
    bool join(Transfer* t);

    // The transfers attached to `leader`, which stops being pending. Empty when
    // `leader` was never registered.
    std::vector<Transfer*> release(Transfer* leader);

private:
    struct Pending {
        Transfer*              leader;
        std::vector<Transfer*> followers;
    };

    std::unordered_map<std::string, Pending> pending_;
};
