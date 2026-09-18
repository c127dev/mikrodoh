#include "coalesce.h"

#include "transfer.h"

bool Coalescer::join(Transfer* t) {
    if (t->cache_key.empty()) return false;

    auto it = pending_.find(t->cache_key);
    if (it == pending_.end()) {
        pending_.emplace(t->cache_key, Pending{t, {}});
        return false;
    }

    it->second.followers.push_back(t);
    return true;
}

std::vector<Transfer*> Coalescer::release(Transfer* leader) {
    auto it = pending_.find(leader->cache_key);
    if (it == pending_.end() || it->second.leader != leader) return {};

    std::vector<Transfer*> followers = std::move(it->second.followers);
    pending_.erase(it);
    return followers;
}
