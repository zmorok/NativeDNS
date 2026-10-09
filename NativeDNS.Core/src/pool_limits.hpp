#pragma once
#include <nativedns/config.hpp>
#include <algorithm>

namespace nd::detail {
// Called with the pool mutex held. Do not retain references to map values
// across a condition-variable wait: a different caller can evict an idle key.
template <class Pool> void limit_idle_pool(Pool& pool, const std::string& key) {
    constexpr size_t max_keys = 128;
    if (pool.contains(key) || pool.size() < max_keys)
        return;
    for (auto item = pool.begin(); item != pool.end();) {
        if (std::all_of(item->second.begin(), item->second.end(), [](const auto& entry) {
                return !entry->busy;
            }))
            item = pool.erase(item);
        else
            ++item;
    }
    if (pool.size() >= max_keys)
        throw Error("UPSTREAM_BUSY", "Upstream connection pool is at capacity");
}
} // namespace nd::detail
