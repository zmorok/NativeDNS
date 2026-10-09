#pragma once
#include <nativedns/config.hpp>
#include <condition_variable>
#include <stop_token>
#include <algorithm>

namespace nd::detail {
// Nested bootstrap and DNSCrypt operations inherit one request's token.
inline thread_local std::stop_token request_cancellation;
class CancellationScope final {
public:
    explicit CancellationScope(std::stop_token token) : previous_(request_cancellation) {
        request_cancellation = token;
    }
    ~CancellationScope() {
        request_cancellation = previous_;
    }
    CancellationScope(const CancellationScope&) = delete;
    CancellationScope& operator=(const CancellationScope&) = delete;

private:
    std::stop_token previous_;
};
inline void check_cancelled() {
    if (request_cancellation.stop_requested())
        throw Error("CANCELLED", "DNS operation cancelled during shutdown");
}
template <class Condition, class Lock>
std::cv_status wait_until_change(Condition& condition,
                                 Lock& lock,
                                 std::chrono::steady_clock::time_point deadline) {
    check_cancelled();
    condition.wait_until(
        lock,
        std::min(deadline, std::chrono::steady_clock::now() + std::chrono::milliseconds(100)));
    check_cancelled();
    return std::chrono::steady_clock::now() >= deadline ? std::cv_status::timeout
                                                        : std::cv_status::no_timeout;
}
} // namespace nd::detail
