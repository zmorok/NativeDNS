#pragma once

#include <condition_variable>
#include <cstddef>
#include <deque>
#include <functional>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <vector>

namespace nd::detail {

class BoundedExecutor final {
public:
    BoundedExecutor() = default;
    ~BoundedExecutor() { stop(); }
    BoundedExecutor(const BoundedExecutor&) = delete;
    BoundedExecutor& operator=(const BoundedExecutor&) = delete;

    void start(std::size_t workers, std::size_t capacity) {
        if (!workers || !capacity) throw std::invalid_argument("executor workers and capacity must be positive");
        std::lock_guard lock(mutex_);
        if (!threads_.empty()) throw std::logic_error("executor already started");
        stopping_ = false;
        capacity_ = capacity;
        try {
            for (std::size_t i = 0; i < workers; ++i) threads_.emplace_back([this] { run(); });
        } catch (...) {
            stopping_ = true;
            changed_.notify_all();
            throw;
        }
    }

    bool submit(std::function<void()> job) {
        std::lock_guard lock(mutex_);
        if (stopping_ || threads_.empty() || jobs_.size() >= capacity_) return false;
        jobs_.push_back(std::move(job));
        changed_.notify_one();
        return true;
    }

    void stop() noexcept {
        {
            std::lock_guard lock(mutex_);
            stopping_ = true;
            jobs_.clear();
        }
        changed_.notify_all();
        for (auto& thread : threads_) if (thread.joinable()) thread.join();
        threads_.clear();
        capacity_ = 0;
    }

private:
    void run() noexcept {
        for (;;) {
            std::function<void()> job;
            {
                std::unique_lock lock(mutex_);
                changed_.wait(lock, [this] { return stopping_ || !jobs_.empty(); });
                if (stopping_ && jobs_.empty()) return;
                job = std::move(jobs_.front());
                jobs_.pop_front();
            }
            try { job(); } catch (...) { }
        }
    }

    std::mutex mutex_;
    std::condition_variable changed_;
    std::deque<std::function<void()>> jobs_;
    std::vector<std::jthread> threads_;
    std::size_t capacity_ = 0;
    bool stopping_ = true;
};

}
