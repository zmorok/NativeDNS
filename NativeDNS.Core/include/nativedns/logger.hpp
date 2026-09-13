#pragma once
#include <nativedns/model.hpp>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <filesystem>
#include <atomic>
#include <future>
#include <thread>
#include <vector>

namespace nd {
std::filesystem::path timestamped_log_path(
    const std::filesystem::path& directory,
    std::chrono::system_clock::time_point started_at = std::chrono::system_clock::now());

struct LogEvent {
    uint64_t sequence;
    std::chrono::system_clock::time_point time;
    Level level;
    std::string code, message;
};
// Bounded in-memory log with an optional independently filtered rotating file sink.
class Logger {
public:
    explicit Logger(size_t capacity = 2048);
    ~Logger();
    bool enabled(Level level) const noexcept;
    void set_display_level(Level level);
    void write(Level level, std::string code, std::string message);
    std::vector<LogEvent> snapshot(Level level, uint64_t after = 0) const;
    std::vector<LogEvent>
    wait_snapshot(Level level, uint64_t after, std::chrono::milliseconds timeout) const;
    void clear_display();
    void configure_file(bool enabled,
                        Level level,
                        std::filesystem::path path,
                        uint64_t maximum_bytes = 4 * 1024 * 1024,
                        uint32_t retained_files = 3);
    void clear_file();
    void flush_file();

private:
    struct FileTask {
        enum class Kind { event, configure, clear, flush, stop } kind = Kind::event;
        LogEvent event{};
        bool enabled = false;
        Level level = Level::normal;
        std::filesystem::path path;
        uint64_t maximum_bytes = 0;
        uint32_t retained_files = 0;
        std::shared_ptr<std::promise<void>> completion;
    };
    void file_loop();
    void submit_file_task(FileTask task);
    void record_file_failure(const std::string& message);
    void write_file_batch(const std::vector<LogEvent>& events);
    void rotate_file(uint64_t incoming_bytes);
    mutable std::mutex mutex_;
    mutable std::condition_variable changed_;
    std::deque<LogEvent> events_;
    size_t capacity_;
    uint64_t sequence_ = 0;
    std::atomic_bool file_enabled_ = false;
    std::atomic<Level> file_level_ = Level::normal;
    std::atomic<Level> display_level_ = Level::debug;
    std::mutex file_mutex_;
    std::condition_variable file_changed_;
    std::deque<FileTask> file_tasks_;
    std::jthread file_thread_;
    std::atomic_uint64_t dropped_file_events_ = 0;
    std::filesystem::path file_path_;
    uint64_t maximum_bytes_ = 4 * 1024 * 1024;
    uint32_t retained_files_ = 3;
};
} // namespace nd
