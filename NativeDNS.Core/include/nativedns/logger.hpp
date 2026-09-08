#pragma once
#include <nativedns/model.hpp>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <filesystem>

namespace nd {
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
    void write(Level level, std::string code, std::string message);
    std::vector<LogEvent> snapshot(Level level, uint64_t after = 0) const;
    std::vector<LogEvent> wait_snapshot(Level level, uint64_t after, std::chrono::milliseconds timeout) const;
    void clear_display();
    void configure_file(bool enabled, Level level, std::filesystem::path path,
                        uint64_t maximum_bytes = 4 * 1024 * 1024, uint32_t retained_files = 3);
    void clear_file();
private:
    void write_file(const LogEvent& event);
    void rotate_file(uint64_t incoming_bytes);
    mutable std::mutex mutex_;
    mutable std::condition_variable changed_;
    std::deque<LogEvent> events_;
    size_t capacity_;
    uint64_t sequence_ = 0;
    bool file_enabled_ = false;
    Level file_level_ = Level::normal;
    std::filesystem::path file_path_;
    uint64_t maximum_bytes_ = 4 * 1024 * 1024;
    uint32_t retained_files_ = 3;
};
}
