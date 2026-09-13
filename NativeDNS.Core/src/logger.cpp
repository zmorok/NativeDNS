#include <nativedns/logger.hpp>
#include <nativedns/platform.hpp>
#include <algorithm>
#include <cctype>
#include <stdexcept>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <vector>
namespace nd {
namespace {
const char* level_name(Level level) {
    switch (level) {
        case Level::errors_only:
            return "ERROR";
        case Level::normal:
            return "INFO";
        case Level::verbose:
            return "VERBOSE";
        case Level::debug:
            return "DEBUG";
    }
    return "UNKNOWN";
}
bool is_timestamped_log_path(const std::filesystem::path& path) {
    const auto name = path.filename().string();
    if (name.size() != 29 || !name.starts_with("NativeDNS-") || !name.ends_with(".log") ||
        name[16] != '-')
        return false;
    return std::all_of(name.begin() + 10,
                       name.begin() + 16,
                       [](unsigned char c) { return std::isdigit(c); }) &&
           std::all_of(name.begin() + 17, name.begin() + 25, [](unsigned char c) {
               return std::isdigit(c);
           });
}
void prune_timestamped_logs(const std::filesystem::path& directory, size_t keep) {
    struct ExistingLog {
        std::filesystem::path path;
        std::filesystem::file_time_type modified;
    };
    std::vector<ExistingLog> files;
    std::error_code error;
    for (std::filesystem::directory_iterator it(directory, error), end; !error && it != end;
         it.increment(error)) {
        const bool regular = it->is_regular_file(error);
        if (error)
            break;
        if (!regular || !is_timestamped_log_path(it->path()))
            continue;
        const auto modified = it->last_write_time(error);
        if (error)
            break;
        files.push_back({it->path(), modified});
    }
    if (error)
        throw std::runtime_error("cannot enumerate log files: " + error.message());
    std::sort(files.begin(), files.end(), [](const auto& left, const auto& right) {
        return left.modified == right.modified ? left.path.filename() < right.path.filename()
                                               : left.modified < right.modified;
    });
    while (files.size() > keep) {
        std::filesystem::remove(files.front().path, error);
        if (error)
            throw std::runtime_error("cannot remove old log file: " + error.message());
        files.erase(files.begin());
    }
}
} // namespace
std::filesystem::path timestamped_log_path(const std::filesystem::path& directory,
                                           std::chrono::system_clock::time_point started_at) {
    for (unsigned collision = 0; collision <= 100; ++collision) {
        const auto instant =
            std::chrono::system_clock::to_time_t(started_at + std::chrono::seconds(collision));
        tm local{};
        platform::local_time(instant, local);
        std::ostringstream name;
        name << "NativeDNS-" << std::put_time(&local, "%H%M%S-%d%m%Y") << ".log";
        auto path = directory / name.str();
        if (!std::filesystem::exists(path))
            return path;
    }
    throw std::runtime_error("cannot allocate a unique timestamped log file name");
}
Logger::Logger(size_t capacity) : capacity_(capacity) {
    if (!capacity)
        throw std::invalid_argument("log capacity must be positive");
    file_thread_ = std::jthread([this] { file_loop(); });
}
Logger::~Logger() {
    file_enabled_ = false;
    try {
        FileTask task;
        task.kind = FileTask::Kind::stop;
        submit_file_task(std::move(task));
    } catch (...) {
    }
    if (file_thread_.joinable())
        file_thread_.join();
}
bool Logger::enabled(Level level) const noexcept {
    return level <= display_level_.load(std::memory_order_relaxed) ||
           (file_enabled_.load(std::memory_order_relaxed) &&
            level <= file_level_.load(std::memory_order_relaxed));
}
void Logger::set_display_level(Level level) {
    if (level > Level::debug)
        throw std::invalid_argument("invalid display logging level");
    display_level_ = level;
}
void Logger::write(Level level, std::string code, std::string message) {
    if (!enabled(level))
        return;
    for (char& c : message)
        if (static_cast<unsigned char>(c) < 32)
            c = ' ';
    for (char& c : code)
        if (static_cast<unsigned char>(c) < 32)
            c = ' ';
    if (message.size() > 4096)
        message.resize(4096);
    if (code.size() > 128)
        code.resize(128);
    LogEvent event;
    {
        std::lock_guard lock(mutex_);
        events_.push_back({++sequence_,
                           std::chrono::system_clock::now(),
                           level,
                           std::move(code),
                           std::move(message)});
        if (events_.size() > capacity_)
            events_.pop_front();
        event = events_.back();
    }
    if (file_enabled_.load(std::memory_order_relaxed) &&
        level <= file_level_.load(std::memory_order_relaxed)) {
        bool queued = false;
        {
            std::lock_guard lock(file_mutex_);
            if (file_tasks_.size() < 8192) {
                FileTask task;
                task.kind = FileTask::Kind::event;
                task.event = std::move(event);
                file_tasks_.push_back(std::move(task));
                queued = true;
            }
        }
        if (queued)
            file_changed_.notify_one();
        else {
            const auto dropped = ++dropped_file_events_;
            if (dropped == 1 || (dropped & (dropped - 1)) == 0)
                record_file_failure("file log queue is full; dropped events=" +
                                    std::to_string(dropped));
        }
    }
    changed_.notify_all();
}
std::vector<LogEvent>
Logger::wait_snapshot(Level level, uint64_t after, std::chrono::milliseconds timeout) const {
    std::unique_lock lock(mutex_);
    if (after > sequence_)
        after = 0; // A reattached client may carry a sequence from a previous Core process.
    changed_.wait_for(lock, timeout, [&] {
        return std::any_of(events_.begin(), events_.end(), [&](const LogEvent& event) {
            return event.sequence > after && event.level <= level;
        });
    });
    std::vector<LogEvent> result;
    for (const auto& event : events_)
        if (event.sequence > after && event.level <= level)
            result.push_back(event);
    return result;
}
std::vector<LogEvent> Logger::snapshot(Level level, uint64_t after) const {
    std::lock_guard lock(mutex_);
    if (after > sequence_)
        after = 0;
    std::vector<LogEvent> result;
    for (const auto& event : events_)
        if (event.sequence > after && event.level <= level)
            result.push_back(event);
    return result;
}
void Logger::clear_display() {
    std::lock_guard lock(mutex_);
    events_.clear();
}
void Logger::configure_file(bool enabled,
                            Level level,
                            std::filesystem::path path,
                            uint64_t maximum_bytes,
                            uint32_t retained_files) {
    if (level > Level::debug || maximum_bytes < 1024 || maximum_bytes > 1024ull * 1024 * 1024 ||
        retained_files > 100)
        throw std::invalid_argument("invalid file logging settings");
    if (enabled && path.empty())
        throw std::invalid_argument("file log path is empty");
    if (!enabled)
        file_enabled_ = false;
    FileTask task;
    task.kind = FileTask::Kind::configure;
    task.enabled = enabled;
    task.level = level;
    task.path = std::move(path);
    task.maximum_bytes = maximum_bytes;
    task.retained_files = retained_files;
    submit_file_task(std::move(task));
}
void Logger::clear_file() {
    FileTask task;
    task.kind = FileTask::Kind::clear;
    submit_file_task(std::move(task));
}
void Logger::flush_file() {
    FileTask task;
    task.kind = FileTask::Kind::flush;
    submit_file_task(std::move(task));
}
void Logger::submit_file_task(FileTask task) {
    task.completion = std::make_shared<std::promise<void>>();
    auto completed = task.completion->get_future();
    {
        std::lock_guard lock(file_mutex_);
        file_tasks_.push_back(std::move(task));
    }
    file_changed_.notify_one();
    completed.get();
}
void Logger::record_file_failure(const std::string& message) {
    std::lock_guard lock(mutex_);
    events_.push_back({++sequence_,
                       std::chrono::system_clock::now(),
                       Level::errors_only,
                       "FILE_LOG_FAILED",
                       message});
    if (events_.size() > capacity_)
        events_.pop_front();
    changed_.notify_all();
}
void Logger::file_loop() {
    bool sink_enabled = false;
    for (;;) {
        FileTask task;
        {
            std::unique_lock lock(file_mutex_);
            file_changed_.wait(lock, [&] { return !file_tasks_.empty(); });
            task = std::move(file_tasks_.front());
            file_tasks_.pop_front();
        }
        try {
            if (task.kind == FileTask::Kind::event) {
                std::vector<LogEvent> batch;
                batch.push_back(std::move(task.event));
                {
                    std::lock_guard lock(file_mutex_);
                    while (batch.size() < 256 && !file_tasks_.empty() &&
                           file_tasks_.front().kind == FileTask::Kind::event) {
                        batch.push_back(std::move(file_tasks_.front().event));
                        file_tasks_.pop_front();
                    }
                }
                if (sink_enabled)
                    write_file_batch(batch);
                continue;
            }
            if (task.kind == FileTask::Kind::configure) {
                if (task.enabled) {
                    const auto parent = task.path.parent_path();
                    if (!parent.empty())
                        std::filesystem::create_directories(parent);
                    std::ofstream probe(task.path, std::ios::binary | std::ios::app);
                    if (!probe)
                        throw std::runtime_error("cannot open log file");
                    probe.close();
                    if (is_timestamped_log_path(task.path))
                        prune_timestamped_logs(parent,
                                               static_cast<size_t>(task.retained_files) + 1);
                }
                file_path_ = std::move(task.path);
                maximum_bytes_ = task.maximum_bytes;
                retained_files_ = task.retained_files;
                file_level_ = task.level;
                sink_enabled = task.enabled;
                file_enabled_ = task.enabled;
                dropped_file_events_ = 0;
            } else if (task.kind == FileTask::Kind::clear) {
                if (!file_path_.empty() && std::filesystem::exists(file_path_)) {
                    std::ofstream stream(file_path_, std::ios::binary | std::ios::trunc);
                    if (!stream)
                        throw std::runtime_error("cannot clear log file");
                    stream.flush();
                    if (!stream)
                        throw std::runtime_error("cannot flush cleared log file");
                }
            } else if (task.kind == FileTask::Kind::stop) {
                if (task.completion)
                    task.completion->set_value();
                return;
            }
            if (task.completion)
                task.completion->set_value();
        } catch (...) {
            const auto failure = std::current_exception();
            sink_enabled = false;
            file_enabled_ = false;
            try {
                std::rethrow_exception(failure);
            } catch (const std::exception& error) {
                record_file_failure(error.what());
            } catch (...) {
                record_file_failure("unknown file logging failure");
            }
            if (task.completion)
                task.completion->set_exception(failure);
        }
    }
}
void Logger::rotate_file(uint64_t incoming_bytes) {
    std::error_code error;
    const auto size = std::filesystem::file_size(file_path_, error);
    if (!error && size + incoming_bytes <= maximum_bytes_)
        return;
    if (is_timestamped_log_path(file_path_)) {
        const auto directory = file_path_.parent_path();
        file_path_ = timestamped_log_path(directory);
        prune_timestamped_logs(directory, retained_files_);
        return;
    }
    if (retained_files_ == 0) {
        std::ofstream stream(file_path_, std::ios::binary | std::ios::trunc);
        if (!stream)
            throw std::runtime_error("cannot truncate log file");
        return;
    }
    for (uint32_t index = retained_files_; index > 0; --index) {
        auto destination = file_path_;
        destination += "." + std::to_string(index);
        auto source = file_path_;
        if (index > 1)
            source += "." + std::to_string(index - 1);
        if (std::filesystem::exists(source)) {
            std::error_code ec;
            std::filesystem::remove(destination, ec);
            ec.clear();
            std::filesystem::rename(source, destination, ec);
            if (ec)
                throw std::runtime_error("cannot rotate log file: " + ec.message());
        }
    }
}
void Logger::write_file_batch(const std::vector<LogEvent>& events) {
    std::ofstream stream;
    std::error_code error;
    uint64_t current = std::filesystem::file_size(file_path_, error);
    if (error)
        current = 0;
    for (const auto& event : events) {
        const auto instant = std::chrono::system_clock::to_time_t(event.time);
        tm local{};
        platform::local_time(instant, local);
        std::ostringstream line;
        line << '[' << std::put_time(&local, "%d.%m.%Y %H:%M:%S") << "] " << event.sequence << " ["
             << level_name(event.level) << "] " << event.code << ' ' << event.message << "\r\n";
        const auto text = line.str();
        if (current + text.size() > maximum_bytes_) {
            if (stream.is_open()) {
                stream.flush();
                if (!stream)
                    throw std::runtime_error("cannot flush log file");
                stream.close();
            }
            rotate_file(text.size());
            error.clear();
            current = std::filesystem::file_size(file_path_, error);
            if (error)
                current = 0;
        }
        if (!stream.is_open()) {
            stream.open(file_path_, std::ios::binary | std::ios::app);
            if (!stream)
                throw std::runtime_error("cannot append log file");
        }
        stream.write(text.data(), static_cast<std::streamsize>(text.size()));
        if (!stream)
            throw std::runtime_error("cannot append log file");
        current += text.size();
    }
    if (stream.is_open()) {
        stream.flush();
        if (!stream)
            throw std::runtime_error("cannot flush log file");
    }
}
} // namespace nd
