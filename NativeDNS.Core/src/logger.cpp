#include <nativedns/logger.hpp>
#include <nativedns/platform.hpp>
#include <algorithm>
#include <stdexcept>
#include <fstream>
#include <iomanip>
#include <sstream>
namespace nd {
Logger::Logger(size_t capacity) : capacity_(capacity) {
    if (!capacity) throw std::invalid_argument("log capacity must be positive");
}
void Logger::write(Level level, std::string code, std::string message) {
    for (char& c : message) if (static_cast<unsigned char>(c) < 32) c = ' ';
    for (char& c : code) if (static_cast<unsigned char>(c) < 32) c = ' ';
    if (message.size() > 4096) message.resize(4096);
    if (code.size() > 128) code.resize(128);
    {
        std::lock_guard lock(mutex_);
        events_.push_back({++sequence_, std::chrono::system_clock::now(), level, std::move(code), std::move(message)});
        if (events_.size() > capacity_) events_.pop_front();
        if (file_enabled_ && level <= file_level_) write_file(events_.back());
    }
    changed_.notify_all();
}
std::vector<LogEvent> Logger::wait_snapshot(Level level,uint64_t after,std::chrono::milliseconds timeout) const {
    std::unique_lock lock(mutex_);
    if(after>sequence_) after=0; // A reattached client may carry a sequence from a previous Core process.
    changed_.wait_for(lock,timeout,[&] {
        return std::any_of(events_.begin(),events_.end(),[&](const LogEvent& event){return event.sequence>after&&event.level<=level;});
    });
    std::vector<LogEvent> result;
    for(const auto& event:events_) if(event.sequence>after&&event.level<=level) result.push_back(event);
    return result;
}
std::vector<LogEvent> Logger::snapshot(Level level, uint64_t after) const {
    std::lock_guard lock(mutex_);
    if(after>sequence_) after=0;
    std::vector<LogEvent> result;
    for (const auto& event : events_)
        if (event.sequence > after && event.level <= level) result.push_back(event);
    return result;
}
void Logger::clear_display() { std::lock_guard lock(mutex_); events_.clear(); }
void Logger::configure_file(bool enabled, Level level, std::filesystem::path path, uint64_t maximum_bytes, uint32_t retained_files) {
    if (level > Level::debug || maximum_bytes < 1024 || maximum_bytes > 1024ull * 1024 * 1024 || retained_files > 100)
        throw std::invalid_argument("invalid file logging settings");
    std::lock_guard lock(mutex_);
    if (enabled) {
        if (path.empty()) throw std::invalid_argument("file log path is empty");
        const auto parent = path.parent_path();
        if (!parent.empty()) std::filesystem::create_directories(parent);
        std::ofstream probe(path, std::ios::binary | std::ios::app);
        if (!probe) throw std::runtime_error("cannot open log file");
    }
    file_enabled_ = enabled; file_level_ = level; file_path_ = std::move(path);
    maximum_bytes_ = maximum_bytes; retained_files_ = retained_files;
}
void Logger::clear_file() {
    std::lock_guard lock(mutex_);
    if (file_path_.empty()) return;
    std::ofstream stream(file_path_, std::ios::binary | std::ios::trunc);
    if (!stream) throw std::runtime_error("cannot clear log file");
    stream.flush();
}
void Logger::rotate_file(uint64_t incoming_bytes) {
    std::error_code error;
    const auto size = std::filesystem::file_size(file_path_, error);
    if (!error && size + incoming_bytes <= maximum_bytes_) return;
    if (retained_files_ == 0) {
        std::ofstream stream(file_path_, std::ios::binary | std::ios::trunc);
        if (!stream) throw std::runtime_error("cannot truncate log file");
        return;
    }
    for (uint32_t index = retained_files_; index > 0; --index) {
        auto destination = file_path_; destination += "." + std::to_string(index);
        auto source = file_path_;
        if (index > 1) source += "." + std::to_string(index - 1);
        if (std::filesystem::exists(source)) {
            std::error_code ec;
            std::filesystem::remove(destination,ec); ec.clear();
            std::filesystem::rename(source,destination,ec);
            if(ec) throw std::runtime_error("cannot rotate log file: "+ec.message());
        }
    }
}
void Logger::write_file(const LogEvent& event) {
    const auto instant = std::chrono::system_clock::to_time_t(event.time);
    tm local{};
    platform::local_time(instant, local);
    const auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(event.time.time_since_epoch()).count() % 1000;
    std::ostringstream line;
    line << '[' << std::put_time(&local, "%Y-%m-%d %H:%M:%S") << '.' << std::setw(3) << std::setfill('0') << millis << "] "
         << event.sequence << ' ' << event.code << ' ' << event.message << "\r\n";
    const auto text = line.str();
    rotate_file(text.size());
    std::ofstream stream(file_path_, std::ios::binary | std::ios::app);
    if (!stream) throw std::runtime_error("cannot append log file");
    stream.write(text.data(), static_cast<std::streamsize>(text.size()));
    stream.flush();
    if (!stream) throw std::runtime_error("cannot flush log file");
}
}
