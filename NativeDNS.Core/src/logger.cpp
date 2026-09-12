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
const char* level_name(Level level){
    switch(level){
    case Level::errors_only:return "ERROR";
    case Level::normal:return "INFO";
    case Level::verbose:return "VERBOSE";
    case Level::debug:return "DEBUG";
    }
    return "UNKNOWN";
}
bool is_timestamped_log_path(const std::filesystem::path& path) {
    const auto name=path.filename().string();
    if(name.size()!=29||!name.starts_with("NativeDNS-")||!name.ends_with(".log")||name[16]!='-')return false;
    return std::all_of(name.begin()+10,name.begin()+16,[](unsigned char c){return std::isdigit(c);})
        &&std::all_of(name.begin()+17,name.begin()+25,[](unsigned char c){return std::isdigit(c);});
}
void prune_timestamped_logs(const std::filesystem::path& directory,size_t keep) {
    struct ExistingLog {
        std::filesystem::path path;
        std::filesystem::file_time_type modified;
    };
    std::vector<ExistingLog> files;
    std::error_code error;
    for(std::filesystem::directory_iterator it(directory,error),end;!error&&it!=end;it.increment(error)){
        const bool regular=it->is_regular_file(error);
        if(error)break;
        if(!regular||!is_timestamped_log_path(it->path()))continue;
        const auto modified=it->last_write_time(error);
        if(error)break;
        files.push_back({it->path(),modified});
    }
    if(error)throw std::runtime_error("cannot enumerate log files: "+error.message());
    std::sort(files.begin(),files.end(),[](const auto& left,const auto& right){
        return left.modified==right.modified?left.path.filename()<right.path.filename():left.modified<right.modified;
    });
    while(files.size()>keep){
        std::filesystem::remove(files.front().path,error);
        if(error)throw std::runtime_error("cannot remove old log file: "+error.message());
        files.erase(files.begin());
    }
}
}
std::filesystem::path timestamped_log_path(const std::filesystem::path& directory,
                                           std::chrono::system_clock::time_point started_at) {
    for(unsigned collision=0;collision<=100;++collision){
        const auto instant=std::chrono::system_clock::to_time_t(started_at+std::chrono::seconds(collision));
        tm local{};
        platform::local_time(instant,local);
        std::ostringstream name;
        name<<"NativeDNS-"<<std::put_time(&local,"%H%M%S-%d%m%Y")<<".log";
        auto path=directory/name.str();
        if(!std::filesystem::exists(path))return path;
    }
    throw std::runtime_error("cannot allocate a unique timestamped log file name");
}
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
        if (file_enabled_ && level <= file_level_) {
            try {
                write_file(events_.back());
            } catch (const std::exception& error) {
                // Diagnostics must never take DNS routing down. Keep the failure
                // visible through the live log and disable the broken sink.
                file_enabled_ = false;
                events_.push_back({++sequence_, std::chrono::system_clock::now(), Level::errors_only,
                                   "FILE_LOG_FAILED", error.what()});
                if (events_.size() > capacity_) events_.pop_front();
            }
        }
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
        probe.close();
        if(is_timestamped_log_path(path))prune_timestamped_logs(parent,static_cast<size_t>(retained_files)+1);
    }
    file_enabled_ = enabled; file_level_ = level; file_path_ = std::move(path);
    maximum_bytes_ = maximum_bytes; retained_files_ = retained_files;
}
void Logger::clear_file() {
    std::lock_guard lock(mutex_);
    if (file_path_.empty() || !std::filesystem::exists(file_path_)) return;
    std::ofstream stream(file_path_, std::ios::binary | std::ios::trunc);
    if (!stream) throw std::runtime_error("cannot clear log file");
    stream.flush();
}
void Logger::rotate_file(uint64_t incoming_bytes) {
    std::error_code error;
    const auto size = std::filesystem::file_size(file_path_, error);
    if (!error && size + incoming_bytes <= maximum_bytes_) return;
    if(is_timestamped_log_path(file_path_)){
        const auto directory=file_path_.parent_path();
        file_path_=timestamped_log_path(directory);
        prune_timestamped_logs(directory,retained_files_);
        return;
    }
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
    std::ostringstream line;
    line << '[' << std::put_time(&local, "%d.%m.%Y %H:%M:%S") << "] "
         << event.sequence << " [" << level_name(event.level) << "] " << event.code << ' ' << event.message << "\r\n";
    const auto text = line.str();
    rotate_file(text.size());
    std::ofstream stream(file_path_, std::ios::binary | std::ios::app);
    if (!stream) throw std::runtime_error("cannot append log file");
    stream.write(text.data(), static_cast<std::streamsize>(text.size()));
    stream.flush();
    if (!stream) throw std::runtime_error("cannot flush log file");
}
}
