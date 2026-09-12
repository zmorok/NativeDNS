#include <nativedns/logger.hpp>
#include <nativedns/core_api.h>
#include <nativedns/platform.hpp>
#include <iostream>
#include <thread>
#include <stdexcept>
#include <filesystem>
#include <fstream>
#include <cctype>
#include <algorithm>
void check(bool value, const char* message = "foundation assertion failed") { if (!value) throw std::runtime_error(message); }
int main() {
    try {
        check(NativeDns_GetApiVersion() == 1);
        auto config = nd::default_config();
        check(config.rules.size() == 1 && config.rules.back().is_default && config.rules.back().server_id == 0);
        nd::Logger logger(32);
        std::jthread first([&] { for (int i = 0; i < 100; ++i) logger.write(nd::Level::debug, "DEBUG", "test"); });
        std::jthread second([&] { for (int i = 0; i < 100; ++i) logger.write(nd::Level::normal, "INFO", "test"); });
        first.join(); second.join();
        logger.write(nd::Level::errors_only, "TIMEOUT", "line1\nline2");
        auto events = logger.snapshot(nd::Level::debug);
        check(events.size() == 32 && events.back().sequence == 201);
        check(logger.snapshot(nd::Level::errors_only).size() == 1);
        check(events.back().message == "line1 line2");
        logger.clear_display(); check(logger.snapshot(nd::Level::debug).empty());
        logger.write(nd::Level::normal, "INFO", "after clear");
        check(logger.snapshot(nd::Level::normal).back().sequence == 202);
        const auto directory = std::filesystem::current_path() / ("logger-test-" + std::to_string(nd::platform::process_id()));
        std::filesystem::create_directories(directory);
        const auto timestamped = nd::timestamped_log_path(directory).filename().string();
        check(timestamped.size() == 29 && timestamped.starts_with("NativeDNS-") && timestamped.ends_with(".log")
              && timestamped[16] == '-'
              && std::all_of(timestamped.begin() + 10,timestamped.begin() + 16,[](unsigned char c){return std::isdigit(c);})
              && std::all_of(timestamped.begin() + 17,timestamped.begin() + 25,[](unsigned char c){return std::isdigit(c);}),
              "timestamped log file name");
        const auto path = directory / "native.log";
        logger.configure_file(true,nd::Level::normal,path,1024,2);
        logger.write(nd::Level::debug,"DEBUG","must not reach file");
        for (int i = 0; i < 40; ++i) logger.write(nd::Level::normal,"NORMAL",std::string(70,'x'));
        logger.flush_file();
        check(std::filesystem::exists(path) && std::filesystem::exists(path.string() + ".1"),"log rotation");
        {
            std::ifstream stream(path,std::ios::binary); std::string contents((std::istreambuf_iterator<char>(stream)),{});
            check(contents.find("must not reach file") == std::string::npos && contents.find("NORMAL") != std::string::npos,"independent file level");
            check(contents.find("[INFO]") != std::string::npos,"file log contains readable level");
            check(contents.size()>20&&contents[3]=='.'&&contents[6]=='.'&&contents[11]==' '&&contents[14]==':'&&contents[17]==':',"file log date/time format");
        }
        logger.clear_display(); check(std::filesystem::file_size(path) > 0,"display clear does not clear file");
        logger.clear_file(); check(std::filesystem::file_size(path) == 0,"clear file");
        logger.configure_file(false,nd::Level::normal,{});
        std::filesystem::remove(path); std::filesystem::remove(path.string() + ".1"); std::filesystem::remove(path.string() + ".2");

        logger.configure_file(true,nd::Level::normal,nd::timestamped_log_path(directory),1024,2);
        for(int i=0;i<40;++i)logger.write(nd::Level::normal,"TIMESTAMPED",std::string(70,'x'));
        logger.configure_file(false,nd::Level::normal,{});
        size_t timestamped_file_count=0;
        for(const auto& entry:std::filesystem::directory_iterator(directory)){
            const auto name=entry.path().filename().string();
            check(name.size()==29&&name.starts_with("NativeDNS-")&&name.ends_with(".log"),"timestamped rotation file name");
            ++timestamped_file_count;
            std::filesystem::remove(entry.path());
        }
        check(timestamped_file_count==3,"timestamped log retention");
        std::filesystem::remove(directory);
        std::cout << "foundation passed\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
