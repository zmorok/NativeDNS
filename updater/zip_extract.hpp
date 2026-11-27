#pragma once

#include <cstdint>
#include <filesystem>
#include <functional>
#include <string>

namespace nd::updater {

struct ExtractProgress {
    size_t files_done = 0;
    size_t files_total = 0;
    uint64_t bytes_done = 0;
    uint64_t bytes_total = 0;
    std::string current_entry;
};

using ExtractProgressCallback = std::function<void(const ExtractProgress&)>;

uint32_t crc32_bytes(const uint8_t* data, size_t size) noexcept;

void extract_zip_archive(const std::filesystem::path& zip_path,
                         const std::filesystem::path& destination_dir,
                         const ExtractProgressCallback& progress = {});

std::filesystem::path locate_package_root(const std::filesystem::path& extracted_dir);

} // namespace nd::updater
