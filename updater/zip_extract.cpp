#include "zip_extract.hpp"

#include <algorithm>
#include <array>
#include <fstream>
#include <limits>
#include <stdexcept>
#include <vector>

namespace nd::updater {
namespace {

constexpr size_t kMaxEntries = 4096;
constexpr uint64_t kMaxTotalUncompressedBytes = 512ULL * 1024ULL * 1024ULL;
constexpr size_t kMaxZipFileBytes = 512ULL * 1024ULL * 1024ULL;

uint16_t read_u16(const uint8_t* p) noexcept {
    return static_cast<uint16_t>(p[0] | (static_cast<uint16_t>(p[1]) << 8));
}

uint32_t read_u32(const uint8_t* p) noexcept {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

uint64_t read_u64(const uint8_t* p) noexcept {
    return static_cast<uint64_t>(read_u32(p)) | (static_cast<uint64_t>(read_u32(p + 4)) << 32);
}

struct BitReader {
    const uint8_t* data = nullptr;
    size_t size = 0;
    size_t pos = 0;
    uint64_t buffer = 0;
    int count = 0;

    void fill(int needed) {
        while (count < needed) {
            if (pos >= size)
                throw std::runtime_error("Unexpected end of compressed stream");
            buffer |= static_cast<uint64_t>(data[pos++]) << count;
            count += 8;
        }
    }

    uint32_t read_bits(int n) {
        if (n == 0)
            return 0;
        fill(n);
        const uint32_t value = static_cast<uint32_t>(buffer & ((1ULL << n) - 1ULL));
        buffer >>= n;
        count -= n;
        return value;
    }

    void align_byte() noexcept {
        const int drop = count & 7;
        buffer >>= drop;
        count -= drop;
    }

    uint8_t read_aligned_byte() {
        if (count >= 8) {
            const uint8_t b = static_cast<uint8_t>(buffer & 0xFFu);
            buffer >>= 8;
            count -= 8;
            return b;
        }
        if (pos >= size)
            throw std::runtime_error("Unexpected end of stored deflate block");
        return data[pos++];
    }

    uint16_t read_aligned_u16() {
        const uint8_t lo = read_aligned_byte();
        const uint8_t hi = read_aligned_byte();
        return static_cast<uint16_t>(lo | (static_cast<uint16_t>(hi) << 8));
    }
};

struct HuffmanTable {
    static constexpr int kMaxBits = 15;
    std::array<int, kMaxBits + 1> count{};
    std::array<int, kMaxBits + 1> first_code{};
    std::array<int, kMaxBits + 1> first_symbol{};
    std::vector<uint16_t> symbols;

    void build(const uint8_t* lengths, size_t num_symbols) {
        count.fill(0);
        for (size_t i = 0; i < num_symbols; ++i) {
            if (lengths[i] > kMaxBits)
                throw std::runtime_error("Invalid Huffman code length");
            if (lengths[i] > 0)
                ++count[lengths[i]];
        }
        int code = 0;
        int index = 0;
        std::array<int, kMaxBits + 1> offsets{};
        for (int len = 1; len <= kMaxBits; ++len) {
            code <<= 1;
            first_code[len] = code;
            first_symbol[len] = index;
            offsets[len] = index;
            code += count[len];
            index += count[len];
            if (code > (1 << len))
                throw std::runtime_error("Oversubscribed Huffman tree");
        }
        symbols.assign(static_cast<size_t>(index), 0);
        for (size_t sym = 0; sym < num_symbols; ++sym) {
            const int len = lengths[sym];
            if (len > 0)
                symbols[static_cast<size_t>(offsets[len]++)] = static_cast<uint16_t>(sym);
        }
    }

    uint16_t decode(BitReader& bits) const {
        int code = 0;
        for (int len = 1; len <= kMaxBits; ++len) {
            code = (code << 1) | static_cast<int>(bits.read_bits(1));
            const int diff = code - first_code[len];
            if (diff >= 0 && diff < count[len])
                return symbols[static_cast<size_t>(first_symbol[len] + diff)];
        }
        throw std::runtime_error("Invalid Huffman code in deflate stream");
    }
};

std::vector<uint8_t>
inflate_deflate(const uint8_t* src, size_t src_size, size_t expected_out_size) {
    static constexpr std::array<uint16_t, 29> kLenBase = {
        3,  4,  5,  6,  7,  8,  9,  10, 11,  13,  15,  17,  19,  23, 27,
        31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258};
    static constexpr std::array<uint8_t, 29> kLenExtra = {
        0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0};
    static constexpr std::array<uint16_t, 30> kDistBase = {
        1,    2,    3,    4,    5,    7,    9,    13,    17,    25,
        33,   49,   65,   97,   129,  193,  257,  385,   513,   769,
        1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577};
    static constexpr std::array<uint8_t, 30> kDistExtra = {
        0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13};
    static constexpr std::array<uint8_t, 19> kCodeLenOrder = {
        16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15};

    BitReader bits{src, src_size, 0, 0, 0};
    std::vector<uint8_t> out;
    out.reserve(expected_out_size);

    bool final_block = false;
    while (!final_block) {
        final_block = bits.read_bits(1) != 0;
        const uint32_t btype = bits.read_bits(2);
        if (btype == 0) {
            bits.align_byte();
            const uint16_t len = bits.read_aligned_u16();
            const uint16_t nlen = bits.read_aligned_u16();
            if (static_cast<uint16_t>(len ^ 0xFFFFu) != nlen)
                throw std::runtime_error("Corrupt stored deflate block length");
            if (out.size() + len > expected_out_size)
                throw std::runtime_error("Inflated entry exceeds declared size");
            for (uint16_t i = 0; i < len; ++i)
                out.push_back(bits.read_aligned_byte());
        } else if (btype == 1 || btype == 2) {
            HuffmanTable litlen_table;
            HuffmanTable dist_table;
            if (btype == 1) {
                std::array<uint8_t, 288> litlen{};
                for (size_t i = 0; i <= 143; ++i)
                    litlen[i] = 8;
                for (size_t i = 144; i <= 255; ++i)
                    litlen[i] = 9;
                for (size_t i = 256; i <= 279; ++i)
                    litlen[i] = 7;
                for (size_t i = 280; i <= 287; ++i)
                    litlen[i] = 8;
                litlen_table.build(litlen.data(), litlen.size());
                std::array<uint8_t, 32> dist{};
                dist.fill(5);
                dist_table.build(dist.data(), dist.size());
            } else {
                const size_t hlit = bits.read_bits(5) + 257;
                const size_t hdist = bits.read_bits(5) + 1;
                const size_t hclen = bits.read_bits(4) + 4;
                if (hlit > 286 || hdist > 30)
                    throw std::runtime_error("Invalid dynamic deflate header");
                std::array<uint8_t, 19> cl_lengths{};
                for (size_t i = 0; i < hclen; ++i)
                    cl_lengths[kCodeLenOrder[i]] = static_cast<uint8_t>(bits.read_bits(3));
                HuffmanTable cl_table;
                cl_table.build(cl_lengths.data(), cl_lengths.size());

                std::vector<uint8_t> lengths(hlit + hdist, 0);
                size_t idx = 0;
                while (idx < lengths.size()) {
                    const uint16_t sym = cl_table.decode(bits);
                    if (sym < 16) {
                        lengths[idx++] = static_cast<uint8_t>(sym);
                    } else if (sym == 16) {
                        if (idx == 0)
                            throw std::runtime_error("Invalid deflate repeat code");
                        const size_t repeat = bits.read_bits(2) + 3;
                        const uint8_t prev = lengths[idx - 1];
                        if (idx + repeat > lengths.size())
                            throw std::runtime_error("Deflate code length overflow");
                        for (size_t r = 0; r < repeat; ++r)
                            lengths[idx++] = prev;
                    } else if (sym == 17) {
                        const size_t repeat = bits.read_bits(3) + 3;
                        if (idx + repeat > lengths.size())
                            throw std::runtime_error("Deflate zero run overflow");
                        idx += repeat;
                    } else if (sym == 18) {
                        const size_t repeat = bits.read_bits(7) + 11;
                        if (idx + repeat > lengths.size())
                            throw std::runtime_error("Deflate long zero run overflow");
                        idx += repeat;
                    } else {
                        throw std::runtime_error("Unknown deflate code length symbol");
                    }
                }
                if (lengths[256] == 0)
                    throw std::runtime_error("Missing end-of-block symbol in deflate tree");
                litlen_table.build(lengths.data(), hlit);
                dist_table.build(lengths.data() + hlit, hdist);
            }

            for (;;) {
                const uint16_t sym = litlen_table.decode(bits);
                if (sym < 256) {
                    if (out.size() + 1 > expected_out_size)
                        throw std::runtime_error("Inflated entry exceeds declared size");
                    out.push_back(static_cast<uint8_t>(sym));
                } else if (sym == 256) {
                    break;
                } else if (sym <= 285) {
                    const size_t len_idx = sym - 257;
                    const size_t length =
                        kLenBase[len_idx] + bits.read_bits(kLenExtra[len_idx]);
                    const uint16_t dist_sym = dist_table.decode(bits);
                    if (dist_sym >= 30)
                        throw std::runtime_error("Invalid deflate distance symbol");
                    const size_t distance =
                        kDistBase[dist_sym] + bits.read_bits(kDistExtra[dist_sym]);
                    if (distance == 0 || distance > out.size())
                        throw std::runtime_error("Invalid deflate back-reference distance");
                    if (out.size() + length > expected_out_size)
                        throw std::runtime_error("Inflated entry exceeds declared size");
                    for (size_t i = 0; i < length; ++i)
                        out.push_back(out[out.size() - distance]);
                } else {
                    throw std::runtime_error("Invalid deflate literal/length symbol");
                }
            }
        } else {
            throw std::runtime_error("Invalid deflate block type");
        }
    }
    return out;
}

std::filesystem::path safe_relative_entry_path(const std::string& raw_name) {
    if (raw_name.empty())
        throw std::runtime_error("Archive contains an empty path");
    for (const char ch : raw_name) {
        if (static_cast<unsigned char>(ch) < 32)
            throw std::runtime_error("Archive entry contains control characters");
    }
    std::string normalized = raw_name;
    std::replace(normalized.begin(), normalized.end(), '\\', '/');
    if (normalized.front() == '/' || normalized.find(':') != std::string::npos)
        throw std::runtime_error("Archive entry uses an absolute or drive-qualified path: " +
                                 raw_name);
    std::filesystem::path result;
    size_t start = 0;
    while (start < normalized.size()) {
        const size_t slash = normalized.find('/', start);
        const std::string part =
            slash == std::string::npos ? normalized.substr(start) : normalized.substr(start, slash - start);
        start = slash == std::string::npos ? normalized.size() : slash + 1;
        if (part.empty() || part == ".")
            continue;
        if (part == "..")
            throw std::runtime_error("Archive entry attempts path traversal: " + raw_name);
        result /= std::filesystem::path(
            std::u8string_view(reinterpret_cast<const char8_t*>(part.data()), part.size()));
    }
    return result;
}

struct ZipEntry {
    std::string raw_name;
    std::filesystem::path relative_path;
    bool is_directory = false;
    uint16_t method = 0;
    uint32_t crc = 0;
    uint64_t compressed_size = 0;
    uint64_t uncompressed_size = 0;
    uint64_t local_header_offset = 0;
};

} // namespace

uint32_t crc32_bytes(const uint8_t* data, size_t size) noexcept {
    static const auto table = [] {
        std::array<uint32_t, 256> t{};
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t c = i;
            for (int k = 0; k < 8; ++k)
                c = (c & 1u) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
            t[i] = c;
        }
        return t;
    }();
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < size; ++i)
        crc = table[(crc ^ data[i]) & 0xFFu] ^ (crc >> 8);
    return ~crc;
}

void extract_zip_archive(const std::filesystem::path& zip_path,
                         const std::filesystem::path& destination_dir,
                         const ExtractProgressCallback& progress) {
    std::error_code ec;
    const auto file_size = std::filesystem::file_size(zip_path, ec);
    if (ec || file_size < 22 || file_size > kMaxZipFileBytes)
        throw std::runtime_error("ZIP archive is missing, truncated, or exceeds size limit");

    std::ifstream file(zip_path, std::ios::binary);
    if (!file)
        throw std::runtime_error("Cannot open ZIP archive");
    std::vector<uint8_t> bytes(static_cast<size_t>(file_size));
    if (!file.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size())))
        throw std::runtime_error("Cannot read ZIP archive");

    // Locate End of Central Directory record (signature 0x06054b50).
    const size_t min_eocd = bytes.size() > 65557 ? bytes.size() - 65557 : 0;
    size_t eocd_pos = std::string::npos;
    for (size_t pos = bytes.size() - 22;; --pos) {
        if (read_u32(bytes.data() + pos) == 0x06054B50u) {
            const uint16_t comment_len = read_u16(bytes.data() + pos + 20);
            if (pos + 22 + comment_len == bytes.size()) {
                eocd_pos = pos;
                break;
            }
        }
        if (pos == min_eocd)
            break;
    }
    if (eocd_pos == std::string::npos)
        throw std::runtime_error("Invalid ZIP archive: End of Central Directory not found");

    const uint16_t disk_number = read_u16(bytes.data() + eocd_pos + 4);
    const uint16_t cd_disk = read_u16(bytes.data() + eocd_pos + 6);
    if (disk_number != 0 || cd_disk != 0)
        throw std::runtime_error("Multi-disk ZIP archives are not supported");

    const uint64_t total_entries = read_u16(bytes.data() + eocd_pos + 10);
    const uint64_t cd_size = read_u32(bytes.data() + eocd_pos + 12);
    const uint64_t cd_offset = read_u32(bytes.data() + eocd_pos + 16);
    if (total_entries > kMaxEntries)
        throw std::runtime_error("ZIP archive exceeds maximum entry limit");
    if (cd_offset > bytes.size() || cd_size > bytes.size() - cd_offset)
        throw std::runtime_error("Corrupt ZIP central directory bounds");

    std::vector<ZipEntry> entries;
    entries.reserve(static_cast<size_t>(total_entries));
    uint64_t total_uncompressed = 0;
    size_t cursor = static_cast<size_t>(cd_offset);
    const size_t cd_end = static_cast<size_t>(cd_offset + cd_size);
    for (uint64_t i = 0; i < total_entries; ++i) {
        if (cursor + 46 > cd_end || read_u32(bytes.data() + cursor) != 0x02014B50u)
            throw std::runtime_error("Corrupt ZIP central directory entry");
        const uint16_t version_made = read_u16(bytes.data() + cursor + 4);
        const uint16_t flags = read_u16(bytes.data() + cursor + 8);
        const uint16_t method = read_u16(bytes.data() + cursor + 10);
        const uint32_t crc = read_u32(bytes.data() + cursor + 16);
        uint64_t comp_size = read_u32(bytes.data() + cursor + 20);
        uint64_t uncomp_size = read_u32(bytes.data() + cursor + 24);
        const uint16_t name_len = read_u16(bytes.data() + cursor + 28);
        const uint16_t extra_len = read_u16(bytes.data() + cursor + 30);
        const uint16_t comment_len = read_u16(bytes.data() + cursor + 32);
        const uint32_t external_attr = read_u32(bytes.data() + cursor + 38);
        uint64_t local_offset = read_u32(bytes.data() + cursor + 42);
        if (cursor + 46 + name_len + extra_len + comment_len > cd_end)
            throw std::runtime_error("Truncated ZIP central directory metadata");
        if ((flags & 0x0001u) != 0)
            throw std::runtime_error("Encrypted ZIP entries are not supported");
        if (((version_made >> 8) == 3) && (((external_attr >> 16) & 0xF000u) == 0xA000u))
            throw std::runtime_error("Symlink entries in ZIP archives are not allowed");

        const std::string raw_name(
            reinterpret_cast<const char*>(bytes.data() + cursor + 46), name_len);

        // Parse ZIP64 extended information if needed.
        size_t ex_pos = cursor + 46 + name_len;
        const size_t ex_end = ex_pos + extra_len;
        while (ex_pos + 4 <= ex_end) {
            const uint16_t ex_id = read_u16(bytes.data() + ex_pos);
            const uint16_t ex_sz = read_u16(bytes.data() + ex_pos + 2);
            ex_pos += 4;
            if (ex_pos + ex_sz > ex_end)
                break;
            if (ex_id == 0x0001u) {
                size_t p = ex_pos;
                if (uncomp_size == 0xFFFFFFFFu && p + 8 <= ex_pos + ex_sz) {
                    uncomp_size = read_u64(bytes.data() + p);
                    p += 8;
                }
                if (comp_size == 0xFFFFFFFFu && p + 8 <= ex_pos + ex_sz) {
                    comp_size = read_u64(bytes.data() + p);
                    p += 8;
                }
                if (local_offset == 0xFFFFFFFFu && p + 8 <= ex_pos + ex_sz) {
                    local_offset = read_u64(bytes.data() + p);
                    p += 8;
                }
            }
            ex_pos += ex_sz;
        }
        cursor += 46 + name_len + extra_len + comment_len;

        const bool is_dir = !raw_name.empty() && (raw_name.back() == '/' || raw_name.back() == '\\');
        const auto rel = safe_relative_entry_path(raw_name);
        if (rel.empty() && !is_dir)
            throw std::runtime_error("Invalid ZIP entry path");
        if (!is_dir) {
            if (method != 0 && method != 8)
                throw std::runtime_error("Unsupported ZIP compression method " +
                                         std::to_string(method));
            if (uncomp_size > kMaxTotalUncompressedBytes - total_uncompressed)
                throw std::runtime_error("ZIP archive uncompressed size exceeds safety limit");
            total_uncompressed += uncomp_size;
        }
        entries.push_back({raw_name, rel, is_dir, method, crc, comp_size, uncomp_size, local_offset});
    }

    std::filesystem::create_directories(destination_dir);
    size_t files_total = 0;
    for (const auto& entry : entries)
        if (!entry.is_directory)
            ++files_total;

    size_t files_done = 0;
    uint64_t bytes_done = 0;
    for (const auto& entry : entries) {
        if (entry.is_directory) {
            if (!entry.relative_path.empty())
                std::filesystem::create_directories(destination_dir / entry.relative_path);
            continue;
        }
        if (entry.local_header_offset + 30 > bytes.size() ||
            read_u32(bytes.data() + entry.local_header_offset) != 0x04034B50u)
            throw std::runtime_error("Corrupt ZIP local file header for " + entry.raw_name);
        const uint16_t local_name_len = read_u16(bytes.data() + entry.local_header_offset + 26);
        const uint16_t local_extra_len = read_u16(bytes.data() + entry.local_header_offset + 28);
        const uint64_t data_offset = entry.local_header_offset + 30 + local_name_len + local_extra_len;
        if (data_offset > bytes.size() || entry.compressed_size > bytes.size() - data_offset)
            throw std::runtime_error("Truncated ZIP entry data for " + entry.raw_name);

        const uint8_t* comp_ptr = bytes.data() + data_offset;
        std::vector<uint8_t> content;
        if (entry.method == 0) {
            if (entry.compressed_size != entry.uncompressed_size)
                throw std::runtime_error("Stored ZIP entry size mismatch for " + entry.raw_name);
            content.assign(comp_ptr, comp_ptr + static_cast<size_t>(entry.compressed_size));
        } else {
            content = inflate_deflate(comp_ptr,
                                      static_cast<size_t>(entry.compressed_size),
                                      static_cast<size_t>(entry.uncompressed_size));
            if (content.size() != entry.uncompressed_size)
                throw std::runtime_error("Inflated ZIP entry size mismatch for " + entry.raw_name);
        }
        if (crc32_bytes(content.data(), content.size()) != entry.crc)
            throw std::runtime_error("CRC-32 mismatch for " + entry.raw_name);

        const auto target = destination_dir / entry.relative_path;
        if (target.has_parent_path())
            std::filesystem::create_directories(target.parent_path());
        std::ofstream out(target, std::ios::binary | std::ios::trunc);
        if (!out)
            throw std::runtime_error("Cannot create extracted file: " + entry.raw_name);
        if (!content.empty() &&
            !out.write(reinterpret_cast<const char*>(content.data()),
                       static_cast<std::streamsize>(content.size())))
            throw std::runtime_error("Cannot write extracted file: " + entry.raw_name);
        out.close();

        ++files_done;
        bytes_done += entry.uncompressed_size;
        if (progress)
            progress({files_done, files_total, bytes_done, total_uncompressed, entry.raw_name});
    }
}

std::filesystem::path locate_package_root(const std::filesystem::path& extracted_dir) {
    std::error_code ec;
    if (std::filesystem::is_regular_file(extracted_dir / L"NativeDNS.exe", ec))
        return extracted_dir;
    std::vector<std::filesystem::path> dirs;
    for (const auto& entry : std::filesystem::directory_iterator(extracted_dir, ec)) {
        if (entry.is_directory(ec))
            dirs.push_back(entry.path());
    }
    if (dirs.size() == 1 && std::filesystem::is_regular_file(dirs.front() / L"NativeDNS.exe", ec))
        return dirs.front();
    throw std::runtime_error("Update archive does not contain a valid NativeDNS package");
}

} // namespace nd::updater
