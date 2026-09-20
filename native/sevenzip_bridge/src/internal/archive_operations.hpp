#pragma once

#include "sevenzip_bridge/bridge.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace sunpack::sevenzip {

using UInt32 = std::uint32_t;
using UInt64 = std::uint64_t;
using Int32 = std::int32_t;

struct ResourceAnalysisResult {
    PasswordTestStatus status = PasswordTestStatus::BackendUnavailable;
    bool is_archive = false;
    bool encrypted = false;
    bool damaged = false;
    bool solid = false;
    UInt32 item_count = 0;
    UInt32 file_count = 0;
    UInt32 dir_count = 0;
    UInt64 archive_size = 0;
    UInt64 total_unpacked_size = 0;
    UInt64 total_packed_size = 0;
    UInt64 largest_item_size = 0;
    UInt64 largest_dictionary_size = 0;
    std::wstring dominant_method;
    std::string message;
};

struct CrcManifestItem {
    std::wstring path;
    UInt64 size = 0;
    UInt32 crc32 = 0;
    bool has_crc = false;
};

struct CrcManifestResult {
    PasswordTestStatus status = PasswordTestStatus::BackendUnavailable;
    bool is_archive = false;
    bool encrypted = false;
    bool damaged = false;
    bool checksum_error = false;
    UInt32 item_count = 0;
    UInt32 file_count = 0;
    std::vector<CrcManifestItem> files;
    std::string message;
};

ResourceAnalysisResult analyze_archive_resources_with_parts(
    const std::wstring& archive_path,
    const std::vector<std::wstring>& part_paths,
    const std::wstring& password
);

CrcManifestResult read_archive_crc_manifest_with_parts(
    const std::wstring& archive_path,
    const std::vector<std::wstring>& part_paths,
    const std::wstring& password,
    UInt32 max_items
);

std::wstring archive_type_for_path(const std::wstring& path);

}  // namespace sunpack::sevenzip
