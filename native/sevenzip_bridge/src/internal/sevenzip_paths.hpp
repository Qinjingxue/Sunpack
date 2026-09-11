#pragma once

#include "sevenzip_sdk.hpp"

#ifdef _WIN32

#include <optional>

#include <string>

#include <vector>

#endif

namespace sunpack::sevenzip
{

#ifdef _WIN32

    std::wstring lower_text(std::wstring value);

    std::wstring filename_lower(const std::wstring &path);

    bool ends_with(const std::wstring &value, const std::wstring &suffix);

    bool is_sfx_path(const std::wstring &path);

    std::optional<int> parse_volume_number(const std::wstring &path);

    std::vector<std::wstring> unique_existing_paths(const std::wstring &archive_path, const std::vector<std::wstring> &part_paths);

    std::vector<std::wstring> sorted_data_volume_paths(const std::vector<std::wstring> &paths);

    std::wstring lower_extension(const std::wstring &path);

    bool looks_missing_volume(const std::wstring &archive_path, Int32 op_res);

    bool has_numbered_split_head(const std::vector<std::wstring> &part_paths);

    bool has_split_volume_evidence(const std::wstring &archive_path, const std::vector<std::wstring> &part_paths);

    UInt64 file_size_or_zero(const std::wstring &path);

    UInt64 archive_input_size(const std::wstring &archive_path, const std::vector<std::wstring> &part_paths);

#endif

}
