#pragma once

#include "sevenzip_sdk.hpp"

#ifdef _WIN32

#include <vector>

#endif

namespace sunpack::sevenzip
{

#ifdef _WIN32

    std::vector<GUID> candidate_formats(const std::wstring &archive_path, const std::vector<std::wstring> &part_paths = {});

    std::vector<GUID> candidate_formats_for_hint(
        const std::wstring &format_hint,
        const std::wstring &archive_path,
        const std::vector<std::wstring> &part_paths = {},
        const std::wstring &signature_path = L"",
        UInt64 signature_offset = 0);

    // Extraction receives an already analyzed format hint from Python. This
    // selector is deliberately metadata-only and never opens or reads input.
    std::vector<GUID> extraction_formats_for_hint(
        const std::wstring &format_hint,
        const std::wstring &archive_path);

#endif

}