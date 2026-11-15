#pragma once

#include "sevenzip_sdk.hpp"

#ifdef _WIN32

#include <vector>

#endif

namespace sunpack::sevenzip
{

#ifdef _WIN32

    struct ExtractionFormats
    {
        std::vector<GUID> handlers;
        bool encrypted_headers = false;
    };

    // Map the analyzed Rust hint to a handler order and header probe policy.
    ExtractionFormats extraction_formats_for_hint(
        const std::wstring &format_hint);

    // Return the canonical archive type represented by a successfully opened
    // handler GUID, or an empty string when the GUID is not recognized.
    std::wstring canonical_archive_type_for_guid(const GUID &format);

#endif

}
