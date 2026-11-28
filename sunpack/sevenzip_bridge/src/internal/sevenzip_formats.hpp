#pragma once

#include "sevenzip_sdk.hpp"

#ifdef _WIN32

#include <string_view>

#endif

namespace sunpack::sevenzip
{

#ifdef _WIN32

    struct ExtractionFormats
    {
        const unsigned char *ids;
        std::size_t count;
        bool encrypted_headers;

        GUID operator[](std::size_t index) const noexcept { return format_guid(ids[index]); }
    };

    // Map the analyzed Rust hint to a handler order and header probe policy.
    ExtractionFormats extraction_formats_for_hint(
        std::wstring_view format_hint) noexcept;

    // Return the canonical archive type represented by a successfully opened
    // handler GUID, or an empty string when the GUID is not recognized.
    std::wstring canonical_archive_type_for_guid(const GUID &format);

#endif

}
