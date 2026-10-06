#pragma once

#include "sevenzip_sdk.hpp"

#ifdef _WIN32

#include <vector>

#endif

namespace sunpack::sevenzip
{

#ifdef _WIN32

    // Extraction receives an already analyzed format hint from Python. This
    // selector is deliberately metadata-only and never opens or reads input.
    // Without a recognized hint, it returns the same generic handler order
    // regardless of the input path.
    std::vector<GUID> extraction_formats_for_hint(
        const std::wstring &format_hint);

    // Return the canonical archive type represented by a successfully opened
    // handler GUID, or an empty string when the GUID is not recognized.
    std::wstring canonical_archive_type_for_guid(const GUID &format);

#endif

}
