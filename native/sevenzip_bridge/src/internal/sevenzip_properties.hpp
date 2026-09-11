#pragma once

#include "archive_operations.hpp"

#include "sevenzip_sdk.hpp"

namespace sunpack::sevenzip
{

#ifdef _WIN32

    bool prop_bool(const PROPVARIANT &value);

    UInt64 prop_u64(const PROPVARIANT &value);

    UInt32 prop_u32(const PROPVARIANT &value);

    std::wstring prop_text(const PROPVARIANT &value);

    void clear_prop(PROPVARIANT &value);

    bool get_archive_property_bool(IInArchive *archive, UInt32 prop_id);

    bool get_item_property(IInArchive *archive, UInt32 index, UInt32 prop_id, PROPVARIANT &value);

    bool archive_has_encrypted_items(IInArchive *archive);

    bool fill_resource_analysis_from_open_archive(IInArchive *archive, ResourceAnalysisResult &result);

#endif

} // namespace sunpack::sevenzip
