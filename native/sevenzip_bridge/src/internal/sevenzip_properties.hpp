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

    // RAR4 may return Open=S_OK with zero items after a wrong encrypted-header
    // password. The handler records that failed header parse in kpidErrorFlags.
    // Only inspect this rare outcome; genuinely empty archives have no error.
    inline bool rar4_rejected_empty_encrypted_headers(
        IInArchive *archive, const GUID &format, UInt32 item_count, bool password_requested)
    {
        if (format.Data4[5] != 0x03 || item_count != 0 || !password_requested)
            return false;
        PROPVARIANT flags{};
        const bool invalid = archive->GetArchiveProperty(kpidErrorFlags, &flags) == S_OK &&
                             prop_u32(flags) != 0;
        clear_prop(flags);
        return invalid;
    }

#endif

} // namespace sunpack::sevenzip
