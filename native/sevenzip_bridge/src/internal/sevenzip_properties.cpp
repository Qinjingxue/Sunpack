#include "sevenzip_properties.hpp"

#ifdef _WIN32
#include <algorithm>
#include <map>
#endif

namespace sunpack::sevenzip
{

#ifdef _WIN32

    bool prop_bool(const PROPVARIANT &value)
    {
        if (value.vt == VT_BOOL)
        {
            return value.boolVal != VARIANT_FALSE;
        }
        if (value.vt == VT_UI1)
        {
            return value.bVal != 0;
        }
        if (value.vt == VT_I4)
        {
            return value.lVal != 0;
        }
        if (value.vt == VT_UI4)
        {
            return value.ulVal != 0;
        }
        return false;
    }

    UInt64 prop_u64(const PROPVARIANT &value)
    {
        switch (value.vt)
        {
        case VT_UI8:
            return value.uhVal.QuadPart;
        case VT_I8:
            return static_cast<UInt64>(value.hVal.QuadPart);
        case VT_UI4:
            return value.ulVal;
        case VT_I4:
            return static_cast<UInt64>(value.lVal);
        case VT_UI2:
            return value.uiVal;
        case VT_I2:
            return static_cast<UInt64>(value.iVal);
        case VT_UI1:
            return value.bVal;
        default:
            return 0;
        }
    }

    UInt32 prop_u32(const PROPVARIANT &value)
    {
        return static_cast<UInt32>(prop_u64(value) & 0xFFFFFFFFu);
    }

    std::wstring prop_text(const PROPVARIANT &value)
    {
        if (value.vt == VT_BSTR && value.bstrVal)
        {
            return std::wstring(value.bstrVal, SysStringLen(value.bstrVal));
        }
        return L"";
    }

    void clear_prop(PROPVARIANT &value)
    {
        if (value.vt == VT_BSTR && value.bstrVal)
        {
            SysFreeString(value.bstrVal);
        }
        value.vt = VT_EMPTY;
    }

    bool get_archive_property_bool(IInArchive *archive, UInt32 prop_id)
    {
        PROPVARIANT value{};
        value.vt = VT_EMPTY;
        if (archive->GetArchiveProperty(prop_id, &value) != S_OK)
        {
            return false;
        }
        const bool result = prop_bool(value);
        clear_prop(value);
        return result;
    }

    bool get_item_property(IInArchive *archive, UInt32 index, UInt32 prop_id, PROPVARIANT &value)
    {
        value = PROPVARIANT{};
        value.vt = VT_EMPTY;
        return archive->GetProperty(index, prop_id, &value) == S_OK && value.vt != VT_EMPTY;
    }

    bool archive_has_encrypted_items(IInArchive *archive)
    {
        UInt32 num_items = 0;
        if (!archive || archive->GetNumberOfItems(&num_items) != S_OK)
        {
            return false;
        }
        for (UInt32 index = 0; index < num_items; ++index)
        {
            PROPVARIANT value{};
            if (get_item_property(archive, index, kpidEncrypted, value))
            {
                const bool encrypted = prop_bool(value);
                clear_prop(value);
                if (encrypted)
                {
                    return true;
                }
            }
            else
            {
                clear_prop(value);
            }
        }
        return false;
    }

    bool fill_resource_analysis_from_open_archive(IInArchive *archive, ResourceAnalysisResult &result)
    {
        result.is_archive = true;
        result.solid = get_archive_property_bool(archive, kpidSolid);
        UInt32 num_items = 0;
        if (archive->GetNumberOfItems(&num_items) != S_OK)
        {
            result.status = PasswordTestStatus::Error;
            result.message = "archive item list could not be read";
            return false;
        }

        std::map<std::wstring, UInt64> method_sizes;
        for (UInt32 index = 0; index < num_items; ++index)
        {
            PROPVARIANT value{};
            const bool is_dir = get_item_property(archive, index, kpidIsDir, value) ? prop_bool(value) : false;
            clear_prop(value);

            UInt64 unpacked_size = 0;
            if (get_item_property(archive, index, kpidSize, value))
            {
                unpacked_size = prop_u64(value);
            }
            clear_prop(value);

            UInt64 packed_size = 0;
            if (get_item_property(archive, index, kpidPackSize, value))
            {
                packed_size = prop_u64(value);
            }
            clear_prop(value);

            UInt64 dictionary_size = 0;
            if (get_item_property(archive, index, kpidDictionarySize, value))
            {
                dictionary_size = prop_u64(value);
            }
            clear_prop(value);

            bool encrypted = false;
            if (get_item_property(archive, index, kpidEncrypted, value))
            {
                encrypted = prop_bool(value);
            }
            clear_prop(value);
            result.encrypted = result.encrypted || encrypted;

            std::wstring method;
            if (get_item_property(archive, index, kpidMethod, value))
            {
                method = prop_text(value);
            }
            clear_prop(value);

            result.item_count += 1;
            if (is_dir)
            {
                result.dir_count += 1;
                continue;
            }
            result.file_count += 1;
            result.total_unpacked_size += unpacked_size;
            result.total_packed_size += packed_size;
            result.largest_item_size = std::max(result.largest_item_size, unpacked_size);
            result.largest_dictionary_size = std::max(result.largest_dictionary_size, dictionary_size);
            if (!method.empty())
            {
                method_sizes[method] += unpacked_size ? unpacked_size : 1;
            }
        }

        if (result.total_packed_size == 0)
        {
            result.total_packed_size = result.archive_size;
        }
        UInt64 best_size = 0;
        for (const auto &item : method_sizes)
        {
            if (item.second > best_size)
            {
                best_size = item.second;
                result.dominant_method = item.first;
            }
        }
        result.status = PasswordTestStatus::Ok;
        result.message = "archive resources analyzed";
        return true;
    }

#endif

} // namespace sunpack::sevenzip
