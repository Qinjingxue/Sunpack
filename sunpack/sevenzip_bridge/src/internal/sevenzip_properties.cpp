#include "sevenzip_properties.hpp"

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

    bool get_item_property(IInArchive *archive, UInt32 index, UInt32 prop_id, PROPVARIANT &value)
    {
        value = PROPVARIANT{};
        value.vt = VT_EMPTY;
        return archive->GetProperty(index, prop_id, &value) == S_OK && value.vt != VT_EMPTY;
    }

#endif

} // namespace sunpack::sevenzip
