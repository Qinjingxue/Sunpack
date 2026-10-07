#include "sevenzip_formats.hpp"

#include "lz4_handler.hpp"
#include "sevenzip_bridge/enc.h"
#include "sevenzip_paths.hpp"

#ifdef _WIN32
#include <vector>
#endif

namespace sunpack::sevenzip
{

#ifdef _WIN32

    namespace
    {
        std::wstring normalized_format_hint(const std::wstring &format_hint)
        {
            std::wstring hint = lower_text(format_hint);
            if (!hint.empty() && hint.front() == L'.')
            {
                hint.erase(hint.begin());
            }
            return hint;
        }

        std::vector<unsigned char> known_format_ids_for_hint(const std::wstring &hint)
        {
            if (hint == L"enc") return {kEncFormatId};
            if (hint == L"zip" || hint == L"zipx")
                return {0x01};
            if (hint == L"7z" || hint == L"sevenzip" || hint == L"seven_zip")
                return {0x07};
            if (hint == L"rar4")
                return {0x03, 0xCC};
            if (hint == L"rar5")
                return {0xCC, 0x03};
            if (hint == L"tar")
                return {0xEE};
            if (hint == L"gz" || hint == L"gzip" || hint == L"tar.gz" || hint == L"tgz")
                return {0xEF, 0xEE};
            if (hint == L"bz2" || hint == L"bzip2" || hint == L"tar.bz2" || hint == L"tbz2" || hint == L"tbz")
                return {0x02, 0xEE};
            if (hint == L"xz" || hint == L"tar.xz" || hint == L"txz")
                return {0x0C, 0xEE};
            if (hint == L"lz4" || hint == L"tar.lz4")
                return {0xFA, 0xEE};
            if (hint == L"zst" || hint == L"zstd" || hint == L"tar.zst" || hint == L"tzst")
                return {0x0E, 0xEE};
            return {};
        }

        const std::vector<unsigned char> &generic_format_ids()
        {
            static const std::vector<unsigned char> ids{
                0x07, 0x01, 0xCC, 0x03, 0xEE, 0xEF, 0x02, 0x0C, 0x0E, 0xFA};
            return ids;
        }

        std::vector<GUID> format_guids(const std::vector<unsigned char> &ids)
        {
            std::vector<GUID> formats;
            formats.reserve(ids.size());
            for (const unsigned char id : ids)
            {
                formats.push_back(format_guid(id));
            }
            return formats;
        }
    } // namespace

    std::vector<GUID> extraction_formats_for_hint(const std::wstring &format_hint)
    {
        const std::wstring hint = normalized_format_hint(format_hint);
        std::vector<unsigned char> ids =
            hint == L"rar"
                ? std::vector<unsigned char>{0xCC, 0x03}
                : known_format_ids_for_hint(hint);
        if (ids.empty())
        {
            return format_guids(generic_format_ids());
        }
        return format_guids(ids);
    }

    std::wstring canonical_archive_type_for_guid(const GUID &format)
    {
        switch (format.Data4[5])
        {
        case 0x01: return L"zip";
        case 0x02: return L"bzip2";
        case 0x03: return L"rar4";
        case 0x07: return L"7z";
        case 0x0C: return L"xz";
        case 0x0E: return L"zstd";
        case 0x0F:
        case 0xEF: return L"gzip";
        case 0xCC: return L"rar5";
        case 0xEE: return L"tar";
        case kLz4FormatId: return L"lz4";
        case kEncFormatId: return L"enc";
        default: return L"";
        }
    }

#endif

} // namespace sunpack::sevenzip
