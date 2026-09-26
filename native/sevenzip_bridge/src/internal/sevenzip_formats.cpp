#include "sevenzip_formats.hpp"

#include "sevenzip_paths.hpp"

#ifdef _WIN32
#include <algorithm>
#include <cwctype>
#include <filesystem>
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
            if (hint == L"zip")
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
            if (hint == L"zst" || hint == L"zstd" || hint == L"tar.zst" || hint == L"tzst")
                return {0x0E, 0xEE};
            return {};
        }

        std::vector<unsigned char> metadata_format_ids_for_path(const std::wstring &archive_path)
        {
            const std::wstring ext = lower_extension(archive_path);
            std::wstring name = std::filesystem::path(archive_path).filename().wstring();
            std::transform(name.begin(), name.end(), name.begin(), [](wchar_t ch)
                           { return static_cast<wchar_t>(::towlower(ch)); });

            if (ext == L".zip" || ext == L".jar" || ext == L".docx" || ext == L".xlsx" || ext == L".apk")
                return {0x01};
            if (name.size() >= 8 && name.compare(name.size() - 8, 8, L".zip.001") == 0)
                return {0x01, 0x07};
            if (name.size() >= 7 && name.compare(name.size() - 7, 7, L".7z.001") == 0)
                return {0x07, 0x01};
            if (ext == L".7z")
                return {0x07};
            if (ext == L".rar" || ext == L".r00")
                return {0xCC, 0x03};
            if (ext == L".tar")
                return {0xEE};
            if (ext == L".gz" || ext == L".tgz")
                return {0xEF, 0xEE};
            if (ext == L".bz2" || ext == L".tbz2" || ext == L".tbz")
                return {0x02, 0xEE};
            if (ext == L".xz" || ext == L".txz")
                return {0x0C, 0xEE};
            if (ext == L".zst" || ext == L".tzst")
                return {0x0E, 0xEE};
            if (ext == L".001")
                return {0x07, 0x01, 0xCC, 0x03};
            return {0x07, 0x01, 0xCC, 0x03, 0xEE, 0xEF, 0x02, 0x0C, 0x0E};
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

    std::vector<GUID> extraction_formats_for_hint(
        const std::wstring &format_hint,
        const std::wstring &archive_path)
    {
        const std::wstring hint = normalized_format_hint(format_hint);
        std::vector<unsigned char> ids =
            hint == L"rar"
                ? std::vector<unsigned char>{0xCC, 0x03}
                : known_format_ids_for_hint(hint);
        if (ids.empty())
        {
            ids = metadata_format_ids_for_path(archive_path);
        }
        return format_guids(ids);
    }

    std::wstring archive_type_for_path(const std::wstring &path)
    {
        const std::wstring ext = lower_extension(path);
        if (ext == L".zip" || ext == L".jar" || ext == L".docx" || ext == L".xlsx" || ext == L".apk")
        {
            return L"zip";
        }
        if (ext == L".7z" || ext == L".001")
        {
            return L"7z";
        }
        if (ext == L".rar" || ext == L".r00")
        {
            return L"rar";
        }
        if (ext == L".exe" || ext == L".dll")
        {
            return L"pe";
        }
        if (ext == L".tar")
        {
            return L"tar";
        }
        if (ext == L".gz" || ext == L".tgz")
        {
            return L"gzip";
        }
        if (ext == L".bz2" || ext == L".tbz" || ext == L".tbz2")
        {
            return L"bzip2";
        }
        if (ext == L".xz" || ext == L".txz")
        {
            return L"xz";
        }
        return L"";
    }

#endif

} // namespace sunpack::sevenzip