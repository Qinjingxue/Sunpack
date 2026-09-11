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

    std::wstring split_volume_family(const std::vector<std::wstring> &part_paths)
    {
        for (const auto &path : sorted_data_volume_paths(part_paths))
        {
            const std::wstring name = filename_lower(path);
            if (name.find(L".zip.") != std::wstring::npos)
            {
                return L"zip";
            }
            if (name.size() >= 4 && name[name.size() - 4] == L'.' && name[name.size() - 3] == L'z' &&
                iswdigit(name[name.size() - 2]) && iswdigit(name[name.size() - 1]))
            {
                return L"zip";
            }
            if (name.find(L".7z.") != std::wstring::npos)
            {
                return L"7z";
            }
            if (name.find(L".rar.") != std::wstring::npos || name.find(L".part") != std::wstring::npos || ends_with(name, L".r00"))
            {
                return L"rar";
            }
        }
        return L"";
    }

    std::vector<unsigned char> format_ids_for_signature(const std::wstring &archive_path, bool scan_prefix = false)
    {
        HANDLE handle = CreateFileW(win32_extended_path(archive_path).c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                    nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (handle == INVALID_HANDLE_VALUE)
        {
            return {};
        }

        const DWORD bytes_to_read = scan_prefix ? 1024 * 1024 : 8;
        std::vector<unsigned char> buffer(bytes_to_read);
        DWORD read = 0;
        const BOOL ok = ReadFile(handle, buffer.data(), bytes_to_read, &read, nullptr);
        CloseHandle(handle);
        if (!ok || read == 0)
        {
            return {};
        }
        buffer.resize(read);

        const unsigned char rar4[] = {'R', 'a', 'r', '!', 0x1A, 0x07, 0x00};
        const unsigned char rar5[] = {'R', 'a', 'r', '!', 0x1A, 0x07, 0x01, 0x00};
        const unsigned char seven_zip[] = {'7', 'z', 0xBC, 0xAF, 0x27, 0x1C};
        const unsigned char zip[] = {'P', 'K', 0x03, 0x04};
        const unsigned char gzip[] = {0x1F, 0x8B};
        const unsigned char bzip2[] = {'B', 'Z', 'h'};
        const unsigned char xz[] = {0xFD, '7', 'z', 'X', 'Z', 0x00};
        const unsigned char zstd[] = {0x28, 0xB5, 0x2F, 0xFD};

        const std::size_t search_limit = scan_prefix ? buffer.size() : 1;
        for (std::size_t offset = 0; offset < search_limit; ++offset)
        {
            const std::size_t remaining = buffer.size() - offset;
            const unsigned char *cursor = buffer.data() + offset;
            if (remaining >= sizeof(rar5) && std::equal(std::begin(rar5), std::end(rar5), cursor))
            {
                return {0xCC};
            }
            if (remaining >= sizeof(rar4) && std::equal(std::begin(rar4), std::end(rar4), cursor))
            {
                return {0x03};
            }
            if (remaining >= sizeof(seven_zip) && std::equal(std::begin(seven_zip), std::end(seven_zip), cursor))
            {
                return {0x07};
            }
            if (remaining >= sizeof(zip) && std::equal(std::begin(zip), std::end(zip), cursor))
            {
                return {0x01};
            }
            if (remaining >= sizeof(xz) && std::equal(std::begin(xz), std::end(xz), cursor))
            {
                return {0x0C};
            }
            if (remaining >= sizeof(zstd) && std::equal(std::begin(zstd), std::end(zstd), cursor))
            {
                return {0x0E};
            }
            if (remaining >= sizeof(bzip2) && std::equal(std::begin(bzip2), std::end(bzip2), cursor))
            {
                return {0x02};
            }
            if (remaining >= sizeof(gzip) && std::equal(std::begin(gzip), std::end(gzip), cursor))
            {
                return {0x0F};
            }
        }
        return {};
    }

    std::vector<unsigned char> rar_format_ids_for_paths(
        const std::wstring &archive_path,
        const std::vector<std::wstring> &part_paths,
        bool scan_prefix = false)
    {
        std::vector<std::wstring> candidates = unique_existing_paths(archive_path, part_paths);
        std::vector<std::wstring> volumes = sorted_data_volume_paths(candidates);
        candidates.insert(candidates.end(), volumes.begin(), volumes.end());
        for (const auto &path : candidates)
        {
            const auto ids = format_ids_for_signature(path, scan_prefix || is_sfx_path(path));
            if (ids == std::vector<unsigned char>{0xCC} || ids == std::vector<unsigned char>{0x03})
            {
                return ids;
            }
        }
        return {0xCC, 0x03};
    }

    std::vector<GUID> candidate_formats(const std::wstring &archive_path, const std::vector<std::wstring> &part_paths)
    {
        const std::wstring ext = lower_extension(archive_path);
        std::wstring name = std::filesystem::path(archive_path).filename().wstring();
        std::transform(name.begin(), name.end(), name.begin(), [](wchar_t ch)
                       { return static_cast<wchar_t>(::towlower(ch)); });
        const std::wstring split_family = split_volume_family(part_paths);
        std::vector<unsigned char> ids;
        if (is_sfx_path(archive_path) && split_family == L"zip")
        {
            ids = {0x01};
        }
        else if (is_sfx_path(archive_path) && split_family == L"7z")
        {
            ids = {0x07};
        }
        else if (is_sfx_path(archive_path) && split_family == L"rar")
        {
            ids = rar_format_ids_for_paths(archive_path, part_paths, true);
        }
        else if (ext == L".zip" || ext == L".jar" || ext == L".docx" || ext == L".xlsx" || ext == L".apk")
        {
            ids = {0x01};
        }
        else if (split_family == L"zip")
        {
            ids = {0x01};
        }
        else if (name.size() >= 8 && name.compare(name.size() - 8, 8, L".zip.001") == 0)
        {
            ids = {0x01, 0x07};
        }
        else if (name.size() >= 7 && name.compare(name.size() - 7, 7, L".7z.001") == 0)
        {
            ids = {0x07, 0x01};
        }
        else if (ext == L".7z")
        {
            ids = {0x07};
        }
        else if (ext == L".tar")
        {
            ids = {0xEE};
        }
        else if (ext == L".gz" || ext == L".tgz")
        {
            ids = {0xEF, 0xEE};
        }
        else if (ext == L".bz2" || ext == L".tbz2" || ext == L".tbz")
        {
            ids = {0x02, 0xEE};
        }
        else if (ext == L".xz" || ext == L".txz")
        {
            ids = {0x0C, 0xEE};
        }
        else if (ext == L".zst" || ext == L".tzst")
        {
            ids = {0x0E, 0xEE};
        }
        else if (ext == L".001")
        {
            ids = format_ids_for_signature(archive_path);
            if (ids.empty())
            {
                ids = {0x07};
            }
        }
        else if (ext == L".rar" || ext == L".r00")
        {
            ids = rar_format_ids_for_paths(archive_path, part_paths);
        }
        else
        {
            ids = format_ids_for_signature(archive_path, is_sfx_path(archive_path));
            if (ids.empty())
            {
                ids = {0x07, 0x01, 0x03, 0xCC, 0xEE, 0xEF, 0x02, 0x0C, 0x0E};
            }
        }

        std::vector<GUID> formats;
        for (const unsigned char id : ids)
        {
            formats.push_back(format_guid(id));
        }
        return formats;
    }

    std::vector<GUID> candidate_formats_for_hint(const std::wstring &format_hint, const std::wstring &archive_path, const std::vector<std::wstring> &part_paths)
    {
        std::wstring hint = lower_text(format_hint);
        if (!hint.empty() && hint.front() == L'.')
        {
            hint.erase(hint.begin());
        }
        std::vector<unsigned char> ids;
        if (hint == L"zip")
        {
            ids = {0x01};
        }
        else if (hint == L"7z" || hint == L"sevenzip" || hint == L"seven_zip")
        {
            ids = {0x07};
        }
        else if (hint == L"rar" || hint == L"rar4")
        {
            ids = {0x03, 0xCC};
        }
        else if (hint == L"rar5")
        {
            ids = {0xCC, 0x03};
        }
        else if (hint == L"tar")
        {
            ids = {0xEE};
        }
        else if (hint == L"gz" || hint == L"gzip" || hint == L"tar.gz" || hint == L"tgz")
        {
            ids = {0xEF, 0xEE};
        }
        else if (hint == L"bz2" || hint == L"bzip2" || hint == L"tar.bz2" || hint == L"tbz2" || hint == L"tbz")
        {
            ids = {0x02, 0xEE};
        }
        else if (hint == L"xz" || hint == L"tar.xz" || hint == L"txz")
        {
            ids = {0x0C, 0xEE};
        }
        else if (hint == L"zst" || hint == L"zstd" || hint == L"tar.zst" || hint == L"tzst")
        {
            ids = {0x0E, 0xEE};
        }
        if (ids.empty())
        {
            return candidate_formats(archive_path, part_paths);
        }
        std::vector<GUID> formats;
        for (const unsigned char id : ids)
        {
            formats.push_back(format_guid(id));
        }
        return formats;
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
