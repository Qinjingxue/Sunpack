#include "sevenzip_bridge/bridge.hpp"

#ifdef _WIN32

#include <algorithm>
#include <cwchar>
#include <filesystem>
#include <string>
#include <vector>

namespace
{

    std::wstring lower_extension(const std::wstring &path)
    {
        std::wstring ext = std::filesystem::path(path).extension().wstring();
        std::transform(ext.begin(), ext.end(), ext.begin(), [](wchar_t ch)
                       { return static_cast<wchar_t>(::towlower(ch)); });
        return ext;
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

    void copy_text(wchar_t *destination, int destination_chars, const std::wstring &text)
    {
        if (!destination || destination_chars <= 0)
        {
            return;
        }
        const int count = static_cast<int>(std::min<std::size_t>(text.size(), static_cast<std::size_t>(destination_chars - 1)));
        std::wmemcpy(destination, text.c_str(), count);
        destination[count] = L'\0';
    }

    void copy_ascii(wchar_t *destination, int destination_chars, const std::string &text)
    {
        copy_text(destination, destination_chars, std::wstring(text.begin(), text.end()));
    }

    std::vector<std::wstring> collect_part_paths(
        const wchar_t *archive_path,
        const wchar_t *const *part_paths,
        int part_count)
    {
        std::vector<std::wstring> parts;
        if (part_paths && part_count > 0)
        {
            for (int i = 0; i < part_count; ++i)
            {
                if (part_paths[i] && part_paths[i][0] != L'\0')
                {
                    parts.emplace_back(part_paths[i]);
                }
            }
        }
        if (parts.empty() && archive_path)
        {
            parts.emplace_back(archive_path);
        }
        return parts;
    }

} // namespace

SUP7Z_API int sup7z_test_archive(
    const wchar_t *seven_zip_dll_path,
    const wchar_t *archive_path,
    const wchar_t *password,
    int *command_ok,
    int *encrypted,
    int *checksum_error,
    wchar_t *archive_type,
    int archive_type_chars,
    wchar_t *message,
    int message_chars)
{
    if (command_ok)
    {
        *command_ok = 0;
    }
    if (encrypted)
    {
        *encrypted = 0;
    }
    if (checksum_error)
    {
        *checksum_error = 0;
    }
    if (!seven_zip_dll_path || !archive_path)
    {
        copy_ascii(message, message_chars, "missing required path");
        return static_cast<int>(sunpack::sevenzip::PasswordTestStatus::Error);
    }

    const std::wstring archive_path_text(archive_path);

    const auto result = sunpack::sevenzip::test_password(
        seven_zip_dll_path,
        archive_path_text,
        password ? password : L"");
    copy_text(
        archive_type,
        archive_type_chars,
        result.archive_type.empty() ? archive_type_for_path(archive_path_text) : result.archive_type);
    if (command_ok)
    {
        *command_ok = result.status == sunpack::sevenzip::PasswordTestStatus::Ok ? 1 : 0;
    }
    if (encrypted)
    {
        *encrypted = result.status == sunpack::sevenzip::PasswordTestStatus::WrongPassword ? 1 : 0;
    }
    if (checksum_error)
    {
        *checksum_error = result.status == sunpack::sevenzip::PasswordTestStatus::Damaged ? 1 : 0;
    }
    copy_ascii(message, message_chars, result.message);
    return static_cast<int>(result.status);
}

SUP7Z_API int sup7z_test_archive_with_parts(
    const wchar_t *seven_zip_dll_path,
    const wchar_t *archive_path,
    const wchar_t *const *part_paths,
    int part_count,
    const wchar_t *password,
    int *command_ok,
    int *encrypted,
    int *checksum_error,
    wchar_t *archive_type,
    int archive_type_chars,
    wchar_t *message,
    int message_chars)
{
    if (command_ok)
    {
        *command_ok = 0;
    }
    if (encrypted)
    {
        *encrypted = 0;
    }
    if (checksum_error)
    {
        *checksum_error = 0;
    }
    if (!seven_zip_dll_path || !archive_path)
    {
        copy_ascii(message, message_chars, "missing required path");
        return static_cast<int>(sunpack::sevenzip::PasswordTestStatus::Error);
    }

    const std::wstring archive_path_text(archive_path);

    const auto result = sunpack::sevenzip::test_password_with_parts(
        seven_zip_dll_path,
        archive_path_text,
        collect_part_paths(archive_path, part_paths, part_count),
        password ? password : L"");
    copy_text(
        archive_type,
        archive_type_chars,
        result.archive_type.empty() ? archive_type_for_path(archive_path_text) : result.archive_type);
    if (command_ok)
    {
        *command_ok = result.status == sunpack::sevenzip::PasswordTestStatus::Ok ? 1 : 0;
    }
    if (encrypted)
    {
        *encrypted = result.status == sunpack::sevenzip::PasswordTestStatus::WrongPassword ? 1 : 0;
    }
    if (checksum_error)
    {
        *checksum_error = result.status == sunpack::sevenzip::PasswordTestStatus::Damaged ? 1 : 0;
    }
    copy_ascii(message, message_chars, result.message);
    return static_cast<int>(result.status);
}

#endif
