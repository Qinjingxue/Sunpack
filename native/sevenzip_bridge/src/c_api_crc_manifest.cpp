#include "sevenzip_bridge/bridge.hpp"

#ifdef _WIN32

#include "c_api_common.hpp"
#include "internal/archive_operations.hpp"

#include <sstream>

namespace {

std::wstring json_escape(const std::wstring& text) {
    std::wstringstream out;
    for (wchar_t ch : text) {
        switch (ch) {
        case L'\\':
            out << L"\\\\";
            break;
        case L'"':
            out << L"\\\"";
            break;
        case L'\b':
            out << L"\\b";
            break;
        case L'\f':
            out << L"\\f";
            break;
        case L'\n':
            out << L"\\n";
            break;
        case L'\r':
            out << L"\\r";
            break;
        case L'\t':
            out << L"\\t";
            break;
        default:
            if (ch < 32) {
                out << L"\\u";
                const wchar_t* hex = L"0123456789abcdef";
                out << hex[(ch >> 12) & 0xF] << hex[(ch >> 8) & 0xF] << hex[(ch >> 4) & 0xF] << hex[ch & 0xF];
            } else {
                out << ch;
            }
            break;
        }
    }
    return out.str();
}

std::wstring manifest_json(const sunpack::sevenzip::CrcManifestResult& result) {
    std::wstringstream out;
    out << L"{";
    out << L"\"is_archive\":" << (result.is_archive ? L"true" : L"false") << L",";
    out << L"\"encrypted\":" << (result.encrypted ? L"true" : L"false") << L",";
    out << L"\"damaged\":" << (result.damaged ? L"true" : L"false") << L",";
    out << L"\"checksum_error\":" << (result.checksum_error ? L"true" : L"false") << L",";
    out << L"\"item_count\":" << result.item_count << L",";
    out << L"\"file_count\":" << result.file_count << L",";
    out << L"\"files\":[";
    bool first = true;
    for (const auto& item : result.files) {
        if (!first) {
            out << L",";
        }
        first = false;
        out << L"{";
        out << L"\"path\":\"" << json_escape(item.path) << L"\",";
        out << L"\"size\":" << item.size << L",";
        out << L"\"has_crc\":" << (item.has_crc ? L"true" : L"false") << L",";
        out << L"\"crc32\":" << item.crc32;
        out << L"}";
    }
    out << L"]}";
    return out.str();
}

int read_manifest(
    const wchar_t* archive_path,
    const wchar_t* const* part_paths,
    int part_count,
    const wchar_t* password,
    int max_items,
    wchar_t* manifest_json_buffer,
    int manifest_json_chars,
    wchar_t* message,
    int message_chars
) {
    using namespace sunpack::sevenzip;
    using namespace sunpack::sevenzip::capi;
    if (!archive_path) {
        copy_message(message, message_chars, "missing required path");
        copy_wide(manifest_json_buffer, manifest_json_chars, L"{}");
        return status_code(PasswordTestStatus::Error);
    }

    const std::wstring archive_path_text(archive_path);
    const auto result = read_archive_crc_manifest_with_parts(
            archive_path_text,
        collect_part_paths(archive_path, part_paths, part_count),
        password ? password : L"",
        static_cast<UInt32>(max_items < 0 ? 0 : max_items));
    copy_wide(manifest_json_buffer, manifest_json_chars, manifest_json(result));
    copy_message(message, message_chars, result.message);
    return status_code(result.status);
}

}  // namespace

SUP7Z_API int sup7z_read_archive_crc_manifest(
    const wchar_t* archive_path,
    const wchar_t* password,
    int max_items,
    wchar_t* manifest_json,
    int manifest_json_chars,
    wchar_t* message,
    int message_chars
) {
    return read_manifest(
            archive_path,
        nullptr,
        0,
        password,
        max_items,
        manifest_json,
        manifest_json_chars,
        message,
        message_chars);
}

SUP7Z_API int sup7z_read_archive_crc_manifest_with_parts(
    const wchar_t* archive_path,
    const wchar_t* const* part_paths,
    int part_count,
    const wchar_t* password,
    int max_items,
    wchar_t* manifest_json,
    int manifest_json_chars,
    wchar_t* message,
    int message_chars
) {
    return read_manifest(
            archive_path,
        part_paths,
        part_count,
        password,
        max_items,
        manifest_json,
        manifest_json_chars,
        message,
        message_chars);
}

#endif
