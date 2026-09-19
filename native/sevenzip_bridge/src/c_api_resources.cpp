#include "sevenzip_bridge/bridge.hpp"

#ifdef _WIN32

#include "c_api_common.hpp"
#include "internal/archive_operations.hpp"

namespace {

void fill_analysis(
    Sup7zArchiveResourceAnalysis* analysis,
    const sunpack::sevenzip::ResourceAnalysisResult& result,
    const std::wstring& archive_path
) {
    using namespace sunpack::sevenzip;
    using namespace sunpack::sevenzip::capi;
    if (!analysis) {
        return;
    }
    analysis->status = status_code(result.status);
    analysis->is_archive = result.is_archive ? 1 : 0;
    analysis->is_encrypted = result.encrypted ? 1 : 0;
    analysis->is_broken = result.damaged ? 1 : 0;
    analysis->solid = result.solid ? 1 : 0;
    analysis->item_count = static_cast<int>(result.item_count);
    analysis->file_count = static_cast<int>(result.file_count);
    analysis->dir_count = static_cast<int>(result.dir_count);
    analysis->archive_size = result.archive_size;
    analysis->total_unpacked_size = result.total_unpacked_size;
    analysis->total_packed_size = result.total_packed_size;
    analysis->largest_item_size = result.largest_item_size;
    analysis->largest_dictionary_size = result.largest_dictionary_size;
    copy_wide(analysis->archive_type, 32, archive_type_for_path(archive_path));
    copy_wide(analysis->dominant_method, 128, result.dominant_method);
}

}  // namespace

SUP7Z_API int sup7z_analyze_archive_resources(
    const wchar_t* seven_zip_dll_path,
    const wchar_t* archive_path,
    const wchar_t* password,
    Sup7zArchiveResourceAnalysis* analysis,
    wchar_t* message,
    int message_chars
) {
    using namespace sunpack::sevenzip;
    using namespace sunpack::sevenzip::capi;
    if (analysis) {
        *analysis = Sup7zArchiveResourceAnalysis{};
    }
    if (!archive_path) {
        copy_message(message, message_chars, "missing required path");
        if (analysis) {
            analysis->status = status_code(PasswordTestStatus::Error);
        }
        return status_code(PasswordTestStatus::Error);
    }

    const std::wstring archive_path_text(archive_path);
    const auto result = analyze_archive_resources_with_parts(
        seven_zip_dll_path,
        archive_path_text,
        {archive_path_text},
        password ? password : L"");
    fill_analysis(analysis, result, archive_path_text);
    copy_message(message, message_chars, result.message);
    return status_code(result.status);
}

SUP7Z_API int sup7z_analyze_archive_resources_with_parts(
    const wchar_t* seven_zip_dll_path,
    const wchar_t* archive_path,
    const wchar_t* const* part_paths,
    int part_count,
    const wchar_t* password,
    Sup7zArchiveResourceAnalysis* analysis,
    wchar_t* message,
    int message_chars
) {
    using namespace sunpack::sevenzip;
    using namespace sunpack::sevenzip::capi;
    if (analysis) {
        *analysis = Sup7zArchiveResourceAnalysis{};
    }
    if (!archive_path) {
        copy_message(message, message_chars, "missing required path");
        if (analysis) {
            analysis->status = status_code(PasswordTestStatus::Error);
        }
        return status_code(PasswordTestStatus::Error);
    }

    const std::wstring archive_path_text(archive_path);
    const auto result = analyze_archive_resources_with_parts(
        seven_zip_dll_path,
        archive_path_text,
        collect_part_paths(archive_path, part_paths, part_count),
        password ? password : L"");
    fill_analysis(analysis, result, archive_path_text);
    copy_message(message, message_chars, result.message);
    return status_code(result.status);
}

#endif
