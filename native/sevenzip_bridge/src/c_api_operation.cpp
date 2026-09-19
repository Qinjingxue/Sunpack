#include "sevenzip_bridge/bridge.hpp"

#ifdef _WIN32

#include "c_api_common.hpp"
#include "internal/operation_dispatch.hpp"

namespace {

using sunpack::sevenzip::ArchiveOperationRequest;
using sunpack::sevenzip::ArchiveOperationResult;
using sunpack::sevenzip::ExtractInputRange;
using sunpack::sevenzip::PasswordTestStatus;

void init_result(Sup7zOperationResult* result) {
    if (!result) {
        return;
    }
    result->status = static_cast<int>(PasswordTestStatus::Error);
    result->command_ok = 0;
    result->is_archive = 0;
    result->is_encrypted = 0;
    result->is_broken = 0;
    result->checksum_error = 0;
    result->matched_index = -1;
    result->attempts = 0;
    result->archive_offset = 0;
    result->item_count = 0;
    result->operation_result = 0;
    result->password_required = 0;
    result->missing_volume = 0;
    result->missing_volume_suspected = 0;
    result->missing_stub = 0;
    result->volume_open_failed = 0;
    result->archive_type[0] = L'\0';
    result->missing_volume_name[0] = L'\0';
    result->missing_volume_evidence[0] = L'\0';
    result->message[0] = L'\0';
}

std::vector<std::wstring> collect_passwords(const wchar_t* const* passwords, int password_count) {
    std::vector<std::wstring> result;
    if (!passwords || password_count <= 0) {
        return result;
    }
    result.reserve(static_cast<std::size_t>(password_count));
    for (int index = 0; index < password_count; ++index) {
        result.emplace_back(passwords[index] ? passwords[index] : L"");
    }
    return result;
}

std::vector<std::wstring> collect_names(const wchar_t* const* names, int count) {
    std::vector<std::wstring> result;
    if (!names || count <= 0) return result;
    result.reserve(static_cast<std::size_t>(count));
    for (int index = 0; index < count; ++index) result.emplace_back(names[index] ? names[index] : L"");
    return result;
}

std::vector<ExtractInputRange> collect_ranges(const Sup7zInputRange* ranges, int range_count, const wchar_t* archive_path) {
    std::vector<ExtractInputRange> result;
    if (!ranges || range_count <= 0) {
        return result;
    }
    result.reserve(static_cast<std::size_t>(range_count));
    for (int index = 0; index < range_count; ++index) {
        ExtractInputRange range;
        range.path = ranges[index].path && ranges[index].path[0] != L'\0'
            ? ranges[index].path
            : (archive_path ? archive_path : L"");
        range.start = ranges[index].start;
        range.end = ranges[index].end;
        range.has_end = ranges[index].has_end != 0;
        result.push_back(std::move(range));
    }
    return result;
}

ArchiveOperationRequest to_request(const Sup7zOperationRequest& request) {
    ArchiveOperationRequest operation;
    operation.operation = static_cast<Sup7zOperationKind>(request.operation);
    operation.archive_path = request.archive_path ? request.archive_path : L"";
    operation.part_paths = sunpack::sevenzip::capi::collect_part_paths(
        request.archive_path,
        request.part_paths,
        request.part_count);
    operation.canonical_names = collect_names(request.canonical_names, request.part_count);
    if (request.volume_numbers && request.part_count > 0) {
        operation.volume_numbers.assign(request.volume_numbers, request.volume_numbers + request.part_count);
    }
    operation.ranges = collect_ranges(request.ranges, request.range_count, request.archive_path);
    operation.format_hint = request.format_hint ? request.format_hint : L"";
    operation.password = request.password ? request.password : L"";
    operation.passwords = collect_passwords(request.passwords, request.password_count);
    return operation;
}

void copy_result(const ArchiveOperationResult& source, Sup7zOperationResult* destination) {
    if (!destination) {
        return;
    }
    destination->status = static_cast<int>(source.status);
    destination->command_ok = source.command_ok ? 1 : 0;
    destination->is_archive = source.is_archive ? 1 : 0;
    destination->is_encrypted = source.is_encrypted ? 1 : 0;
    destination->is_broken = source.is_broken ? 1 : 0;
    destination->checksum_error = source.checksum_error ? 1 : 0;
    destination->matched_index = source.matched_index;
    destination->attempts = source.attempts;
    destination->archive_offset = source.archive_offset;
    destination->item_count = source.item_count;
    destination->operation_result = source.operation_result;
    destination->password_required = source.password_required ? 1 : 0;
    destination->missing_volume = source.missing_volume ? 1 : 0;
    destination->missing_volume_suspected = source.missing_volume_suspected ? 1 : 0;
    destination->missing_stub = source.missing_stub ? 1 : 0;
    destination->volume_open_failed = source.volume_open_failed ? 1 : 0;
    sunpack::sevenzip::capi::copy_wide(destination->archive_type, 64, source.archive_type);
    sunpack::sevenzip::capi::copy_wide(destination->missing_volume_name, 260, source.missing_volume_name);
    sunpack::sevenzip::capi::copy_wide(
        destination->missing_volume_evidence,
        64,
        std::wstring(source.missing_volume_evidence.begin(), source.missing_volume_evidence.end()));
    sunpack::sevenzip::capi::copy_message(destination->message, 512, source.message);
}

}  // namespace

SUP7Z_API int sup7z_run_operation(
    const Sup7zOperationRequest* request,
    Sup7zOperationResult* result
) {
    init_result(result);
    if (!request || !result) {
        return static_cast<int>(PasswordTestStatus::Error);
    }

    const ArchiveOperationResult operation_result = sunpack::sevenzip::run_archive_operation(to_request(*request));
    copy_result(operation_result, result);
    return static_cast<int>(operation_result.status);
}

#endif
