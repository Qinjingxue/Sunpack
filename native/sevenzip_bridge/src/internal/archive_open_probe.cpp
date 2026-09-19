#include "archive_operations.hpp"

#include "archive_open_plan.hpp"
#include "sevenzip_callbacks.hpp"
#include "sevenzip_formats.hpp"
#include "sevenzip_paths.hpp"
#include "sevenzip_properties.hpp"
#include "sevenzip_status.hpp"
#include "sevenzip_streams.hpp"
#include "strict_archive_validation.hpp"

namespace sunpack::sevenzip {

#ifdef _WIN32

namespace {

ArchiveOpenProbeResult missing_tail_result(const char* evidence, const char* message) {
    ArchiveOpenProbeResult result;
    result.backend_available = true;
    result.status = PasswordTestStatus::Damaged;
    result.is_archive = true;
    result.damaged = true;
    result.missing_volume = true;
    result.missing_volume_evidence = evidence ? evidence : "";
    result.message = message ? message : "archive split tail is unavailable";
    return result;
}

}  // namespace

ArchiveOpenProbeResult probe_archive_open_internal(
    const std::wstring& archive_path,
    const std::wstring& password,
    const std::vector<std::wstring>& part_paths
) {
    ArchiveOpenProbeResult result;
    result.backend_available = true;
    result.archive_type = archive_type_for_path(archive_path);

    if (seven_zip_parts_prove_missing_tail(part_paths, false)) {
        auto missing = missing_tail_result(
            "seven_zip_start_header_length",
            "7z start header proves that the split archive tail is missing");
        missing.archive_type = result.archive_type;
        return missing;
    }
    if (zip_parts_require_unavailable_tail(part_paths, false)) {
        auto missing = missing_tail_result(
            "zip_eocd_unavailable",
            "ZIP end-of-central-directory record is unavailable in the supplied volumes");
        missing.archive_type = result.archive_type;
        return missing;
    }

    bool any_format_created = false;
    HRESULT last_hr = E_FAIL;
    Int32 last_op_res = kOpOk;
    bool last_encryption_evidence = false;

    const auto plans = password_test_open_plans(
        archive_path,
        part_paths,
        candidate_formats(archive_path, part_paths),
        {});
    for (const auto& plan : plans) {
        for (const GUID& format : plan.formats) {
        ComPtr<IInArchive> archive;
        HRESULT hr = create_in_archive(format, archive.out());
        if (hr != S_OK || !archive) {
            last_hr = hr;
            continue;
        }
        any_format_created = true;

        bool stream_opened = false;
        ComPtr<IInStream> stream = open_stream_for_plan(plan, archive_path, part_paths, stream_opened);
        if (!stream_opened) {
            if (is_sfx_path(archive_path) && !sorted_data_volume_paths(part_paths).empty()) {
                result.status = PasswordTestStatus::Damaged;
                result.is_archive = true;
                result.damaged = true;
                result.missing_stub = true;
                result.missing_volume_evidence = "sfx_stub_not_found";
                result.message = "split self-extracting archive stub is missing";
                return result;
            }
            result.status = PasswordTestStatus::Error;
            result.message = "archive file could not be opened";
            return result;
        }

        result.archive_offset = plan.archive_offset;
        if (!plan.archive_type.empty()) {
            result.archive_type = plan.archive_type;
        }
        auto* raw_open_callback = new OpenCallback(
            password,
            callback_archive_path(archive_path, part_paths),
            part_paths);
        ComPtr<IArchiveOpenCallback> open_callback(raw_open_callback);
        hr = archive->Open(stream.get(), nullptr, open_callback.get());
        last_encryption_evidence = raw_open_callback->password_requested();

        if (raw_open_callback->missing_volume_requested()) {
            result.status = PasswordTestStatus::Damaged;
            result.is_archive = true;
            result.damaged = true;
            result.missing_volume = true;
            result.missing_volume_name = raw_open_callback->missing_volume_name();
            result.missing_volume_evidence = "open_volume_callback_not_found";
            result.message = "archive handler requested a missing split volume";
            return result;
        }
        if (raw_open_callback->volume_open_failed()) {
            result.status = PasswordTestStatus::Error;
            result.is_archive = true;
            result.volume_open_failed = true;
            result.missing_volume_name = raw_open_callback->failed_volume_name();
            result.missing_volume_evidence = "open_volume_callback_open_failed";
            result.message = "archive split volume could not be opened";
            return result;
        }
        if (hr != S_OK) {
            if (last_encryption_evidence) {
                result.status = PasswordTestStatus::WrongPassword;
                result.is_archive = true;
                result.encrypted = true;
                result.password_required = true;
                result.wrong_password = true;
                result.message = "archive is encrypted or password is required";
                return result;
            }
            last_hr = hr;
            continue;
        }

        result.is_archive = true;
        result.operation_result = kOpOk;
        const bool opened_as_encrypted = archive_has_encrypted_items(archive.get());
        last_encryption_evidence = last_encryption_evidence || opened_as_encrypted;
        result.encrypted = opened_as_encrypted || raw_open_callback->password_requested();
        result.password_required = result.encrypted;
        archive->Close();

        if (result.password_required && password.empty()) {
            result.status = PasswordTestStatus::WrongPassword;
            result.wrong_password = true;
            result.message = "archive is encrypted or password is required";
            return result;
        }

        result.status = PasswordTestStatus::Ok;
        result.message = "archive open probe opened archive";
        return result;
        }
    }

    result.operation_result = last_op_res;
    if (!any_format_created) {
        result.status = PasswordTestStatus::Unsupported;
        result.message = "the embedded 7-Zip backend did not create a supported archive handler";
    } else if (looks_damaged_probe_result(password, last_op_res)) {
        result.status = PasswordTestStatus::Damaged;
        result.is_archive = true;
        result.damaged = true;
        result.message = "archive appears damaged";
    } else if (looks_wrong_password(last_hr, last_op_res, last_encryption_evidence)) {
        result.status = PasswordTestStatus::WrongPassword;
        result.is_archive = true;
        result.encrypted = true;
        result.password_required = true;
        result.wrong_password = true;
        result.message = "archive is encrypted or password is wrong";
    } else {
        result.status = PasswordTestStatus::Unsupported;
        result.message = "archive could not be opened by supported handlers";
    }
    return result;
}

#endif

ArchiveOpenProbeResult probe_archive_open_with_parts(
    const std::wstring& archive_path,
    const std::vector<std::wstring>& part_paths,
    const std::wstring& password
) {
#ifdef _WIN32
    return probe_archive_open_internal(archive_path, password, part_paths);
#else
    (void)archive_path;
    (void)part_paths;
    (void)password;
    ArchiveOpenProbeResult result;
    result.status = PasswordTestStatus::BackendUnavailable;
    result.message = "native archive open probing is only implemented on Windows";
    return result;
#endif
}

}  // namespace sunpack::sevenzip
