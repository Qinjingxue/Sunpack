#include "operation_dispatch.hpp"

#include "archive_operations.hpp"

#include <algorithm>
#include <cwctype>
#include <filesystem>

namespace sunpack::sevenzip
{

    namespace
    {

        std::wstring lower_extension(const std::wstring &path)
        {
            std::wstring ext = std::filesystem::path(path).extension().wstring();
            std::transform(ext.begin(), ext.end(), ext.begin(), [](wchar_t ch)
                           { return static_cast<wchar_t>(::towlower(ch)); });
            return ext;
        }

        bool is_archive_type(const std::wstring &type)
        {
            return !type.empty() && type != L"pe" && type != L"elf" && type != L"macho" && type != L"te";
        }

        std::vector<const wchar_t *> password_ptrs(const std::vector<std::wstring> &passwords, const std::wstring &fallback)
        {
            std::vector<const wchar_t *> pointers;
            if (passwords.empty())
            {
                pointers.push_back(fallback.c_str());
                return pointers;
            }
            pointers.reserve(passwords.size());
            for (const auto &item : passwords)
            {
                pointers.push_back(item.c_str());
            }
            return pointers;
        }

        std::vector<std::wstring> effective_parts(const ArchiveOperationRequest &request)
        {
            if (!request.part_paths.empty())
            {
                return request.part_paths;
            }
            return {request.archive_path};
        }

        std::wstring operation_archive_type(const ArchiveOperationRequest &request, const PasswordTestResult &result)
        {
            if (!result.archive_type.empty())
            {
                return result.archive_type;
            }
            if (!request.format_hint.empty())
            {
                return request.format_hint;
            }
            return archive_type_for_path(request.archive_path);
        }

        ArchiveOperationResult from_password_result(const ArchiveOperationRequest &request, const PasswordTestResult &result)
        {
            ArchiveOperationResult output;
            output.status = result.status;
            output.command_ok = result.status == PasswordTestStatus::Ok;
            output.is_archive = result.is_archive;
            output.is_encrypted = result.status == PasswordTestStatus::WrongPassword;
            output.password_required = result.password_required;
            output.is_encrypted = output.is_encrypted || result.encrypted;
            output.is_broken = result.damaged || result.status == PasswordTestStatus::Damaged || result.missing_volume || result.missing_stub || result.volume_open_failed;
            output.checksum_error = result.damaged || result.status == PasswordTestStatus::Damaged;
            output.missing_volume = result.missing_volume;
            output.missing_volume_suspected = result.missing_volume_suspected;
            output.missing_stub = result.missing_stub;
            output.volume_open_failed = result.volume_open_failed;
            output.matched_index = result.matched_index;
            output.attempts = result.attempts;
            output.archive_offset = result.archive_offset;
            output.archive_type = operation_archive_type(request, result);
            output.missing_volume_name = result.missing_volume_name;
            output.missing_volume_evidence = result.missing_volume_evidence;
            output.item_count = result.status == PasswordTestStatus::Ok ? 1 : 0;
            output.operation_result = result.operation_result;
            output.message = result.message;
            return output;
        }

        PasswordTestResult run_password_attempts(const ArchiveOperationRequest &request)
        {
            const std::wstring fallback_password;
            const auto pointers = password_ptrs(request.passwords, fallback_password);
            if (!request.ranges.empty())
            {
                return test_passwords_with_ranges(
                    request.seven_zip_dll_path,
                    request.archive_path,
                    request.ranges,
                    request.format_hint,
                    pointers.data(),
                    static_cast<int>(pointers.size()));
            }
            return test_passwords_with_parts(
                request.seven_zip_dll_path,
                request.archive_path,
                effective_parts(request),
                pointers.data(),
                static_cast<int>(pointers.size()),
                request.canonical_names);
        }

        PasswordTestResult run_single_test(const ArchiveOperationRequest &request)
        {
            if (!request.ranges.empty())
            {
                const auto pointers = password_ptrs({}, request.password);
                return test_passwords_with_ranges(
                    request.seven_zip_dll_path,
                    request.archive_path,
                    request.ranges,
                    request.format_hint,
                    pointers.data(),
                    static_cast<int>(pointers.size()));
            }
            return test_password_with_parts(
                request.seven_zip_dll_path,
                request.archive_path,
                effective_parts(request),
                request.password,
                request.canonical_names);
        }

        ArchiveOperationResult run_probe(const ArchiveOperationRequest &request)
        {
            if (request.ranges.empty())
            {
                const auto open_probe = probe_archive_open_with_parts(
                    request.seven_zip_dll_path,
                    request.archive_path,
                    effective_parts(request),
                    L"");
                ArchiveOperationResult output;
                output.status = open_probe.status;
                output.command_ok = open_probe.status == PasswordTestStatus::Ok;
                output.is_archive = open_probe.is_archive;
                output.is_encrypted = open_probe.encrypted;
                output.password_required = open_probe.password_required;
                output.is_broken = open_probe.damaged || open_probe.missing_volume || open_probe.missing_stub || open_probe.volume_open_failed;
                output.checksum_error = open_probe.damaged;
                output.missing_volume = open_probe.missing_volume;
                output.missing_volume_suspected = open_probe.missing_volume_suspected;
                output.missing_stub = open_probe.missing_stub;
                output.volume_open_failed = open_probe.volume_open_failed;
                output.archive_offset = open_probe.archive_offset;
                output.archive_type = open_probe.archive_type.empty()
                                          ? archive_type_for_path(request.archive_path)
                                          : open_probe.archive_type;
                output.missing_volume_name = open_probe.missing_volume_name;
                output.missing_volume_evidence = open_probe.missing_volume_evidence;
                output.item_count = open_probe.status == PasswordTestStatus::Ok ? 1 : 0;
                output.operation_result = open_probe.operation_result;
                output.message = open_probe.message;
                return output;
            }
            ArchiveOperationRequest probe_request = request;
            probe_request.password.clear();
            probe_request.passwords.clear();
            const PasswordTestResult result = run_single_test(probe_request);
            ArchiveOperationResult output = from_password_result(request, result);
            const std::wstring type = output.archive_type;
            const bool encrypted_result = result.status == PasswordTestStatus::WrongPassword ||
                                          (result.status == PasswordTestStatus::Unsupported && lower_extension(request.archive_path) == L".7z");
            const bool damaged_result = result.status == PasswordTestStatus::Damaged;
            output.archive_type = type;
            output.is_archive = result.status == PasswordTestStatus::Ok ||
                                encrypted_result ||
                                damaged_result ||
                                is_archive_type(type);
            output.is_encrypted = encrypted_result;
            output.password_required = result.password_required || encrypted_result;
            output.is_broken = damaged_result;
            output.checksum_error = damaged_result;
            output.item_count = result.status == PasswordTestStatus::Ok ? 1 : 0;
            return output;
        }

        ArchiveOperationResult invalid_request(const std::string &message)
        {
            ArchiveOperationResult output;
            output.status = PasswordTestStatus::Error;
            output.message = message;
            return output;
        }

    } // namespace

    ArchiveOperationResult run_archive_operation(const ArchiveOperationRequest &request)
    {
        if (request.seven_zip_dll_path.empty() || request.archive_path.empty())
        {
            return invalid_request("missing required path");
        }
        if (request.part_paths.size() > 1 && request.operation != SUP7Z_OPERATION_PROBE)
        {
            if (request.canonical_names.size() != request.part_paths.size() || request.volume_numbers.size() != request.part_paths.size())
            {
                return invalid_request("structured multi-volume input is required");
            }
            for (std::size_t index = 0; index < request.volume_numbers.size(); ++index)
            {
                if (request.volume_numbers[index] != static_cast<int>(index + 1) || request.canonical_names[index].empty())
                {
                    return invalid_request("invalid structured volume sequence");
                }
            }
        }

        switch (request.operation)
        {
        case SUP7Z_OPERATION_PROBE:
            return run_probe(request);
        case SUP7Z_OPERATION_TEST:
            return from_password_result(request, run_single_test(request));
        case SUP7Z_OPERATION_TRY_PASSWORDS:
            return from_password_result(request, run_password_attempts(request));
        default:
            return invalid_request("unsupported operation");
        }
    }

} // namespace sunpack::sevenzip
