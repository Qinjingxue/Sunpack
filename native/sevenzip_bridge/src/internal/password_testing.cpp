#include "sevenzip_bridge/bridge.hpp"

#include <algorithm>

#include "archive_open_plan.hpp"

#include "sevenzip_callbacks.hpp"

#include "sevenzip_formats.hpp"

#include "sevenzip_paths.hpp"

#include "sevenzip_properties.hpp"

#include "sevenzip_status.hpp"

#include "sevenzip_streams.hpp"

#include "strict_archive_validation.hpp"

namespace sunpack::sevenzip
{

#ifdef _WIN32

    namespace
    {

        PasswordTestResult needs_volume_or_tail_damaged_result(
            const char *evidence,
            const std::wstring &requested_name = L"")
        {
            PasswordTestResult result;
            result.backend_available = true;
            result.status = PasswordTestStatus::NeedsVolumeOrTailDamaged;
            result.is_archive = true;
            result.damaged = true;
            result.missing_volume = true;
            result.missing_volume_suspected = true;
            result.missing_volume_evidence = evidence ? evidence : "";
            result.missing_volume_name = requested_name;
            result.message = "password probe could not read required tail data; missing volume or damaged tail offset/structure";
            if (evidence && *evidence)
            {
                result.message += " [evidence=";
                result.message += evidence;
                result.message += "]";
            }
            if (!requested_name.empty())
            {
                result.message += " [requested_volume=";
                for (wchar_t ch : requested_name)
                {
                    result.message.push_back(ch >= 0x20 && ch <= 0x7e ? static_cast<char>(ch) : '?');
                }
                result.message += "]";
            }
            return result;
        }

        bool encrypted_header_range_probe_candidate(const std::wstring &archive_type)
        {
            return archive_type == L"7z" || archive_type == L"rar" || archive_type == L"rar4" || archive_type == L"rar5";
        }

        std::vector<UInt32> bounded_password_probe_indices(IInArchive *archive)
        {
            if (!archive)
            {
                return {};
            }
            UInt32 item_count = 0;
            if (archive->GetNumberOfItems(&item_count) != S_OK)
            {
                return {};
            }
            PROPVARIANT archive_value;
            PropVariantInit(&archive_value);
            const bool solid = archive->GetArchiveProperty(kpidSolid, &archive_value) == S_OK && prop_bool(archive_value);
            clear_prop(archive_value);

            struct Candidate
            {
                UInt32 index;
                UInt64 size;
                bool encrypted;
            };
            std::vector<Candidate> regular;
            bool has_encrypted = false;
            for (UInt32 index = 0; index < item_count; ++index)
            {
                PROPVARIANT value;
                PropVariantInit(&value);
                const bool is_dir = get_item_property(archive, index, kpidIsDir, value) && prop_bool(value);
                clear_prop(value);
                if (is_dir)
                {
                    continue;
                }
                const bool encrypted = get_item_property(archive, index, kpidEncrypted, value) && prop_bool(value);
                clear_prop(value);
                UInt64 size = 0;
                if (get_item_property(archive, index, kpidSize, value))
                {
                    size = prop_u64(value);
                }
                clear_prop(value);
                regular.push_back({index, size, encrypted});
                has_encrypted = has_encrypted || encrypted;
            }
            if (regular.empty())
            {
                return {};
            }
            auto eligible = [has_encrypted](const Candidate &item)
            {
                return !has_encrypted || item.encrypted;
            };
            auto selected = std::find_if(regular.begin(), regular.end(), eligible);
            if (selected == regular.end())
            {
                return {};
            }
            if (!solid)
            {
                for (auto it = selected; it != regular.end(); ++it)
                {
                    if (eligible(*it) && it->size < selected->size)
                    {
                        selected = it;
                    }
                }
            }
            return {selected->index};
        }

    } // namespace

    PasswordTestResult test_one_password(

        CreateObjectFunc create_object,

        const std::wstring &archive_path,

        const std::wstring &password,

        const std::vector<std::wstring> &part_paths,

        const std::vector<GUID> &formats,

        const std::vector<ExtractInputRange> &input_ranges = {},
        bool bounded_password_probe = false,

        const std::vector<std::wstring> &canonical_names = {}

    );

    PasswordTestResult test_one_password(

        CreateObjectFunc create_object,

        const std::wstring &archive_path,

        const std::wstring &password,

        const std::vector<std::wstring> &part_paths

    )
    {

        return test_one_password(

            create_object,

            archive_path,

            password,

            part_paths,

            candidate_formats(archive_path, part_paths),

            {},

            false);
    }

    PasswordTestResult test_one_password(

        CreateObjectFunc create_object,

        const std::wstring &archive_path,

        const std::wstring &password,

        const std::vector<std::wstring> &part_paths,

        const std::vector<GUID> &formats,

        const std::vector<ExtractInputRange> &input_ranges,
        bool bounded_password_probe,

        const std::vector<std::wstring> &canonical_names

    )
    {

        PasswordTestResult fallback;

        fallback.backend_available = true;

        bool has_fallback = false;

        const auto plans = password_test_open_plans(archive_path, part_paths, formats, input_ranges);

        for (const auto &plan : plans)
        {

            PasswordTestResult result;

            result.backend_available = true;

            apply_plan_metadata(result, plan);

            bool any_format_created = false;

            bool any_opened = false;

            HRESULT last_hr = E_FAIL;

            Int32 last_op_res = kOpOk;
            bool last_encryption_evidence = false;

            for (const GUID &format : plan.formats)
            {

                ComPtr<IInArchive> archive;

                HRESULT hr = create_object(&format, &IID_IInArchive, reinterpret_cast<void **>(archive.out()));

                if (hr != S_OK || !archive)
                {

                    last_hr = hr;

                    continue;
                }

                any_format_created = true;

                bool stream_opened = false;

                ComPtr<IInStream> stream = open_stream_for_plan(plan, archive_path, part_paths, stream_opened);

                if (!stream_opened)
                {

                    if (is_sfx_path(archive_path) && !sorted_data_volume_paths(part_paths).empty())
                    {
                        result.status = PasswordTestStatus::NeedsVolumeOrTailDamaged;
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

                const std::wstring callback_path = canonical_names.empty() ? callback_archive_path(archive_path, part_paths) : canonical_names.front();
                auto *raw_open_callback = new OpenCallback(password, callback_path, part_paths, canonical_names);
                ComPtr<IArchiveOpenCallback> open_callback(raw_open_callback);

                hr = archive->Open(stream.get(), nullptr, open_callback.get());
                last_encryption_evidence = raw_open_callback->password_requested();

                if (raw_open_callback->missing_volume_requested())
                {
                    auto missing = needs_volume_or_tail_damaged_result(
                        "open_volume_callback_not_found",
                        raw_open_callback->missing_volume_name());
                    apply_plan_metadata(missing, plan);
                    return missing;
                }

                if (raw_open_callback->volume_open_failed())
                {
                    result.status = PasswordTestStatus::Error;
                    result.is_archive = true;
                    result.volume_open_failed = true;
                    result.missing_volume_name = raw_open_callback->failed_volume_name();
                    result.missing_volume_evidence = "open_volume_callback_open_failed";
                    result.message = "archive split volume could not be opened";
                    return result;
                }

                if (hr != S_OK)
                {

                    last_hr = hr;

                    continue;
                }

                any_opened = true;
                result.is_archive = true;
                last_encryption_evidence = last_encryption_evidence || archive_has_encrypted_items(archive.get());
                result.encrypted = result.encrypted || last_encryption_evidence;
                result.password_required = result.password_required || last_encryption_evidence;

                auto *raw_extract_callback = new ExtractCallback(password);

                ComPtr<IArchiveExtractCallback> extract_callback(raw_extract_callback);

                const auto probe_indices = bounded_password_probe_indices(archive.get());

                if (bounded_password_probe && probe_indices.empty())
                {

                    hr = S_OK;

                    last_op_res = kOpOk;
                }
                else
                {

                    hr = archive->Extract(

                        bounded_password_probe ? probe_indices.data() : nullptr,

                        bounded_password_probe ? static_cast<UInt32>(probe_indices.size()) : static_cast<UInt32>(kAllItems),

                        kTestMode,

                        extract_callback.get());

                    last_op_res = raw_extract_callback->operation_result();
                    result.operation_result = last_op_res;
                    last_encryption_evidence = last_encryption_evidence || raw_extract_callback->password_requested();
                }

                last_hr = hr;

                archive->Close();

                if (hr == S_OK && last_op_res == kOpOk)
                {

                    result.status = PasswordTestStatus::Ok;

                    result.message = "password accepted";

                    return result;
                }

                if (looks_wrong_password(hr, last_op_res, last_encryption_evidence))
                {

                    result.status = PasswordTestStatus::WrongPassword;
                    result.is_archive = true;
                    result.encrypted = true;
                    result.password_required = true;
                    result.wrong_password = true;

                    result.message = "wrong password";

                    break;
                }

                if (looks_damaged(last_op_res))
                {

                    result.status = PasswordTestStatus::Damaged;

                    result.message = std::string("archive appears damaged [operation_result=") +
                                     operation_result_name(last_op_res) + "]";

                    break;
                }
            }

            if (!any_format_created)
            {

                result.status = PasswordTestStatus::Unsupported;

                result.message = "7z.dll did not create a supported archive handler";
            }
            else if (!any_opened && plan.uses_ranges() && encrypted_header_range_probe_candidate(plan.archive_type))
            {

                result.status = PasswordTestStatus::WrongPassword;
                result.is_archive = true;
                result.encrypted = true;
                result.password_required = true;
                result.wrong_password = true;

                result.message = "wrong password";
            }
            else if (!any_opened)
            {

                result.status = PasswordTestStatus::Unsupported;

                result.message = "archive could not be opened by supported handlers";
            }
            else if (looks_damaged(last_op_res))
            {

                result.status = PasswordTestStatus::Damaged;

                result.message = std::string("archive appears damaged [operation_result=") +
                                 operation_result_name(last_op_res) + "]";
            }
            else if (looks_wrong_password(last_hr, last_op_res, last_encryption_evidence))
            {

                result.status = PasswordTestStatus::WrongPassword;
                result.is_archive = true;
                result.encrypted = true;
                result.password_required = true;
                result.wrong_password = true;

                result.message = "wrong password";
            }
            else
            {

                result.status = PasswordTestStatus::Error;

                result.message = "archive test failed";
            }

            if (
                !has_fallback ||
                fallback.status == PasswordTestStatus::Unsupported ||
                fallback.status == PasswordTestStatus::Error ||
                result.status == PasswordTestStatus::WrongPassword)
            {
                fallback = result;
                has_fallback = true;
            }
        }

        if (has_fallback)
        {

            return fallback;
        }

        PasswordTestResult result;

        result.backend_available = true;

        result.status = PasswordTestStatus::Unsupported;

        result.message = "archive could not be opened by supported handlers";

        return result;
    }

    PasswordTestResult test_one_password_reuse_stream(

        CreateObjectFunc create_object,

        const std::wstring &archive_path,

        const std::wstring &password,

        const std::vector<std::wstring> &part_paths,

        const std::vector<GUID> &formats,

        IInStream *stream

    )
    {

        PasswordTestResult result;

        result.backend_available = true;

        bool any_format_created = false;

        bool any_opened = false;

        HRESULT last_hr = E_FAIL;

        Int32 last_op_res = kOpOk;
        bool last_encryption_evidence = false;

        UInt64 pos = 0;

        stream->Seek(0, 0, &pos);

        for (const GUID &format : formats)
        {

            ComPtr<IInArchive> archive;

            HRESULT hr = create_object(&format, &IID_IInArchive, reinterpret_cast<void **>(archive.out()));

            if (hr != S_OK || !archive)
            {

                last_hr = hr;

                continue;
            }

            any_format_created = true;

            auto *raw_open_callback = new OpenCallback(password, callback_archive_path(archive_path, part_paths), part_paths);
            ComPtr<IArchiveOpenCallback> open_callback(raw_open_callback);

            hr = archive->Open(stream, nullptr, open_callback.get());
            last_encryption_evidence = raw_open_callback->password_requested();

            if (raw_open_callback->missing_volume_requested())
            {
                return needs_volume_or_tail_damaged_result(
                    "open_volume_callback_not_found",
                    raw_open_callback->missing_volume_name());
            }

            if (raw_open_callback->volume_open_failed())
            {
                result.status = PasswordTestStatus::Error;
                result.is_archive = true;
                result.volume_open_failed = true;
                result.missing_volume_name = raw_open_callback->failed_volume_name();
                result.missing_volume_evidence = "open_volume_callback_open_failed";
                result.message = "archive split volume could not be opened";
                return result;
            }

            if (hr != S_OK)
            {

                last_hr = hr;

                continue;
            }

            any_opened = true;
            result.is_archive = true;
            last_encryption_evidence = last_encryption_evidence || archive_has_encrypted_items(archive.get());
            result.encrypted = result.encrypted || last_encryption_evidence;
            result.password_required = result.password_required || last_encryption_evidence;

            auto *raw_extract_callback = new ExtractCallback(password);

            ComPtr<IArchiveExtractCallback> extract_callback(raw_extract_callback);

            hr = archive->Extract(nullptr, static_cast<UInt32>(kAllItems), kTestMode, extract_callback.get());

            last_hr = hr;

            last_op_res = raw_extract_callback->operation_result();
            result.operation_result = last_op_res;
            last_encryption_evidence = last_encryption_evidence || raw_extract_callback->password_requested();

            archive->Close();

            if (hr == S_OK && last_op_res == kOpOk)
            {

                result.status = PasswordTestStatus::Ok;

                result.message = "password accepted";

                return result;
            }

            if (looks_wrong_password(hr, last_op_res, last_encryption_evidence))
            {

                result.status = PasswordTestStatus::WrongPassword;
                result.is_archive = true;
                result.encrypted = true;
                result.password_required = true;
                result.wrong_password = true;

                result.message = "wrong password";

                return result;
            }

            if (looks_damaged(last_op_res))
            {

                result.status = PasswordTestStatus::Damaged;

                result.message = std::string("archive appears damaged [operation_result=") +
                                 operation_result_name(last_op_res) + "]";

                return result;
            }
        }

        if (!any_format_created)
        {

            result.status = PasswordTestStatus::Unsupported;

            result.message = "7z.dll did not create a supported archive handler";
        }
        else if (!any_opened)
        {

            result.status = PasswordTestStatus::Unsupported;

            result.message = "archive could not be opened by supported handlers";
        }
        else if (looks_damaged(last_op_res))
        {

            result.status = PasswordTestStatus::Damaged;

            result.message = std::string("archive appears damaged [operation_result=") +
                             operation_result_name(last_op_res) + "]";
        }
        else if (looks_wrong_password(last_hr, last_op_res, last_encryption_evidence))
        {

            result.status = PasswordTestStatus::WrongPassword;
            result.is_archive = true;
            result.encrypted = true;
            result.password_required = true;
            result.wrong_password = true;

            result.message = "wrong password";
        }
        else
        {

            result.status = PasswordTestStatus::Error;

            result.message = "archive test failed";
        }

        return result;
    }

#endif

    PasswordTestResult test_password_with_parts(

        const std::wstring &seven_zip_dll_path,

        const std::wstring &archive_path,

        const std::vector<std::wstring> &part_paths,

        const std::wstring &password,

        const std::vector<std::wstring> &canonical_names

    );

    PasswordTestResult test_passwords_with_parts(

        const std::wstring &seven_zip_dll_path,

        const std::wstring &archive_path,

        const std::vector<std::wstring> &part_paths,

        const wchar_t *const *passwords,

        int password_count,

        const std::vector<std::wstring> &canonical_names

    );

    PasswordTestResult test_password(

        const std::wstring &seven_zip_dll_path,

        const std::wstring &archive_path,

        const std::wstring &password

    )
    {

        return test_password_with_parts(seven_zip_dll_path, archive_path, {archive_path}, password);
    }

    PasswordTestResult test_password_with_parts(

        const std::wstring &seven_zip_dll_path,

        const std::wstring &archive_path,

        const std::vector<std::wstring> &part_paths,

        const std::wstring &password,

        const std::vector<std::wstring> &canonical_names

    )
    {

#ifdef _WIN32

        CreateObjectFunc create_object = cached_create_object(seven_zip_dll_path);

        if (!create_object)
        {

            PasswordTestResult result;

            result.status = PasswordTestStatus::BackendUnavailable;

            result.message = "7z.dll could not be loaded";

            return result;
        }

        const auto effective_parts = part_paths.empty() ? std::vector<std::wstring>{archive_path} : part_paths;
        PasswordTestResult result = test_one_password(
            create_object, archive_path, password, effective_parts,
            candidate_formats(archive_path, effective_parts), {}, false, canonical_names);

        result.attempts = 1;

        result.matched_index = result.status == PasswordTestStatus::Ok ? 0 : -1;

        return result;

#else

        (void)seven_zip_dll_path;

        (void)archive_path;

        (void)password;

        PasswordTestResult result;

        result.status = PasswordTestStatus::BackendUnavailable;

        result.message = "native password testing is only implemented on Windows";

        return result;

#endif
    }

    PasswordTestResult test_passwords(

        const std::wstring &seven_zip_dll_path,

        const std::wstring &archive_path,

        const wchar_t *const *passwords,

        int password_count

    )
    {

        return test_passwords_with_parts(seven_zip_dll_path, archive_path, {archive_path}, passwords, password_count);
    }

    PasswordTestResult test_passwords_with_parts(

        const std::wstring &seven_zip_dll_path,

        const std::wstring &archive_path,

        const std::vector<std::wstring> &part_paths,

        const wchar_t *const *passwords,

        int password_count,

        const std::vector<std::wstring> &canonical_names

    )
    {

#ifdef _WIN32

        CreateObjectFunc create_object = cached_create_object(seven_zip_dll_path);

        if (!create_object)
        {

            PasswordTestResult result;

            result.status = PasswordTestStatus::BackendUnavailable;

            result.message = "7z.dll could not be loaded";

            return result;
        }

        PasswordTestResult last;

        last.backend_available = true;

        if (password_count <= 0)
        {

            const wchar_t *empty = L"";

            passwords = &empty;

            password_count = 1;
        }

        const std::wstring ext = lower_extension(archive_path);

        const bool retry_unsupported_as_password =

            ext == L".7z" ||

            ext == L".001" ||

            ext == L".rar" ||

            ext == L".r00" ||

            ext == L".jpg" ||

            ext == L".jpeg" ||

            ext == L".png" ||

            ext == L".gif" ||

            ext == L".pdf" ||

            ext == L".webp" ||

            is_sfx_path(archive_path);

        const std::vector<std::wstring> effective_part_paths =

            part_paths.empty() ? std::vector<std::wstring>{archive_path} : part_paths;

        if (seven_zip_parts_prove_missing_tail(effective_part_paths, !canonical_names.empty()))
        {
            return needs_volume_or_tail_damaged_result("seven_zip_start_header_length");
        }
        if (zip_parts_require_unavailable_tail(effective_part_paths, !canonical_names.empty()))
        {
            return needs_volume_or_tail_damaged_result("zip_eocd_unavailable");
        }

        const std::vector<GUID> formats = candidate_formats(archive_path, effective_part_paths);

        for (int i = 0; i < password_count; ++i)
        {

            const wchar_t *raw_password = passwords[i] ? passwords[i] : L"";

            PasswordTestResult current = test_one_password(

                create_object,

                archive_path,

                raw_password,

                effective_part_paths,

                formats,

                {},

                true,

                canonical_names);

            current.attempts = i + 1;

            last = current;

            if (current.status == PasswordTestStatus::Ok)
            {

                current.matched_index = i;

                return current;
            }

            if (current.status == PasswordTestStatus::Damaged &&
                current.operation_result == kOpHeadersError)
            {

                continue;
            }

            if (current.status == PasswordTestStatus::BackendUnavailable ||

                current.status == PasswordTestStatus::Damaged ||

                current.status == PasswordTestStatus::NeedsVolumeOrTailDamaged ||

                current.status == PasswordTestStatus::Error)
            {

                current.matched_index = -1;

                return current;
            }

            if (current.status == PasswordTestStatus::Unsupported && !retry_unsupported_as_password)
            {

                current.matched_index = -1;

                return current;
            }
        }

        last.status = PasswordTestStatus::WrongPassword;

        last.matched_index = -1;

        last.attempts = password_count;

        last.message = "wrong password";

        return last;

#else

        (void)seven_zip_dll_path;

        (void)archive_path;

        (void)passwords;

        (void)password_count;

        PasswordTestResult result;

        result.status = PasswordTestStatus::BackendUnavailable;

        result.message = "native password testing is only implemented on Windows";

        return result;

#endif
    }

    PasswordTestResult test_passwords_with_ranges(

        const std::wstring &seven_zip_dll_path,

        const std::wstring &archive_path,

        const std::vector<ExtractInputRange> &ranges,

        const std::wstring &format_hint,

        const wchar_t *const *passwords,

        int password_count

    )
    {

#ifdef _WIN32

        CreateObjectFunc create_object = cached_create_object(seven_zip_dll_path);

        if (!create_object)
        {

            PasswordTestResult result;

            result.status = PasswordTestStatus::BackendUnavailable;

            result.message = "7z.dll could not be loaded";

            return result;
        }

        PasswordTestResult last;

        last.backend_available = true;

        if (password_count <= 0)
        {

            const wchar_t *empty = L"";

            passwords = &empty;

            password_count = 1;
        }

        const std::vector<std::wstring> part_paths{archive_path};

        const std::vector<GUID> formats = candidate_formats_for_hint(format_hint, archive_path, part_paths);

        for (int i = 0; i < password_count; ++i)
        {

            const wchar_t *raw_password = passwords[i] ? passwords[i] : L"";

            PasswordTestResult current = test_one_password(

                create_object,

                archive_path,

                raw_password,

                part_paths,

                formats,

                ranges,

                true);

            current.attempts = i + 1;

            last = current;

            if (current.status == PasswordTestStatus::Ok)
            {

                current.matched_index = i;

                return current;
            }

            if (current.status == PasswordTestStatus::Damaged &&
                current.operation_result == kOpHeadersError)
            {

                continue;
            }

            if (current.status == PasswordTestStatus::BackendUnavailable ||

                current.status == PasswordTestStatus::Damaged ||

                current.status == PasswordTestStatus::NeedsVolumeOrTailDamaged ||

                current.status == PasswordTestStatus::Error)
            {

                current.matched_index = -1;

                return current;
            }
        }

        last.status = PasswordTestStatus::WrongPassword;

        last.matched_index = -1;

        last.attempts = password_count;

        last.message = "wrong password";

        return last;

#else

        (void)seven_zip_dll_path;

        (void)archive_path;

        (void)ranges;

        (void)format_hint;

        (void)passwords;

        (void)password_count;

        PasswordTestResult result;

        result.status = PasswordTestStatus::BackendUnavailable;

        result.message = "native password testing is only implemented on Windows";

        return result;

#endif
    }

} // namespace sunpack::sevenzip
