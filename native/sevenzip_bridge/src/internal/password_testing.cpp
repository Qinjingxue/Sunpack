#include "sevenzip_bridge/bridge.hpp"

#include <algorithm>
#include <optional>

#include "password_probe_policy.hpp"

#include "sevenzip_callbacks.hpp"

#include "sevenzip_formats.hpp"

#include "sevenzip_paths.hpp"

#include "sevenzip_properties.hpp"

#include "sevenzip_status.hpp"

#include "sevenzip_streams.hpp"

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

        bool encrypted_header_range_probe_candidate(const std::wstring &format_hint)
        {
            std::wstring hint = lower_text(format_hint);
            if (!hint.empty() && hint.front() == L'.')
            {
                hint.erase(hint.begin());
            }
            return hint == L"7z" || hint == L"sevenzip" || hint == L"seven_zip" ||
                   hint == L"rar" || hint == L"rar4" || hint == L"rar5";
        }

        struct BoundedPasswordProbeSelection
        {
            std::optional<UInt32> index;
            bool item_count_known = false;
            UInt32 item_count = 0;
            bool encrypted = false;
        };

        BoundedPasswordProbeSelection bounded_password_probe_selection(IInArchive *archive)
        {
            BoundedPasswordProbeSelection selection;
            if (!archive)
            {
                return selection;
            }
            if (archive->GetNumberOfItems(&selection.item_count) != S_OK)
            {
                return selection;
            }
            selection.item_count_known = true;
            PROPVARIANT archive_value;
            PropVariantInit(&archive_value);
            const bool solid = archive->GetArchiveProperty(kpidSolid, &archive_value) == S_OK && prop_bool(archive_value);
            clear_prop(archive_value);

            struct Candidate { UInt32 index; UInt64 size; };
            std::optional<Candidate> regular, encrypted;
            auto remember = [solid](std::optional<Candidate> &current, Candidate item) {
                if (!current || (!solid && item.size < current->size)) current = item;
            };
            for (UInt32 index = 0; index < selection.item_count; ++index)
            {
                PROPVARIANT value{};
                const bool is_encrypted = get_item_property(archive, index, kpidEncrypted, value) && prop_bool(value);
                clear_prop(value);
                selection.encrypted = selection.encrypted || is_encrypted;
                const bool is_dir = get_item_property(archive, index, kpidIsDir, value) && prop_bool(value);
                clear_prop(value);
                if (is_dir) continue;
                const bool size_known = get_item_property(archive, index, kpidSize, value);
                const UInt64 size = prop_u64(value);
                clear_prop(value);
                // An empty ZipCrypto item proves only the weak header byte.
                // Missing size metadata must not be mistaken for an empty file.
                if (size_known && size == 0) continue;
                remember(regular, {index, size});
                if (is_encrypted)
                {
                    remember(encrypted, {index, size});
                    if (solid) break; // The first eligible encrypted item is final.
                }
            }
            const auto &selected = selection.encrypted ? encrypted : regular;
            if (!selected) return selection;
            selection.index = selected->index;
            return selection;
        }

        // One batch owns at most one reusable handler. Encrypted headers still
        // open per candidate; neither archive objects nor callbacks enter a
        // process cache or survive the batch's last confirmation.
        struct PasswordProbeCache
        {
            CMyComPtr<IInArchive> archive;
            CMyComPtr<IArchiveOpenCallback> callback;
            OpenCallback *callback_state = nullptr;
            BoundedPasswordProbeSelection selection;
            PasswordTestResult evidence;

            void reset()
            {
                if (archive) archive->Close();
                archive.Release();
                callback.Release();
                callback_state = nullptr;
            }
            ~PasswordProbeCache() { reset(); }
        };

        bool probe_opened_archive(
            IInArchive *archive, const BoundedPasswordProbeSelection &selection,
            const std::wstring &password, bool &encryption_evidence,
            HRESULT &hr, Int32 &operation)
        {
            auto *raw_callback = new ExtractCallback(password);
            CMyComPtr<IArchiveExtractCallback> callback(raw_callback);
            if (!selection.index)
            {
                const auto disposition = empty_bounded_password_probe_disposition(
                    selection.item_count_known, selection.item_count, encryption_evidence);
                if (disposition == EmptyBoundedPasswordProbeDisposition::AcceptOpenProof)
                {
                    hr = S_OK;
                    operation = kOpOk;
                    return true;
                }
                if (disposition == EmptyBoundedPasswordProbeDisposition::RejectInconclusive)
                {
                    hr = S_FALSE;
                    operation = kOpWrongPassword;
                    return false;
                }
                hr = archive->Extract(nullptr, static_cast<UInt32>(kAllItems), kTestMode, callback);
            }
            else
            {
                hr = archive->Extract(&*selection.index, 1, kTestMode, callback);
            }
            operation = raw_callback->operation_result();
            encryption_evidence = encryption_evidence || raw_callback->password_requested();
            return true;
        }

    } // namespace

    PasswordTestResult test_one_password(


        const std::wstring &archive_path,

        const std::wstring &password,

        const std::vector<std::wstring> &part_paths,

        const std::vector<GUID> &formats,

        const std::vector<ExtractInputRange> &input_ranges,

        const std::vector<std::wstring> &canonical_names,
        const std::wstring &format_hint,
        PasswordProbeCache &cache,
        bool scan_only

    )
    {
        if (native_job_cancelled()) {
            PasswordTestResult result;
            result.status = PasswordTestStatus::Error;
            result.message = "password probe cancelled";
            return result;
        }
        if (cache.archive)
        {
            PasswordTestResult result = cache.evidence;
            bool encrypted = result.encrypted;
            HRESULT hr = S_OK;
            Int32 operation = kOpOk;
            const bool tested = probe_opened_archive(cache.archive, cache.selection, password,
                encrypted, hr, operation);
            result.operation_result = operation;
            if (tested && !cache.callback_state->password_requested())
            {
                if (hr == S_OK && operation == kOpOk)
                {
                    result.status = PasswordTestStatus::Ok;
                    result.message = "password accepted";
                    return result;
                }
                if (looks_wrong_password(hr, operation, encrypted))
                {
                    result.status = PasswordTestStatus::WrongPassword;
                    result.encrypted = result.password_required = result.wrong_password = true;
                    result.message = "wrong password";
                    return result;
                }
            }
            // An inconclusive handler result keeps the original fallback path.
            cache.reset();
        }

        PasswordTestResult result;

        result.backend_available = true;

        result.archive_offset = input_ranges.empty() ? 0 : input_ranges.front().start;
        result.archive_type = format_hint;

        bool any_format_created = false;

        bool any_opened = false;

        HRESULT last_hr = E_FAIL;

        Int32 last_op_res = kOpOk;
        bool last_encryption_evidence = false;

        const UInt64 start_only = 0;
        for (std::size_t attempt_index = 0; attempt_index < formats.size() * 2; ++attempt_index)
        {
            if (native_job_cancelled()) {
                result.status = PasswordTestStatus::Error;
                result.message = "password probe cancelled";
                return result;
            }
            const GUID &format = formats[attempt_index % formats.size()];
            const UInt64 *search_limit = attempt_index < formats.size() ? &start_only : nullptr;

            CMyComPtr<IInArchive> archive;

            HRESULT hr = create_in_archive(format, &archive);

            if (hr != S_OK || !archive)
            {

                last_hr = hr;

                continue;
            }

            any_format_created = true;

            bool stream_opened = false;

            CMyComPtr<IInStream> stream = open_archive_stream(archive_path, part_paths, stream_opened,
                nullptr, !canonical_names.empty(), InputPrefetchConfig{false}, input_ranges);

            if (!stream_opened)
            {

                const auto numbered = [](const std::wstring& path) { return parse_volume_number(path).has_value(); };
                if (is_sfx_path(archive_path) &&
                    (std::any_of(part_paths.begin(), part_paths.end(), numbered) ||
                     (part_paths.empty() && !canonical_names.empty() &&
                      std::any_of(input_ranges.begin(), input_ranges.end(), [&](const ExtractInputRange& range) {
                          return numbered(range.path);
                      }))))
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
            auto *raw_open_callback = new OpenCallback(password, callback_path, part_paths, canonical_names, InputPrefetchConfig{false}, native_job_cancel_token(), input_ranges);
            CMyComPtr<IArchiveOpenCallback> open_callback(raw_open_callback);

            hr = archive->Open(stream.Interface(), search_limit, open_callback.Interface());
            // A later handler/search attempt cannot erase an earlier
            // encrypted-header callback from this candidate's Open.
            last_encryption_evidence = last_encryption_evidence || raw_open_callback->password_requested();

            if (raw_open_callback->missing_volume_requested())
            {
                auto missing = needs_volume_or_tail_damaged_result(
                    "open_volume_callback_not_found",
                    raw_open_callback->missing_volume_name());
                missing.archive_offset = result.archive_offset;
                if (!format_hint.empty()) missing.archive_type = format_hint;
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
            result.archive_type = canonical_archive_type_for_guid(format);
            result.is_archive = true;
            auto selection = bounded_password_probe_selection(archive);
            if (selection.item_count_known && rar4_rejected_empty_encrypted_headers(
                    archive.Interface(), format, selection.item_count, raw_open_callback->password_requested()))
            {
                result.status = PasswordTestStatus::WrongPassword;
                result.encrypted = result.password_required = result.wrong_password = true;
                result.operation_result = kOpWrongPassword;
                result.message = "RAR4 encrypted headers could not be decoded";
                archive->Close();
                return result;
            }
            last_encryption_evidence = last_encryption_evidence || selection.encrypted;
            result.encrypted = result.encrypted || last_encryption_evidence;
            result.password_required = result.password_required || last_encryption_evidence;
            if (scan_only && !selection.encrypted && !last_encryption_evidence && selection.item_count_known)
            {
                archive->Close();
                result.status = PasswordTestStatus::Ok;
                return result;
            }
            if (scan_only && !selection.index && selection.item_count != 0 && selection.encrypted)
            {
                archive->Close();
                result.status = PasswordTestStatus::Error;
                result.message = "no nonempty encrypted item can confirm the password";
                return result;
            }
            const bool tested = probe_opened_archive(archive, selection, password,
                last_encryption_evidence, hr, last_op_res);
            result.operation_result = last_op_res;
            last_hr = hr;
            if (!tested)
            {
                archive->Close();
                continue;
            }
            if (!raw_open_callback->password_requested() &&
                looks_wrong_password(hr, last_op_res, last_encryption_evidence))
            {
                cache.reset();
                cache.archive = archive;
                cache.callback = open_callback;
                cache.callback_state = raw_open_callback;
                cache.selection = std::move(selection);
                cache.evidence = result;
            }
            else archive->Close();

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

            result.message = "the embedded 7-Zip backend did not create a supported archive handler";
        }
        else if (!any_opened &&
                 (looks_wrong_password(last_hr, last_op_res, last_encryption_evidence) ||
                  (!input_ranges.empty() && encrypted_header_range_probe_candidate(format_hint))))
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

        return result;
    }

#endif

    PasswordTestResult test_password_batch(
        const std::wstring &archive_path,
        const std::vector<std::wstring> &part_paths,
        const std::vector<ExtractInputRange> &input_ranges,
        const std::wstring &format_hint,
        const std::wstring *candidates,
        std::size_t candidate_count,
        const std::vector<std::wstring> &canonical_names,
        bool scan_only)
    {
#ifdef _WIN32
        PasswordProbeCache cache;
        const auto formats = extraction_formats_for_hint(format_hint);
        const std::wstring empty;
        const auto count = (std::max)(candidate_count, std::size_t{1});
        PasswordTestResult last;
        for (std::size_t index = 0; index < count; ++index)
        {
            if (native_job_cancelled()) {
                last.status = PasswordTestStatus::Error;
                last.message = "password probe cancelled";
                return last;
            }
            auto current = test_one_password(archive_path, candidate_count == 0 ? empty : candidates[index],
                part_paths, formats, input_ranges, canonical_names, format_hint, cache, scan_only);
            current.attempts = static_cast<int>(index + 1);
            if (native_job_cancelled()) {
                current.status = PasswordTestStatus::Error;
                current.message = "password probe cancelled";
                return current;
            }
            if (current.status == PasswordTestStatus::Ok)
            {
                current.matched_index = static_cast<int>(index);
                return current;
            }
            if (current.status != PasswordTestStatus::WrongPassword &&
                !(current.status == PasswordTestStatus::Damaged && current.operation_result == kOpHeadersError))
                return current;
            last = std::move(current);
        }
        last.status = PasswordTestStatus::WrongPassword;
        last.matched_index = -1;
        last.attempts = static_cast<int>(count);
        last.message = "wrong password";
        return last;
#else
        PasswordTestResult result;
        result.status = PasswordTestStatus::BackendUnavailable;
        result.message = "native password testing is only implemented on Windows";
        return result;
#endif
    }

} // namespace sunpack::sevenzip
