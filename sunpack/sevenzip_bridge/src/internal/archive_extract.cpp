#include "sevenzip_bridge/bridge.hpp"

#include "archive_operations.hpp"

#include "sevenzip_callbacks.hpp"

#include "sevenzip_formats.hpp"
#include "lz4_handler.hpp"

#include "sevenzip_paths.hpp"

#include "sevenzip_status.hpp"

#include "sevenzip_streams.hpp"

#ifdef _WIN32
#include "sevenzip_async_output.hpp"
#include "sevenzip_space_directory.hpp"
#include "Windows/PropVariant.h"
#endif

#ifdef _WIN32

#include <algorithm>
#include <utility>

#endif

namespace sunpack::sevenzip
{

#ifdef _WIN32

    namespace
    {

        bool set_memory_failure(ExtractArchiveResult &result, const char *stage, HRESULT hr)
        {
            if (!is_memory_hresult(hr)) return false;
            result.status = PasswordTestStatus::Error;
            result.failure_stage = stage;
            result.failure_kind = "resource_unavailable";
            result.hresult = static_cast<int>(hr);
            result.message = "insufficient memory to process archive";
            return true;
        }

        void set_failure(ExtractArchiveResult &result, const std::string &stage, const std::string &kind, HRESULT hr = S_OK)
        {

            if (result.failure_stage.empty())
            {

                result.failure_stage = stage;
            }

            if (result.failure_kind.empty())
            {

                result.failure_kind = kind;
            }

            if (hr != S_OK || result.hresult == 0)
            {

                result.hresult = static_cast<int>(hr);
            }
        }

        void set_missing_volume_failure(
            ExtractArchiveResult &result,
            const std::string &stage,
            const std::string &evidence,
            const std::wstring &requested_name = L"",
            HRESULT hr = S_OK)
        {
            result.status = PasswordTestStatus::Damaged;
            result.damaged = true;
            result.missing_volume = true;
            result.missing_volume_evidence = evidence;
            result.missing_volume_name = requested_name;
            set_failure(result, stage, "missing_volume", hr);
            result.message = requested_name.empty()
                                 ? "archive split volume appears incomplete"
                                 : "archive handler requested a missing split volume";
        }

        std::string kind_for_operation_result(Int32 op_res)
        {

            if (op_res == kOpWrongPassword)
            {

                return "encrypted_or_wrong_password";
            }

            if (op_res == kOpCrcError)
            {

                return "checksum_error";
            }

            if (unsupported_method(op_res))
            {

                return "unsupported_method";
            }

            if (op_res == kOpUnexpectedEnd)
            {
                return "unexpected_end";
            }
            if (op_res == kOpHeadersError)
            {
                return "headers_error";
            }
            if (op_res == kOpIsNotArc)
            {
                return "not_archive";
            }
            if (op_res == kOpDataError)
            {
                return "data_error";
            }

            return "unknown";
        }

        std::string summarize_failed_output(ExtractArchiveResult &result, bool collect_damage)
        {
            bool collect_proof = result.encrypted;
            if (!collect_damage && !collect_proof) return {};
            for (const auto &item : result.output_trace.items)
            {
                // A later success cannot prove the password was right after an earlier failure:
                // only CRC matches completed before the first failing item count as evidence.
                if (item.failed || item.operation_result != kOpOk)
                {
                    if (!collect_damage) break;
                    if (!unsupported_method(item.operation_result))
                    {
                        const std::string kind = kind_for_operation_result(item.operation_result);
                        return kind == "unknown" ? "corrupted_data" : kind;
                    }
                    collect_proof = false;
                    continue;
                }
                if (
                    collect_proof && item.encrypted &&
                    !item.is_dir &&
                    item.done &&
                    (!item.has_expected_size || item.bytes_written == item.expected_size) &&
                    (item.password_proof == OutputPasswordProof::Strong ||
                     (item.password_proof == OutputPasswordProof::MeasureSize && strong_member_crc(item.bytes_written))))
                {
                    ++result.password_crc_proven_items;
                }
            }
            return {};
        }

        HRESULT apply_zip_codepage(IInArchive *archive, const std::wstring &codepage)
        {
            if (!archive || codepage.empty())
            {
                return codepage.empty() ? S_OK : E_POINTER;
            }

            UInt32 parsed = 0;
            for (const wchar_t ch : codepage)
            {
                if (ch < L'0' || ch > L'9')
                {
                    return E_INVALIDARG;
                }
                const UInt32 digit = static_cast<UInt32>(ch - L'0');
                if (parsed > (0xFFFFFFFFu - digit) / 10u)
                {
                    return E_INVALIDARG;
                }
                parsed = parsed * 10u + digit;
            }
            if (parsed == 0)
            {
                return E_INVALIDARG;
            }

            CMyComPtr<ISetProperties> properties;
            HRESULT hr = archive->QueryInterface(IID_ISetProperties, (void **)&properties);
            if (hr != S_OK || !properties)
            {
                return hr == S_OK ? E_NOINTERFACE : hr;
            }

            const wchar_t *names[] = {L"cp"};
            PROPVARIANT value{};
            value.vt = VT_UI4;
            value.ulVal = parsed;
            return properties->SetProperties(names, &value, 1);
        }

    } // namespace

#endif

    ExtractArchiveResult extract_archive(
        const std::wstring &archive_path,
        const std::vector<std::wstring> &part_paths,
        const std::vector<ExtractInputRange> &input_ranges,
        const std::wstring &format_hint,
        const std::wstring &password,
        const std::wstring &output_dir,
        const std::wstring &codepage,
        ExtractProgressCallback progress,
        const std::vector<std::wstring> &canonical_names,
        ArchiveOpenMode mode,
        std::shared_ptr<AsyncFileWriter> shared_writer,
        std::shared_ptr<std::atomic<bool>> cancel_token,
        bool output_inventory)
    {
#ifdef _WIN32
        ExtractArchiveResult result;

#ifdef SUP7Z_DEBUG
        auto pipeline_timing = pipeline_timing_enabled() ? std::make_unique<PipelineTiming>(true) : nullptr;
        result.input_trace.pipeline_timing = pipeline_timing.get();
        struct PipelineTimingCapture final
        {
            ExtractArchiveResult &result;
            PipelineTiming *timing;

            ~PipelineTimingCapture() noexcept
            {
                if (timing) result.pipeline_timing = timing->snapshot();
                result.input_trace.pipeline_timing = nullptr;
            }
        } pipeline_capture{result, pipeline_timing.get()};
#endif

        bool any_format_created = false;

        bool any_opened = false;

        HRESULT last_hr = E_FAIL;

        Int32 last_op_res = kOpOk;
        bool last_encryption_evidence = false;

        {
            // The space gate must come from the already existing shared_writer: this runs
            // before ExtractToDiskCallback exists, and the writer is the only gate source.
            VolumeSpaceGate *space_gate = nullptr;
            if (shared_writer)
            {
                space_gate = shared_writer->volume_state()->space_gate.get();
            }
            // 终态谓词：显式取消（executor stop() 会置真 cancel_tokens_）或
            // writer 整体停止（registry shutdown → AsyncFileWriter::finish()）。
            const TerminalPredicate space_terminal = [&cancel_token, &shared_writer]
            {
                if (cancel_token && cancel_token->load(std::memory_order_acquire))
                {
                    return true;
                }
                return shared_writer && shared_writer->stopping();
            };

            std::error_code prepare_error;
#ifdef SUP7Z_DEBUG
            bool directory_ready = false;
            {
                PipelinePrepareScope scope(pipeline_timing.get(), PipelinePreparePhase::OutputDirectory);
                directory_ready = create_directories_with_space_gate(
                    std::filesystem::path(win32_extended_path(output_dir)),
                    space_gate,
                    space_terminal,
                    &prepare_error);
            }
#else
            const bool directory_ready = create_directories_with_space_gate(
                std::filesystem::path(win32_extended_path(output_dir)),
                space_gate,
                space_terminal,
                &prepare_error);
#endif

            if (!directory_ready)
            {
                result.status = PasswordTestStatus::Error;

                set_failure(result, "output_prepare", "output_filesystem");

                // Forward the raw std::error_code through the existing trace channel so the
                // caller can tell "no space" apart from "path unusable".
                result.output_trace.last_hresult =
                    static_cast<int>(HRESULT_FROM_WIN32(static_cast<DWORD>(prepare_error.value())));

                result.message = "output directory could not be created";

                return result;
            }
        }

#ifdef SUP7Z_DEBUG
        const auto formats = [&]()
        {
            PipelinePrepareScope scope(pipeline_timing.get(), PipelinePreparePhase::FormatCandidates);
            return extraction_formats_for_hint(format_hint);
        }();
#else
        const auto formats = extraction_formats_for_hint(format_hint);
#endif
        const auto prefetch_config = input_prefetch_config(format_hint, mode == ArchiveOpenMode::NativeVolumes);

        // Try each handler at the canonical input start before allowing
        // signature search. A wrong handler must not scan the whole archive
        // before the right one gets its turn. Keep search for carrier fallback.
        const UInt64 start_only = 0;
        const bool bounded_composition = current_extraction_replay && current_extraction_replay->volumes.started;
        OpenedArchiveStream input{};
        for (std::size_t attempt_index = 0; attempt_index < formats.count * (bounded_composition ? 1 : 2); ++attempt_index)
        {
            if (cancel_token && cancel_token->load(std::memory_order_acquire)) {
                result.status = PasswordTestStatus::Error;
                set_failure(result, "native_cancel", "cancelled", E_ABORT);
                result.message = "archive extraction cancelled";
                return result;
            }
            const GUID &format = formats[attempt_index % formats.count];
            const UInt64 *search_limit = attempt_index < formats.count ? &start_only : nullptr;

            CMyComPtr<IInArchive> archive;

#ifdef SUP7Z_DEBUG
            HRESULT hr = E_FAIL;
            {
                PipelinePrepareScope scope(pipeline_timing.get(), PipelinePreparePhase::HandlerCreate);
                hr = create_in_archive(format, &archive);
            }
#else
            HRESULT hr = create_in_archive(format, &archive);
#endif

            if (set_memory_failure(result, "handler_create", hr)) return result;

            if (hr != S_OK || !archive)
            {

                last_hr = hr;

                continue;
            }

            any_format_created = true;

            if (!codepage.empty() && format.Data4[5] == 0x01)
            {
                hr = apply_zip_codepage(archive.Interface(), codepage);
                if (hr != S_OK)
                {
                    result.status = PasswordTestStatus::Error;
                    set_failure(result, "filename_encoding", "codepage_apply_failed", hr);
                    result.message = "ZIP filename codepage could not be applied to the archive handler";
                    return result;
                }
            }

            {
#ifdef SUP7Z_DEBUG
                PipelinePrepareScope scope(pipeline_timing.get(), PipelinePreparePhase::StreamOpen);
#endif
                // All handlers in this attempt use the same logical input.
                // Rewind it instead of reopening and restating its volumes.
                if (!input.stream || input.stream->Seek(0, STREAM_SEEK_SET, nullptr) != S_OK)
                    input = open_archive_stream(archive_path, part_paths, &result.input_trace,
                        canonical_names, prefetch_config, input_ranges, nullptr, mode);
            }

            if (!input.opened)
            {

                const HRESULT error = static_cast<HRESULT>(result.input_trace.read_hresult);
                if (set_memory_failure(result, "input_open", error))
                    return result;

                if (!canonical_names.empty() && is_missing_input_file(error)) {
                    set_missing_volume_failure(result, "input_open", "open_volume_file_missing",
                        result.input_trace.last_source_path, error);
                    return result;
                }

                result.status = PasswordTestStatus::Error;

                set_failure(result, "input_open", "input_stream", error);

                result.message = "archive file could not be opened";

                return result;
            }

            auto *raw_open_callback = [&] {
#ifdef SUP7Z_DEBUG
                PipelinePrepareScope scope(pipeline_timing.get(), PipelinePreparePhase::CallbackSetup);
#endif
                return new OpenCallback(
                    password, input.callback_path, part_paths, canonical_names, prefetch_config, cancel_token, input_ranges);
            }();
            CMyComPtr<IArchiveOpenCallback> open_callback(raw_open_callback);

#ifdef SUP7Z_DEBUG
            {
                PipelinePrepareScope scope(pipeline_timing.get(), PipelinePreparePhase::ArchiveOpen);
                hr = archive->Open(input.stream.Interface(), search_limit, open_callback.Interface());
            }
#else
            hr = archive->Open(input.stream.Interface(), search_limit, open_callback.Interface());
#endif
            // A later fallback handler cannot erase the encrypted-header
            // evidence observed by an earlier handler for this password.
            last_encryption_evidence = last_encryption_evidence || raw_open_callback->password_requested();

            if (set_memory_failure(result, "archive_open", hr)) return result;

            const auto volume_read_failed = [&]() {
                const HRESULT callback_error = raw_open_callback->input_error();
                const HRESULT error = FAILED(callback_error) ? callback_error : static_cast<HRESULT>(result.input_trace.read_hresult);
                if (!FAILED(error)) return false;
                if (set_memory_failure(result, "input_read", error)) return true;
                if (FAILED(callback_error))
                    record_input_error(&result.input_trace, raw_open_callback->failed_volume_name(), callback_error);
                if (is_missing_input_file(error)) {
                    const auto &name = FAILED(callback_error) ? raw_open_callback->failed_volume_name()
                        : result.input_trace.last_source_path;
                    set_missing_volume_failure(result, "input_read", "open_volume_file_missing", name, error);
                } else {
                    result.status = PasswordTestStatus::Error;
                    set_failure(result, "input_read", "input_stream", error);
                    result.message = "archive volume could not be read";
                }
                return true;
            };
            if (volume_read_failed()) return result;

            if (raw_open_callback->missing_volume_requested())
            {
                set_missing_volume_failure(
                    result,
                    "archive_open",
                    "open_volume_callback_not_found",
                    raw_open_callback->missing_volume_name(),
                    hr);
                return result;
            }

            if (hr != S_OK)
            {

                last_hr = hr;

                continue;
            }

            any_opened = true;

            UInt32 num_items = 0;
            bool item_count_read;
            {
#ifdef SUP7Z_DEBUG
                PipelinePrepareScope scope(pipeline_timing.get(), PipelinePreparePhase::ItemProbe);
#endif
                item_count_read = archive->GetNumberOfItems(&num_items) == S_OK;
            }
            if (item_count_read) result.item_count = num_items;

            result.archive_type = canonical_archive_type_for_guid(format);
            if (rar4_rejected_empty_encrypted_headers(
                    archive.Interface(), format, num_items, raw_open_callback->password_requested()))
            {
                result.status = PasswordTestStatus::WrongPassword;
                result.encrypted = result.wrong_password = result.password_rejected = true;
                result.operation_result = kOpWrongPassword;
                set_failure(result, "archive_open", "encrypted_or_wrong_password");
                result.message = "RAR4 encrypted headers could not be decoded";
                return result;
            }
            if (format.Data4[5] == 0x01 || format.Data4[5] == 0x03 ||
                format.Data4[5] == 0xCC || format.Data4[5] == 0xEE)
            {
                // An archive can open and yield valid members despite a short
                // structural record. Do not let their success publish the prefix.
                NWindows::NCOM::CPropVariant flags;
                if (archive->GetArchiveProperty(kpidErrorFlags, &flags) == S_OK &&
                    flags.vt == VT_UI4 && (flags.ulVal & kpv_ErrorFlags_UnexpectedEnd))
                {
                    result.status = PasswordTestStatus::Damaged;
                    result.damaged = true;
                    result.operation_result = kOpUnexpectedEnd;
                    set_failure(result, "archive_open", "unexpected_end");
                    result.message = "archive structure is incomplete";
                    return result;
                }
            }
            auto *job_replay = current_extraction_replay;
            std::array<std::uint8_t, 16> handler{};
            static_assert(sizeof(format) == handler.size());
            std::memcpy(handler.data(), &format, sizeof(format));
            // The SDK fallback plan can try more than one handler. Only the
            // handler that produced the saved output may reuse its receipts.
            ExtractionReplayScope handler_replay(job_replay &&
                (!job_replay->initialized || job_replay->handler == handler) ? job_replay : nullptr);
            if (current_extraction_replay && !job_replay->initialized) job_replay->handler = handler;

            ExtractToDiskCallback *raw_extract_callback;
            {
#ifdef SUP7Z_DEBUG
                PipelinePrepareScope scope(pipeline_timing.get(), PipelinePreparePhase::CallbackSetup);
#endif
                raw_extract_callback = new ExtractToDiskCallback(
                    archive.Interface(),
                    password,
                    output_dir,
                    progress,
                    result.output_trace,
                    num_items,
                    shared_writer,
                    cancel_token,
                    output_inventory,
                    &archive_path
#ifdef SUP7Z_DEBUG
                    , pipeline_timing.get()
#endif
                );
            }

            CMyComPtr<IArchiveExtractCallback> extract_callback(raw_extract_callback);

#ifdef SUP7Z_DEBUG
            if (pipeline_timing) pipeline_timing->start_pipeline();
            PipelineThreadCpuScope compute_cpu_scope(pipeline_timing.get());
            PipelineStageScope compute_scope(pipeline_timing.get(), PipelineStage::Compute);
#endif
            hr = archive->Extract(nullptr, static_cast<UInt32>(kAllItems), 0, extract_callback.Interface());
#ifdef SUP7Z_DEBUG
            if (pipeline_timing) result.resolution_decode_qpc = resolution_qpc();
            compute_scope.finish();
#endif

            // Extraction success must not be published before every queued write and close
            // has finished and any delayed filesystem error has been folded back in.
            if (is_memory_hresult(hr))
                if (auto *memory = current_native_memory_job(); memory && !memory->revoked.load())
                    memory->owner.retry(*memory);
            // Output callbacks have captured all item metadata. Release the
            // decoder and its cached dictionaries before draining disk output
            // or allocating a replay inventory under pressure.
            {
#ifdef SUP7Z_DEBUG
                PipelinePrepareScope scope(pipeline_timing.get(), PipelinePreparePhase::ArchiveClose);
#endif
                archive->Close();
                archive.Release();
                input.stream.Release();
            }
            {
#ifdef SUP7Z_DEBUG
                PipelinePrepareScope scope(pipeline_timing.get(), PipelinePreparePhase::OutputFinalize);
#endif
                raw_extract_callback->finalize_output(current_native_cpu_job_context());
            }
            last_hr = hr;

            last_op_res = raw_extract_callback->operation_result();

            result.operation_result = last_op_res;

            result.files_written = raw_extract_callback->files_written();

            result.output_inventory_complete = raw_extract_callback->output_root_initially_empty();

            // Some solid/encrypted handlers ask for a password before GetStream
            // and can fail before an item trace exists. The callback records
            // both password requests and encrypted member properties.
            result.encrypted = result.encrypted || raw_extract_callback->encrypted();
            last_encryption_evidence = last_encryption_evidence || result.encrypted;
            result.hresult = static_cast<int>(hr);

            if (set_memory_failure(result, "item_extract", hr)) return result;
            const bool read_failed = volume_read_failed();
            if (!read_failed && raw_extract_callback->output_error() &&
                set_memory_failure(result, "output_write", static_cast<HRESULT>(result.output_trace.last_hresult)))
                return result;

            if (!read_failed && hr == S_OK && last_op_res == kOpOk)
            {
                result.status = PasswordTestStatus::Ok;
                result.message = "archive extracted";
                return result;
            }

            // CRC receipts only decide whether extraction failures can be
            // attributed to damage after a password was confirmed.
            const bool output_failed = raw_extract_callback->output_error();
            const auto trace_damage_kind = summarize_failed_output(result, !read_failed && !output_failed);
            if (read_failed) return result;

            if (output_failed)
            {

                result.status = PasswordTestStatus::Error;

                set_failure(result, "output_write", "output_filesystem", static_cast<HRESULT>(result.output_trace.last_hresult));

                result.message = "archive item could not be written safely";

                return result;
            }

            if (!trace_damage_kind.empty() && (!last_encryption_evidence || result.password_crc_proven_items != 0))
            {
                result.status = PasswordTestStatus::Damaged;
                result.damaged = true;
                result.checksum_error = trace_damage_kind == "checksum_error";
                set_failure(result, "item_extract", trace_damage_kind, hr);
                result.message = result.checksum_error ? "archive checksum error" : "archive appears damaged";
                return result;
            }

            if (looks_wrong_password(hr, last_op_res, last_encryption_evidence))
            {

                if (password.empty() && (last_op_res == kOpDataError || last_op_res == kOpCrcError || last_op_res == kOpHeadersError || last_op_res == kOpUnexpectedEnd))
                {

                    result.status = PasswordTestStatus::Damaged;

                    result.damaged = true;

                    result.checksum_error = last_op_res == kOpCrcError;

                    set_failure(result, "item_extract", kind_for_operation_result(last_op_res), hr);

                    result.message = result.checksum_error ? "archive checksum error" : "archive appears damaged";

                    return result;
                }

                if (!password.empty() && (last_op_res == kOpDataError || last_op_res == kOpCrcError) &&
                    (result.files_written > 0 || raw_extract_callback->failed_item_had_data()))
                {

                    result.status = PasswordTestStatus::Damaged;

                    result.damaged = true;

                    result.checksum_error = last_op_res == kOpCrcError;

                    set_failure(result, "item_extract", kind_for_operation_result(last_op_res), hr);

                    result.message = result.checksum_error ? "archive checksum error" : "archive appears damaged";

                    return result;
                }

                result.status = PasswordTestStatus::WrongPassword;

                result.encrypted = true;

                result.wrong_password = true;

                result.password_rejected = last_op_res == kOpWrongPassword;

                result.checksum_error = last_op_res == kOpCrcError;

                set_failure(result, "item_extract", "encrypted_or_wrong_password", hr);

                result.message = "archive is encrypted or password is wrong";

                return result;
            }

            if (looks_damaged(last_op_res))
            {

                result.status = PasswordTestStatus::Damaged;

                result.damaged = true;

                set_failure(result, "item_extract", kind_for_operation_result(last_op_res), hr);

                result.message = "archive appears damaged";

                return result;
            }

            result.status = PasswordTestStatus::Unsupported;

            result.unsupported_method = unsupported_method(last_op_res);

            set_failure(result, "item_extract", result.unsupported_method ? "unsupported_method" : "unknown", hr);

            result.message = result.unsupported_method ? "archive uses an unsupported method" : "archive could not be extracted";
        }

        if (!any_format_created)
        {

            result.status = PasswordTestStatus::Unsupported;

            set_failure(result, "handler_create", "unsupported", last_hr);

            result.message = "the embedded 7-Zip backend did not create a supported archive handler";
        }
        else if (!any_opened)
        {

            if (password.empty() && (last_op_res == kOpDataError || last_op_res == kOpCrcError || last_op_res == kOpHeadersError || last_op_res == kOpUnexpectedEnd))
            {

                result.status = PasswordTestStatus::Damaged;

                result.damaged = true;

                result.checksum_error = last_op_res == kOpCrcError;

                set_failure(result, "archive_open", kind_for_operation_result(last_op_res), last_hr);

                result.message = result.checksum_error ? "archive checksum error" : "archive appears damaged";

                return result;
            }

            const bool wrong_password = looks_wrong_password(last_hr, last_op_res, last_encryption_evidence);
            if (wrong_password)
            {
                result.status = PasswordTestStatus::WrongPassword;
                result.wrong_password = true;
                result.password_rejected = last_op_res == kOpWrongPassword;
                result.encrypted = true;
                set_failure(result, "archive_open", "encrypted_or_wrong_password", last_hr);
                result.message = "archive is encrypted or password is wrong";
            }
            else if (!format_hint.empty())
            {
                // Extraction receives an already analyzed format identity from
                // the discovery pipeline. If that exact handler was created but
                // cannot open the supplied input, the format is not unsupported:
                // the confirmed archive structure is incomplete or damaged.
                result.status = PasswordTestStatus::Damaged;
                result.damaged = true;
                set_failure(result, "archive_open", "structure_recognition", last_hr);
                result.message = "confirmed archive structure could not be opened";
            }
            else
            {
                result.status = PasswordTestStatus::Unsupported;
                set_failure(result, "archive_open", "structure_recognition", last_hr);
                result.message = "archive could not be opened by supported handlers";
            }
        }

        return result;
#else
        ExtractArchiveResult result;
        result.status = PasswordTestStatus::BackendUnavailable;
        result.failure_stage = "backend_load";
        result.failure_kind = "backend_unavailable";
        result.message = "native archive extraction is only implemented on Windows";
        return result;
#endif
    }

} // namespace sunpack::sevenzip
