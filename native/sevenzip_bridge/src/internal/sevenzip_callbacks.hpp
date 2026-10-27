#pragma once

#include "sevenzip_properties.hpp"
#include "sevenzip_paths.hpp"

#include "sevenzip_streams.hpp"

#include "sevenzip_async_output.hpp"

#include "sevenzip_space_directory.hpp"
#include "native_memory.hpp"
#include "sevenzip_status.hpp"
#include <exception>

#ifdef _WIN32

#include <algorithm>

#include <cstddef>

#include <cwctype>

#include <filesystem>

#include <map>

#include <optional>

#include <mutex>

#include <string>
#include <stdexcept>

#include <unordered_set>
#include <unordered_map>

#include <utility>

#include <vector>

#endif

namespace sunpack::sevenzip
{

#ifdef _WIN32

    class OpenCallback final : public CMyUnknownImp, public IArchiveOpenCallback, public IArchiveOpenVolumeCallback, public ICryptoGetTextPassword
    {
        Z7_COM_UNKNOWN_IMP_3(IArchiveOpenCallback, IArchiveOpenVolumeCallback, ICryptoGetTextPassword)
        

    public:
        explicit OpenCallback(
            std::wstring password,
            std::wstring archive_path = L"",
            std::vector<std::wstring> part_paths = {},
            std::vector<std::wstring> canonical_names = {},
            InputPrefetchConfig volume_prefetch_config = input_prefetch_config())

            : password_(std::move(password)),

              archive_path_(std::move(archive_path)),

              part_paths_(std::move(part_paths)),

              volume_prefetch_config_(volume_prefetch_config)
        {

            if (!canonical_names.empty() && canonical_names.size() == part_paths_.size())
            {
                for (std::size_t index = 0; index < part_paths_.size(); ++index)
                {
                    const std::wstring alias = lower_path(std::filesystem::path(canonical_names[index]).filename().wstring());
                    if (!alias.empty())
                        volume_paths_[alias] = part_paths_[index];
                }
                return;
            }

            for (const auto &path : part_paths_)
            {

                const std::wstring name = lower_path(std::filesystem::path(path).filename().wstring());

                if (!name.empty())
                {

                    volume_paths_[name] = path;
                }

                volume_paths_[lower_path(std::filesystem::path(path).wstring())] = path;
            }

            if (!archive_path_.empty())
            {

                const std::wstring name = lower_path(std::filesystem::path(archive_path_).filename().wstring());

                if (!name.empty())
                {

                    volume_paths_[name] = archive_path_;
                }

                volume_paths_[lower_path(std::filesystem::path(archive_path_).wstring())] = archive_path_;
            }
        }


        HRESULT STDMETHODCALLTYPE SetTotal(const UInt64 *, const UInt64 *) SUP7Z_NOEXCEPT override { return S_OK; }

        HRESULT STDMETHODCALLTYPE SetCompleted(const UInt64 *, const UInt64 *) SUP7Z_NOEXCEPT override { return S_OK; }

        HRESULT STDMETHODCALLTYPE GetProperty(PROPID propID, PROPVARIANT *value) SUP7Z_NOEXCEPT override
        {

            if (!value)
            {

                return E_POINTER;
            }

            value->vt = VT_EMPTY;

            if (propID == kpidName && !archive_path_.empty())
            {

                value->vt = VT_BSTR;

                value->bstrVal = SysAllocString(archive_path_.c_str());

                return value->bstrVal ? S_OK : E_OUTOFMEMORY;
            }

            return S_OK;
        }

        HRESULT STDMETHODCALLTYPE GetStream(const wchar_t *name, IInStream **inStream) SUP7Z_NOEXCEPT override
        {

            if (!inStream)
            {

                return E_POINTER;
            }

            *inStream = nullptr;

            if (!name)
            {
                volume_open_failed_ = true;
                return E_FAIL;
            }

            std::wstring requested = lower_path(std::filesystem::path(name).filename().wstring());

            auto found = volume_paths_.find(requested);

            if (found == volume_paths_.end())
            {

                requested = lower_path(std::wstring(name));

                found = volume_paths_.find(requested);
            }

            if (found == volume_paths_.end())
            {
                missing_volume_requested_ = true;
                missing_volume_name_ = std::filesystem::path(name).filename().wstring();
                return E_FAIL;
            }

            // CMyComPtr's raw-pointer constructor AddRefs, giving the object its
            // first reference. The holder also releases it on every early return.
            CMyComPtr<IInStream> stream_holder(
                new FileInStream(found->second, nullptr, L"file", volume_prefetch_config_));
            auto *stream = static_cast<FileInStream *>(stream_holder.Interface());

            if (!stream->is_open())
            {
                volume_open_failed_ = true;
                failed_volume_name_ = std::filesystem::path(found->second).filename().wstring();

                return E_FAIL;
            }

            // The holder's reference is the one being handed over, so Detach
            // instead of AddRef: ownership moves to the caller untouched.
            *inStream = stream_holder.Detach();

            return S_OK;
        }

        bool missing_volume_requested() const { return missing_volume_requested_; }
        bool volume_open_failed() const { return volume_open_failed_; }
        bool password_requested() const { return password_requested_; }
        const std::wstring &missing_volume_name() const { return missing_volume_name_; }
        const std::wstring &failed_volume_name() const { return failed_volume_name_; }

        HRESULT STDMETHODCALLTYPE CryptoGetTextPassword(BSTR *password) SUP7Z_NOEXCEPT override
        {

            if (!password)
            {

                return E_POINTER;
            }

            password_requested_ = true;
            *password = SysAllocString(password_.c_str());

            return *password ? S_OK : E_OUTOFMEMORY;
        }

    private:
        static std::wstring lower_path(std::wstring value)
        {
            return lower_text(std::move(value));
        }


        std::wstring password_;

        std::wstring archive_path_;

        std::vector<std::wstring> part_paths_;

        const InputPrefetchConfig volume_prefetch_config_;

        std::map<std::wstring, std::wstring> volume_paths_;

        bool missing_volume_requested_ = false;
        bool volume_open_failed_ = false;
        bool password_requested_ = false;
        std::wstring missing_volume_name_;
        std::wstring failed_volume_name_;
    };

    class ExtractCallback final : public CMyUnknownImp, public IArchiveExtractCallback, public ICryptoGetTextPassword
    {
        Z7_COM_UNKNOWN_IMP_3(IArchiveExtractCallback, IProgress, ICryptoGetTextPassword)
        

    public:
        explicit ExtractCallback(std::wstring password) : password_(std::move(password)) {}

        Int32 operation_result() const { return operation_result_; }
        bool password_requested() const { return password_requested_; }


        HRESULT STDMETHODCALLTYPE SetTotal(UInt64) SUP7Z_NOEXCEPT override { return S_OK; }

        HRESULT STDMETHODCALLTYPE SetCompleted(const UInt64 *) SUP7Z_NOEXCEPT override { return S_OK; }

        HRESULT STDMETHODCALLTYPE GetStream(UInt32, ISequentialOutStream **outStream, Int32) SUP7Z_NOEXCEPT override
        {

            if (!outStream)
            {

                return E_POINTER;
            }

            *outStream = nullptr;

            return S_OK;
        }

        HRESULT STDMETHODCALLTYPE PrepareOperation(Int32) SUP7Z_NOEXCEPT override { return S_OK; }

        HRESULT STDMETHODCALLTYPE SetOperationResult(Int32 opRes) SUP7Z_NOEXCEPT override
        {

            operation_result_ = opRes;

            return S_OK;
        }

        HRESULT STDMETHODCALLTYPE CryptoGetTextPassword(BSTR *password) SUP7Z_NOEXCEPT override
        {

            if (!password)
            {

                return E_POINTER;
            }

            password_requested_ = true;
            *password = SysAllocString(password_.c_str());

            return *password ? S_OK : E_OUTOFMEMORY;
        }

    private:

        std::wstring password_;

        Int32 operation_result_ = kOpOk;
        bool password_requested_ = false;
    };

    class AsyncFileOutStream final : public CMyUnknownImp, public ISequentialOutStream
    {
        Z7_COM_UNKNOWN_IMP_1(ISequentialOutStream)
        

    public:
        AsyncFileOutStream(
            std::shared_ptr<AsyncFileWriter> writer,
            AsyncFileWriter::FileStatePtr file) : writer_(std::move(writer)),
                                                  file_(std::move(file))
        {
            magic_.reserve(512);
        }

        ~AsyncFileOutStream()
        {
            if (writer_ && file_)
            {
                std::lock_guard<std::mutex> lock(mutex_);
                writer_->close_file(file_, std::move(magic_));
            }
        }


        HRESULT STDMETHODCALLTYPE Write(const void *data, UInt32 size, UInt32 *processedSize) SUP7Z_NOEXCEPT override
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!writer_ || !file_)
            {
                if (processedSize)
                {
                    *processedSize = 0;
                }
                return E_FAIL;
            }
            UInt32 consumed = 0;
            HRESULT hr = S_OK;
            while (consumed < size) {
                const auto run = file_->previous_writes().next(position_, size - consumed);
                UInt32 done = 0;
                const auto amount = static_cast<UInt32>(run.second);
                if (run.first) {
                    hr = writer_->skip_written(file_, amount);
                    if (hr == S_OK) done = amount;
                } else hr = writer_->write(file_, static_cast<const unsigned char *>(data) + consumed, amount, &done);
                consumed += done;
                position_ += done;
                if (hr != S_OK || done != amount) break;
            }
            if (consumed != 0 && magic_.size() < 512)
            {
                const auto *bytes = static_cast<const unsigned char *>(data);
                const std::size_t take = std::min<std::size_t>(512 - magic_.size(), consumed);
                magic_.insert(magic_.end(), bytes, bytes + take);
            }
            if (processedSize)
            {
                *processedSize = consumed;
            }
            return hr;
        }

    private:
        std::shared_ptr<AsyncFileWriter> writer_;
        AsyncFileWriter::FileStatePtr file_;
        std::vector<unsigned char> magic_;
        UInt64 position_ = 0;
        std::mutex mutex_;
    };

    class TraceOutStream final : public CMyUnknownImp, public ISequentialOutStream
    {
        Z7_COM_UNKNOWN_IMP_1(ISequentialOutStream)
        

    public:
        explicit TraceOutStream(ExtractOutputTrace *trace = nullptr, std::size_t item_trace_index = 0)

            : trace_(trace),
              item_trace_index_(item_trace_index)
        {
        }

        UInt64 bytes_written() const { return bytes_written_; }


        HRESULT STDMETHODCALLTYPE Write(const void *, UInt32 size, UInt32 *processedSize) SUP7Z_NOEXCEPT override
        {

            bytes_written_ += size;

            if (trace_)
            {

                trace_->total_bytes_written += size;

                trace_->current_item_bytes_written += size;

                trace_->last_write_size = size;

                trace_->last_hresult = S_OK;

                trace_->last_win32_error = 0;

                if (item_trace_index_ < trace_->items.size())
                {

                    trace_->items[item_trace_index_].bytes_written += size;

                    trace_->items[item_trace_index_].hresult = S_OK;

                    trace_->items[item_trace_index_].win32_error = 0;
                }
            }

            if (processedSize)
            {

                *processedSize = size;
            }

            return S_OK;
        }

    private:

        ExtractOutputTrace *trace_ = nullptr;

        std::size_t item_trace_index_ = 0;

        UInt64 bytes_written_ = 0;
    };

    inline bool directory_is_empty_or_missing(const std::filesystem::path &path)
    {
        std::error_code error;
        if (!std::filesystem::exists(path, error))
        {
            return !error;
        }
        error.clear();
        const bool empty = std::filesystem::is_empty(path, error);
        return !error && empty;
    }

    inline std::wstring normalized_output_path_key(const std::filesystem::path &path)
    {
        return lower_text(path.lexically_normal().wstring());
    }

    class OutputPathAllocator
    {
    public:
        explicit OutputPathAllocator(const std::filesystem::path &root, ExtractionReplay *replay = nullptr) : root_(root), replay_(replay) {
            if (replay_) {
                for (const auto &item : replay_->files) if (!item.second.path.empty()) used_.insert(normalized_output_path_key(item.second.path));
                for (const auto &directory : replay_->directories) {
                    directories_.emplace(directory);
                    used_.insert(normalized_output_path_key(directory.second));
                }
            }
        }
        void reserve(std::size_t count) { used_.reserve(count); }
        void preserve_replay() { if (replay_) replay_->directories = std::move(directories_); }

        void clear() noexcept
        {
            std::unordered_set<std::wstring>{}.swap(used_);
            std::unordered_map<std::wstring, std::size_t>{}.swap(next_numbers_);
            std::unordered_map<std::wstring, std::filesystem::path>{}.swap(directories_);
        }

        std::filesystem::path allocate(const std::filesystem::path &requested, bool initially_empty, bool is_directory = false)
        {
            if (is_directory) { return directory(requested, initially_empty); }
            const auto parent = directory(requested.parent_path(), initially_empty);
            return allocate_name(parent / requested.filename(), initially_empty, false);
        }

    private:
        std::filesystem::path directory(const std::filesystem::path &requested, bool initially_empty)
        {
            std::vector<std::filesystem::path> missing;
            auto cursor = requested;
            std::filesystem::path parent;
            for (;;)
            {
                if (cursor == root_) { parent = root_; break; }
                const auto found = directories_.find(normalized_output_path_key(cursor));
                if (found != directories_.end()) { parent = found->second; break; }
                if (cursor.empty() || cursor == cursor.parent_path())
                {
                    throw std::invalid_argument("output path is outside its allocation root");
                }
                missing.push_back(cursor);
                cursor = cursor.parent_path();
            }
            for (auto item = missing.rbegin(); item != missing.rend(); ++item)
            {
                parent = allocate_name(parent / item->filename(), initially_empty, true);
                directories_.emplace(normalized_output_path_key(*item), parent);
            }
            return parent;
        }

        std::filesystem::path allocate_name(const std::filesystem::path &requested, bool initially_empty, bool is_directory)
        {
            auto key = normalized_output_path_key(requested);
            // Keep the common empty-output case to one hash-set insertion.
            if (initially_empty)
            {
                const auto reservation = used_.insert(std::move(key));
                if (reservation.second) { return requested; }
                key = *reservation.first;
            }
            std::error_code directory_error;
            if (!initially_empty && used_.find(key) == used_.end()
                && (available(requested, key) || (is_directory && std::filesystem::is_directory(requested, directory_error))))
            {
                used_.insert(std::move(key));
                return requested;
            }
            auto &next = next_numbers_[key];
            if (next == 0) { next = 1; }
            const auto parent = requested.parent_path();
            const auto stem = (is_directory ? requested.filename() : requested.stem()).wstring();
            const auto extension = is_directory ? std::wstring{} : requested.extension().wstring();
            for (;;)
            {
                const auto candidate = parent / (stem + L"(" + std::to_wstring(next++) + L")" + extension);
                auto candidate_key = normalized_output_path_key(candidate);
                if (available(candidate, candidate_key))
                {
                    used_.insert(std::move(candidate_key));
                    return candidate;
                }
            }
        }

    private:
        bool available(const std::filesystem::path &path, const std::wstring &key) const
        {
            // A queued or failed async write still owns its name. Never wait
            // for it to appear on disk; every conflict advances the number.
            if (used_.find(key) != used_.end()) { return false; }
            std::error_code error;
            return !std::filesystem::exists(path, error);
        }

        std::unordered_set<std::wstring> used_;
        std::unordered_map<std::wstring, std::size_t> next_numbers_;
        std::unordered_map<std::wstring, std::filesystem::path> directories_;
        std::filesystem::path root_;
        ExtractionReplay *replay_;
    };

    inline bool is_windows_invalid_name_char(wchar_t value)
    {
        return value < 0x20 || value == L'<' || value == L'>' || value == L':' || value == L'"' ||
               value == L'|' || value == L'?' || value == L'*';
    }

    // CON/PRN/AUX/NUL/COM1-9/LPT1-9 are reserved with any extension ("con.txt")
    // and with spaces before the extension ("nul .txt").
    inline bool is_windows_reserved_device_name(const std::wstring &part)
    {
        std::size_t stem = part.find(L'.');
        if (stem == std::wstring::npos)
        {
            stem = part.size();
        }
        while (stem > 0 && part[stem - 1] == L' ')
        {
            --stem;
        }
        if (stem != 3 && stem != 4)
        {
            return false;
        }
        const auto lower = [&](std::size_t index)
        {
            const wchar_t value = part[index];
            return (value >= L'A' && value <= L'Z') ? static_cast<wchar_t>(value + (L'a' - L'A')) : value;
        };
        const wchar_t a = lower(0);
        const wchar_t b = lower(1);
        const wchar_t c = lower(2);
        if (stem == 3)
        {
            return (a == L'c' && b == L'o' && c == L'n') || (a == L'p' && b == L'r' && c == L'n') ||
                   (a == L'a' && b == L'u' && c == L'x') || (a == L'n' && b == L'u' && c == L'l');
        }
        const wchar_t digit = part[3];
        return digit >= L'1' && digit <= L'9' &&
               ((a == L'c' && b == L'o' && c == L'm') || (a == L'l' && b == L'p' && c == L't'));
    }

    // Output paths are opened through the \\?\ prefix, which disables Win32 name
    // normalization: ':' would create an alternate data stream, trailing dots or
    // spaces and device names would create entries ordinary tools cannot remove,
    // and the remaining characters fail the item.  Mirror 7-Zip's extractor:
    // replace them with '_' and prefix reserved device names.
    inline void make_windows_safe_path_part(std::wstring &part)
    {
        for (auto &value : part)
        {
            if (is_windows_invalid_name_char(value))
            {
                value = L'_';
            }
        }
        for (std::size_t index = part.size(); index > 0 && (part[index - 1] == L'.' || part[index - 1] == L' '); --index)
        {
            part[index - 1] = L'_';
        }
        if (is_windows_reserved_device_name(part))
        {
            part.insert(part.begin(), L'_');
        }
    }

    inline std::optional<std::filesystem::path> safe_relative_item_path(const std::wstring &raw_name)
    {

        if (raw_name.empty())
        {

            return std::nullopt;
        }

        std::filesystem::path candidate(raw_name);

        if (candidate.is_absolute() || candidate.has_root_name() || candidate.has_root_directory())
        {

            return std::nullopt;
        }

        std::filesystem::path normalized;

        for (const auto &part : candidate)
        {

            auto text = part.wstring();

            if (text.empty() || text == L"." || text == L"/" || text == L"\\")
            {

                continue;
            }

            if (text == L"..")
            {

                return std::nullopt;
            }

            make_windows_safe_path_part(text);

            normalized /= text;
        }

        if (normalized.empty())
        {

            return std::nullopt;
        }

        return normalized;
    }

    class ExtractToDiskCallback final : public CMyUnknownImp, public IArchiveExtractCallback, public ICryptoGetTextPassword
    {
        Z7_COM_UNKNOWN_IMP_3(IArchiveExtractCallback, IProgress, ICryptoGetTextPassword)
        

    public:
        ExtractToDiskCallback(

            IInArchive *archive,

            std::wstring password,

            std::wstring output_dir,

            ExtractProgressCallback progress,

            bool dry_run = false,

            ExtractOutputTrace *output_trace = nullptr,

            UInt32 estimated_items = 0,

            std::shared_ptr<AsyncFileWriter> shared_writer = nullptr,

            std::size_t job_buffer_budget = 0,

            std::shared_ptr<std::atomic<bool>> cancel_token = nullptr
#ifdef SUP7Z_ENABLE_PIPELINE_TIMING
            , PipelineTiming *pipeline_timing = nullptr
#endif

            ) : archive_(archive),

                password_(std::move(password)),

                output_dir_(std::move(output_dir)),

                progress_(std::move(progress)),

                dry_run_(dry_run),

                output_trace_(output_trace ? output_trace : &owned_output_trace_)
#ifdef SUP7Z_ENABLE_PIPELINE_TIMING
                , pipeline_timing_(pipeline_timing)
#endif
                ,
                async_writer_(dry_run ? nullptr : (shared_writer ? std::move(shared_writer) : std::make_shared<AsyncFileWriter>())),

                cancel_token_(std::move(cancel_token)),

                async_job_(async_writer_ ? async_writer_->make_job(job_buffer_budget, cancel_token_
#ifdef SUP7Z_ENABLE_PIPELINE_TIMING
                    , pipeline_timing_
#endif
                    ) : nullptr),

                output_root_(win32_extended_path(output_dir_)),

                replay_(current_extraction_replay),
                output_root_initially_empty_(replay_ && replay_->initialized ? replay_->root_was_empty : directory_is_empty_or_missing(output_root_)),
                output_paths_(output_root_, replay_)
        {
            if (replay_ && !replay_->initialized) {
                replay_->root_was_empty = output_root_initially_empty_;
            }
            output_paths_.reserve(static_cast<std::size_t>(estimated_items) * 2U + 1U);
            created_directories_.reserve(static_cast<std::size_t>(estimated_items) + 1U);
            // Query the handler's property schema once. ZIP/7z/stream hot paths
            // need neither a per-file link query nor a link index.
            UInt32 count = 0;
            if (archive_ && archive_->GetNumberOfProperties(&count) == S_OK)
                for (UInt32 i = 0; i < count; ++i)
                {
                    BSTR name = nullptr;
                    PROPID property = 0;
                    VARTYPE type = VT_EMPTY;
                    const HRESULT hr = archive_->GetPropertyInfo(i, &name, &property, &type);
                    SysFreeString(name);
                    if (hr == S_OK && property == kpidHardLink) { supports_hard_links_ = true; break; }
                }
        }

        ~ExtractToDiskCallback() { finalize_output(); }

        void set_input_file(const std::wstring &path)
        {
            default_input_name_ = std::filesystem::path(path).stem().wstring();
            // Same fallback as 7z.exe for disk input. The canonical entry path
            // already comes from the input plan; do not inspect/reclassify parts.
            WIN32_FILE_ATTRIBUTE_DATA data{};
            if (!dry_run_ && GetFileAttributesExW(win32_extended_path(path).c_str(),
                    GetFileExInfoStandard, &data))
            {
                archive_mtime_ = data.ftLastWriteTime;
                has_archive_mtime_ = true;
            }
        }

        Int32 operation_result() const { return operation_result_; }
        bool password_requested() const { return password_requested_; }

        UInt32 files_written() const { return files_written_; }

        UInt32 dirs_written() const { return dirs_written_; }

        UInt64 bytes_written() const { return bytes_written_; }

        UInt64 completed_bytes() const { return completed_bytes_; }

        const std::wstring &failed_item() const { return failed_item_; }

        UInt32 failed_item_index() const { return failed_item_index_; }

        UInt64 failed_item_bytes_written() const { return failed_item_bytes_written_; }

        bool output_error() const { return output_error_; }

        bool output_root_initially_empty() const { return output_root_initially_empty_; }

#ifdef _WIN32
        // 直接驱动条目目录创建（ensure_directory 本身是 private），生产代码不调用。
        bool ensure_directory_for_test(const std::wstring &directory, int *out_error_code)
        {
            std::error_code error;
            const bool ready = ensure_directory(std::filesystem::path(directory), &error);
            if (out_error_code)
            {
                *out_error_code = error.value();
            }
            return ready;
        }
#endif

        void finalize_output() noexcept
        {
            if (output_finalized_)
            {
                return;
            }
            output_finalized_ = true;
            archive_ = nullptr; // metadata needed below was captured during GetStream
            // Decoder callbacks are over. Directory reservations survive until
            // the final snapshot, so a late interruption can replay collisions.
            std::unordered_set<std::wstring>{}.swap(created_directories_);
            if (!async_writer_)
            {
                output_paths_.clear();
                finalize_hard_links();
                return;
            }

            const HRESULT writer_error = async_writer_->finish_job(async_job_);
            const int writer_win32_error = writer_error == S_OK
                                               ? 0
                                               : async_writer_->current_win32_error(async_job_);
            bool has_failed_file = false;
            UInt64 total_written = 0;
            UInt32 completed_files = 0;
            for (const auto &state : async_files_)
            {
                if (!state)
                {
                    continue;
                }
                const auto snapshot = async_writer_->snapshot_file(state);
                total_written += snapshot.written_bytes;
                const bool decoder_ok = snapshot.operation_result_set &&
                                        snapshot.operation_result == kOpOk;
                const bool output_ok = snapshot.closed && !snapshot.failed;
                if (decoder_ok && output_ok)
                {
                    ++completed_files;
                    record_metadata_errors(snapshot.metadata_errors, state->item_index, state->item_path, false);
                }

                if (output_trace_ && state->trace_index < output_trace_->items.size())
                {
                    auto &item = output_trace_->items[state->trace_index];
                    item.bytes_written = snapshot.written_bytes;
                    item.operation_result = snapshot.operation_result;
                    item.magic = snapshot.magic;
                    item.has_mtime_ns = snapshot.has_mtime_ns;
                    item.mtime_ns = snapshot.mtime_ns;
                    item.failed = item.failed || !decoder_ok || !output_ok;
                    item.done = decoder_ok && output_ok;
                    if (item.done && item.has_source_crc32)
                    {
                        item.output_crc32 = item.source_crc32;
                        item.has_output_crc32 = true;
                    }
                    item.crc_verified = item.done && (!item.has_source_crc32 ||
                                                      (item.has_output_crc32 && item.source_crc32 == item.output_crc32));
                    if (snapshot.failed)
                    {
                        item.hresult = static_cast<int>(snapshot.hresult);
                        item.win32_error = snapshot.win32_error;
                    }
                }

                if (snapshot.failed)
                {
                    has_failed_file = true;
                    output_error_ = true;
                    if (failed_item_.empty())
                    {
                        failed_item_ = state->item_path;
                        failed_item_index_ = state->item_index;
                        failed_item_bytes_written_ = snapshot.written_bytes;
                    }
                    if (output_trace_)
                    {
                        output_trace_->last_hresult = static_cast<int>(snapshot.hresult);
                        output_trace_->last_win32_error = snapshot.win32_error;
                    }
                }
            }
            files_written_ = completed_files;
            bytes_written_ = total_written;
            if (output_trace_)
            {
                output_trace_->total_bytes_written = total_written;
                if (!async_files_.empty() && async_files_.back())
                {
                    output_trace_->current_item_bytes_written =
                        async_writer_->snapshot_file(async_files_.back()).written_bytes;
                }
            }
            if (writer_error != S_OK)
            {
                output_error_ = true;
                // FileState 诊断在 writer 排空后才是权威，仅对无关联文件的调度失败回退。
                if (!has_failed_file)
                {
                    mark_current_item_failure(writer_error, writer_win32_error);
                    if (output_trace_)
                    {
                        output_trace_->last_hresult = static_cast<int>(writer_error);
                        output_trace_->last_win32_error = writer_win32_error;
                    }
                }
            }
            if (output_error_ && operation_result_ == kOpOk)
            {
                operation_result_ = kOpDataError;
            }
            finalize_hard_links();
            restore_directory_metadata();
            const auto *memory = current_native_memory_job();
            if (replay_ && (is_cancelled() || std::uncaught_exceptions() ||
                is_memory_hresult(writer_error) || (memory && (memory->revoked.load() || memory->denied.load())))) {
                replay_->initialized = true;
                output_paths_.preserve_replay();
                for (const auto &state : async_files_) async_writer_->capture_replay(state, replay_);
                for (const auto &item : output_trace_->items)
                    if (!item.is_dir && item.done && !item.output_path.empty() && replay_->files.find(item.index) == replay_->files.end()) {
                        auto &receipt = replay_->files[item.index];
                        receipt.path = (output_root_ / item.output_path).native();
                        receipt.created = receipt.complete = true;
                        receipt.written.add(0, item.bytes_written);
                        receipt.has_mtime = item.has_mtime_ns;
                        receipt.mtime = item.mtime_ns;
                    }
            }
            output_paths_.clear();
        }


        HRESULT STDMETHODCALLTYPE SetTotal(UInt64 total) SUP7Z_NOEXCEPT override
        {

            std::lock_guard<std::recursive_mutex> lock(state_mutex_);

            if (is_cancelled())
            {
                return E_ABORT;
            }

            total_bytes_ = total;

            emit("total", 0, L"");

            return S_OK;
        }

        HRESULT STDMETHODCALLTYPE SetCompleted(const UInt64 *completeValue) SUP7Z_NOEXCEPT override
        {

            std::lock_guard<std::recursive_mutex> lock(state_mutex_);

            if (is_cancelled())
            {
                return E_ABORT;
            }

            if (completeValue)
            {

                completed_bytes_ = *completeValue;

                emit("progress", current_index_, current_item_);
            }

            return S_OK;
        }

        HRESULT STDMETHODCALLTYPE GetStream(UInt32 index, ISequentialOutStream **outStream, Int32 askExtractMode) SUP7Z_NOEXCEPT override
        {

            std::lock_guard<std::recursive_mutex> lock(state_mutex_);

            if (!outStream)
            {

                return E_POINTER;
            }

            *outStream = nullptr;

            if (is_cancelled())
            {
                return E_ABORT;
            }

            current_index_ = index;

            current_item_.clear();

            current_item_bytes_written_ = 0;

            current_item_is_dir_ = false;

            current_trace_active_ = false;

            current_async_file_.reset();

            if (askExtractMode != kExtractMode)
            {

                return S_OK;
            }

            PROPVARIANT value{};

            bool is_dir = false;

            if (get_item_property(archive_, index, kpidIsDir, value))
            {

                is_dir = prop_bool(value);
            }

            clear_prop(value);

            UInt64 expected_size = 0;
            bool has_expected_size = false;
            if (!is_dir && get_item_property(archive_, index, kpidSize, value))
            {
                expected_size = prop_u64(value);
                has_expected_size = true;
            }
            clear_prop(value);

            UInt32 source_crc32 = 0;
            bool has_source_crc32 = false;
            if (!is_dir && get_item_property(archive_, index, kpidCRC, value))
            {
                source_crc32 = prop_u32(value);
                has_source_crc32 = true;
            }
            clear_prop(value);

            bool encrypted = false;
            if (!is_dir && get_item_property(archive_, index, kpidEncrypted, value))
            {
                encrypted = prop_bool(value);
            }
            clear_prop(value);

            std::wstring name;
            if (get_item_property(archive_, index, kpidPath, value))
            {
                name = prop_text(value);
            }
            clear_prop(value);
            if (name.empty() && get_item_property(archive_, index, kpidName, value))
            {
                name = prop_text(value);
            }
            clear_prop(value);

            std::wstring hard_link;
            const bool is_hard_link = !is_dir && supports_hard_links_ && get_item_property(archive_, index, kpidHardLink, value);
            if (is_hard_link)
                hard_link = prop_text(value);
            clear_prop(value);
            // RAR5 exposes a zero CRC for its payload-less link record. It is
            // not a checksum of the referenced file; finalization inherits the
            // verified target receipt instead of comparing against that zero.
            if (is_hard_link) has_source_crc32 = false;

            if (name.empty())
            {
                // Stream handlers (bzip2/xz/zstd, gzip without FNAME) carry no
                // item name.  Like 7-Zip's default-name rule, name the payload
                // after the input filename with its outer extension removed.
                // Output reservations must never rename a nested volume.
                name = default_item_name(index);
            }

            current_item_ = name;

            current_item_is_dir_ = is_dir;

            if (output_trace_)
            {

                output_trace_->current_item_index = index;

                output_trace_->current_item_path = name;

                output_trace_->current_item_bytes_written = 0;

                begin_item_trace(
                    index,
                    name,
                    is_dir,
                    encrypted,
                    expected_size,
                    has_expected_size,
                    source_crc32,
                    has_source_crc32);
            }

            // Like 7z's normal x mode, ignore entries denoting the output root.
            if (is_dir && (name == L"." || name == L"./" || name == L".\\"))
            {
                emit("item_start", index, name);
                dirs_written_ += 1;
                return S_OK;
            }

            const auto safe_path = safe_relative_item_path(name);

            if (!safe_path.has_value())
            {

                failed_item_ = name;

                failed_item_index_ = index;

                failed_item_bytes_written_ = 0;

                output_error_ = true;

                mark_current_item_failure(E_INVALIDARG, 0);

                return E_INVALIDARG;
            }

            emit("item_start", index, name);

            std::filesystem::path target;
            ReplayFile *receipt = nullptr;
            if (replay_) {
                const auto found = replay_->files.find(index);
                if (found != replay_->files.end()) receipt = &found->second;
            }
            try
            {
                // 目录创建失败按真实 std::error_code 判定并透传，空间错误码不能被吞成 E_FAIL。
                std::error_code directory_error;
                bool directory_ready = true;

                if (is_dir)
                {

                    if (!dry_run_)
                    {

                        target = receipt && !receipt->path.empty() ? std::filesystem::path(receipt->path)
                            : output_paths_.allocate(output_root_ / safe_path.value(), output_root_initially_empty_, true);
                        if (receipt) receipt->path = target.native();

                        directory_ready = ensure_directory(target, &directory_error);
                        if (directory_ready)
                        {
                            const auto metadata = read_item_metadata(index, true);
                            if (metadata.defined)
                            {
                                const auto &text = target.native();
                                const auto depth = static_cast<std::size_t>(std::count_if(
                                    text.begin(), text.end(), [](wchar_t c) { return c == L'/' || c == L'\\'; }));
                                directory_metadata_.push_back({target, metadata, depth, index, current_trace_index_});
                            }
                        }

                        if (directory_ready && output_trace_ && current_trace_index_ < output_trace_->items.size())
                        {
                            output_trace_->items[current_trace_index_].output_path = target.lexically_relative(output_root_).generic_wstring();
                        }
                    }

                    if (directory_ready)
                    {
                        dirs_written_ += 1;

                        return S_OK;
                    }
                }
                else if (!dry_run_)
                {

                    target = receipt && !receipt->path.empty() ? std::filesystem::path(receipt->path)
                        : available_output_path(output_root_ / safe_path.value());
                    if (receipt) receipt->path = target.native();

                    directory_ready = ensure_directory(target.parent_path(), &directory_error);

                    if (directory_ready && output_trace_ && current_trace_index_ < output_trace_->items.size())
                    {

                        output_trace_->items[current_trace_index_].output_path = target.lexically_relative(output_root_).generic_wstring();
                    }
                }

                if (!directory_ready)
                {
                    failed_item_ = name;

                    failed_item_index_ = index;

                    failed_item_bytes_written_ = current_item_bytes_written_;

                    output_error_ = true;

                    // 透传真实错误码：空间不足与路径不可用必须能被上层区分。
                    const int win32_error = directory_error.value();
                    if (output_trace_)
                    {
                        output_trace_->last_win32_error = win32_error;
                    }
                    mark_current_item_failure(
                        HRESULT_FROM_WIN32(static_cast<DWORD>(win32_error)), win32_error);

                    return static_cast<Int32>(HRESULT_FROM_WIN32(static_cast<DWORD>(win32_error)));
                }
            }
            catch (const std::bad_alloc &)
            {
                output_error_ = true;
                mark_current_item_failure(E_OUTOFMEMORY, ERROR_OUTOFMEMORY);
                return E_OUTOFMEMORY;
            }
            catch (...)
            {
                // Preserve the explicit allocation error above for replay.

                failed_item_ = name;

                failed_item_index_ = index;

                failed_item_bytes_written_ = current_item_bytes_written_;

                output_error_ = true;

                mark_current_item_failure(E_FAIL, 0);

                return E_FAIL;
            }

            if (dry_run_)
            {

                if (is_hard_link) return defer_hard_link(std::move(hard_link));

                // Objects start at refcount 0, so the CMyComPtr constructor
                // performs the first AddRef and Detach hands that single owned
                // reference to 7-Zip, which will Release it.
                CMyComPtr<ISequentialOutStream> stream_owner(new TraceOutStream(output_trace_, current_trace_index_));
                *outStream = stream_owner.Detach();

                return S_OK;
            }

            if (!async_writer_)
            {
                mark_current_item_failure(E_FAIL, 0);
                output_error_ = true;
                return E_FAIL;
            }
            // Link entries contain no decoder payload. In particular RAR5 must
            // receive a null stream, otherwise it tries to decode an empty body.
            if (is_hard_link) return defer_hard_link(std::move(hard_link));
            const auto metadata = read_item_metadata(index, false);
            current_async_file_ = async_writer_->make_file(async_job_,
                                                           target.wstring(), name, index, current_trace_index_, metadata
#ifdef SUP7Z_ENABLE_WRITER_PROBE
                                                           , has_expected_size ? expected_size : 0
#endif
                                                           , receipt
                                                           );
            async_files_.push_back(current_async_file_);

            CMyComPtr<ISequentialOutStream> stream_owner(new AsyncFileOutStream(async_writer_, current_async_file_));
            *outStream = stream_owner.Detach();

            return S_OK;
        }

        HRESULT STDMETHODCALLTYPE PrepareOperation(Int32) SUP7Z_NOEXCEPT override { return S_OK; }

        HRESULT STDMETHODCALLTYPE SetOperationResult(Int32 opRes) SUP7Z_NOEXCEPT override
        {

            std::lock_guard<std::recursive_mutex> lock(state_mutex_);

            if (is_cancelled())
            {
                return E_ABORT;
            }

            if (current_async_file_)
            {
                async_writer_->record_operation_result(current_async_file_, opRes);
                current_item_bytes_written_ = async_writer_->accepted_bytes(current_async_file_);
                if (output_trace_)
                {
                    output_trace_->current_item_bytes_written = current_item_bytes_written_;
                }
            }

            if (opRes != kOpOk || operation_result_ == kOpOk)
            {

                operation_result_ = opRes;
            }

            if (opRes == kOpOk && !current_item_.empty() && !current_item_is_dir_ && !async_writer_)
            {

                files_written_ += 1;
            }
            else if (opRes != kOpOk && failed_item_.empty())
            {

                failed_item_ = current_item_;

                failed_item_index_ = current_index_;
            }

            current_item_bytes_written_ = output_trace_ ? output_trace_->current_item_bytes_written : current_item_bytes_written_;

            finish_current_item_trace(opRes);

            if (opRes != kOpOk)
            {

                failed_item_bytes_written_ = current_item_bytes_written_;
            }

            emit(opRes == kOpOk ? "item_done" : "item_failed", current_index_, current_item_);

            if (async_writer_)
            {
                const HRESULT writer_error = async_writer_->current_error(async_job_);
                if (writer_error != S_OK)
                {
                    output_error_ = true;
                    mark_current_item_failure(writer_error, async_writer_->current_win32_error(async_job_));
                    return writer_error;
                }
            }
            return S_OK;
        }

        HRESULT STDMETHODCALLTYPE CryptoGetTextPassword(BSTR *password) SUP7Z_NOEXCEPT override
        {

            std::lock_guard<std::recursive_mutex> lock(state_mutex_);

            if (!password)
            {

                return E_POINTER;
            }

            password_requested_ = true;
            *password = SysAllocString(password_.c_str());

            return *password ? S_OK : E_OUTOFMEMORY;
        }

    private:
        struct HardLink
        {
            std::size_t trace;
            std::wstring target;
            std::size_t source = static_cast<std::size_t>(-1);
            unsigned char state = 0;
        };

        static std::wstring archive_path_key(const std::wstring &name)
        {
            // Archive identity is case sensitive; Windows output collisions
            // have already been resolved by OutputPathAllocator.
            return std::filesystem::path(name).lexically_normal().generic_wstring();
        }

        HRESULT defer_hard_link(std::wstring target)
        {
            if (!safe_relative_item_path(target))
            {
                output_error_ = true;
                mark_current_item_failure(E_INVALIDARG, ERROR_INVALID_NAME);
                return E_INVALIDARG;
            }
            hard_links_.push_back({current_trace_index_, archive_path_key(target)});
            // Some SDK handlers skip SetOperationResult for a null stream.
            // Only finalization may publish success for these entries.
            output_trace_->items[current_trace_index_].done = false;
            return S_OK;
        }

        void finalize_hard_links() noexcept
        {
            if (hard_links_.empty()) return;
            auto &items = output_trace_->items;
            const auto fail = [&](HardLink &link, DWORD error, bool output_failure)
            {
                auto &item = items[link.trace];
                item.done = false;
                item.failed = true;
                item.crc_verified = false;
                item.operation_result = kOpDataError;
                // A missing/cyclic/unverified target is archive damage, not a
                // failed filesystem operation. Preserve the decoder's error.
                item.win32_error = output_failure ? error : 0;
                item.hresult = output_failure ? static_cast<int>(HRESULT_FROM_WIN32(error)) : S_OK;
                output_error_ = output_error_ || output_failure;
                if (operation_result_ == kOpOk) operation_result_ = kOpDataError;
                if (failed_item_.empty())
                {
                    failed_item_ = item.path;
                    failed_item_index_ = item.index;
                }
                if (output_failure)
                {
                    output_trace_->last_win32_error = error;
                    output_trace_->last_hresult = item.hresult;
                }
            };
            try
            {
                // Allocate only for names actually referenced by hard links.
                std::unordered_map<std::wstring, std::vector<std::size_t>> targets;
                std::unordered_map<std::size_t, std::size_t> links;
                for (std::size_t i = 0; i < hard_links_.size(); ++i)
                {
                    targets.try_emplace(hard_links_[i].target);
                    links.emplace(hard_links_[i].trace, i);
                    items[hard_links_[i].trace].done = false;
                }
                for (std::size_t i = 0; i < items.size(); ++i)
                    if (!items[i].is_dir)
                    {
                        const auto found = targets.find(archive_path_key(items[i].path));
                        if (found != targets.end()) found->second.push_back(i);
                    }
                for (auto &link : hard_links_)
                {
                    const auto &candidates = targets.at(link.target);
                    const auto next = std::lower_bound(candidates.begin(), candidates.end(), link.trace);
                    // Repeated archive names refer to their latest preceding
                    // version; otherwise allow a forward reference.
                    if (next != candidates.begin()) link.source = *std::prev(next);
                    else if (next != candidates.end()) link.source = *next;
                }
                std::vector<std::size_t> chain;
                for (std::size_t start = 0; start < hard_links_.size(); ++start)
                {
                    chain.clear();
                    auto cursor = start;
                    while (hard_links_[cursor].state == 0)
                    {
                        auto &link = hard_links_[cursor];
                        link.state = 1;
                        chain.push_back(cursor);
                        const auto next = links.find(link.source);
                        if (next == links.end()) break;
                        cursor = next->second;
                    }
                    for (auto it = chain.rbegin(); it != chain.rend(); ++it)
                    {
                        auto &link = hard_links_[*it];
                        auto &item = items[link.trace];
                        DWORD error = ERROR_INVALID_DATA;
                        bool output_failure = false;
                        if (link.source < items.size())
                        {
                            const auto &source = items[link.source];
                            if (!item.failed && source.done && !source.failed && source.crc_verified &&
                                (!item.has_expected_size || item.expected_size == 0 || item.expected_size == source.bytes_written))
                            {
                                const auto path = (output_root_ / item.output_path).make_preferred();
                                const auto target = (output_root_ / source.output_path).make_preferred();
                                const auto saved = replay_ ? replay_->files.find(item.index) : std::map<std::uint32_t, ReplayFile>::iterator{};
                                const bool already_created = replay_ && saved != replay_->files.end() && saved->second.complete;
                                const auto result = dry_run_ || already_created ? AttemptResult{} : retry_with_space_gate(
                                    volume_space_gate(), [&] { return space_terminal_predicate(); }, path.native(),
                                    [&]() noexcept -> AttemptResult
                                    {
                                        if (is_cancelled()) return {AttemptResult::Kind::Terminal, 0};
                                        if (CreateHardLinkW(path.c_str(), target.c_str(), nullptr)) return {};
                                        const DWORD code = GetLastError();
                                        return {is_space_exhaustion_error(code) ? AttemptResult::Kind::SpaceFailure : AttemptResult::Kind::PermanentFailure, code};
                                    });
                                if (result.kind == AttemptResult::Kind::Succeeded)
                                {
                                    item.bytes_written = source.bytes_written;
                                    item.expected_size = source.bytes_written;
                                    item.has_expected_size = true;
                                    item.magic = source.magic;
                                    item.has_mtime_ns = source.has_mtime_ns;
                                    item.mtime_ns = source.mtime_ns;
                                    item.has_output_crc32 = source.has_output_crc32;
                                    item.output_crc32 = source.output_crc32;
                                    item.crc_verified = true;
                                    item.done = true;
                                    item.operation_result = kOpOk;
                                    ++files_written_;
                                    bytes_written_ += item.bytes_written;
                                    output_trace_->total_bytes_written += item.bytes_written;
                                    error = 0;
                                }
                                else
                                {
                                    error = result.win32_error ? result.win32_error : ERROR_CANCELLED;
                                    output_failure = true;
                                }
                            }
                        }
                        if (error) fail(link, error, output_failure);
                        link.state = 2;
                    }
                }
            }
            catch (...)
            {
                for (auto &link : hard_links_) if (link.state != 2) fail(link, ERROR_NOT_ENOUGH_MEMORY, true);
            }
            std::vector<HardLink>{}.swap(hard_links_);
        }

        ArchiveItemMetadata read_item_metadata(UInt32 index, bool is_dir) const
        {
            ArchiveItemMetadata metadata;
            PROPVARIANT value{};
            const auto read_time = [&](UInt32 property, FILETIME &time, unsigned char flag)
            {
                if (get_item_property(archive_, index, property, value) && value.vt == VT_FILETIME)
                {
                    time = value.filetime;
                    metadata.defined |= flag;
                }
                clear_prop(value);
            };
            read_time(kpidCTime, metadata.creation, ArchiveItemMetadata::Creation);
            read_time(kpidATime, metadata.access, ArchiveItemMetadata::Access);
            read_time(kpidMTime, metadata.modification, ArchiveItemMetadata::Modification);
            if (!(metadata.defined & ArchiveItemMetadata::Modification) && has_archive_mtime_)
            {
                metadata.modification = archive_mtime_;
                metadata.defined |= ArchiveItemMetadata::Modification;
            }
            if (get_item_property(archive_, index, kpidAttrib, value) && value.vt == VT_UI4)
            {
                metadata.attributes = value.ulVal;
                metadata.defined |= ArchiveItemMetadata::Attributes;
            }
            clear_prop(value);
            // Match 7z's small POSIX -> Windows attribute mapping, without
            // implementing Unix permissions or owners.
            if (!(metadata.defined & ArchiveItemMetadata::Attributes) &&
                get_item_property(archive_, index, kpidPosixAttrib, value) && value.vt == VT_UI4)
            {
                metadata.attributes = is_dir ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_ARCHIVE;
                if ((value.ulVal & 0222) == 0) metadata.attributes |= FILE_ATTRIBUTE_READONLY;
                metadata.defined |= ArchiveItemMetadata::Attributes;
            }
            clear_prop(value);
            return metadata;
        }

        void record_metadata_errors(const ArchiveMetadataErrors &errors, UInt32 index,
                                    const std::wstring &name, bool is_dir)
        {
            if (!errors.first_error() || !output_trace_) return;
            auto &trace = *output_trace_;
            if (trace.metadata_failed_files == 0 && trace.metadata_failed_directories == 0)
            {
                trace.metadata_first_item_index = index;
                trace.metadata_first_item = name;
                trace.metadata_first_win32_error = errors.first_error();
                trace.metadata_first_is_attributes = errors.time == 0;
            }
            if (is_dir) ++trace.metadata_failed_directories;
            else ++trace.metadata_failed_files;
            if (errors.time) ++trace.metadata_failed_times;
            if (errors.attributes) ++trace.metadata_failed_attributes;
        }

        struct DirectoryMetadata
        {
            std::filesystem::path target;
            ArchiveItemMetadata metadata;
            std::size_t depth;
            UInt32 item_index;
            std::size_t trace_index;
        };

        void restore_directory_metadata() noexcept
        {
            // Like 7z: children before parents, original order at equal depth.
            std::sort(directory_metadata_.begin(), directory_metadata_.end(),
                [](const DirectoryMetadata &a, const DirectoryMetadata &b)
                { return a.depth != b.depth ? a.depth > b.depth : a.item_index < b.item_index; });
            for (const auto &directory : directory_metadata_)
            {
                ArchiveMetadataErrors errors;
                try
                {
                    ensure_no_reparse_ancestors(directory.target);
                    const HANDLE handle = CreateFileW(win32_extended_path(directory.target.native()).c_str(),
                        FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
                    if (handle == INVALID_HANDLE_VALUE)
                    {
                        const DWORD error = GetLastError();
                        if (directory.metadata.has_times()) errors.time = error;
                        if (directory.metadata.defined & ArchiveItemMetadata::Attributes) errors.attributes = error;
                    }
                    else
                    {
                        errors.time = directory.metadata.set_times(handle);
                        errors.attributes = directory.metadata.set_attributes(handle);
                        if (!CloseHandle(handle) && !errors.first_error()) errors.time = GetLastError();
                    }
                }
                catch (const std::filesystem::filesystem_error &error)
                {
                    if (directory.metadata.has_times()) errors.time = static_cast<DWORD>(error.code().value());
                    if (directory.metadata.defined & ArchiveItemMetadata::Attributes)
                        errors.attributes = static_cast<DWORD>(error.code().value());
                }
                catch (...)
                {
                    if (directory.metadata.has_times()) errors.time = ERROR_NOT_ENOUGH_MEMORY;
                    if (directory.metadata.defined & ArchiveItemMetadata::Attributes)
                        errors.attributes = ERROR_NOT_ENOUGH_MEMORY;
                }
                if (output_trace_ && directory.trace_index < output_trace_->items.size())
                    record_metadata_errors(errors, directory.item_index,
                        output_trace_->items[directory.trace_index].path, true);
            }
            std::vector<DirectoryMetadata>{}.swap(directory_metadata_);
        }

        std::wstring default_item_name(UInt32 index) const
        {
            const std::wstring &leaf = default_input_name_;
            if (leaf.empty() || leaf == L"." || leaf == L"..")
            {
                return L"#" + std::to_wstring(index);
            }
            return index == 0 ? leaf : leaf + L"_" + std::to_wstring(index);
        }

        // 本 callback 所属卷的空间 gate，可能为 nullptr（功能关闭 / 无卷身份）。
        VolumeSpaceGate *volume_space_gate() const noexcept
        {
#ifdef _WIN32
            return async_writer_ ? async_writer_->volume_state()->space_gate.get() : nullptr;
#else
            return nullptr;
#endif
        }

        // gate 的终态谓词：显式取消或 writer 整体停止，只读 atomic。
        TerminalPredicate space_terminal_predicate() const
        {
            const auto token = cancel_token_;
            const auto writer = async_writer_;
            return [token, writer]
            {
                if (token && token->load(std::memory_order_acquire))
                {
                    return true;
                }
#ifdef _WIN32
                return writer && writer->stopping();
#else
                return false;
#endif
            };
        }

        std::filesystem::path available_output_path(const std::filesystem::path &requested)
        {
            return output_paths_.allocate(requested, output_root_initially_empty_);
        }

        // 可暂停的目录创建，与根输出目录创建共用同一个原语。
        // created_directories_.insert 必须在成功之后：把失败的目录记进 memo 会让它不再被创建。
        // ensure_no_reparse_ancestors() 会抛 filesystem_error，必须在 noexcept 的 helper 之外 catch。
        bool ensure_directory(const std::filesystem::path &directory, std::error_code *out_error)
        {
            if (out_error)
            {
                out_error->clear();
            }

            const auto key = normalized_output_path_key(directory);
            if (created_directories_.find(key) != created_directories_.end())
            {
                // Successful checks/creation belong to this extraction callback.
                // Repeated files in the same directory reuse that result.
                return true;
            }

            try
            {
                ensure_no_reparse_ancestors(directory);
            }
            catch (const std::filesystem::filesystem_error &error)
            {
                if (out_error)
                {
                    *out_error = error.code();
                }
                return false;
            }
            catch (const std::bad_alloc &)
            {
                throw; // GetStream translates it to E_OUTOFMEMORY, not a path failure.
            }
            catch (...)
            {
                if (out_error)
                {
                    *out_error = std::make_error_code(std::errc::permission_denied);
                }
                return false;
            }

            std::error_code create_error;
            if (!create_directories_with_space_gate(
                    directory, volume_space_gate(), space_terminal_predicate(), &create_error))
            {
                if (out_error)
                {
                    *out_error = create_error;
                }
                return false;
            }

            created_directories_.insert(key);
            return true;
        }

        void ensure_no_reparse_ancestors(const std::filesystem::path &directory) const
        {
            const auto relative = directory.lexically_relative(output_root_);
            if (relative.empty())
            {
                return;
            }
            for (const auto &part : relative)
            {
                if (part == L"..")
                {
                    throw std::filesystem::filesystem_error(
                        "output path escapes extraction root",
                        directory,
                        std::make_error_code(std::errc::permission_denied));
                }
            }
            auto current = output_root_;
            for (const auto &part : relative)
            {
                current /= part;
                std::error_code error;
                const auto status = std::filesystem::symlink_status(current, error);
                if (!error && std::filesystem::is_symlink(status))
                {
                    throw std::filesystem::filesystem_error(
                        "output path traverses a symbolic link",
                        current,
                        std::make_error_code(std::errc::permission_denied));
                }
#ifdef _WIN32
                const DWORD attributes = GetFileAttributesW(current.c_str());
                if (attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
                {
                    throw std::filesystem::filesystem_error(
                        "output path traverses a reparse point",
                        current,
                        std::make_error_code(std::errc::permission_denied));
                }
#endif
            }
        }

        void begin_item_trace(
            UInt32 index,
            const std::wstring &item_path,
            bool is_dir,
            bool encrypted,
            UInt64 expected_size,
            bool has_expected_size,
            UInt32 source_crc32,
            bool has_source_crc32)
        {

            if (!output_trace_)
            {

                return;
            }

            ExtractOutputItemTrace item;

            item.index = index;

            item.path = item_path;

            item.is_dir = is_dir;

            item.encrypted = encrypted;

            item.expected_size = expected_size;

            item.has_expected_size = has_expected_size;

            item.source_crc32 = source_crc32;

            item.has_source_crc32 = has_source_crc32;

            item.operation_result = kOpOk;

            output_trace_->items.push_back(std::move(item));

            current_trace_index_ = output_trace_->items.size() - 1;

            current_trace_active_ = true;
        }

        void finish_current_item_trace(Int32 opRes)
        {

            if (!output_trace_ || !current_trace_active_ || current_trace_index_ >= output_trace_->items.size())
            {

                return;
            }

            auto &item = output_trace_->items[current_trace_index_];

            item.bytes_written = output_trace_->current_item_bytes_written;

            item.operation_result = opRes;

            item.done = opRes == kOpOk && !item.failed;

            if (item.done && item.has_source_crc32)
            {
                // Seven-Zip 只在按归档 CRC 校验通过后才报 kOpOk，直接复用该值。
                item.output_crc32 = item.source_crc32;
                item.has_output_crc32 = true;
            }

            item.failed = item.failed || opRes != kOpOk;

            item.crc_verified = item.done && (!item.has_source_crc32 ||
                                              (item.has_output_crc32 && item.source_crc32 == item.output_crc32));

            item.hresult = output_trace_->last_hresult;

            item.win32_error = output_trace_->last_win32_error;
        }

        void mark_current_item_failure(HRESULT hr, int win32_error)
        {

            if (!output_trace_ || !current_trace_active_ || current_trace_index_ >= output_trace_->items.size())
            {

                return;
            }

            auto &item = output_trace_->items[current_trace_index_];

            item.bytes_written = output_trace_->current_item_bytes_written;

            item.hresult = static_cast<int>(hr);

            item.win32_error = win32_error;

            item.failed = true;

            output_trace_->last_hresult = static_cast<int>(hr);

            output_trace_->last_win32_error = win32_error;
        }

        void emit(const std::string &event, UInt32 item_index, const std::wstring &item_path)
        {

            std::lock_guard<std::recursive_mutex> lock(state_mutex_);

            if (!progress_)
            {

                return;
            }

            ExtractProgressEvent progress;

            progress.event = event;

            progress.completed_bytes = completed_bytes_;

            progress.total_bytes = total_bytes_;

            progress.item_index = item_index;

            progress.item_path = item_path;

            progress_(progress);
        }


        IInArchive *archive_ = nullptr;

        std::wstring password_;

        std::wstring output_dir_;
        std::wstring default_input_name_;
        FILETIME archive_mtime_{};
        bool has_archive_mtime_ = false;
        std::vector<DirectoryMetadata> directory_metadata_;

        ExtractProgressCallback progress_;

        bool dry_run_ = false;

        ExtractOutputTrace owned_output_trace_;
        ExtractOutputTrace *output_trace_ = nullptr;
        std::vector<HardLink> hard_links_;
        bool supports_hard_links_ = false;

#ifdef SUP7Z_ENABLE_PIPELINE_TIMING
        PipelineTiming *pipeline_timing_ = nullptr;
#endif

        std::shared_ptr<AsyncFileWriter> async_writer_;

        std::shared_ptr<std::atomic<bool>> cancel_token_;

        AsyncFileWriter::JobStatePtr async_job_;

        mutable std::recursive_mutex state_mutex_;

        std::vector<AsyncFileWriter::FileStatePtr> async_files_;

        AsyncFileWriter::FileStatePtr current_async_file_;

        bool is_cancelled() const noexcept
        {
            return cancel_token_ && cancel_token_->load(std::memory_order_acquire);
        }

        std::filesystem::path output_root_;
        ExtractionReplay *replay_ = nullptr;

        bool output_root_initially_empty_ = false;

        OutputPathAllocator output_paths_;

        std::unordered_set<std::wstring> created_directories_;

        UInt64 completed_bytes_ = 0;

        UInt64 total_bytes_ = 0;

        UInt64 bytes_written_ = 0;

        UInt64 current_item_bytes_written_ = 0;

        UInt64 failed_item_bytes_written_ = 0;

        UInt32 current_index_ = 0;

        UInt32 failed_item_index_ = 0;

        UInt32 files_written_ = 0;

        UInt32 dirs_written_ = 0;

        std::size_t current_trace_index_ = 0;

        std::wstring current_item_;

        std::wstring failed_item_;

        Int32 operation_result_ = kOpOk;

        bool current_item_is_dir_ = false;

        bool current_trace_active_ = false;

        bool output_error_ = false;

        bool output_finalized_ = false;
        bool password_requested_ = false;
    };

#endif

} // namespace sunpack::sevenzip
