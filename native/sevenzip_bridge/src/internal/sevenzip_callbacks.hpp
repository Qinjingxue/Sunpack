#pragma once



#include "sevenzip_properties.hpp"

#include "sevenzip_streams.hpp"

#include "sevenzip_async_output.hpp"



#ifdef _WIN32

#include <algorithm>

#include <array>

#include <cstddef>

#include <cstring>

#include <cwctype>

#include <filesystem>

#include <map>

#include <optional>

#include <mutex>

#include <string>

#include <unordered_set>

#include <utility>

#include <vector>

#endif



namespace sunpack::sevenzip {



#ifdef _WIN32

inline UInt32 update_crc32(UInt32 crc, const void* data, std::size_t size) {
    using RtlComputeCrc32Fn = ULONG(WINAPI*)(ULONG, const void*, SIZE_T);
    static const auto system_crc32 = []() -> RtlComputeCrc32Fn {
        const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        return ntdll ? reinterpret_cast<RtlComputeCrc32Fn>(GetProcAddress(ntdll, "RtlComputeCrc32")) : nullptr;
    }();
    if (system_crc32 != nullptr) {
        const UInt32 finalized = system_crc32(crc ^ 0xFFFFFFFFU, data, size);
        return finalized ^ 0xFFFFFFFFU;
    }
    static const std::array<std::array<UInt32, 256>, 16> tables = [] {
        std::array<std::array<UInt32, 256>, 16> values{};
        for (UInt32 index = 0; index < 256; ++index) {
            UInt32 value = index;
            for (int bit = 0; bit < 8; ++bit) {
                value = (value >> 1) ^ ((value & 1) ? 0xEDB88320U : 0U);
            }
            values[0][index] = value;
        }
        for (std::size_t slice = 1; slice < values.size(); ++slice) {
            for (std::size_t index = 0; index < 256; ++index) {
                const UInt32 previous = values[slice - 1][index];
                values[slice][index] = values[0][previous & 0xFFU] ^ (previous >> 8);
            }
        }
        return values;
    }();
    const auto* bytes = static_cast<const unsigned char*>(data);
    while (size >= 16) {
        UInt32 first = 0;
        std::memcpy(&first, bytes, sizeof(first));
        first ^= crc;
        crc = tables[15][first & 0xFFU]
            ^ tables[14][(first >> 8) & 0xFFU]
            ^ tables[13][(first >> 16) & 0xFFU]
            ^ tables[12][(first >> 24) & 0xFFU]
            ^ tables[11][bytes[4]] ^ tables[10][bytes[5]]
            ^ tables[9][bytes[6]] ^ tables[8][bytes[7]]
            ^ tables[7][bytes[8]] ^ tables[6][bytes[9]]
            ^ tables[5][bytes[10]] ^ tables[4][bytes[11]]
            ^ tables[3][bytes[12]] ^ tables[2][bytes[13]]
            ^ tables[1][bytes[14]] ^ tables[0][bytes[15]];
        bytes += 16;
        size -= 16;
    }
    while (size-- > 0) {
        crc = tables[0][(crc ^ *bytes++) & 0xFFU] ^ (crc >> 8);
    }
    return crc;
}



class OpenCallback final : public IArchiveOpenCallback, public IArchiveOpenVolumeCallback, public ICryptoGetTextPassword {

public:

    explicit OpenCallback(std::wstring password, std::wstring archive_path = L"", std::vector<std::wstring> part_paths = {}, std::vector<std::wstring> canonical_names = {})

        : password_(std::move(password)),

          archive_path_(std::move(archive_path)),

          part_paths_(std::move(part_paths)) {

        if (!canonical_names.empty() && canonical_names.size() == part_paths_.size()) {
            for (std::size_t index = 0; index < part_paths_.size(); ++index) {
                const std::wstring alias = lower_path(std::filesystem::path(canonical_names[index]).filename().wstring());
                if (!alias.empty()) volume_paths_[alias] = part_paths_[index];
            }
            return;
        }

        for (const auto& path : part_paths_) {

            const std::wstring name = lower_path(std::filesystem::path(path).filename().wstring());

            if (!name.empty()) {

                volume_paths_[name] = path;

            }

            volume_paths_[lower_path(std::filesystem::path(path).wstring())] = path;

        }

        if (!archive_path_.empty()) {

            const std::wstring name = lower_path(std::filesystem::path(archive_path_).filename().wstring());

            if (!name.empty()) {

                volume_paths_[name] = archive_path_;

            }

            volume_paths_[lower_path(std::filesystem::path(archive_path_).wstring())] = archive_path_;

        }

    }



    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** object) override {

        if (!object) {

            return E_POINTER;

        }

        *object = nullptr;

        if (IsEqualGUID(iid, IID_IUnknown) || IsEqualGUID(iid, IID_IArchiveOpenCallback)) {

            *object = static_cast<IArchiveOpenCallback*>(this);

        } else if (IsEqualGUID(iid, IID_IArchiveOpenVolumeCallback)) {

            *object = static_cast<IArchiveOpenVolumeCallback*>(this);

        } else if (IsEqualGUID(iid, IID_ICryptoGetTextPassword)) {

            *object = static_cast<ICryptoGetTextPassword*>(this);

        } else {

            return E_NOINTERFACE;

        }

        AddRef();

        return S_OK;

    }

    ULONG STDMETHODCALLTYPE AddRef() override { return InterlockedIncrement(&refs_); }

    ULONG STDMETHODCALLTYPE Release() override {

        const ULONG refs = InterlockedDecrement(&refs_);

        if (refs == 0) {

            delete this;

        }

        return refs;

    }

    HRESULT STDMETHODCALLTYPE SetTotal(const UInt64*, const UInt64*) override { return S_OK; }

    HRESULT STDMETHODCALLTYPE SetCompleted(const UInt64*, const UInt64*) override { return S_OK; }

    HRESULT STDMETHODCALLTYPE GetProperty(UInt32 propID, PROPVARIANT* value) override {

        if (!value) {

            return E_POINTER;

        }

        value->vt = VT_EMPTY;

        if (propID == kpidName && !archive_path_.empty()) {

            value->vt = VT_BSTR;

            value->bstrVal = SysAllocString(archive_path_.c_str());

            return value->bstrVal ? S_OK : E_OUTOFMEMORY;

        }

        return S_OK;

    }

    HRESULT STDMETHODCALLTYPE GetStream(const wchar_t* name, IInStream** inStream) override {

        if (!inStream) {

            return E_POINTER;

        }

        *inStream = nullptr;

        if (!name) {
            volume_open_failed_ = true;
            return E_FAIL;

        }



        std::wstring requested = lower_path(std::filesystem::path(name).filename().wstring());

        auto found = volume_paths_.find(requested);

        if (found == volume_paths_.end()) {

            requested = lower_path(std::wstring(name));

            found = volume_paths_.find(requested);

        }

        if (found == volume_paths_.end()) {
            missing_volume_requested_ = true;
            missing_volume_name_ = std::filesystem::path(name).filename().wstring();
            return E_FAIL;

        }



        auto* stream = new FileInStream(found->second);

        if (!stream->is_open()) {
            volume_open_failed_ = true;
            failed_volume_name_ = std::filesystem::path(found->second).filename().wstring();
            stream->Release();

            return E_FAIL;

        }

        *inStream = stream;

        return S_OK;

    }

    bool missing_volume_requested() const { return missing_volume_requested_; }
    bool volume_open_failed() const { return volume_open_failed_; }
    bool password_requested() const { return password_requested_; }
    const std::wstring& missing_volume_name() const { return missing_volume_name_; }
    const std::wstring& failed_volume_name() const { return failed_volume_name_; }

    HRESULT STDMETHODCALLTYPE CryptoGetTextPassword(BSTR* password) override {

        if (!password) {

            return E_POINTER;

        }

        password_requested_ = true;
        *password = SysAllocString(password_.c_str());

        return *password ? S_OK : E_OUTOFMEMORY;

    }



private:

    static std::wstring lower_path(std::wstring value) {

        std::transform(value.begin(), value.end(), value.begin(), [](wchar_t ch) { return static_cast<wchar_t>(::towlower(ch)); });

        return value;

    }



    LONG refs_ = 1;

    std::wstring password_;

    std::wstring archive_path_;

    std::vector<std::wstring> part_paths_;

    std::map<std::wstring, std::wstring> volume_paths_;

    bool missing_volume_requested_ = false;
    bool volume_open_failed_ = false;
    bool password_requested_ = false;
    std::wstring missing_volume_name_;
    std::wstring failed_volume_name_;

};



class ExtractCallback final : public IArchiveExtractCallback, public ICryptoGetTextPassword {

public:

    explicit ExtractCallback(std::wstring password) : password_(std::move(password)) {}

    Int32 operation_result() const { return operation_result_; }
    bool password_requested() const { return password_requested_; }



    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** object) override {

        if (!object) {

            return E_POINTER;

        }

        *object = nullptr;

        if (IsEqualGUID(iid, IID_IUnknown) || IsEqualGUID(iid, IID_IProgress) || IsEqualGUID(iid, IID_IArchiveExtractCallback)) {

            *object = static_cast<IArchiveExtractCallback*>(this);

        } else if (IsEqualGUID(iid, IID_ICryptoGetTextPassword)) {

            *object = static_cast<ICryptoGetTextPassword*>(this);

        } else {

            return E_NOINTERFACE;

        }

        AddRef();

        return S_OK;

    }

    ULONG STDMETHODCALLTYPE AddRef() override { return InterlockedIncrement(&refs_); }

    ULONG STDMETHODCALLTYPE Release() override {

        const ULONG refs = InterlockedDecrement(&refs_);

        if (refs == 0) {

            delete this;

        }

        return refs;

    }

    HRESULT STDMETHODCALLTYPE SetTotal(UInt64) override { return S_OK; }

    HRESULT STDMETHODCALLTYPE SetCompleted(const UInt64*) override { return S_OK; }

    HRESULT STDMETHODCALLTYPE GetStream(UInt32, ISequentialOutStream** outStream, Int32) override {

        if (!outStream) {

            return E_POINTER;

        }

        *outStream = nullptr;

        return S_OK;

    }

    HRESULT STDMETHODCALLTYPE PrepareOperation(Int32) override { return S_OK; }

    HRESULT STDMETHODCALLTYPE SetOperationResult(Int32 opRes) override {

        operation_result_ = opRes;

        return S_OK;

    }

    HRESULT STDMETHODCALLTYPE CryptoGetTextPassword(BSTR* password) override {

        if (!password) {

            return E_POINTER;

        }

        password_requested_ = true;
        *password = SysAllocString(password_.c_str());

        return *password ? S_OK : E_OUTOFMEMORY;

    }



private:

    LONG refs_ = 1;

    std::wstring password_;

    Int32 operation_result_ = kOpOk;
    bool password_requested_ = false;

};



class SynchronousFileOutStream final : public ISequentialOutStream {

public:

    explicit SynchronousFileOutStream(const std::wstring& path, ExtractOutputTrace* trace = nullptr, std::size_t item_trace_index = 0)

        : trace_(trace),
          item_trace_index_(item_trace_index),

          compute_crc_(trace_ && item_trace_index_ < trace_->items.size() &&
                       !trace_->items[item_trace_index_].has_source_crc32),

          handle_(CreateFileW(win32_extended_path(path).c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                              FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr)) {

        if (trace_ && handle_ == INVALID_HANDLE_VALUE) {

            const DWORD error = GetLastError();

            trace_->last_hresult = HRESULT_FROM_WIN32(error);

            trace_->last_win32_error = static_cast<int>(error);

            mark_item_failure(trace_->last_hresult, trace_->last_win32_error);

        }

    }

    ~SynchronousFileOutStream() {

        if (handle_ != INVALID_HANDLE_VALUE) {

            CloseHandle(handle_);

        }

    }

    bool is_open() const { return handle_ != INVALID_HANDLE_VALUE; }

    UInt64 bytes_written() const { return bytes_written_; }



    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** object) override {

        if (!object) {

            return E_POINTER;

        }

        *object = nullptr;

        if (IsEqualGUID(iid, IID_IUnknown) || IsEqualGUID(iid, IID_ISequentialOutStream)) {

            *object = static_cast<IUnknown*>(this);

        } else {

            return E_NOINTERFACE;

        }

        AddRef();

        return S_OK;

    }

    ULONG STDMETHODCALLTYPE AddRef() override { return InterlockedIncrement(&refs_); }

    ULONG STDMETHODCALLTYPE Release() override {

        const ULONG refs = InterlockedDecrement(&refs_);

        if (refs == 0) {

            delete this;

        }

        return refs;

    }

    HRESULT STDMETHODCALLTYPE Write(const void* data, UInt32 size, UInt32* processedSize) override {

        if (processedSize) {

            *processedSize = 0;

        }

        if (handle_ == INVALID_HANDLE_VALUE) {

            if (trace_) {

                trace_->last_hresult = E_FAIL;

            }

            return E_FAIL;

        }

        DWORD written = 0;

        if (!WriteFile(handle_, data, size, &written, nullptr)) {

            const DWORD error = GetLastError();

            const HRESULT hr = HRESULT_FROM_WIN32(error);

            if (trace_) {

                trace_->last_hresult = hr;

                trace_->last_win32_error = static_cast<int>(error);

                trace_->last_write_size = 0;

                mark_item_failure(hr, static_cast<int>(error));

            }

            return hr;

        }

        bytes_written_ += written;
        if (compute_crc_) {
            crc32_ = update_crc32(crc32_, data, written);
        }

        if (trace_) {

            trace_->total_bytes_written += written;

            trace_->current_item_bytes_written += written;

            trace_->last_write_size = written;

            trace_->last_hresult = S_OK;

            trace_->last_win32_error = 0;

            if (item_trace_index_ < trace_->items.size()) {

                trace_->items[item_trace_index_].bytes_written += written;
                if (compute_crc_) {
                    trace_->items[item_trace_index_].output_crc32 = crc32_ ^ 0xFFFFFFFFU;
                    trace_->items[item_trace_index_].has_output_crc32 = true;
                }

                trace_->items[item_trace_index_].hresult = S_OK;

                trace_->items[item_trace_index_].win32_error = 0;

            }

        }

        if (processedSize) {

            *processedSize = written;

        }

        return S_OK;

    }



private:

    void mark_item_failure(HRESULT hr, int win32_error) {

        if (!trace_ || item_trace_index_ >= trace_->items.size()) {

            return;

        }

        auto& item = trace_->items[item_trace_index_];

        item.failed = true;

        item.hresult = static_cast<int>(hr);

        item.win32_error = win32_error;

    }

    LONG refs_ = 1;

    ExtractOutputTrace* trace_ = nullptr;

    std::size_t item_trace_index_ = 0;

    bool compute_crc_ = false;

    HANDLE handle_ = INVALID_HANDLE_VALUE;

    UInt64 bytes_written_ = 0;

    UInt32 crc32_ = 0xFFFFFFFFU;

};



class AsyncFileOutStream final : public ISequentialOutStream {

public:
    AsyncFileOutStream(
        std::shared_ptr<AsyncFileWriter> writer,
        AsyncFileWriter::FileStatePtr file,
        bool compute_crc
    ) : writer_(std::move(writer)),
        file_(std::move(file)),
        compute_crc_(compute_crc) {
        magic_.reserve(16);
    }

    ~AsyncFileOutStream() {
        if (writer_ && file_) {
            std::lock_guard<std::mutex> lock(mutex_);
            writer_->close_file(file_, crc32_ ^ 0xFFFFFFFFU, compute_crc_, std::move(magic_));
        }
    }

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** object) override {
        if (!object) {
            return E_POINTER;
        }
        *object = nullptr;
        if (IsEqualGUID(iid, IID_IUnknown) || IsEqualGUID(iid, IID_ISequentialOutStream)) {
            *object = static_cast<IUnknown*>(this);
        } else {
            return E_NOINTERFACE;
        }
        AddRef();
        return S_OK;
    }

    ULONG STDMETHODCALLTYPE AddRef() override { return InterlockedIncrement(&refs_); }

    ULONG STDMETHODCALLTYPE Release() override {
        const ULONG refs = InterlockedDecrement(&refs_);
        if (refs == 0) {
            delete this;
        }
        return refs;
    }

    HRESULT STDMETHODCALLTYPE Write(const void* data, UInt32 size, UInt32* processedSize) override {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!writer_ || !file_) {
            if (processedSize) {
                *processedSize = 0;
            }
            return E_FAIL;
        }
        UInt32 consumed = 0;
        const HRESULT hr = writer_->write(file_, data, size, &consumed);
        if (compute_crc_ && consumed != 0) {
            crc32_ = update_crc32(crc32_, data, consumed);
        }
        if (consumed != 0 && magic_.size() < 16) {
            const auto* bytes = static_cast<const unsigned char*>(data);
            const std::size_t take = std::min<std::size_t>(16 - magic_.size(), consumed);
            magic_.insert(magic_.end(), bytes, bytes + take);
        }
        if (processedSize) {
            *processedSize = consumed;
        }
        return hr;
    }

private:
    LONG refs_ = 1;
    std::shared_ptr<AsyncFileWriter> writer_;
    AsyncFileWriter::FileStatePtr file_;
    bool compute_crc_ = false;
    UInt32 crc32_ = 0xFFFFFFFFU;
    std::vector<unsigned char> magic_;
    std::mutex mutex_;
};


class TraceOutStream final : public ISequentialOutStream {

public:

    explicit TraceOutStream(ExtractOutputTrace* trace = nullptr, std::size_t item_trace_index = 0)

        : trace_(trace),
          item_trace_index_(item_trace_index),
          compute_crc_(trace_ && item_trace_index_ < trace_->items.size() &&
                       !trace_->items[item_trace_index_].has_source_crc32) {}

    UInt64 bytes_written() const { return bytes_written_; }



    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** object) override {

        if (!object) {

            return E_POINTER;

        }

        *object = nullptr;

        if (IsEqualGUID(iid, IID_IUnknown) || IsEqualGUID(iid, IID_ISequentialOutStream)) {

            *object = static_cast<IUnknown*>(this);

        } else {

            return E_NOINTERFACE;

        }

        AddRef();

        return S_OK;

    }

    ULONG STDMETHODCALLTYPE AddRef() override { return InterlockedIncrement(&refs_); }

    ULONG STDMETHODCALLTYPE Release() override {

        const ULONG refs = InterlockedDecrement(&refs_);

        if (refs == 0) {

            delete this;

        }

        return refs;

    }

    HRESULT STDMETHODCALLTYPE Write(const void* data, UInt32 size, UInt32* processedSize) override {

        bytes_written_ += size;
        if (compute_crc_) {
            crc32_ = update_crc32(crc32_, data, size);
        }

        if (trace_) {

            trace_->total_bytes_written += size;

            trace_->current_item_bytes_written += size;

            trace_->last_write_size = size;

            trace_->last_hresult = S_OK;

            trace_->last_win32_error = 0;

            if (item_trace_index_ < trace_->items.size()) {

                trace_->items[item_trace_index_].bytes_written += size;
                if (compute_crc_) {
                    trace_->items[item_trace_index_].output_crc32 = crc32_ ^ 0xFFFFFFFFU;
                    trace_->items[item_trace_index_].has_output_crc32 = true;
                }

                trace_->items[item_trace_index_].hresult = S_OK;

                trace_->items[item_trace_index_].win32_error = 0;

            }

        }

        if (processedSize) {

            *processedSize = size;

        }

        return S_OK;

    }



private:

    LONG refs_ = 1;

    ExtractOutputTrace* trace_ = nullptr;

    std::size_t item_trace_index_ = 0;

    bool compute_crc_ = false;

    UInt64 bytes_written_ = 0;

    UInt32 crc32_ = 0xFFFFFFFFU;

};


inline std::filesystem::path browser_style_available_path(const std::filesystem::path& requested) {
    std::error_code error;
    if (!std::filesystem::exists(requested, error)) {
        return requested;
    }
    const auto parent = requested.parent_path();
    const auto stem = requested.stem().wstring();
    const auto extension = requested.extension().wstring();
    for (unsigned int index = 1; ; ++index) {
        const auto candidate = parent / (stem + L"(" + std::to_wstring(index) + L")" + extension);
        error.clear();
        if (!std::filesystem::exists(candidate, error)) {
            return candidate;
        }
    }
}

inline bool directory_is_empty_or_missing(const std::filesystem::path& path) {
    std::error_code error;
    if (!std::filesystem::exists(path, error)) {
        return !error;
    }
    error.clear();
    const bool empty = std::filesystem::is_empty(path, error);
    return !error && empty;
}

inline std::wstring normalized_output_path_key(const std::filesystem::path& path) {
    auto key = path.lexically_normal().wstring();
    std::transform(key.begin(), key.end(), key.begin(), [](wchar_t value) {
        return static_cast<wchar_t>(std::towlower(value));
    });
    return key;
}



inline std::optional<std::filesystem::path> safe_relative_item_path(const std::wstring& raw_name) {

    if (raw_name.empty()) {

        return std::nullopt;

    }

    std::filesystem::path candidate(raw_name);

    if (candidate.is_absolute() || candidate.has_root_name() || candidate.has_root_directory()) {

        return std::nullopt;

    }

    std::filesystem::path normalized;

    for (const auto& part : candidate) {

        const auto text = part.wstring();

        if (text.empty() || text == L"." || text == L"/" || text == L"\\") {

            continue;

        }

        if (text == L"..") {

            return std::nullopt;

        }

        normalized /= part;

    }

    if (normalized.empty()) {

        return std::nullopt;

    }

    return normalized;

}



class ExtractToDiskCallback final : public IArchiveExtractCallback, public ICryptoGetTextPassword {

public:

    ExtractToDiskCallback(

        IInArchive* archive,

        std::wstring password,

        std::wstring output_dir,

        std::vector<std::wstring> decoded_names,

        ExtractProgressCallback progress,

        bool dry_run = false,

        ExtractOutputTrace* output_trace = nullptr,

        UInt32 estimated_items = 0,

        std::shared_ptr<AsyncFileWriter> shared_writer = nullptr,

        std::size_t job_buffer_budget = 0,

        std::shared_ptr<std::atomic<bool>> cancel_token = nullptr

    ) : archive_(archive),

        password_(std::move(password)),

        output_dir_(std::move(output_dir)),

        decoded_names_(std::move(decoded_names)),

        progress_(std::move(progress)),

        dry_run_(dry_run),

        output_trace_(output_trace),

        async_writer_(dry_run ? nullptr : (shared_writer ? std::move(shared_writer) : std::make_shared<AsyncFileWriter>())),

        cancel_token_(std::move(cancel_token)),

        async_job_(async_writer_ ? async_writer_->make_job(job_buffer_budget, cancel_token_) : nullptr),

        output_root_(win32_extended_path(output_dir_)),

        output_root_initially_empty_(directory_is_empty_or_missing(output_root_)) {
        used_output_paths_.reserve(static_cast<std::size_t>(estimated_items) * 2U + 1U);
        created_directories_.reserve(static_cast<std::size_t>(estimated_items) + 1U);
    }

    ~ExtractToDiskCallback() { finalize_output(); }



    Int32 operation_result() const { return operation_result_; }
    bool password_requested() const { return password_requested_; }

    UInt32 files_written() const { return files_written_; }

    UInt32 dirs_written() const { return dirs_written_; }

    UInt64 bytes_written() const { return bytes_written_; }

    UInt64 completed_bytes() const { return completed_bytes_; }

    const std::wstring& failed_item() const { return failed_item_; }

    UInt32 failed_item_index() const { return failed_item_index_; }

    UInt64 failed_item_bytes_written() const { return failed_item_bytes_written_; }

    bool output_error() const { return output_error_; }

    bool output_root_initially_empty() const { return output_root_initially_empty_; }

    void finalize_output() noexcept {
        if (output_finalized_) {
            return;
        }
        output_finalized_ = true;
        if (!async_writer_) {
            return;
        }

        const HRESULT writer_error = async_writer_->finish_job(async_job_);
        const int writer_win32_error = writer_error == S_OK
            ? 0
            : async_writer_->current_win32_error(async_job_);
        bool has_failed_file = false;
        UInt64 total_written = 0;
        UInt32 completed_files = 0;
        for (const auto& state : async_files_) {
            if (!state) {
                continue;
            }
            const auto snapshot = async_writer_->snapshot_file(state);
            total_written += snapshot.written_bytes;
            const bool decoder_ok = snapshot.operation_result_set &&
                snapshot.operation_result == kOpOk;
            const bool output_ok = snapshot.closed && !snapshot.failed;
            if (decoder_ok && output_ok) {
                ++completed_files;
            }

            if (output_trace_ && state->trace_index < output_trace_->items.size()) {
                auto& item = output_trace_->items[state->trace_index];
                item.bytes_written = snapshot.written_bytes;
                item.operation_result = snapshot.operation_result;
                item.magic = snapshot.magic;
                item.has_mtime_ns = snapshot.has_mtime_ns;
                item.mtime_ns = snapshot.mtime_ns;
                item.failed = item.failed || !decoder_ok || !output_ok;
                item.done = decoder_ok && output_ok;
                if (item.done && item.has_source_crc32) {
                    item.output_crc32 = item.source_crc32;
                    item.has_output_crc32 = true;
                } else if (snapshot.has_output_crc32) {
                    item.output_crc32 = snapshot.output_crc32;
                    item.has_output_crc32 = true;
                }
                item.crc_verified = item.done && (!item.has_source_crc32 ||
                    (item.has_output_crc32 && item.source_crc32 == item.output_crc32));
                if (snapshot.failed) {
                    item.hresult = static_cast<int>(snapshot.hresult);
                    item.win32_error = snapshot.win32_error;
                }
            }

            if (snapshot.failed) {
                has_failed_file = true;
                output_error_ = true;
                if (failed_item_.empty()) {
                    failed_item_ = state->item_path;
                    failed_item_index_ = state->item_index;
                    failed_item_bytes_written_ = snapshot.written_bytes;
                }
                if (output_trace_) {
                    output_trace_->last_hresult = static_cast<int>(snapshot.hresult);
                    output_trace_->last_win32_error = snapshot.win32_error;
                }
            }
        }
        files_written_ = completed_files;
        bytes_written_ = total_written;
        if (output_trace_) {
            output_trace_->total_bytes_written = total_written;
            if (!async_files_.empty() && async_files_.back()) {
                output_trace_->current_item_bytes_written =
                    async_writer_->snapshot_file(async_files_.back()).written_bytes;
            }
        }
        if (writer_error != S_OK) {
            output_error_ = true;
            // FileState diagnostics are authoritative once the writer has drained.
            // Fall back only for scheduler failures that have no associated file.
            if (!has_failed_file) {
                mark_current_item_failure(writer_error, writer_win32_error);
                if (output_trace_) {
                    output_trace_->last_hresult = static_cast<int>(writer_error);
                    output_trace_->last_win32_error = writer_win32_error;
                }
            }
        }
        if (output_error_ && operation_result_ == kOpOk) {
            operation_result_ = kOpDataError;
        }
    }



    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** object) override {

        if (!object) {

            return E_POINTER;

        }

        *object = nullptr;

        if (IsEqualGUID(iid, IID_IUnknown) || IsEqualGUID(iid, IID_IProgress) || IsEqualGUID(iid, IID_IArchiveExtractCallback)) {

            *object = static_cast<IArchiveExtractCallback*>(this);

        } else if (IsEqualGUID(iid, IID_ICryptoGetTextPassword)) {

            *object = static_cast<ICryptoGetTextPassword*>(this);

        } else {

            return E_NOINTERFACE;

        }

        AddRef();

        return S_OK;

    }

    ULONG STDMETHODCALLTYPE AddRef() override { return InterlockedIncrement(&refs_); }

    ULONG STDMETHODCALLTYPE Release() override {

        const ULONG refs = InterlockedDecrement(&refs_);

        if (refs == 0) {

            delete this;

        }

        return refs;

    }

    HRESULT STDMETHODCALLTYPE SetTotal(UInt64 total) override {

        std::lock_guard<std::recursive_mutex> lock(state_mutex_);

        if (is_cancelled()) {
            return E_ABORT;
        }

        total_bytes_ = total;

        emit("total", 0, L"");

        return S_OK;

    }

    HRESULT STDMETHODCALLTYPE SetCompleted(const UInt64* completeValue) override {

        std::lock_guard<std::recursive_mutex> lock(state_mutex_);

        if (is_cancelled()) {
            return E_ABORT;
        }

        if (completeValue) {

            completed_bytes_ = *completeValue;

            emit("progress", current_index_, current_item_);

        }

        return S_OK;

    }

    HRESULT STDMETHODCALLTYPE GetStream(UInt32 index, ISequentialOutStream** outStream, Int32 askExtractMode) override {

        std::lock_guard<std::recursive_mutex> lock(state_mutex_);

        if (!outStream) {

            return E_POINTER;

        }

        *outStream = nullptr;

        if (is_cancelled()) {
            return E_ABORT;
        }

        current_index_ = index;

        current_item_.clear();

        current_item_bytes_written_ = 0;

        current_item_is_dir_ = false;

        current_trace_active_ = false;

        current_async_file_.reset();

        if (askExtractMode != kExtractMode) {

            return S_OK;

        }



        PROPVARIANT value{};

        bool is_dir = false;

        if (get_item_property(archive_, index, kpidIsDir, value)) {

            is_dir = prop_bool(value);

        }

        clear_prop(value);

        UInt64 expected_size = 0;
        bool has_expected_size = false;
        if (!is_dir && get_item_property(archive_, index, kpidSize, value)) {
            expected_size = prop_u64(value);
            has_expected_size = true;
        }
        clear_prop(value);

        UInt32 source_crc32 = 0;
        bool has_source_crc32 = false;
        if (!is_dir && get_item_property(archive_, index, kpidCRC, value)) {
            source_crc32 = prop_u32(value);
            has_source_crc32 = true;
        }
        clear_prop(value);

        bool encrypted = false;
        if (!is_dir && get_item_property(archive_, index, kpidEncrypted, value)) {
            encrypted = prop_bool(value);
        }
        clear_prop(value);



        std::wstring name;
        if (!decoded_names_.empty()) {
            name = decoded_names_[index];
        } else {
            if (get_item_property(archive_, index, kpidPath, value)) {
                name = prop_text(value);
            }
            clear_prop(value);
            if (name.empty() && get_item_property(archive_, index, kpidName, value)) {
                name = prop_text(value);
            }
            clear_prop(value);
        }

        if (name.empty()) {

            name = L"#" + std::to_wstring(index);

        }

        current_item_ = name;

        current_item_is_dir_ = is_dir;

        if (output_trace_) {

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



        const auto safe_path = safe_relative_item_path(name);

        if (!safe_path.has_value()) {

            failed_item_ = name;

            failed_item_index_ = index;

            failed_item_bytes_written_ = 0;

            output_error_ = true;

            mark_current_item_failure(E_INVALIDARG, 0);

            return E_INVALIDARG;

        }

        emit("item_start", index, name);

        std::filesystem::path target;
        try {

            if (is_dir) {

                if (!dry_run_) {

                    target = output_root_ / safe_path.value();

                    ensure_directory(target);

                    if (output_trace_ && current_trace_index_ < output_trace_->items.size()) {
                        output_trace_->items[current_trace_index_].output_path = target.lexically_relative(output_root_).generic_wstring();
                    }

                }

                dirs_written_ += 1;

                return S_OK;

            }

            if (!dry_run_) {

                target = available_output_path(output_root_ / safe_path.value());

                ensure_directory(target.parent_path());

                if (output_trace_ && current_trace_index_ < output_trace_->items.size()) {

                    output_trace_->items[current_trace_index_].output_path = target.lexically_relative(output_root_).generic_wstring();

                }

            }

        } catch (...) {

            failed_item_ = name;

            failed_item_index_ = index;

            failed_item_bytes_written_ = current_item_bytes_written_;

            output_error_ = true;

            mark_current_item_failure(E_FAIL, 0);

            return E_FAIL;

        }

        if (dry_run_) {

            *outStream = new TraceOutStream(output_trace_, current_trace_index_);

            return S_OK;

        }

        if (!async_writer_) {
            mark_current_item_failure(E_FAIL, 0);
            output_error_ = true;
            return E_FAIL;
        }
        const bool compute_crc = output_trace_ && current_trace_index_ < output_trace_->items.size() &&
            !output_trace_->items[current_trace_index_].has_source_crc32;
        current_async_file_ = async_writer_->make_file(async_job_,
            target.wstring(), name, index, current_trace_index_);
        async_files_.push_back(current_async_file_);
        *outStream = new AsyncFileOutStream(async_writer_, current_async_file_, compute_crc);

        return S_OK;

    }

    HRESULT STDMETHODCALLTYPE PrepareOperation(Int32) override { return S_OK; }

    HRESULT STDMETHODCALLTYPE SetOperationResult(Int32 opRes) override {

        std::lock_guard<std::recursive_mutex> lock(state_mutex_);

        if (is_cancelled()) {
            return E_ABORT;
        }

        if (current_async_file_) {
            async_writer_->record_operation_result(current_async_file_, opRes);
            current_item_bytes_written_ = async_writer_->accepted_bytes(current_async_file_);
            if (output_trace_) {
                output_trace_->current_item_bytes_written = current_item_bytes_written_;
            }
        }

        if (opRes != kOpOk || operation_result_ == kOpOk) {

            operation_result_ = opRes;

        }

        if (opRes == kOpOk && !current_item_.empty() && !current_item_is_dir_ && !async_writer_) {

            files_written_ += 1;

        } else if (opRes != kOpOk && failed_item_.empty()) {

            failed_item_ = current_item_;

            failed_item_index_ = current_index_;

        }

        current_item_bytes_written_ = output_trace_ ? output_trace_->current_item_bytes_written : current_item_bytes_written_;

        finish_current_item_trace(opRes);

        if (opRes != kOpOk) {

            failed_item_bytes_written_ = current_item_bytes_written_;

        }

        emit(opRes == kOpOk ? "item_done" : "item_failed", current_index_, current_item_);

        if (async_writer_) {
            const HRESULT writer_error = async_writer_->current_error(async_job_);
            if (writer_error != S_OK) {
                output_error_ = true;
                mark_current_item_failure(writer_error, async_writer_->current_win32_error(async_job_));
                return writer_error;
            }
        }
        return S_OK;

    }

    HRESULT STDMETHODCALLTYPE CryptoGetTextPassword(BSTR* password) override {

        std::lock_guard<std::recursive_mutex> lock(state_mutex_);

        if (!password) {

            return E_POINTER;

        }

        password_requested_ = true;
        *password = SysAllocString(password_.c_str());

        return *password ? S_OK : E_OUTOFMEMORY;

    }



private:

    std::filesystem::path available_output_path(const std::filesystem::path& requested) {
        const auto requested_key = normalized_output_path_key(requested);
        if (output_root_initially_empty_ && used_output_paths_.insert(requested_key).second) {
            return requested;
        }
        auto candidate = browser_style_available_path(requested);
        while (!used_output_paths_.insert(normalized_output_path_key(candidate)).second) {
            candidate = browser_style_available_path(candidate);
        }
        return candidate;
    }

    void ensure_directory(const std::filesystem::path& directory) {
        ensure_no_reparse_ancestors(directory);
        const auto key = normalized_output_path_key(directory);
        if (created_directories_.insert(key).second) {
            std::filesystem::create_directories(directory);
        }
    }

    void ensure_no_reparse_ancestors(const std::filesystem::path& directory) const {
        const auto relative = directory.lexically_relative(output_root_);
        if (relative.empty()) {
            return;
        }
        for (const auto& part : relative) {
            if (part == L"..") {
                throw std::filesystem::filesystem_error(
                    "output path escapes extraction root",
                    directory,
                    std::make_error_code(std::errc::permission_denied));
            }
        }
        auto current = output_root_;
        for (const auto& part : relative) {
            current /= part;
            std::error_code error;
            const auto status = std::filesystem::symlink_status(current, error);
            if (!error && std::filesystem::is_symlink(status)) {
                throw std::filesystem::filesystem_error(
                    "output path traverses a symbolic link",
                    current,
                    std::make_error_code(std::errc::permission_denied));
            }
#ifdef _WIN32
            const DWORD attributes = GetFileAttributesW(current.c_str());
            if (attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
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
        const std::wstring& item_path,
        bool is_dir,
        bool encrypted,
        UInt64 expected_size,
        bool has_expected_size,
        UInt32 source_crc32,
        bool has_source_crc32
    ) {

        if (!output_trace_) {

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

        if (!is_dir) {

            item.output_crc32 = 0;

            item.has_output_crc32 = true;

        }

        item.operation_result = kOpOk;

        output_trace_->items.push_back(std::move(item));

        current_trace_index_ = output_trace_->items.size() - 1;

        current_trace_active_ = true;

    }

    void finish_current_item_trace(Int32 opRes) {

        if (!output_trace_ || !current_trace_active_ || current_trace_index_ >= output_trace_->items.size()) {

            return;

        }

        auto& item = output_trace_->items[current_trace_index_];

        item.bytes_written = output_trace_->current_item_bytes_written;

        item.operation_result = opRes;

        item.done = opRes == kOpOk && !item.failed;

        if (item.done && item.has_source_crc32) {
            // Seven-Zip only reports kOpOk after validating the decoded bytes
            // against the archive CRC. Reuse that proven value instead of
            // hashing the same pre-write buffer a second time.
            item.output_crc32 = item.source_crc32;
            item.has_output_crc32 = true;
        }

        item.failed = item.failed || opRes != kOpOk;

        item.crc_verified = item.done && (!item.has_source_crc32 ||
            (item.has_output_crc32 && item.source_crc32 == item.output_crc32));

        item.hresult = output_trace_->last_hresult;

        item.win32_error = output_trace_->last_win32_error;

    }

    void mark_current_item_failure(HRESULT hr, int win32_error) {

        if (!output_trace_ || !current_trace_active_ || current_trace_index_ >= output_trace_->items.size()) {

            return;

        }

        auto& item = output_trace_->items[current_trace_index_];

        item.bytes_written = output_trace_->current_item_bytes_written;

        item.hresult = static_cast<int>(hr);

        item.win32_error = win32_error;

        item.failed = true;

        output_trace_->last_hresult = static_cast<int>(hr);

        output_trace_->last_win32_error = win32_error;

    }

    void emit(const std::string& event, UInt32 item_index, const std::wstring& item_path) {

        std::lock_guard<std::recursive_mutex> lock(state_mutex_);

        if (!progress_) {

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



    LONG refs_ = 1;

    IInArchive* archive_ = nullptr;

    std::wstring password_;

    std::wstring output_dir_;

    std::vector<std::wstring> decoded_names_;

    ExtractProgressCallback progress_;

    bool dry_run_ = false;

    ExtractOutputTrace* output_trace_ = nullptr;

    std::shared_ptr<AsyncFileWriter> async_writer_;

    std::shared_ptr<std::atomic<bool>> cancel_token_;

    AsyncFileWriter::JobStatePtr async_job_;

    mutable std::recursive_mutex state_mutex_;

    std::vector<AsyncFileWriter::FileStatePtr> async_files_;

    AsyncFileWriter::FileStatePtr current_async_file_;

    bool is_cancelled() const noexcept {
        return cancel_token_ && cancel_token_->load(std::memory_order_acquire);
    }

    std::filesystem::path output_root_;

    bool output_root_initially_empty_ = false;

    std::unordered_set<std::wstring> used_output_paths_;

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



}  // namespace sunpack::sevenzip
