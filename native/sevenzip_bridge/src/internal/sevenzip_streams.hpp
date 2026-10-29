#pragma once

#include "sevenzip_paths.hpp"

#ifdef SUP7Z_ENABLE_PIPELINE_TIMING
#include "worker_pipeline_timing.hpp"
#endif

#include "sevenzip_sdk.hpp"

#ifdef _WIN32

#include <algorithm>

#include <array>

#include <chrono>

#include <cstring>

#include <cstdlib>

#include <filesystem>

#include <functional>

#include <memory>

#include <string>

#include <utility>

#include <vector>

#endif

namespace sunpack::sevenzip
{

#ifdef _WIN32

    inline bool read_file_timing_enabled() noexcept
    {
        static const bool enabled = []
        {
            const char *value = std::getenv("SUNPACK_SEVENZIP_PROFILE_READS");
            return value && value[0] == '1';
        }();
        return enabled;
    }

    struct InputPrefetchConfig
    {
        bool enabled = true;
        UInt32 window_bytes = 512 * 1024;
    };

    inline InputPrefetchConfig input_prefetch_config() noexcept
    {
        static const InputPrefetchConfig config = []
        {
            InputPrefetchConfig value;
            if (const char *enabled = std::getenv("SUNPACK_SEVENZIP_PREFETCH"))
            {
                value.enabled = enabled[0] != '0';
            }
            if (const char *window_kib = std::getenv("SUNPACK_SEVENZIP_PREFETCH_WINDOW_KIB"))
            {
                const unsigned long parsed = std::strtoul(window_kib, nullptr, 10);
                if (parsed >= 64 && parsed <= 16 * 1024)
                {
                    value.window_bytes = static_cast<UInt32>(parsed * 1024);
                }
            }
            return value;
        }();
        return config;
    }

    inline InputPrefetchConfig input_prefetch_config_for_archive(
        const std::wstring &format_hint,
        bool native_volume_input) noexcept
    {
        InputPrefetchConfig config = input_prefetch_config();
        // Explicit process-level overrides are also used by paired benchmarks.
        if (!config.enabled || format_hint.empty() || std::getenv("SUNPACK_SEVENZIP_PREFETCH"))
        {
            return config;
        }

        std::wstring normalized = format_hint;
        for (wchar_t &character : normalized)
        {
            if (character >= L'A' && character <= L'Z')
            {
                character = static_cast<wchar_t>(character - L'A' + L'a');
            }
        }
        // Cached-read A/B: these formats do not consistently recover the cost
        // of speculative reads/copies. Keep their direct input path by default.
        if (normalized == L"gz" || normalized == L"gzip" || normalized == L"xz" ||
            normalized == L"lz4" || normalized == L"zst" || normalized == L"zstd" || normalized == L"tar" ||
            (native_volume_input &&
             (normalized == L"rar" || normalized == L"rar4" || normalized == L"rar5")))
        {
            config.enabled = false;
        }
        return config;
    }

    class ReadFileWallTimer final
    {
    public:
        explicit ReadFileWallTimer(ExtractInputTrace *trace) noexcept
            : trace_(read_file_timing_enabled() ? trace : nullptr)
#ifdef SUP7Z_ENABLE_PIPELINE_TIMING
              , pipeline_scope_(trace ? trace->pipeline_timing : nullptr, PipelineStage::Input)
#endif
        {
            if (trace_)
            {
                started_ = std::chrono::steady_clock::now();
            }
        }

        ~ReadFileWallTimer() noexcept
        {
            if (!trace_)
            {
                return;
            }
            const auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
                                     std::chrono::steady_clock::now() - started_)
                                     .count();
            const auto elapsed_ns = elapsed > 0 ? static_cast<unsigned long long>(elapsed) : 0ULL;
            ++trace_->read_file_call_count;
            trace_->read_file_wall_ns += elapsed_ns;
            trace_->read_file_max_wall_ns = std::max(trace_->read_file_max_wall_ns, elapsed_ns);
        }

    private:
        ExtractInputTrace *trace_ = nullptr;
        std::chrono::steady_clock::time_point started_{};
#ifdef SUP7Z_ENABLE_PIPELINE_TIMING
        PipelineStageScope pipeline_scope_;
#endif
    };

    inline void record_logical_read(ExtractInputTrace *trace, UInt64 start, UInt32 returned) noexcept
    {
        if (!trace || !read_file_timing_enabled() || returned == 0)
        {
            return;
        }
        ++trace->logical_read_call_count;
        if (trace->has_last_logical_read_end && start == trace->last_logical_read_end)
        {
            trace->sequential_read_bytes += returned;
            trace->current_sequential_run_bytes += returned;
        }
        else
        {
            trace->nonsequential_read_bytes += returned;
            ++trace->sequential_run_count;
            trace->current_sequential_run_bytes = returned;
        }
        trace->max_sequential_run_bytes = std::max(trace->max_sequential_run_bytes, trace->current_sequential_run_bytes);
        trace->last_logical_read_end = start + returned;
        trace->has_last_logical_read_end = true;
    }

    inline void record_logical_seek(ExtractInputTrace *trace, UInt64 from, UInt64 to) noexcept
    {
        if (!trace || !read_file_timing_enabled())
        {
            return;
        }
        ++trace->seek_count;
        if (to > from)
        {
            trace->seek_forward_bytes += to - from;
        }
        else if (from > to)
        {
            trace->seek_backward_bytes += from - to;
            trace->has_last_logical_read_end = false;
        }
        if (from != to)
        {
            trace->has_last_logical_read_end = false;
        }
    }

    struct PrefetchSource
    {
        const std::wstring *path = nullptr;
        UInt64 offset = 0;
        UInt64 length = 0;
    };

    // Single-consumer prefetch: two stable buffers and event-based OVERLAPPED
    // reads. Submission, consumption and cancellation all run on the decoder
    // thread; only the OS owns an in-flight buffer between Read calls.
    class OverlappedPrefetcher final
    {
    public:
        // Sources borrow immutable path/range metadata from the owning stream.
        // Each slot clips its request at that source's end; no format probing
        // or copying of the stream's volume/range table is needed here.
        using Resolver = std::function<bool(UInt64, PrefetchSource &)>;

        OverlappedPrefetcher(InputPrefetchConfig config, UInt64 size, Resolver resolver,
                            ExtractInputTrace *trace = nullptr)
            : window_bytes_(config.window_bytes), virtual_size_(size),
              resolver_(std::move(resolver)), trace_(trace),
              enabled_(config.enabled && config.window_bytes && size)
        {
            if (!enabled_) return;
            for (auto &slot : slots_)
            {
                slot.overlapped.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
                if (!slot.overlapped.hEvent)
                {
                    close();
                    return;
                }
            }
        }

        OverlappedPrefetcher(const OverlappedPrefetcher &) = delete;
        OverlappedPrefetcher &operator=(const OverlappedPrefetcher &) = delete;
        ~OverlappedPrefetcher() { close(); }

        bool enabled() const noexcept { return enabled_; }

        bool consume(UInt64 offset, void *data, UInt32 size, ExtractInputTrace *trace)
        {
            if (!enabled() || !size)
            {
                return false;
            }
            const bool profiling = trace && read_file_timing_enabled();
            // A decoder read may straddle the two windows. Verify coverage
            // before copying; an uncovered or short read uses the direct path.
            UInt64 cursor = offset;
            UInt32 remaining = size;
            while (remaining)
            {
                Slot *slot = find(cursor);
                if (!slot || slot->state == State::Failed)
                {
                    if (profiling) ++trace->prefetch_miss_count;
                    return false;
                }
                const UInt32 count = static_cast<UInt32>(std::min<UInt64>(remaining, slot->offset + slot->size - cursor));
                cursor += count;
                remaining -= count;
            }
            const auto started = profiling ? std::chrono::steady_clock::now()
                                           : std::chrono::steady_clock::time_point{};
            cursor = offset;
            remaining = size;
            auto *destination = static_cast<unsigned char *>(data);
            while (remaining)
            {
                Slot &slot = *find(cursor);
                if (slot.state == State::Pending)
                {
                    DWORD read = 0;
#ifdef SUP7Z_ENABLE_PIPELINE_TIMING
                    PipelineStageScope input_scope(trace_ ? trace_->pipeline_timing : nullptr, PipelineStage::Input);
#endif
                    const BOOL ok = GetOverlappedResult(slot.handle, &slot.overlapped, &read, TRUE);
                    slot.state = ok && read == slot.size ? State::Ready : State::Failed;
                }
                if (slot.state != State::Ready)
                {
                    if (profiling)
                    {
                        ++trace->prefetch_miss_count;
                        trace->prefetch_consumer_wait_ns += elapsed_ns(started);
                    }
                    return false;
                }
                const auto displacement = static_cast<std::size_t>(cursor - slot.offset);
                const UInt32 count = std::min<UInt32>(remaining, slot.size - static_cast<UInt32>(displacement));
                std::memcpy(destination, slot.bytes.get() + displacement, count);
                cursor += count;
                destination += count;
                remaining -= count;
            }
            if (profiling)
            {
                ++trace->prefetch_hit_count;
                trace->prefetch_consumer_wait_ns += elapsed_ns(started);
            }
            return true;
        }

        void after_sync_read(UInt64 end) { advance(end); }
        void after_cached_read(UInt64 end) { advance(end); }

        void invalidate(UInt64 next, ExtractInputTrace *trace)
        {
            if (trace && read_file_timing_enabled() &&
                std::any_of(slots_.begin(), slots_.end(), [](const Slot &slot) { return slot.state != State::Empty; }))
            {
                ++trace->prefetch_invalidation_count;
            }
            cancel();
            next_offset_ = next;
        }

    private:
        enum class State { Empty, Pending, Ready, Failed };
        struct Slot
        {
            OVERLAPPED overlapped{};
            HANDLE handle = INVALID_HANDLE_VALUE;
            const std::wstring *path = nullptr;
            std::unique_ptr<unsigned char[]> bytes;
            UInt64 offset = 0;
            UInt32 size = 0;
            State state = State::Empty;
        };

        static unsigned long long elapsed_ns(std::chrono::steady_clock::time_point started) noexcept
        {
            return static_cast<unsigned long long>(std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now() - started).count());
        }

        Slot *find(UInt64 offset) noexcept
        {
            for (auto &slot : slots_)
            {
                if (slot.state != State::Empty && offset >= slot.offset && offset - slot.offset < slot.size)
                    return &slot;
            }
            return nullptr;
        }

        static void drain(Slot &slot) noexcept
        {
            if (slot.state == State::Pending)
            {
                DWORD ignored = 0;
                // CancelIoEx requests cancellation; completion still owns both
                // OVERLAPPED and bytes until GetOverlappedResult has returned.
                GetOverlappedResult(slot.handle, &slot.overlapped, &ignored, TRUE);
            }
            slot.state = State::Empty;
        }

        static void retire(Slot &slot) noexcept
        {
            if (slot.state == State::Pending) CancelIoEx(slot.handle, &slot.overlapped);
            drain(slot);
        }

        void cancel() noexcept
        {
            // Request both cancellations before waiting for either completion.
            for (auto &slot : slots_)
                if (slot.state == State::Pending) CancelIoEx(slot.handle, &slot.overlapped);
            for (auto &slot : slots_) drain(slot);
        }

        void close() noexcept
        {
            cancel();
            for (auto &slot : slots_)
            {
                if (slot.overlapped.hEvent) CloseHandle(slot.overlapped.hEvent);
                slot.overlapped.hEvent = nullptr;
                if (slot.handle != INVALID_HANDLE_VALUE) CloseHandle(slot.handle);
                slot.handle = INVALID_HANDLE_VALUE;
                slot.path = nullptr;
            }
            enabled_ = false;
        }

        void advance(UInt64 end)
        {
            if (!enabled() || end > virtual_size_) return;
            for (auto &slot : slots_)
                if (slot.state != State::Empty && slot.offset + slot.size <= end) retire(slot);
            if (std::all_of(slots_.begin(), slots_.end(), [](const Slot &slot) { return slot.state == State::Empty; }))
                next_offset_ = end;
            for (auto &slot : slots_)
            {
                if (slot.state != State::Empty || next_offset_ >= virtual_size_) continue;
                PrefetchSource source;
                if (!resolver_(next_offset_, source) || !source.path || !source.length) break;
                if (slot.handle == INVALID_HANDLE_VALUE || slot.path != source.path)
                {
                    if (slot.handle != INVALID_HANDLE_VALUE) CloseHandle(slot.handle);
                    slot.handle = CreateFileW(win32_extended_path(*source.path).c_str(), GENERIC_READ,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, nullptr);
                    slot.path = source.path;
                    // Failed speculative opens remain recoverable: the direct
                    // path reports the error, and a later read can try again.
                    if (slot.handle == INVALID_HANDLE_VALUE) break;
                }
                if (!slot.bytes) slot.bytes.reset(new unsigned char[window_bytes_]);
                const HANDLE event = slot.overlapped.hEvent;
                slot.overlapped = {};
                slot.overlapped.hEvent = event;
                ResetEvent(event);
                slot.offset = next_offset_;
                slot.size = static_cast<UInt32>(std::min<UInt64>(window_bytes_,
                    std::min<UInt64>(source.length, virtual_size_ - next_offset_)));
                slot.overlapped.Offset = static_cast<DWORD>(source.offset);
                slot.overlapped.OffsetHigh = static_cast<DWORD>(source.offset >> 32);
                DWORD read = 0;
                BOOL ok;
                DWORD error = ERROR_SUCCESS;
                {
                    // Submission itself can block on cached Windows I/O; it
                    // belongs in consumer blocking time as well as the wait.
                    ReadFileWallTimer timer(trace_);
                    ok = ReadFile(slot.handle, slot.bytes.get(), slot.size, &read, &slot.overlapped);
                    if (!ok) error = GetLastError();
                }
                slot.state = ok ? (read == slot.size ? State::Ready : State::Failed)
                                : (error == ERROR_IO_PENDING ? State::Pending : State::Failed);
                next_offset_ += slot.size;
            }
        }

        UInt32 window_bytes_;
        UInt64 virtual_size_;
        UInt64 next_offset_ = 0;
        Resolver resolver_;
        ExtractInputTrace *trace_;
        bool enabled_;
        // At most two file handles, even for thousands of volumes/ranges.
        std::array<Slot, 2> slots_;
    };

    class FileInStream final : public CMyUnknownImp, public IInStream
    {
        Z7_COM_UNKNOWN_IMP_2(ISequentialInStream, IInStream)
        

    public:
        explicit FileInStream(
            const std::wstring &path,
            ExtractInputTrace *trace = nullptr,
            std::wstring mode = L"file",
            InputPrefetchConfig prefetch_config = input_prefetch_config())

            : path_(path),

              trace_(trace),

              handle_(CreateFileW(win32_extended_path(path).c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,

                                  nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr))
        {

            LARGE_INTEGER size{};
            if (handle_ != INVALID_HANDLE_VALUE && GetFileSizeEx(handle_, &size))
            {
                size_ = static_cast<UInt64>(size.QuadPart);
            }

            if (trace_)
            {

                trace_->mode = std::move(mode);

                trace_->last_source_path = path_;

                if (handle_ != INVALID_HANDLE_VALUE && size_)
                {

                    trace_->virtual_size = size_;
                }
                else if (handle_ == INVALID_HANDLE_VALUE)
                {

                    const DWORD error = GetLastError();

                    trace_->read_error = true;

                    trace_->last_hresult = HRESULT_FROM_WIN32(error);

                    trace_->last_win32_error = static_cast<int>(error);
                }
            }

            if (size_ && prefetch_config.enabled)
            {
                prefetch_ = std::make_unique<OverlappedPrefetcher>(prefetch_config, size_,
                    [this](UInt64 offset, PrefetchSource &source)
                    {
                        source = PrefetchSource{&path_, offset, size_ - offset};
                        return true;
                    }, trace_);
            }
            if (trace_ && read_file_timing_enabled())
            {
                trace_->prefetch_enabled = prefetch_ && prefetch_->enabled();
            }
        }

        ~FileInStream()
        {

            if (handle_ != INVALID_HANDLE_VALUE)
            {

                CloseHandle(handle_);
            }
        }

        bool is_open() const { return handle_ != INVALID_HANDLE_VALUE; }

        bool prefetch_enabled() const noexcept { return prefetch_ && prefetch_->enabled(); }


        HRESULT STDMETHODCALLTYPE Read(void *data, UInt32 size, UInt32 *processedSize) SUP7Z_NOEXCEPT override
        {

            if (processedSize)
            {

                *processedSize = 0;
            }

            const UInt64 read_start = position_;
            if (trace_)
            {

                trace_->last_read_virtual_offset = position_;

                trace_->last_read_source_offset = position_;

                trace_->last_read_requested = size;

                trace_->last_read_returned = 0;

                trace_->last_source_path = path_;

                trace_->last_range_index = 0;
            }

            if (prefetch_ && prefetch_->consume(position_, data, size, trace_))
            {
                position_ += size;
                LARGE_INTEGER cached_position{};
                cached_position.QuadPart = static_cast<LONGLONG>(position_);
                if (!SetFilePointerEx(handle_, cached_position, nullptr, FILE_BEGIN))
                {
                    const DWORD error = GetLastError();
                    const HRESULT hr = HRESULT_FROM_WIN32(error);
                    if (trace_)
                    {
                        trace_->read_error = true;
                        trace_->last_hresult = hr;
                        trace_->last_win32_error = static_cast<int>(error);
                    }
                    return hr;
                }
                record_logical_read(trace_, read_start, size);
                prefetch_->after_cached_read(position_);
                if (trace_)
                {
                    trace_->position = position_;
                    trace_->max_position_seen = std::max<UInt64>(trace_->max_position_seen, position_);
                    trace_->total_bytes_returned += size;
                    trace_->last_read_returned = size;
                    trace_->last_hresult = S_OK;
                    trace_->last_win32_error = 0;
                }
                if (processedSize)
                {
                    *processedSize = size;
                }
                return S_OK;
            }

            DWORD read = 0;

            BOOL ok = FALSE;
            DWORD error = ERROR_SUCCESS;
            {
                ReadFileWallTimer timer(trace_);
                ok = ReadFile(handle_, data, size, &read, nullptr);
                if (!ok)
                {
                    error = GetLastError();
                }
            }
            if (!ok)
            {

                const HRESULT hr = HRESULT_FROM_WIN32(error);

                if (trace_)
                {

                    trace_->read_error = true;

                    trace_->last_hresult = hr;

                    trace_->last_win32_error = static_cast<int>(error);
                }

                return hr;
            }

            position_ += read;

            if (prefetch_ && read)
            {
                prefetch_->after_sync_read(position_);
            }

            record_logical_read(trace_, read_start, read);

            if (trace_)
            {

                trace_->position = position_;

                trace_->max_position_seen = std::max<UInt64>(trace_->max_position_seen, position_);

                trace_->total_bytes_returned += read;

                trace_->last_read_returned = read;

                trace_->last_hresult = S_OK;

                trace_->last_win32_error = 0;
            }

            if (processedSize)
            {

                *processedSize = read;
            }

            return S_OK;
        }

        HRESULT STDMETHODCALLTYPE Seek(Int64 offset, UInt32 seekOrigin, UInt64 *newPosition) SUP7Z_NOEXCEPT override
        {

            LARGE_INTEGER distance{};

            distance.QuadPart = offset;

            LARGE_INTEGER new_pos{};

            if (!SetFilePointerEx(handle_, distance, &new_pos, seekOrigin))
            {

                const DWORD error = GetLastError();

                const HRESULT hr = HRESULT_FROM_WIN32(error);

                if (trace_)
                {

                    trace_->last_seek_offset = offset;

                    trace_->last_seek_origin = seekOrigin;

                    trace_->last_hresult = hr;

                    trace_->last_win32_error = static_cast<int>(error);
                }

                return hr;
            }

            const UInt64 prior_position = position_;
            position_ = static_cast<UInt64>(new_pos.QuadPart);

            record_logical_seek(trace_, prior_position, position_);

            if (prefetch_ && prior_position != position_)
            {
                prefetch_->invalidate(position_, trace_);
            }

            if (trace_)
            {

                trace_->position = position_;

                trace_->max_position_seen = std::max<UInt64>(trace_->max_position_seen, position_);

                trace_->last_seek_offset = offset;

                trace_->last_seek_origin = seekOrigin;

                trace_->last_seek_new_position = position_;

                trace_->last_hresult = S_OK;

                trace_->last_win32_error = 0;
            }

            if (newPosition)
            {

                *newPosition = position_;
            }

            return S_OK;
        }

    private:

        std::wstring path_;

        ExtractInputTrace *trace_ = nullptr;

        HANDLE handle_ = INVALID_HANDLE_VALUE;

        UInt64 position_ = 0;

        UInt64 size_ = 0;

        std::unique_ptr<OverlappedPrefetcher> prefetch_;
    };

    class MultiFileInStream final : public CMyUnknownImp, public IInStream
    {
        Z7_COM_UNKNOWN_IMP_2(ISequentialInStream, IInStream)
        

    public:
        explicit MultiFileInStream(
            std::vector<std::wstring> paths,
            ExtractInputTrace *trace = nullptr,
            InputPrefetchConfig prefetch_config = input_prefetch_config())

            : paths_(std::move(paths)), trace_(trace)
        {

            UInt64 total = 0;

            for (const auto &path : paths_)
            {

                try
                {

                    const UInt64 size = static_cast<UInt64>(std::filesystem::file_size(path));

                    sizes_.push_back(size);

                    offsets_.push_back(total);

                    total += size;
                }
                catch (...)
                {

                    valid_ = false;

                    sizes_.push_back(0);

                    offsets_.push_back(total);
                }
            }

            total_size_ = total;

            valid_ = valid_ && !paths_.empty();

            if (trace_)
            {

                trace_->mode = L"multi_file";

                trace_->virtual_size = total_size_;
            }

            if (valid_ && total_size_ && prefetch_config.enabled)
            {
                prefetch_ = std::make_unique<OverlappedPrefetcher>(prefetch_config, total_size_,
                    [this](UInt64 offset, PrefetchSource &source)
                    {
                        const std::size_t index = find_part_index(offset);
                        if (index >= paths_.size()) return false;
                        const UInt64 part_offset = offset - offsets_[index];
                        source = PrefetchSource{&paths_[index], part_offset, sizes_[index] - part_offset};
                        return true;
                    }, trace_);
            }
            if (trace_ && read_file_timing_enabled())
            {
                trace_->prefetch_enabled = prefetch_ && prefetch_->enabled();
            }
        }

        ~MultiFileInStream() { close_cached_handle(); }

        bool is_open() const { return valid_; }


        HRESULT STDMETHODCALLTYPE Read(void *data, UInt32 size, UInt32 *processedSize) SUP7Z_NOEXCEPT override
        {

            if (processedSize)
            {

                *processedSize = 0;
            }

            if (!valid_ || !data)
            {

                return E_FAIL;
            }

            const UInt64 read_start = position_;
            auto *out = static_cast<unsigned char *>(data);

            if (prefetch_ && prefetch_->consume(position_, data, size, trace_))
            {
                position_ += size;
                record_logical_read(trace_, read_start, size);
                prefetch_->after_cached_read(position_);
                if (trace_)
                {
                    const std::size_t index = find_part_index(read_start);
                    trace_->position = position_;
                    trace_->max_position_seen = std::max<UInt64>(trace_->max_position_seen, position_);
                    trace_->total_bytes_returned += size;
                    trace_->last_read_virtual_offset = read_start;
                    trace_->last_read_source_offset = index < offsets_.size() ? read_start - offsets_[index] : 0;
                    trace_->last_read_requested = size;
                    trace_->last_read_returned = size;
                    trace_->last_source_path = index < paths_.size() ? paths_[index] : L"";
                    trace_->last_range_index = static_cast<UInt32>(index);
                    trace_->last_hresult = S_OK;
                    trace_->last_win32_error = 0;
                }
                if (processedSize)
                {
                    *processedSize = size;
                }
                return S_OK;
            }

            UInt32 total_read = 0;

            while (total_read < size && position_ < total_size_)
            {

                const std::size_t index = find_part_index(position_);

                if (index >= paths_.size())
                {

                    break;
                }

                const UInt64 part_offset = position_ - offsets_[index];

                const UInt64 remaining_in_part = sizes_[index] - part_offset;

                const UInt32 want = static_cast<UInt32>(std::min<UInt64>(size - total_read, remaining_in_part));

                if (want == 0)
                {

                    break;
                }

                if (trace_)
                {

                    trace_->last_read_virtual_offset = position_;

                    trace_->last_read_source_offset = part_offset;

                    trace_->last_read_requested = want;

                    trace_->last_read_returned = 0;

                    trace_->last_source_path = paths_[index];

                    trace_->last_range_index = static_cast<UInt32>(index);
                }

                const HRESULT open_result = ensure_cached_handle(index);

                if (open_result != S_OK)
                {

                    const DWORD error = GetLastError();

                    const HRESULT hr = open_result;

                    if (trace_)
                    {

                        trace_->read_error = true;

                        trace_->last_hresult = hr;

                        trace_->last_win32_error = static_cast<int>(error);
                    }

                    return hr;
                }

                if (cached_handle_position_ != part_offset)
                {

                    LARGE_INTEGER distance{};

                    distance.QuadPart = static_cast<LONGLONG>(part_offset);

                    if (!SetFilePointerEx(cached_handle_, distance, nullptr, FILE_BEGIN))
                    {

                        const DWORD error = GetLastError();

                        const HRESULT hr = HRESULT_FROM_WIN32(error);

                        close_cached_handle();

                        if (trace_)
                        {

                            trace_->read_error = true;

                            trace_->last_hresult = hr;

                            trace_->last_win32_error = static_cast<int>(error);
                        }

                        return hr;
                    }

                    cached_handle_position_ = part_offset;
                }

                DWORD read = 0;

                BOOL ok = FALSE;
                DWORD error = ERROR_SUCCESS;
                {
                    ReadFileWallTimer timer(trace_);
                    ok = ReadFile(cached_handle_, out + total_read, want, &read, nullptr);
                    if (!ok)
                    {
                        error = GetLastError();
                    }
                }

                if (!ok)
                {

                    close_cached_handle();

                    const HRESULT hr = HRESULT_FROM_WIN32(error);

                    if (trace_)
                    {

                        trace_->read_error = true;

                        trace_->last_hresult = hr;

                        trace_->last_win32_error = static_cast<int>(error);
                    }

                    return hr;
                }

                if (read == 0)
                {

                    break;
                }

                total_read += read;

                position_ += read;

                cached_handle_position_ += read;

                if (trace_)
                {

                    trace_->position = position_;

                    trace_->max_position_seen = std::max<UInt64>(trace_->max_position_seen, position_);

                    trace_->total_bytes_returned += read;

                    trace_->last_read_returned = read;

                    trace_->last_hresult = S_OK;

                    trace_->last_win32_error = 0;
                }
            }

            record_logical_read(trace_, read_start, total_read);

            if (prefetch_ && total_read)
            {
                prefetch_->after_sync_read(position_);
            }

            if (processedSize)
            {

                *processedSize = total_read;
            }

            return S_OK;
        }

        HRESULT STDMETHODCALLTYPE Seek(Int64 offset, UInt32 seekOrigin, UInt64 *newPosition) SUP7Z_NOEXCEPT override
        {

            Int64 base = 0;

            if (seekOrigin == FILE_CURRENT)
            {

                base = static_cast<Int64>(position_);
            }
            else if (seekOrigin == FILE_END)
            {

                base = static_cast<Int64>(total_size_);
            }

            const Int64 next = base + offset;

            if (next < 0)
            {

                return E_INVALIDARG;
            }

            const UInt64 prior_position = position_;
            position_ = static_cast<UInt64>(next);

            record_logical_seek(trace_, prior_position, position_);

            if (prefetch_ && prior_position != position_)
            {
                prefetch_->invalidate(position_, trace_);
            }

            if (trace_)
            {

                trace_->position = position_;

                trace_->max_position_seen = std::max<UInt64>(trace_->max_position_seen, position_);

                trace_->last_seek_offset = offset;

                trace_->last_seek_origin = seekOrigin;

                trace_->last_seek_new_position = position_;

                trace_->last_hresult = S_OK;

                trace_->last_win32_error = 0;
            }

            if (newPosition)
            {

                *newPosition = position_;
            }

            return S_OK;
        }

    private:
        std::size_t find_part_index(UInt64 position) const
        {

            const auto upper = std::upper_bound(offsets_.begin(), offsets_.end(), position);

            if (upper == offsets_.begin())
            {

                return paths_.size();
            }

            const std::size_t index = static_cast<std::size_t>(std::distance(offsets_.begin(), upper) - 1);

            return index < sizes_.size() && position - offsets_[index] < sizes_[index] ? index : paths_.size();
        }

        HRESULT ensure_cached_handle(std::size_t index)
        {

            if (cached_handle_ != INVALID_HANDLE_VALUE && cached_index_ == index)
            {

                return S_OK;
            }

            close_cached_handle();

            cached_handle_ = CreateFileW(win32_extended_path(paths_[index]).c_str(), GENERIC_READ,
                                         FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                         nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

            if (cached_handle_ == INVALID_HANDLE_VALUE)
            {

                return HRESULT_FROM_WIN32(GetLastError());
            }

            cached_index_ = index;

            cached_handle_position_ = 0;

            return S_OK;
        }

        void close_cached_handle()
        {

            if (cached_handle_ != INVALID_HANDLE_VALUE)
            {

                CloseHandle(cached_handle_);

                cached_handle_ = INVALID_HANDLE_VALUE;
            }

            cached_index_ = static_cast<std::size_t>(-1);

            cached_handle_position_ = 0;
        }


        std::vector<std::wstring> paths_;

        std::vector<UInt64> sizes_;

        std::vector<UInt64> offsets_;

        UInt64 total_size_ = 0;

        UInt64 position_ = 0;

        ExtractInputTrace *trace_ = nullptr;

        HANDLE cached_handle_ = INVALID_HANDLE_VALUE;

        std::size_t cached_index_ = static_cast<std::size_t>(-1);

        UInt64 cached_handle_position_ = 0;

        bool valid_ = true;

        std::unique_ptr<OverlappedPrefetcher> prefetch_;
    };

    struct NormalizedInputRange
    {

        std::wstring path;

        UInt64 start = 0;

        UInt64 length = 0;

        UInt64 virtual_offset = 0;
    };

    class MultiRangeInStream final : public CMyUnknownImp, public IInStream
    {
        Z7_COM_UNKNOWN_IMP_2(ISequentialInStream, IInStream)
        

    public:
        explicit MultiRangeInStream(
            const std::vector<ExtractInputRange> &ranges,
            ExtractInputTrace *trace = nullptr,
            InputPrefetchConfig prefetch_config = InputPrefetchConfig{false, 512 * 1024})

            : trace_(trace)
        {

            UInt64 virtual_offset = 0;

            for (const auto &input : ranges)
            {

                if (input.path.empty())
                {

                    valid_ = false;

                    continue;
                }

                UInt64 file_size = 0;

                try
                {

                    file_size = static_cast<UInt64>(std::filesystem::file_size(input.path));
                }
                catch (...)
                {

                    valid_ = false;

                    continue;
                }

                const UInt64 start = std::min<UInt64>(input.start, file_size);

                const UInt64 end = input.has_end ? std::min<UInt64>(input.end, file_size) : file_size;

                if (end < start)
                {

                    valid_ = false;

                    continue;
                }

                const UInt64 length = end - start;

                if (length == 0)
                {

                    continue;
                }

                ranges_.push_back(NormalizedInputRange{input.path, start, length, virtual_offset});

                virtual_offset += length;
            }

            total_size_ = virtual_offset;

            valid_ = valid_ && !ranges_.empty();

            if (trace_)
            {

                trace_->mode = ranges_.size() == 1 ? L"file_range" : L"concat_ranges";

                trace_->virtual_size = total_size_;
            }

            if (valid_ && total_size_ && prefetch_config.enabled)
            {
                prefetch_ = std::make_unique<OverlappedPrefetcher>(prefetch_config, total_size_,
                    [this](UInt64 offset, PrefetchSource &source)
                    {
                        const std::size_t index = find_range_index(offset);
                        if (index >= ranges_.size()) return false;
                        const auto &range = ranges_[index];
                        const UInt64 displacement = offset - range.virtual_offset;
                        source = PrefetchSource{&range.path, range.start + displacement, range.length - displacement};
                        return true;
                    }, trace_);
            }
            if (trace_ && read_file_timing_enabled())
            {
                trace_->prefetch_enabled = prefetch_ && prefetch_->enabled();
            }
        }

        ~MultiRangeInStream()
        {
            prefetch_.reset();
            close_cached_handle();
        }

        bool is_open() const { return valid_; }


        HRESULT STDMETHODCALLTYPE Read(void *data, UInt32 size, UInt32 *processedSize) SUP7Z_NOEXCEPT override
        {

            if (processedSize)
            {

                *processedSize = 0;
            }

            if (!valid_ || !data)
            {

                return E_FAIL;
            }

            const UInt64 read_start = position_;
            auto *out = static_cast<unsigned char *>(data);

            if (prefetch_ && prefetch_->consume(position_, data, size, trace_))
            {
                position_ += size;
                record_logical_read(trace_, read_start, size);
                prefetch_->after_cached_read(position_);
                if (trace_)
                {
                    const std::size_t index = find_range_index(read_start);
                    const auto &range = ranges_[index];
                    const UInt64 offset_in_range = read_start - range.virtual_offset;
                    trace_->position = position_;
                    trace_->max_position_seen = std::max<UInt64>(trace_->max_position_seen, position_);
                    trace_->total_bytes_returned += size;
                    trace_->last_read_virtual_offset = read_start;
                    trace_->last_read_source_offset = range.start + offset_in_range;
                    trace_->last_read_requested = size;
                    trace_->last_read_returned = size;
                    trace_->last_source_path = range.path;
                    trace_->last_range_index = static_cast<UInt32>(index);
                    trace_->last_hresult = S_OK;
                    trace_->last_win32_error = 0;
                }
                if (processedSize)
                {
                    *processedSize = size;
                }
                return S_OK;
            }

            UInt32 total_read = 0;

            while (total_read < size && position_ < total_size_)
            {

                const std::size_t index = find_range_index(position_);

                if (index >= ranges_.size())
                {

                    break;
                }

                const auto *range = &ranges_[index];

                const UInt64 offset_in_range = position_ - range->virtual_offset;

                const UInt64 remaining = range->length - offset_in_range;

                const UInt32 want = static_cast<UInt32>(std::min<UInt64>(size - total_read, remaining));

                if (trace_)
                {

                    trace_->last_read_virtual_offset = position_;

                    trace_->last_read_source_offset = range->start + offset_in_range;

                    trace_->last_read_requested = want;

                    trace_->last_read_returned = 0;

                    trace_->last_source_path = range->path;

                    trace_->last_range_index = static_cast<UInt32>(index);
                }

                const HRESULT open_result = ensure_cached_handle(index);

                if (open_result != S_OK)
                {

                    const DWORD error = GetLastError();

                    const HRESULT hr = open_result;

                    if (trace_)
                    {

                        trace_->read_error = true;

                        trace_->last_hresult = hr;

                        trace_->last_win32_error = static_cast<int>(error);
                    }

                    return hr;
                }

                const UInt64 source_offset = range->start + offset_in_range;

                if (cached_handle_position_ != source_offset)
                {

                    LARGE_INTEGER distance{};

                    distance.QuadPart = static_cast<LONGLONG>(source_offset);

                    if (!SetFilePointerEx(cached_handle_, distance, nullptr, FILE_BEGIN))
                    {

                        const DWORD error = GetLastError();

                        const HRESULT hr = HRESULT_FROM_WIN32(error);

                        close_cached_handle();

                        if (trace_)
                        {

                            trace_->read_error = true;

                            trace_->last_hresult = hr;

                            trace_->last_win32_error = static_cast<int>(error);
                        }

                        return hr;
                    }

                    cached_handle_position_ = source_offset;
                }

                DWORD read = 0;

                BOOL ok = FALSE;
                DWORD error = ERROR_SUCCESS;
                {
                    ReadFileWallTimer timer(trace_);
                    ok = ReadFile(cached_handle_, out + total_read, want, &read, nullptr);
                    if (!ok)
                    {
                        error = GetLastError();
                    }
                }

                if (!ok)
                {

                    close_cached_handle();

                    const HRESULT hr = HRESULT_FROM_WIN32(error);

                    if (trace_)
                    {

                        trace_->read_error = true;

                        trace_->last_hresult = hr;

                        trace_->last_win32_error = static_cast<int>(error);
                    }

                    return hr;
                }

                if (read == 0)
                {

                    break;
                }

                total_read += read;

                position_ += read;

                cached_handle_position_ += read;

                if (trace_)
                {

                    trace_->position = position_;

                    trace_->max_position_seen = std::max<UInt64>(trace_->max_position_seen, position_);

                    trace_->total_bytes_returned += read;

                    trace_->last_read_returned = read;

                    trace_->last_hresult = S_OK;

                    trace_->last_win32_error = 0;
                }
            }

            record_logical_read(trace_, read_start, total_read);

            if (prefetch_ && total_read)
            {
                prefetch_->after_sync_read(position_);
            }

            if (processedSize)
            {

                *processedSize = total_read;
            }

            return S_OK;
        }

        HRESULT STDMETHODCALLTYPE Seek(Int64 offset, UInt32 seekOrigin, UInt64 *newPosition) SUP7Z_NOEXCEPT override
        {

            Int64 base = 0;

            if (seekOrigin == FILE_CURRENT)
            {

                base = static_cast<Int64>(position_);
            }
            else if (seekOrigin == FILE_END)
            {

                base = static_cast<Int64>(total_size_);
            }

            const Int64 next = base + offset;

            if (next < 0)
            {

                return E_INVALIDARG;
            }

            const UInt64 prior_position = position_;
            position_ = static_cast<UInt64>(next);

            record_logical_seek(trace_, prior_position, position_);

            if (prefetch_ && prior_position != position_)
            {
                prefetch_->invalidate(position_, trace_);
            }

            if (trace_)
            {

                trace_->position = position_;

                trace_->max_position_seen = std::max<UInt64>(trace_->max_position_seen, position_);

                trace_->last_seek_offset = offset;

                trace_->last_seek_origin = seekOrigin;

                trace_->last_seek_new_position = position_;

                trace_->last_hresult = S_OK;

                trace_->last_win32_error = 0;
            }

            if (newPosition)
            {

                *newPosition = position_;
            }

            return S_OK;
        }

    private:
        std::size_t find_range_index(UInt64 position) const
        {

            const auto upper = std::upper_bound(
                ranges_.begin(), ranges_.end(), position,
                [](UInt64 value, const NormalizedInputRange &range)
                { return value < range.virtual_offset; });

            if (upper == ranges_.begin())
            {

                return ranges_.size();
            }

            const std::size_t index = static_cast<std::size_t>(std::distance(ranges_.begin(), upper) - 1);

            const auto &range = ranges_[index];

            return position - range.virtual_offset < range.length ? index : ranges_.size();
        }

        HRESULT ensure_cached_handle(std::size_t index)
        {

            if (cached_handle_ != INVALID_HANDLE_VALUE && cached_index_ == index)
            {

                return S_OK;
            }

            close_cached_handle();

            cached_handle_ = CreateFileW(win32_extended_path(ranges_[index].path).c_str(), GENERIC_READ,
                                         FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                         nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

            if (cached_handle_ == INVALID_HANDLE_VALUE)
            {

                return HRESULT_FROM_WIN32(GetLastError());
            }

            cached_index_ = index;

            cached_handle_position_ = 0;

            return S_OK;
        }

        void close_cached_handle()
        {

            if (cached_handle_ != INVALID_HANDLE_VALUE)
            {

                CloseHandle(cached_handle_);

                cached_handle_ = INVALID_HANDLE_VALUE;
            }

            cached_index_ = static_cast<std::size_t>(-1);

            cached_handle_position_ = 0;
        }


        std::vector<NormalizedInputRange> ranges_;

        UInt64 total_size_ = 0;

        UInt64 position_ = 0;

        ExtractInputTrace *trace_ = nullptr;

        HANDLE cached_handle_ = INVALID_HANDLE_VALUE;

        std::size_t cached_index_ = static_cast<std::size_t>(-1);

        UInt64 cached_handle_position_ = 0;

        std::unique_ptr<OverlappedPrefetcher> prefetch_;

        bool valid_ = true;

    };

    CMyComPtr<IInStream> open_archive_stream(

        const std::wstring &archive_path,

        const std::vector<std::wstring> &part_paths,

        bool &opened,

        ExtractInputTrace *trace = nullptr,

        bool structured_order = false,

        InputPrefetchConfig prefetch_config = input_prefetch_config()

    );

    std::wstring callback_archive_path(const std::wstring &archive_path, const std::vector<std::wstring> &part_paths);

#endif

} // namespace sunpack::sevenzip
