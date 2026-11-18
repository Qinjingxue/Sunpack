#pragma once

#include "sevenzip_paths.hpp"
#include "extraction_replay.hpp"

#ifdef SUP7Z_DEBUG
#include "worker_pipeline_timing.hpp"
#endif

#include "sevenzip_sdk.hpp"
#include <cstdlib>

#ifdef _WIN32

#include <algorithm>

#include <array>

#include <cstring>

#include <filesystem>

#include <functional>

#include <memory>

#include <new>

#include <string>

#include <utility>

#include <vector>

#endif

namespace sunpack::sevenzip
{

#ifdef _WIN32

#ifdef SUP7Z_DEBUG
    inline thread_local UInt64 observed_logical_read_bytes = 0;
    inline thread_local std::size_t observed_range_size_queries = 0;
    inline thread_local std::size_t observed_range_handle_opens = 0;
#endif

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

    inline void record_input_error(ExtractInputTrace *trace, const std::wstring &path,
                                   HRESULT hr, UInt64 offset = 0,
                                   UInt64 source = 0, UInt32 requested = 0) noexcept
    {
        if (!trace || FAILED(trace->read_hresult)) return;
        trace->read_hresult = hr;
        trace->last_read_virtual_offset = offset;
        trace->last_read_source_offset = source;
        trace->last_read_requested = requested;
        try { trace->last_source_path = path; }
        catch (const std::bad_alloc &) { trace->last_source_path.clear(); }
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
                            [[maybe_unused]] ExtractInputTrace *trace = nullptr)
            : window_bytes_(config.window_bytes), virtual_size_(size),
              resolver_(std::move(resolver)),
#ifdef SUP7Z_DEBUG
              pipeline_timing_(trace ? trace->pipeline_timing : nullptr),
#endif
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

        bool consume(UInt64 offset, void *data, UInt32 size)
        {
            if (!enabled() || !size)
            {
                return false;
            }
            // A decoder read may straddle the two windows. Verify coverage
            // before copying; an uncovered or short read uses the direct path.
            UInt64 cursor = offset;
            UInt32 remaining = size;
            while (remaining)
            {
                Slot *slot = find(cursor);
                if (!slot || slot->state == State::Failed)
                {
                    return false;
                }
                const UInt32 count = static_cast<UInt32>(std::min<UInt64>(remaining, slot->offset + slot->size - cursor));
                cursor += count;
                remaining -= count;
            }
            cursor = offset;
            remaining = size;
            auto *destination = static_cast<unsigned char *>(data);
            while (remaining)
            {
                Slot &slot = *find(cursor);
                if (slot.state == State::Pending)
                {
                    DWORD read = 0;
#ifdef SUP7Z_DEBUG
                    PipelineStageScope input_scope(pipeline_timing_, PipelineStage::Input);
#endif
                    const BOOL ok = GetOverlappedResult(slot.handle, &slot.overlapped, &read, TRUE);
                    slot.state = ok && read == slot.size ? State::Ready : State::Failed;
                }
                if (slot.state != State::Ready)
                {
                    return false;
                }
                const auto displacement = static_cast<std::size_t>(cursor - slot.offset);
                const UInt32 count = std::min<UInt32>(remaining, slot.size - static_cast<UInt32>(displacement));
                std::memcpy(destination, slot.bytes.get() + displacement, count);
                cursor += count;
                destination += count;
                remaining -= count;
            }
            return true;
        }

        void after_read(UInt64 end) { advance_safely(end); }

        void invalidate(UInt64 next)
        {
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

        void advance_safely(UInt64 end) noexcept
        {
            try
            {
                advance(end);
            }
            catch (const std::bad_alloc &)
            {
                // A speculative read must never turn memory pressure into a
                // decoder failure. Drain any pending I/O and use direct reads.
                close();
            }
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
#ifdef SUP7Z_DEBUG
                    PipelineStageScope input_scope(pipeline_timing_, PipelineStage::Input);
#endif
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
#ifdef SUP7Z_DEBUG
        PipelineTiming *pipeline_timing_;
#endif
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
            InputPrefetchConfig prefetch_config = input_prefetch_config())

            : path_(path),

              trace_(trace),

              handle_(CreateFileW(win32_extended_path(path).c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,

                                  nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr))
        {
            const DWORD open_error = handle_ == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
            open_hresult_ = HRESULT_FROM_WIN32(open_error);
            // A failed constructor does not run ~FileInStream. Keep the input
            // handle owned while prefetch setup can still allocate.
            std::unique_ptr<void, decltype(&CloseHandle)> handle_owner(
                handle_ == INVALID_HANDLE_VALUE ? nullptr : handle_, &CloseHandle);
            LARGE_INTEGER size{};
            if (handle_ != INVALID_HANDLE_VALUE && GetFileSizeEx(handle_, &size))
            {
                size_ = static_cast<UInt64>(size.QuadPart);
            }

            if (handle_ == INVALID_HANDLE_VALUE)
                record_input_error(trace_, path_, open_hresult_);

            if (size_ && prefetch_config.enabled)
            {
                prefetch_ = std::make_unique<OverlappedPrefetcher>(prefetch_config, size_,
                    [this](UInt64 offset, PrefetchSource &source)
                    {
                        source = PrefetchSource{&path_, offset, size_ - offset};
                        return true;
                    }, trace_);
            }
            handle_owner.release();
        }

        ~FileInStream()
        {

            if (handle_ != INVALID_HANDLE_VALUE)
            {

                CloseHandle(handle_);
            }
        }

        bool is_open() const { return handle_ != INVALID_HANDLE_VALUE; }
        HRESULT open_hresult() const { return open_hresult_; }

        HRESULT STDMETHODCALLTYPE Read(void *data, UInt32 size, UInt32 *processedSize) SUP7Z_NOEXCEPT override
        {
            if (attempt_replay_) attempt_replay_->observe_volume_read(position_, size, &path_);


            if (processedSize)
            {

                *processedSize = 0;
            }

            const UInt64 read_start = position_;
            if (prefetch_ && prefetch_->consume(position_, data, size))
            {
                position_ += size;
                // The decoder handle is independent of the OVERLAPPED handles.
                // Reposition it only if a later read misses the prefetch cache.
                file_pointer_dirty_ = true;
#ifdef SUP7Z_DEBUG
                observed_logical_read_bytes += size;
#endif
                prefetch_->after_read(position_);
                if (processedSize)
                {
                    *processedSize = size;
                }
                return S_OK;
            }

            if (file_pointer_dirty_ && size != 0)
            {
                LARGE_INTEGER logical_position{};
                logical_position.QuadPart = static_cast<LONGLONG>(position_);
                if (!SetFilePointerEx(handle_, logical_position, nullptr, FILE_BEGIN))
                {
                    const DWORD error = GetLastError();
                    const HRESULT hr = HRESULT_FROM_WIN32(error);
                    record_input_error(trace_, path_, hr, read_start, read_start, size);
                    return hr;
                }
                file_pointer_dirty_ = false;
            }

            DWORD read = 0;

            BOOL ok = FALSE;
            DWORD error = ERROR_SUCCESS;
            {
#ifdef SUP7Z_DEBUG
                PipelineStageScope input_scope(trace_ ? trace_->pipeline_timing : nullptr, PipelineStage::Input);
#endif
                ok = ReadFile(handle_, data, size, &read, nullptr);
                if (!ok)
                {
                    error = GetLastError();
                }
            }
            if (!ok)
            {

                const HRESULT hr = HRESULT_FROM_WIN32(error);

                record_input_error(trace_, path_, hr, read_start, read_start, size);

                return hr;
            }

            position_ += read;

            if (prefetch_ && read)
            {
                prefetch_->after_read(position_);
            }

#ifdef SUP7Z_DEBUG
            observed_logical_read_bytes += read;
#endif

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
            // FILE_CURRENT is relative to the decoder's logical position, not
            // the possibly stale file pointer after prefetched reads.
            BOOL positioned = TRUE;
            if (file_pointer_dirty_ && seekOrigin == FILE_CURRENT)
            {
                LARGE_INTEGER logical_position{};
                logical_position.QuadPart = static_cast<LONGLONG>(position_);
                positioned = SetFilePointerEx(handle_, logical_position, nullptr, FILE_BEGIN);
            }
            if (positioned)
                positioned = SetFilePointerEx(handle_, distance, &new_pos, seekOrigin);

            if (!positioned) return HRESULT_FROM_WIN32(GetLastError());

            const UInt64 prior_position = position_;
            position_ = static_cast<UInt64>(new_pos.QuadPart);
            file_pointer_dirty_ = false;

            if (prefetch_ && prior_position != position_)
            {
                prefetch_->invalidate(position_);
            }

            if (newPosition)
            {

                *newPosition = position_;
            }

            return S_OK;
        }

    private:
        ExtractionReplay* attempt_replay_ = current_extraction_replay;

        std::wstring path_;

        ExtractInputTrace *trace_ = nullptr;

        HANDLE handle_ = INVALID_HANDLE_VALUE;
        HRESULT open_hresult_ = S_OK;

        UInt64 position_ = 0;

        UInt64 size_ = 0;

        bool file_pointer_dirty_ = false;
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
            std::vector<std::wstring> paths,
            ExtractInputTrace *trace,
            InputPrefetchConfig prefetch_config)
            : trace_(trace)
        {
            ranges_.reserve(paths.size());
            for (auto &path : paths)
            {
                std::error_code error;
                const auto length = std::filesystem::file_size(path, error);
                if (error)
                {
                    open_hresult_ = HRESULT_FROM_WIN32(error.value());
                    record_input_error(trace_, path, open_hresult_);
                    continue;
                }
                ranges_.push_back({std::move(path), 0, length, total_size_});
                total_size_ += length;
            }
            initialize(prefetch_config);
        }

        explicit MultiRangeInStream(
            const std::vector<ExtractInputRange> &ranges,
            ExtractInputTrace *trace = nullptr,
            InputPrefetchConfig prefetch_config = InputPrefetchConfig{false, 512 * 1024},
            bool physical_volume = false, VolumeReadUncertainty* probe_reads = nullptr)

            : trace_(trace), physical_volume_(physical_volume), probe_reads_(probe_reads)
        {

            ranges_.reserve(ranges.size());
            const std::wstring* sized_path = nullptr;
            UInt64 file_size = 0;

            for (const auto &input : ranges)
            {

                if (input.path.empty())
                {
                    if (open_hresult_ == S_OK) open_hresult_ = E_FAIL;
                    continue;
                }

                if (!sized_path || *sized_path != input.path)
                {
                    std::error_code error;
#ifdef SUP7Z_DEBUG
                    ++observed_range_size_queries;
#endif
                    const auto size = std::filesystem::file_size(input.path, error);
                    if (error)
                    {
                        open_hresult_ = HRESULT_FROM_WIN32(error.value());
                        record_input_error(trace_, input.path, open_hresult_);
                        continue;
                    }
                    sized_path = &input.path;
                    file_size = size;
                }

                const UInt64 start = std::min<UInt64>(input.start, file_size);

                const UInt64 end = input.has_end ? std::min<UInt64>(input.end, file_size) : file_size;

                if (end < start)
                {
                    if (open_hresult_ == S_OK) open_hresult_ = E_FAIL;
                    continue;
                }

                const UInt64 length = end - start;

                if (length == 0)
                {

                    continue;
                }

                ranges_.push_back({input.path, start, length, total_size_});

                total_size_ += length;
            }

            initialize(prefetch_config);
        }

        ~MultiRangeInStream()
        {
            prefetch_.reset();
            close_cached_handle();
        }

        bool is_open() const { return open_hresult_ == S_OK; }
        HRESULT open_hresult() const { return open_hresult_; }


        HRESULT STDMETHODCALLTYPE Read(void *data, UInt32 size, UInt32 *processedSize) SUP7Z_NOEXCEPT override
        {
            if (probe_reads_) probe_reads_->observe_logical_read(position_, size);
            else if (attempt_replay_) attempt_replay_->observe_volume_read(position_, size, !physical_volume_ || ranges_.empty() ? nullptr : &ranges_.front().path);


            if (processedSize)
            {

                *processedSize = 0;
            }

            if (!is_open() || !data)
            {

                return E_FAIL;
            }

            auto *out = static_cast<unsigned char *>(data);

            if (prefetch_ && prefetch_->consume(position_, data, size))
            {
                position_ += size;
#ifdef SUP7Z_DEBUG
                observed_logical_read_bytes += size;
#endif
                prefetch_->after_read(position_);
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
                const UInt64 source_offset = range->start + offset_in_range;
                const HRESULT open_result = ensure_cached_handle(index);
                if (open_result != S_OK)
                {
                    record_input_error(trace_, range->path, open_result, position_, source_offset, want);
                    return open_result;
                }

                if (cached_handle_position_ != source_offset)
                {

                    LARGE_INTEGER distance{};

                    distance.QuadPart = static_cast<LONGLONG>(source_offset);

                    if (!SetFilePointerEx(cached_handle_, distance, nullptr, FILE_BEGIN))
                    {

                        const DWORD error = GetLastError();

                        const HRESULT hr = HRESULT_FROM_WIN32(error);

                        close_cached_handle();

                        record_input_error(trace_, range->path, hr, position_, source_offset, want);

                        return hr;
                    }

                    cached_handle_position_ = source_offset;
                }

                DWORD read = 0;

                BOOL ok = FALSE;
                DWORD error = ERROR_SUCCESS;
                {
#ifdef SUP7Z_DEBUG
                    PipelineStageScope input_scope(trace_ ? trace_->pipeline_timing : nullptr, PipelineStage::Input);
#endif
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

                    record_input_error(trace_, range->path, hr, position_, source_offset, want);

                    return hr;
                }

                if (read == 0)
                {
                    break;
                }
                total_read += read;
                position_ += read;
                cached_handle_position_ += read;
            }

#ifdef SUP7Z_DEBUG
            observed_logical_read_bytes += total_read;
#endif

            if (prefetch_ && total_read)
            {
                prefetch_->after_read(position_);
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

            if (prefetch_ && prior_position != position_)
            {
                prefetch_->invalidate(position_);
            }

            if (newPosition)
            {

                *newPosition = position_;
            }

            return S_OK;
        }

    private:
        void initialize(InputPrefetchConfig prefetch_config)
        {
            if (ranges_.empty() && open_hresult_ == S_OK) open_hresult_ = E_FAIL;

            if (is_open() && total_size_ && prefetch_config.enabled)
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
        }

        ExtractionReplay* attempt_replay_ = current_extraction_replay;
        VolumeReadUncertainty* probe_reads_ = nullptr;
        std::size_t find_range_index(UInt64 position) const
        {
            if (cached_index_ < ranges_.size())
            {
                const auto &cached = ranges_[cached_index_];
                if (position >= cached.virtual_offset && position - cached.virtual_offset < cached.length)
                    return cached_index_;
            }
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
            if (cached_handle_ != INVALID_HANDLE_VALUE &&
                (cached_index_ == index || ranges_[cached_index_].path == ranges_[index].path))
            {
                cached_index_ = index;
                return S_OK;
            }

            close_cached_handle();

#ifdef SUP7Z_DEBUG
            ++observed_range_handle_opens;
#endif
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
        bool physical_volume_ = false;

        HANDLE cached_handle_ = INVALID_HANDLE_VALUE;

        std::size_t cached_index_ = static_cast<std::size_t>(-1);

        UInt64 cached_handle_position_ = 0;

        std::unique_ptr<OverlappedPrefetcher> prefetch_;

        HRESULT open_hresult_ = S_OK;

    };

    struct OpenedArchiveStream
    {
        CMyComPtr<IInStream> stream;
        std::wstring callback_path;
        bool opened;
    };

    OpenedArchiveStream open_archive_stream(

        const std::wstring &archive_path,

        const std::vector<std::wstring> &part_paths,

        ExtractInputTrace *trace = nullptr,

        const std::vector<std::wstring> &canonical_names = {},

        InputPrefetchConfig prefetch_config = input_prefetch_config(),
        const std::vector<ExtractInputRange> &input_ranges = {}, VolumeReadUncertainty* probe_reads = nullptr);

#endif

} // namespace sunpack::sevenzip
