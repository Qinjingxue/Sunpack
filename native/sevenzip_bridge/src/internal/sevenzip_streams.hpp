#pragma once

#include "sevenzip_paths.hpp"

#include "sevenzip_sdk.hpp"

#ifdef _WIN32

#include <algorithm>

#include <chrono>

#include <condition_variable>

#include <cstring>

#include <cstdlib>

#include <filesystem>

#include <functional>

#include <map>

#include <memory>

#include <mutex>

#include <string>

#include <thread>

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
        std::size_t depth = 2;
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
            if (const char *depth = std::getenv("SUNPACK_SEVENZIP_PREFETCH_DEPTH"))
            {
                const unsigned long parsed = std::strtoul(depth, nullptr, 10);
                if (parsed >= 1 && parsed <= 8)
                {
                    value.depth = static_cast<std::size_t>(parsed);
                }
            }
            return value;
        }();
        return config;
    }

    inline bool open_prefetch_enabled() noexcept
    {
#ifdef SUP7Z_USE_OPEN_PREFETCH
        return true;
#else
        return false;
#endif
    }

#ifdef SUP7Z_USE_PLANNED_IO
    struct PlannedPrefetchConfig
    {
        // Two large slabs by default: enough overlap for the decoder while keeping ReadFile count low.
        UInt64 buffer_bytes = 32ULL * 1024 * 1024;
        UInt32 io_bytes = 16U * 1024 * 1024;
    };

    inline PlannedPrefetchConfig planned_prefetch_config() noexcept
    {
        static const PlannedPrefetchConfig config = []
        {
            PlannedPrefetchConfig value;
            if (const char *buffer_mib = std::getenv("SUNPACK_SEVENZIP_PLANNED_BUFFER_MIB"))
            {
                const unsigned long parsed = std::strtoul(buffer_mib, nullptr, 10);
                if (parsed >= 4 && parsed <= 512)
                {
                    value.buffer_bytes = static_cast<UInt64>(parsed) * 1024 * 1024;
                }
            }
            if (const char *io_mib = std::getenv("SUNPACK_SEVENZIP_PLANNED_IO_MIB"))
            {
                const unsigned long parsed = std::strtoul(io_mib, nullptr, 10);
                if (parsed >= 1 && parsed <= 128)
                {
                    value.io_bytes = static_cast<UInt32>(parsed * 1024 * 1024);
                }
            }
            if (value.io_bytes > value.buffer_bytes)
            {
                value.io_bytes = static_cast<UInt32>(std::min<UInt64>(value.buffer_bytes, (UInt64)(UInt32)(Int32)-1));
            }
            return value;
        }();
        return config;
    }
#endif

    inline void capture_open_input_trace(ExtractInputTrace &trace) noexcept
    {
        if (!read_file_timing_enabled())
        {
            return;
        }
        trace.open_read_file_call_count = trace.read_file_call_count;
        trace.open_read_file_wall_ns = trace.read_file_wall_ns;
        trace.open_logical_read_call_count = trace.logical_read_call_count;
        trace.open_seek_count = trace.seek_count;
        trace.open_prefetch_hit_count = trace.prefetch_hit_count;
        trace.open_prefetch_miss_count = trace.prefetch_miss_count;
        trace.open_prefetch_invalidation_count = trace.prefetch_invalidation_count;
        trace.open_prefetch_consumer_wait_ns = trace.prefetch_consumer_wait_ns;
        trace.open_prefetch_issued_count = trace.prefetch_issued_count;
        trace.open_prefetch_issued_bytes = trace.prefetch_issued_bytes;
    }

    inline InputPrefetchConfig input_prefetch_config_for_archive(
        const std::wstring &format_hint,
        bool native_volume_input) noexcept
    {
        InputPrefetchConfig config = input_prefetch_config();
        if (!config.enabled || format_hint.empty())
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

        if (normalized == L"tar" ||
            (native_volume_input &&
             (normalized == L"rar" || normalized == L"rar4" || normalized == L"rar5")))
        {
            config.enabled = false;
        }
        return config;
    }

    inline InputPrefetchConfig prefetch_worker_config(InputPrefetchConfig config) noexcept
    {
#ifdef SUP7Z_USE_PLANNED_IO
        // Preserve the global runtime off switch. Only bypass format-specific legacy disables
        // (TAR and native RAR volumes) so they can still execute an explicit read plan.
        if (!config.enabled && input_prefetch_config().enabled)
        {
            config.enabled = true;
        }
#endif
        return config;
    }

    // Opened once per file and reused; the handle carries its own file cursor and is owned by exactly one thread that reads sequentially.
    // Streams that also serve the embedded 7-Zip decoder keep a second,
    // independent handle for decoder driven Seek/Read calls.
    class [[nodiscard]] PathHandle final
    {
    public:
        explicit PathHandle(const std::wstring &path) noexcept
            : handle_(CreateFileW(win32_extended_path(path).c_str(), GENERIC_READ,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                  nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr)),
              open_error_(handle_ == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS) {}

        PathHandle(const PathHandle &) = delete;
        PathHandle &operator=(const PathHandle &) = delete;
        PathHandle(PathHandle &&) = delete;
        PathHandle &operator=(PathHandle &&) = delete;

        ~PathHandle() { close(); }

        bool valid() const noexcept { return handle_ != INVALID_HANDLE_VALUE; }

        // Win32 error of the failed open, so callers report the real reason.
        DWORD open_error() const noexcept { return open_error_; }

        // Reads directly at the requested offset; the caller's own position is not part of the contract.
        HRESULT read_at(UInt64 offset, void *data, UInt32 size, UInt32 *processed) noexcept
        {
            if (processed)
            {
                *processed = 0;
            }
            if (handle_ == INVALID_HANDLE_VALUE)
            {
                return HRESULT_FROM_WIN32(open_error_ != ERROR_SUCCESS ? open_error_ : ERROR_INVALID_HANDLE);
            }
            LARGE_INTEGER distance{};
            distance.QuadPart = static_cast<LONGLONG>(offset);
            if (!SetFilePointerEx(handle_, distance, nullptr, FILE_BEGIN))
            {
                return HRESULT_FROM_WIN32(GetLastError());
            }
            DWORD read = 0;
            const BOOL ok = ReadFile(handle_, data, size, &read, nullptr);
            if (!ok)
            {
                return HRESULT_FROM_WIN32(GetLastError());
            }
            if (processed)
            {
                *processed = read;
            }
            return S_OK;
        }

        void close() noexcept
        {
            if (handle_ != INVALID_HANDLE_VALUE)
            {
                CloseHandle(handle_);
                handle_ = INVALID_HANDLE_VALUE;
            }
        }

    private:
        HANDLE handle_ = INVALID_HANDLE_VALUE;
        DWORD open_error_ = ERROR_SUCCESS;
    };

    // One long lived handle per distinct path, opened on first use; only the owning thread touches a cache, never two at once.
    // Failed opens are not remembered, so a file that is still locked when first probed is retried on the next read.
    class PathHandleCache final
    {
    public:
        PathHandleCache() = default;
        PathHandleCache(const PathHandleCache &) = delete;
        PathHandleCache &operator=(const PathHandleCache &) = delete;

        HRESULT read_at(const std::wstring &path, UInt64 offset, void *data, UInt32 size, UInt32 *processed) noexcept
        {
            if (processed)
            {
                *processed = 0;
            }
            const auto found = handles_.find(path);
            if (found != handles_.end())
            {
                return found->second->read_at(offset, data, size, processed);
            }
            auto handle = std::make_unique<PathHandle>(path);
            if (!handle->valid())
            {
                return HRESULT_FROM_WIN32(handle->open_error());
            }
            PathHandle *raw = handle.get();
            handles_.emplace(path, std::move(handle));
            return raw->read_at(offset, data, size, processed);
        }

    private:
        std::map<std::wstring, std::unique_ptr<PathHandle>> handles_;
    };

    class SequentialPrefetcher final
    {
    public:
        using Reader = std::function<HRESULT(UInt64, void *, UInt32, UInt32 *)>;

        SequentialPrefetcher(InputPrefetchConfig config, UInt64 virtual_size, Reader reader, bool start_immediately = true, ExtractInputTrace *trace = nullptr)
            : config_(config), virtual_size_(virtual_size), reader_(std::move(reader)), trace_(trace)
#ifdef SUP7Z_USE_PLANNED_IO
              , planned_config_(planned_prefetch_config())
#endif
        {
            if (config_.enabled && virtual_size_)
            {
                if (start_immediately)
                {
                    worker_ = std::thread(&SequentialPrefetcher::worker_loop, this);
                }
            }
            else
            {
                config_.enabled = false;
            }
        }

        ~SequentialPrefetcher()
        {
            {
                std::lock_guard lock(mutex_);
                stopping_ = true;
            }
            ready_.notify_all();
            if (worker_.joinable())
            {
                worker_.join();
            }
        }

        bool enabled() const noexcept { return config_.enabled; }

        void ensure_worker()
        {
            std::lock_guard lock(mutex_);
            ensure_worker_locked();
        }

        bool planned_mode()
        {
#ifdef SUP7Z_USE_PLANNED_IO
            std::lock_guard lock(mutex_);
            return planned_mode_;
#else
            return false;
#endif
        }

#ifdef SUP7Z_USE_PLANNED_IO
        void begin_plan()
        {
            std::lock_guard lock(mutex_);
            ++epoch_;
            chunks_.clear();
            plan_.clear();
            plan_index_ = 0;
            next_offset_ = 0;
            planned_required_bytes_ = 0;
            active_ = false;
            planned_mode_ = false;
            building_plan_ = true;
            ready_.notify_all();
        }

        void add_plan(UInt64 offset, UInt64 size)
        {
            std::lock_guard lock(mutex_);
            if (!building_plan_ || offset >= virtual_size_ || size == 0)
            {
                return;
            }

            UInt64 end = virtual_size_;
            if (size != (UInt64)(Int64)-1 && size < virtual_size_ - offset)
            {
                end = offset + size;
            }
            if (end <= offset)
            {
                return;
            }

            if (!plan_.empty())
            {
                PlannedRange &last = plan_.back();
                const UInt64 last_end = last.offset + last.size;
                const UInt64 merge_limit = last_end > (UInt64)(Int64)-1 - kPlanMergeGap
                                               ? (UInt64)(Int64)-1
                                               : last_end + kPlanMergeGap;
                // Absorb tiny headers/padding into the same physical read extent.
                if (offset >= last.offset && offset <= merge_limit)
                {
                    if (end > last_end)
                    {
                        last.size = end - last.offset;
                    }
                    return;
                }
            }
            plan_.push_back(PlannedRange{offset, end - offset});
        }

        void end_plan()
        {
            std::lock_guard lock(mutex_);
            building_plan_ = false;
            planned_mode_ = !plan_.empty();
            // Do not touch storage until the decoder asks for the first planned byte.
            // This keeps unopened RAR/ZIP volumes dormant.
            active_ = false;
            plan_index_ = 0;
            next_offset_ = planned_mode_ ? plan_[0].offset : 0;
            planned_required_bytes_ = 0;
            ready_.notify_all();
        }
#endif

        bool consume(UInt64 offset, void *data, UInt32 size, ExtractInputTrace *trace)
        {
            if (!config_.enabled || size == 0)
            {
                return false;
            }
            const bool profiling = trace && read_file_timing_enabled();
            const auto wait_started = profiling ? std::chrono::steady_clock::now()
                                                : std::chrono::steady_clock::time_point{};
            std::unique_lock lock(mutex_);

#ifdef SUP7Z_USE_PLANNED_IO
            if (planned_mode_)
            {
                return consume_planned_locked(offset, data, size, trace, profiling, wait_started, lock);
            }
#endif

            auto chunk = find_chunk_locked(offset, size);
            if (chunk == chunks_.end())
            {
                if (profiling)
                {
                    ++trace->prefetch_miss_count;
                }
                return false;
            }
            const UInt64 epoch = chunk->epoch;
            while ((chunk->state == ChunkState::Queued || chunk->state == ChunkState::Reading) && !stopping_ && epoch == epoch_)
            {
                ready_.wait(lock);
                chunk = find_chunk_locked(offset, size);
                if (chunk == chunks_.end())
                {
                    if (profiling)
                    {
                        ++trace->prefetch_miss_count;
                        trace->prefetch_consumer_wait_ns += elapsed_ns(wait_started);
                    }
                    return false;
                }
            }
            if (chunk->state != ChunkState::Ready || epoch != epoch_)
            {
                if (profiling)
                {
                    ++trace->prefetch_miss_count;
                    trace->prefetch_consumer_wait_ns += elapsed_ns(wait_started);
                }
                return false;
            }
            std::memcpy(data, chunk->bytes.data() + static_cast<std::size_t>(offset - chunk->offset), size);
            if (profiling)
            {
                ++trace->prefetch_hit_count;
                trace->prefetch_consumer_wait_ns += elapsed_ns(wait_started);
            }
            return true;
        }

        void after_sync_read(UInt64 end)
        {
            if (!config_.enabled || end > virtual_size_)
            {
                return;
            }
#ifdef SUP7Z_USE_PLANNED_IO
            if (planned_mode())
            {
                return;
            }
#endif
            std::lock_guard lock(mutex_);
            chunks_.erase(std::remove_if(chunks_.begin(), chunks_.end(), [end](const Chunk &chunk)
                                         { return chunk.offset + chunk.size <= end; }),
                          chunks_.end());
            if (chunks_.empty())
            {
                next_offset_ = end;
            }
            active_ = true;
            ensure_worker_locked();
            schedule_locked();
            ready_.notify_all();
        }

        void after_cached_read(UInt64 end)
        {
            if (!config_.enabled)
            {
                return;
            }
            std::lock_guard lock(mutex_);
            chunks_.erase(std::remove_if(chunks_.begin(), chunks_.end(), [end](const Chunk &chunk)
                                         { return chunk.offset + chunk.size <= end; }),
                          chunks_.end());
            schedule_locked();
            ready_.notify_all();
        }

        void invalidate(UInt64 next, ExtractInputTrace *trace)
        {
            if (!config_.enabled)
            {
                return;
            }
#ifdef SUP7Z_USE_PLANNED_IO
            if (planned_mode())
            {
                return;
            }
#endif
            std::lock_guard lock(mutex_);
            if (!chunks_.empty() && trace && read_file_timing_enabled())
            {
                ++trace->prefetch_invalidation_count;
            }
            ++epoch_;
            chunks_.clear();
            next_offset_ = next;
            active_ = false;
            ready_.notify_all();
        }

    private:
        enum class ChunkState
        {
            Queued,
            Reading,
            Ready,
            Failed
        };

        struct Chunk
        {
            UInt64 epoch = 0;
            UInt64 offset = 0;
            UInt32 size = 0;
            ChunkState state = ChunkState::Queued;
            std::vector<unsigned char> bytes;
        };

        static unsigned long long elapsed_ns(std::chrono::steady_clock::time_point started) noexcept
        {
            const auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now() - started).count();
            return elapsed > 0 ? static_cast<unsigned long long>(elapsed) : 0ULL;
        }

        void ensure_worker_locked()
        {
            if (config_.enabled && !worker_.joinable() && !stopping_)
            {
                worker_ = std::thread(&SequentialPrefetcher::worker_loop, this);
            }
        }

        void record_prefetch_issue_locked(UInt32 size) noexcept
        {
            if (trace_ && read_file_timing_enabled())
            {
                ++trace_->prefetch_issued_count;
                trace_->prefetch_issued_bytes += size;
            }
        }

        std::vector<Chunk>::iterator find_chunk_locked(UInt64 offset, UInt32 size)
        {
            return std::find_if(chunks_.begin(), chunks_.end(), [offset, size](const Chunk &chunk)
                                { return chunk.offset <= offset && offset + size <= chunk.offset + chunk.size; });
        }

#ifdef SUP7Z_USE_PLANNED_IO
        struct PlannedRange
        {
            UInt64 offset = 0;
            UInt64 size = 0;
        };

        enum class PlannedRequestState
        {
            Missing,
            Pending,
            Ready,
            Failed
        };

        static constexpr UInt64 kPlanMergeGap = 64 * 1024;

        UInt64 planned_reserved_bytes_locked() const
        {
            UInt64 total = 0;
            for (const Chunk &chunk : chunks_)
            {
                total += chunk.size;
            }
            return total;
        }

        std::vector<Chunk>::iterator find_chunk_containing_locked(UInt64 offset)
        {
            return std::find_if(chunks_.begin(), chunks_.end(), [offset](const Chunk &chunk)
                                { return chunk.offset <= offset && offset < chunk.offset + chunk.size; });
        }

        PlannedRequestState planned_request_state_locked(UInt64 offset, UInt32 size)
        {
            UInt64 cursor = offset;
            const UInt64 end = offset + size;
            bool pending = false;
            while (cursor < end)
            {
                const auto chunk = find_chunk_containing_locked(cursor);
                if (chunk == chunks_.end())
                {
                    return PlannedRequestState::Missing;
                }
                if (chunk->state == ChunkState::Failed)
                {
                    return PlannedRequestState::Failed;
                }
                if (chunk->state != ChunkState::Ready)
                {
                    pending = true;
                }
                cursor = std::min<UInt64>(end, chunk->offset + chunk->size);
            }
            return pending ? PlannedRequestState::Pending : PlannedRequestState::Ready;
        }

        void copy_planned_locked(UInt64 offset, void *data, UInt32 size)
        {
            UInt64 cursor = offset;
            const UInt64 end = offset + size;
            auto *out = static_cast<unsigned char *>(data);
            while (cursor < end)
            {
                const auto chunk = find_chunk_containing_locked(cursor);
                const UInt64 chunk_end = chunk->offset + chunk->size;
                const UInt64 take = std::min<UInt64>(end, chunk_end) - cursor;
                std::memcpy(out + static_cast<std::size_t>(cursor - offset),
                            chunk->bytes.data() + static_cast<std::size_t>(cursor - chunk->offset),
                            static_cast<std::size_t>(take));
                cursor += take;
            }
        }

        bool rebase_plan_locked(UInt64 offset, UInt32 size)
        {
            if (offset > virtual_size_ || size > virtual_size_ - offset)
            {
                return false;
            }
            const UInt64 end = offset + size;
            for (std::size_t i = 0; i < plan_.size(); ++i)
            {
                const PlannedRange &range = plan_[i];
                const UInt64 range_end = range.offset + range.size;
                if (range.offset <= offset && end <= range_end)
                {
                    ++epoch_;
                    chunks_.clear();
                    plan_index_ = i;
                    next_offset_ = offset;
                    planned_required_bytes_ = size;
                    active_ = true;
                    ensure_worker_locked();
                    return true;
                }
            }
            return false;
        }

        bool consume_planned_locked(
            UInt64 offset,
            void *data,
            UInt32 size,
            ExtractInputTrace *trace,
            bool profiling,
            std::chrono::steady_clock::time_point wait_started,
            std::unique_lock<std::mutex> &lock)
        {
            ensure_worker_locked();
            PlannedRequestState state = planned_request_state_locked(offset, size);
            if (state == PlannedRequestState::Missing)
            {
                if (!rebase_plan_locked(offset, size))
                {
                    if (profiling)
                    {
                        ++trace->prefetch_miss_count;
                    }
                    return false;
                }
                schedule_locked();
                ready_.notify_all();
                state = planned_request_state_locked(offset, size);
            }

            while (!stopping_)
            {
                if (state == PlannedRequestState::Ready)
                {
                    copy_planned_locked(offset, data, size);
                    if (profiling)
                    {
                        ++trace->prefetch_hit_count;
                        trace->prefetch_consumer_wait_ns += elapsed_ns(wait_started);
                    }
                    return true;
                }
                if (state == PlannedRequestState::Failed)
                {
                    if (profiling)
                    {
                        ++trace->prefetch_miss_count;
                        trace->prefetch_consumer_wait_ns += elapsed_ns(wait_started);
                    }
                    return false;
                }
                if (state == PlannedRequestState::Missing)
                {
                    if (!rebase_plan_locked(offset, size))
                    {
                        if (profiling)
                        {
                            ++trace->prefetch_miss_count;
                            trace->prefetch_consumer_wait_ns += elapsed_ns(wait_started);
                        }
                        return false;
                    }
                    schedule_locked();
                    ready_.notify_all();
                }
                ready_.wait(lock);
                state = planned_request_state_locked(offset, size);
            }
            return false;
        }

        void schedule_plan_locked()
        {
            UInt64 budget = planned_config_.buffer_bytes;
            if (planned_required_bytes_ > budget)
            {
                budget = planned_required_bytes_;
            }
            planned_required_bytes_ = 0;

            UInt64 reserved = planned_reserved_bytes_locked();
            while (reserved < budget && plan_index_ < plan_.size())
            {
                const PlannedRange &range = plan_[plan_index_];
                const UInt64 range_end = range.offset + range.size;
                if (next_offset_ < range.offset)
                {
                    next_offset_ = range.offset;
                }
                if (next_offset_ >= range_end)
                {
                    ++plan_index_;
                    if (plan_index_ < plan_.size())
                    {
                        next_offset_ = plan_[plan_index_].offset;
                    }
                    continue;
                }

                const UInt64 free_bytes = budget - reserved;
                const UInt64 remaining = range_end - next_offset_;
                const UInt64 wanted = std::min<UInt64>(planned_config_.io_bytes, free_bytes);
                if (wanted == 0)
                {
                    break;
                }
                const UInt32 read_size = static_cast<UInt32>(std::min<UInt64>(remaining, wanted));
                chunks_.push_back(Chunk{epoch_, next_offset_, read_size});
                record_prefetch_issue_locked(read_size);
                next_offset_ += read_size;
                reserved += read_size;
            }
            if (plan_index_ >= plan_.size())
            {
                active_ = false;
            }
        }
#endif

        void schedule_locked()
        {
            if (!active_)
            {
                return;
            }
#ifdef SUP7Z_USE_PLANNED_IO
            if (planned_mode_)
            {
                schedule_plan_locked();
                return;
            }
#endif
            while (chunks_.size() < config_.depth && next_offset_ < virtual_size_)
            {
                const UInt64 remaining = virtual_size_ - next_offset_;
                const UInt32 size = static_cast<UInt32>(std::min<UInt64>(remaining, config_.window_bytes));
                chunks_.push_back(Chunk{epoch_, next_offset_, size});
                record_prefetch_issue_locked(size);
                next_offset_ += size;
            }
        }

        void worker_loop()
        {
            while (true)
            {
                UInt64 epoch = 0;
                UInt64 offset = 0;
                UInt32 size = 0;
                {
                    std::unique_lock lock(mutex_);
                    ready_.wait(lock, [this]
                                { return stopping_ || std::any_of(chunks_.begin(), chunks_.end(), [](const Chunk &chunk)
                                                                  { return chunk.state == ChunkState::Queued; }); });
                    if (stopping_)
                    {
                        return;
                    }
                    const auto chunk = std::find_if(chunks_.begin(), chunks_.end(), [](const Chunk &candidate)
                                                    { return candidate.state == ChunkState::Queued; });
                    epoch = chunk->epoch;
                    offset = chunk->offset;
                    size = chunk->size;
                    chunk->state = ChunkState::Reading;
                }
                std::vector<unsigned char> bytes(size);
                UInt32 read = 0;
                const HRESULT result = reader_(offset, bytes.data(), size, &read);
                {
                    std::lock_guard lock(mutex_);
                    const auto chunk = std::find_if(chunks_.begin(), chunks_.end(), [epoch, offset](const Chunk &candidate)
                                                    { return candidate.epoch == epoch && candidate.offset == offset; });
                    if (chunk != chunks_.end() && epoch == epoch_)
                    {
                        if (result == S_OK && read == size)
                        {
                            chunk->bytes = std::move(bytes);
                            chunk->state = ChunkState::Ready;
                        }
                        else
                        {
                            chunk->state = ChunkState::Failed;
                        }
                    }
                }
                ready_.notify_all();
            }
        }

        InputPrefetchConfig config_;
        UInt64 virtual_size_ = 0;
        Reader reader_;
        ExtractInputTrace *trace_ = nullptr;
        std::mutex mutex_;
        std::condition_variable ready_;
        std::thread worker_;
        std::vector<Chunk> chunks_;
        UInt64 epoch_ = 0;
        UInt64 next_offset_ = 0;
#ifdef SUP7Z_USE_PLANNED_IO
        PlannedPrefetchConfig planned_config_;
        std::vector<PlannedRange> plan_;
        std::size_t plan_index_ = 0;
        UInt64 planned_required_bytes_ = 0;
        bool planned_mode_ = false;
        bool building_plan_ = false;
#endif
        bool active_ = false;
        bool stopping_ = false;
    };

    class ReadFileWallTimer final
    {
    public:
        explicit ReadFileWallTimer(ExtractInputTrace *trace) noexcept
            : trace_(read_file_timing_enabled() ? trace : nullptr)
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

    class FileInStream final : public CMyUnknownImp, public IInStream, public IStreamSetReadPlan
    {
        Z7_COM_UNKNOWN_IMP_3(ISequentialInStream, IInStream, IStreamSetReadPlan)
        

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

            legacy_prefetch_enabled_ = prefetch_config.enabled;
            legacy_prefetch_active_ = legacy_prefetch_enabled_ && open_prefetch_enabled();
            const InputPrefetchConfig worker_prefetch_config = prefetch_worker_config(prefetch_config);
            if (size_ && worker_prefetch_config.enabled)
            {
                // A handle of its own, so prefetch offset reads never touch the decoder handle or its file cursor.
                prefetch_reader_ = std::make_unique<PathHandle>(path_);
                if (prefetch_reader_->valid())
                {
                    PathHandle *reader = prefetch_reader_.get();
                    prefetch_ = std::make_unique<SequentialPrefetcher>(worker_prefetch_config, size_, [reader](UInt64 offset, void *data, UInt32 read_size, UInt32 *processed)
                                                                       { return reader->read_at(offset, data, read_size, processed); }, legacy_prefetch_active_, trace_);
                }
                else
                {
                    prefetch_reader_.reset();
                }
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

        HRESULT STDMETHODCALLTYPE BeginReadPlan() SUP7Z_NOEXCEPT override
        {
#ifdef SUP7Z_USE_PLANNED_IO
            if (!prefetch_) return S_FALSE;
            prefetch_->begin_plan();
            return S_OK;
#else
            return S_FALSE;
#endif
        }

        HRESULT STDMETHODCALLTYPE AddReadPlan(UInt64 offset, UInt64 size) SUP7Z_NOEXCEPT override
        {
#ifdef SUP7Z_USE_PLANNED_IO
            if (!prefetch_) return S_FALSE;
            prefetch_->add_plan(offset, size);
            return S_OK;
#else
            (void)offset;
            (void)size;
            return S_FALSE;
#endif
        }

        HRESULT STDMETHODCALLTYPE EndReadPlan() SUP7Z_NOEXCEPT override
        {
#ifdef SUP7Z_USE_PLANNED_IO
            if (!prefetch_) return S_FALSE;
            prefetch_->end_plan();
            return S_OK;
#else
            return S_FALSE;
#endif
        }

        HRESULT STDMETHODCALLTYPE SetLegacyPrefetchActive(Int32 active) SUP7Z_NOEXCEPT override
        {
            legacy_prefetch_active_ = legacy_prefetch_enabled_ && active != 0;
            if (legacy_prefetch_active_ && prefetch_)
            {
                prefetch_->ensure_worker();
            }
            return S_OK;
        }


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

            if (prefetch_ && (legacy_prefetch_active_ || prefetch_->planned_mode()) && prefetch_->consume(position_, data, size, trace_))
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

            if (prefetch_ && legacy_prefetch_active_ && read)
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

            if (prefetch_ && legacy_prefetch_active_ && prior_position != position_)
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

        // Declared before the prefetcher so it outlives the prefetch thread.
        std::unique_ptr<PathHandle> prefetch_reader_;

        std::unique_ptr<SequentialPrefetcher> prefetch_;
        bool legacy_prefetch_enabled_ = false;
        bool legacy_prefetch_active_ = false;
    };

    class MultiFileInStream final : public CMyUnknownImp, public IInStream, public IStreamSetReadPlan
    {
        Z7_COM_UNKNOWN_IMP_3(ISequentialInStream, IInStream, IStreamSetReadPlan)
        

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

            legacy_prefetch_enabled_ = prefetch_config.enabled;
            legacy_prefetch_active_ = legacy_prefetch_enabled_ && open_prefetch_enabled();
            const InputPrefetchConfig worker_prefetch_config = prefetch_worker_config(prefetch_config);
            if (valid_ && total_size_ && worker_prefetch_config.enabled)
            {
                prefetch_ = std::make_unique<SequentialPrefetcher>(worker_prefetch_config, total_size_, [this](UInt64 offset, void *data, UInt32 read_size, UInt32 *processed)
                                                                   { return read_prefetch_at(offset, data, read_size, processed); }, legacy_prefetch_active_, trace_);
            }
            if (trace_ && read_file_timing_enabled())
            {
                trace_->prefetch_enabled = prefetch_ && prefetch_->enabled();
            }
        }

        ~MultiFileInStream() { close_cached_handle(); }

        bool is_open() const { return valid_; }

        HRESULT STDMETHODCALLTYPE BeginReadPlan() SUP7Z_NOEXCEPT override
        {
#ifdef SUP7Z_USE_PLANNED_IO
            if (!prefetch_) return S_FALSE;
            prefetch_->begin_plan();
            return S_OK;
#else
            return S_FALSE;
#endif
        }

        HRESULT STDMETHODCALLTYPE AddReadPlan(UInt64 offset, UInt64 size) SUP7Z_NOEXCEPT override
        {
#ifdef SUP7Z_USE_PLANNED_IO
            if (!prefetch_) return S_FALSE;
            prefetch_->add_plan(offset, size);
            return S_OK;
#else
            (void)offset;
            (void)size;
            return S_FALSE;
#endif
        }

        HRESULT STDMETHODCALLTYPE EndReadPlan() SUP7Z_NOEXCEPT override
        {
#ifdef SUP7Z_USE_PLANNED_IO
            if (!prefetch_) return S_FALSE;
            prefetch_->end_plan();
            return S_OK;
#else
            return S_FALSE;
#endif
        }

        HRESULT STDMETHODCALLTYPE SetLegacyPrefetchActive(Int32 active) SUP7Z_NOEXCEPT override
        {
            legacy_prefetch_active_ = legacy_prefetch_enabled_ && active != 0;
            if (legacy_prefetch_active_ && prefetch_)
            {
                prefetch_->ensure_worker();
            }
            return S_OK;
        }


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

            if (prefetch_ && (legacy_prefetch_active_ || prefetch_->planned_mode()) && prefetch_->consume(position_, data, size, trace_))
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

            if (prefetch_ && legacy_prefetch_active_ && total_read)
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

            if (prefetch_ && legacy_prefetch_active_ && prior_position != position_)
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

        HRESULT read_prefetch_at(UInt64 offset, void *data, UInt32 size, UInt32 *processed) const
        {
            if (processed)
            {
                *processed = 0;
            }
            auto *out = static_cast<unsigned char *>(data);
            UInt32 total_read = 0;
            while (total_read < size && offset < total_size_)
            {
                const std::size_t index = find_part_index(offset);
                if (index >= paths_.size())
                {
                    break;
                }
                const UInt64 part_offset = offset - offsets_[index];
                const UInt64 remaining = sizes_[index] - part_offset;
                const UInt32 want = static_cast<UInt32>(std::min<UInt64>(size - total_read, remaining));
                UInt32 read = 0;
                const HRESULT result = prefetch_handles_.read_at(paths_[index], part_offset, out + total_read, want, &read);
                if (result != S_OK)
                {
                    return result;
                }
                total_read += read;
                offset += read;
                if (read != want)
                {
                    break;
                }
            }
            if (processed)
            {
                *processed = total_read;
            }
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

        // Declared before the prefetcher so the handles outlive its thread; mutable because the prefetch reader runs from a const accessor.
        mutable PathHandleCache prefetch_handles_;

        std::unique_ptr<SequentialPrefetcher> prefetch_;
        bool legacy_prefetch_enabled_ = false;
        bool legacy_prefetch_active_ = false;
    };

    struct NormalizedInputRange
    {

        std::wstring path;

        UInt64 start = 0;

        UInt64 length = 0;

        UInt64 virtual_offset = 0;
    };

    class MultiRangeInStream final : public CMyUnknownImp, public IInStream, public IStreamSetReadPlan
    {
        Z7_COM_UNKNOWN_IMP_3(ISequentialInStream, IInStream, IStreamSetReadPlan)
        

    public:
        explicit MultiRangeInStream(
            const std::vector<ExtractInputRange> &ranges,
            ExtractInputTrace *trace = nullptr,
            InputPrefetchConfig prefetch_config = InputPrefetchConfig{false, 512 * 1024, 2})

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

            legacy_prefetch_enabled_ = prefetch_config.enabled;
            legacy_prefetch_active_ = legacy_prefetch_enabled_ && open_prefetch_enabled();
            const InputPrefetchConfig worker_prefetch_config = prefetch_worker_config(prefetch_config);
            if (valid_ && total_size_ && worker_prefetch_config.enabled)
            {
                prefetch_ = std::make_unique<SequentialPrefetcher>(worker_prefetch_config, total_size_, [this](UInt64 offset, void *data, UInt32 read_size, UInt32 *processed)
                                                                   { return read_prefetch_at(offset, data, read_size, processed); }, legacy_prefetch_active_, trace_);
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

        HRESULT STDMETHODCALLTYPE BeginReadPlan() SUP7Z_NOEXCEPT override
        {
#ifdef SUP7Z_USE_PLANNED_IO
            if (!prefetch_) return S_FALSE;
            prefetch_->begin_plan();
            return S_OK;
#else
            return S_FALSE;
#endif
        }

        HRESULT STDMETHODCALLTYPE AddReadPlan(UInt64 offset, UInt64 size) SUP7Z_NOEXCEPT override
        {
#ifdef SUP7Z_USE_PLANNED_IO
            if (!prefetch_) return S_FALSE;
            prefetch_->add_plan(offset, size);
            return S_OK;
#else
            (void)offset;
            (void)size;
            return S_FALSE;
#endif
        }

        HRESULT STDMETHODCALLTYPE EndReadPlan() SUP7Z_NOEXCEPT override
        {
#ifdef SUP7Z_USE_PLANNED_IO
            if (!prefetch_) return S_FALSE;
            prefetch_->end_plan();
            return S_OK;
#else
            return S_FALSE;
#endif
        }

        HRESULT STDMETHODCALLTYPE SetLegacyPrefetchActive(Int32 active) SUP7Z_NOEXCEPT override
        {
            legacy_prefetch_active_ = legacy_prefetch_enabled_ && active != 0;
            if (legacy_prefetch_active_ && prefetch_)
            {
                prefetch_->ensure_worker();
            }
            return S_OK;
        }


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

            if (prefetch_ && (legacy_prefetch_active_ || prefetch_->planned_mode()) && prefetch_->consume(position_, data, size, trace_))
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

            if (prefetch_ && legacy_prefetch_active_ && total_read)
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

            if (prefetch_ && legacy_prefetch_active_ && prior_position != position_)
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
        HRESULT read_prefetch_at(UInt64 offset, void *data, UInt32 size, UInt32 *processed) const
        {
            if (processed)
            {
                *processed = 0;
            }
            auto *out = static_cast<unsigned char *>(data);
            UInt32 total_read = 0;
            while (total_read < size && offset < total_size_)
            {
                const std::size_t index = find_range_index(offset);
                if (index >= ranges_.size())
                {
                    break;
                }
                const auto &range = ranges_[index];
                const UInt64 offset_in_range = offset - range.virtual_offset;
                const UInt64 remaining = range.length - offset_in_range;
                const UInt32 want = static_cast<UInt32>(std::min<UInt64>(size - total_read, remaining));
                UInt32 read = 0;
                const HRESULT result = prefetch_handles_.read_at(range.path, range.start + offset_in_range, out + total_read, want, &read);
                if (result != S_OK)
                {
                    return result;
                }
                total_read += read;
                offset += read;
                if (read != want)
                {
                    break;
                }
            }
            if (processed)
            {
                *processed = total_read;
            }
            return S_OK;
        }

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

        std::unique_ptr<SequentialPrefetcher> prefetch_;
        bool legacy_prefetch_enabled_ = false;
        bool legacy_prefetch_active_ = false;

        bool valid_ = true;

        // Declared after the prefetcher, which stops its thread before this closes the handles; mutable as in MultiFileInStream.
        mutable PathHandleCache prefetch_handles_;
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
