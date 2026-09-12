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

    // Opened once per file and reused; the handle carries its own file cursor and is owned by exactly one thread that reads sequentially.
    // Streams that also serve the 7z.dll decoder keep a second, independent handle for decoder driven Seek/Read calls.
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

        SequentialPrefetcher(InputPrefetchConfig config, UInt64 virtual_size, Reader reader)
            : config_(config), virtual_size_(virtual_size), reader_(std::move(reader))
        {
            if (config_.enabled && virtual_size_)
            {
                worker_ = std::thread(&SequentialPrefetcher::worker_loop, this);
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
            std::lock_guard lock(mutex_);
            chunks_.erase(std::remove_if(chunks_.begin(), chunks_.end(), [end](const Chunk &chunk)
                                         { return chunk.offset + chunk.size <= end; }),
                          chunks_.end());
            if (chunks_.empty())
            {
                next_offset_ = end;
            }
            active_ = true;
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

        std::vector<Chunk>::iterator find_chunk_locked(UInt64 offset, UInt32 size)
        {
            return std::find_if(chunks_.begin(), chunks_.end(), [offset, size](const Chunk &chunk)
                                { return chunk.offset <= offset && offset + size <= chunk.offset + chunk.size; });
        }

        void schedule_locked()
        {
            if (!active_)
            {
                return;
            }
            while (chunks_.size() < config_.depth && next_offset_ < virtual_size_)
            {
                const UInt64 remaining = virtual_size_ - next_offset_;
                const UInt32 size = static_cast<UInt32>(std::min<UInt64>(remaining, config_.window_bytes));
                chunks_.push_back(Chunk{epoch_, next_offset_, size});
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
        std::mutex mutex_;
        std::condition_variable ready_;
        std::thread worker_;
        std::vector<Chunk> chunks_;
        UInt64 epoch_ = 0;
        UInt64 next_offset_ = 0;
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

    class FileInStream final : public IInStream
    {

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
                // A handle of its own, so prefetch offset reads never touch the decoder handle or its file cursor.
                prefetch_reader_ = std::make_unique<PathHandle>(path_);
                if (prefetch_reader_->valid())
                {
                    PathHandle *reader = prefetch_reader_.get();
                    prefetch_ = std::make_unique<SequentialPrefetcher>(prefetch_config, size_, [reader](UInt64 offset, void *data, UInt32 read_size, UInt32 *processed)
                                                                       { return reader->read_at(offset, data, read_size, processed); });
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

        HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void **object) override
        {

            if (!object)
            {

                return E_POINTER;
            }

            *object = nullptr;

            if (IsEqualGUID(iid, IID_IUnknown) || IsEqualGUID(iid, IID_ISequentialInStream) || IsEqualGUID(iid, IID_IInStream))
            {

                *object = static_cast<IInStream *>(this);

                AddRef();

                return S_OK;
            }

            return E_NOINTERFACE;
        }

        ULONG STDMETHODCALLTYPE AddRef() override { return InterlockedIncrement(&refs_); }

        ULONG STDMETHODCALLTYPE Release() override
        {

            const ULONG refs = InterlockedDecrement(&refs_);

            if (refs == 0)
            {

                delete this;
            }

            return refs;
        }

        HRESULT STDMETHODCALLTYPE Read(void *data, UInt32 size, UInt32 *processedSize) override
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

        HRESULT STDMETHODCALLTYPE Seek(Int64 offset, UInt32 seekOrigin, UInt64 *newPosition) override
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
        LONG refs_ = 1;

        std::wstring path_;

        ExtractInputTrace *trace_ = nullptr;

        HANDLE handle_ = INVALID_HANDLE_VALUE;

        UInt64 position_ = 0;

        UInt64 size_ = 0;

        // Declared before the prefetcher so it outlives the prefetch thread.
        std::unique_ptr<PathHandle> prefetch_reader_;

        std::unique_ptr<SequentialPrefetcher> prefetch_;
    };

    class MultiFileInStream final : public IInStream
    {

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
                prefetch_ = std::make_unique<SequentialPrefetcher>(prefetch_config, total_size_, [this](UInt64 offset, void *data, UInt32 read_size, UInt32 *processed)
                                                                   { return read_prefetch_at(offset, data, read_size, processed); });
            }
            if (trace_ && read_file_timing_enabled())
            {
                trace_->prefetch_enabled = prefetch_ && prefetch_->enabled();
            }
        }

        ~MultiFileInStream() { close_cached_handle(); }

        bool is_open() const { return valid_; }

        HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void **object) override
        {

            if (!object)
            {

                return E_POINTER;
            }

            *object = nullptr;

            if (IsEqualGUID(iid, IID_IUnknown) || IsEqualGUID(iid, IID_ISequentialInStream) || IsEqualGUID(iid, IID_IInStream))
            {

                *object = static_cast<IInStream *>(this);

                AddRef();

                return S_OK;
            }

            return E_NOINTERFACE;
        }

        ULONG STDMETHODCALLTYPE AddRef() override { return InterlockedIncrement(&refs_); }

        ULONG STDMETHODCALLTYPE Release() override
        {

            const ULONG refs = InterlockedDecrement(&refs_);

            if (refs == 0)
            {

                delete this;
            }

            return refs;
        }

        HRESULT STDMETHODCALLTYPE Read(void *data, UInt32 size, UInt32 *processedSize) override
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

        HRESULT STDMETHODCALLTYPE Seek(Int64 offset, UInt32 seekOrigin, UInt64 *newPosition) override
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

        LONG refs_ = 1;

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
    };

    struct NormalizedInputRange
    {

        std::wstring path;

        UInt64 start = 0;

        UInt64 length = 0;

        UInt64 virtual_offset = 0;
    };

    struct PatchedInputSegment
    {

        enum class Kind
        {
            FileRange,
            Bytes
        };

        Kind kind = Kind::FileRange;

        std::wstring path;

        UInt64 source_start = 0;

        UInt64 length = 0;

        UInt64 virtual_offset = 0;

        std::vector<unsigned char> data;
    };

    class MultiRangeInStream final : public IInStream
    {

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

            if (valid_ && total_size_ && prefetch_config.enabled)
            {
                prefetch_ = std::make_unique<SequentialPrefetcher>(prefetch_config, total_size_, [this](UInt64 offset, void *data, UInt32 read_size, UInt32 *processed)
                                                                   { return read_prefetch_at(offset, data, read_size, processed); });
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

        HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void **object) override
        {

            if (!object)
            {

                return E_POINTER;
            }

            *object = nullptr;

            if (IsEqualGUID(iid, IID_IUnknown) || IsEqualGUID(iid, IID_ISequentialInStream) || IsEqualGUID(iid, IID_IInStream))
            {

                *object = static_cast<IInStream *>(this);

                AddRef();

                return S_OK;
            }

            return E_NOINTERFACE;
        }

        ULONG STDMETHODCALLTYPE AddRef() override { return InterlockedIncrement(&refs_); }

        ULONG STDMETHODCALLTYPE Release() override
        {

            const ULONG refs = InterlockedDecrement(&refs_);

            if (refs == 0)
            {

                delete this;
            }

            return refs;
        }

        HRESULT STDMETHODCALLTYPE Read(void *data, UInt32 size, UInt32 *processedSize) override
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

        HRESULT STDMETHODCALLTYPE Seek(Int64 offset, UInt32 seekOrigin, UInt64 *newPosition) override
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

        LONG refs_ = 1;

        std::vector<NormalizedInputRange> ranges_;

        UInt64 total_size_ = 0;

        UInt64 position_ = 0;

        ExtractInputTrace *trace_ = nullptr;

        HANDLE cached_handle_ = INVALID_HANDLE_VALUE;

        std::size_t cached_index_ = static_cast<std::size_t>(-1);

        UInt64 cached_handle_position_ = 0;

        std::unique_ptr<SequentialPrefetcher> prefetch_;

        bool valid_ = true;

        // Declared after the prefetcher, which stops its thread before this closes the handles; mutable as in MultiFileInStream.
        mutable PathHandleCache prefetch_handles_;
    };

    class PatchedInStream final : public IInStream
    {

    public:
        PatchedInStream(
            const std::vector<ExtractInputRange> &ranges,
            const std::vector<ExtractPatchOperation> &patches,
            ExtractInputTrace *trace = nullptr) : trace_(trace)
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
                PatchedInputSegment segment;
                segment.kind = PatchedInputSegment::Kind::FileRange;
                segment.path = input.path;
                segment.source_start = start;
                segment.length = length;
                segment.virtual_offset = virtual_offset;
                segments_.push_back(std::move(segment));
                virtual_offset += length;
            }
            valid_ = valid_ && !segments_.empty();
            if (valid_)
            {
                for (const auto &patch : patches)
                {
                    if (!apply_patch(patch))
                    {
                        valid_ = false;
                        break;
                    }
                }
            }
            reindex_segments();
            if (trace_)
            {
                trace_->mode = L"virtual_patch";
                trace_->virtual_size = total_size_;
            }
        }

        bool is_open() const { return valid_; }

        HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void **object) override
        {
            if (!object)
            {
                return E_POINTER;
            }
            *object = nullptr;
            if (IsEqualGUID(iid, IID_IUnknown) || IsEqualGUID(iid, IID_ISequentialInStream) || IsEqualGUID(iid, IID_IInStream))
            {
                *object = static_cast<IInStream *>(this);
                AddRef();
                return S_OK;
            }
            return E_NOINTERFACE;
        }

        ULONG STDMETHODCALLTYPE AddRef() override { return InterlockedIncrement(&refs_); }

        ULONG STDMETHODCALLTYPE Release() override
        {
            const ULONG refs = InterlockedDecrement(&refs_);
            if (refs == 0)
            {
                delete this;
            }
            return refs;
        }

        HRESULT STDMETHODCALLTYPE Read(void *data, UInt32 size, UInt32 *processedSize) override
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
            UInt32 total_read = 0;
            while (total_read < size && position_ < total_size_)
            {
                const auto *segment = find_segment(position_);
                if (!segment)
                {
                    break;
                }
                const UInt64 offset_in_segment = position_ - segment->virtual_offset;
                const UInt64 remaining = segment->length - offset_in_segment;
                const UInt32 want = static_cast<UInt32>(std::min<UInt64>(size - total_read, remaining));
                UInt32 read = 0;
                HRESULT hr = S_OK;
                if (segment->kind == PatchedInputSegment::Kind::Bytes)
                {
                    std::copy_n(segment->data.data() + offset_in_segment, want, out + total_read);
                    read = want;
                }
                else
                {
                    hr = read_file_segment(*segment, offset_in_segment, want, out + total_read, &read);
                    if (hr != S_OK)
                    {
                        return hr;
                    }
                }
                if (read == 0)
                {
                    break;
                }
                total_read += read;
                position_ += read;
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

            if (processedSize)
            {
                *processedSize = total_read;
            }
            return S_OK;
        }

        HRESULT STDMETHODCALLTYPE Seek(Int64 offset, UInt32 seekOrigin, UInt64 *newPosition) override
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
        bool apply_patch(const ExtractPatchOperation &patch)
        {
            if (!patch.target.empty() && patch.target != L"logical")
            {
                return false;
            }
            if (patch.op == L"replace_range")
            {
                const UInt64 size = patch.has_size ? patch.size : static_cast<UInt64>(patch.data.size());
                if (size != patch.data.size() || patch.offset + size > total_length())
                {
                    return false;
                }
                auto before = slice_segments(0, patch.offset);
                auto after = slice_segments(patch.offset + size, total_length());
                PatchedInputSegment replacement;
                replacement.kind = PatchedInputSegment::Kind::Bytes;
                replacement.length = static_cast<UInt64>(patch.data.size());
                replacement.data = patch.data;
                segments_ = std::move(before);
                segments_.push_back(std::move(replacement));
                segments_.insert(segments_.end(), after.begin(), after.end());
                reindex_segments();
                return true;
            }
            if (patch.op == L"truncate")
            {
                segments_ = slice_segments(0, patch.offset);
                reindex_segments();
                return true;
            }
            if (patch.op == L"append")
            {
                if (!patch.data.empty())
                {
                    PatchedInputSegment segment;
                    segment.kind = PatchedInputSegment::Kind::Bytes;
                    segment.length = static_cast<UInt64>(patch.data.size());
                    segment.data = patch.data;
                    segments_.push_back(std::move(segment));
                    reindex_segments();
                }
                return true;
            }
            if (patch.op == L"insert")
            {
                if (patch.offset > total_length())
                {
                    return false;
                }
                auto before = slice_segments(0, patch.offset);
                auto after = slice_segments(patch.offset, total_length());
                segments_ = std::move(before);
                if (!patch.data.empty())
                {
                    PatchedInputSegment segment;
                    segment.kind = PatchedInputSegment::Kind::Bytes;
                    segment.length = static_cast<UInt64>(patch.data.size());
                    segment.data = patch.data;
                    segments_.push_back(std::move(segment));
                }
                segments_.insert(segments_.end(), after.begin(), after.end());
                reindex_segments();
                return true;
            }
            if (patch.op == L"delete")
            {
                if (!patch.has_size || patch.offset + patch.size > total_length())
                {
                    return false;
                }
                auto before = slice_segments(0, patch.offset);
                auto after = slice_segments(patch.offset + patch.size, total_length());
                segments_ = std::move(before);
                segments_.insert(segments_.end(), after.begin(), after.end());
                reindex_segments();
                return true;
            }
            return false;
        }

        std::vector<PatchedInputSegment> slice_segments(UInt64 start, UInt64 end) const
        {
            std::vector<PatchedInputSegment> out;
            for (const auto &segment : segments_)
            {
                const UInt64 segment_start = segment.virtual_offset;
                const UInt64 segment_end = segment.virtual_offset + segment.length;
                if (segment_end <= start)
                {
                    continue;
                }
                if (segment_start >= end)
                {
                    break;
                }
                const UInt64 take_start = std::max<UInt64>(start, segment_start) - segment_start;
                const UInt64 take_end = std::min<UInt64>(end, segment_end) - segment_start;
                if (take_end <= take_start)
                {
                    continue;
                }
                PatchedInputSegment copy = segment;
                copy.virtual_offset = 0;
                copy.length = take_end - take_start;
                if (copy.kind == PatchedInputSegment::Kind::Bytes)
                {
                    copy.data.assign(segment.data.begin() + take_start, segment.data.begin() + take_end);
                }
                else
                {
                    copy.source_start = segment.source_start + take_start;
                }
                out.push_back(std::move(copy));
            }
            return out;
        }

        void reindex_segments()
        {
            UInt64 offset = 0;
            for (auto &segment : segments_)
            {
                segment.virtual_offset = offset;
                offset += segment.length;
            }
            total_size_ = offset;
        }

        UInt64 total_length() const
        {
            UInt64 length = 0;
            for (const auto &segment : segments_)
            {
                length += segment.length;
            }
            return length;
        }

        const PatchedInputSegment *find_segment(UInt64 position) const
        {
            for (const auto &segment : segments_)
            {
                if (position >= segment.virtual_offset && position < segment.virtual_offset + segment.length)
                {
                    return &segment;
                }
            }
            return nullptr;
        }

        HRESULT read_file_segment(const PatchedInputSegment &segment, UInt64 offset_in_segment, UInt32 want, unsigned char *out, UInt32 *read_out)
        {
            if (read_out)
            {
                *read_out = 0;
            }
            const UInt64 source_offset = segment.source_start + offset_in_segment;
            if (trace_)
            {
                trace_->last_read_virtual_offset = position_;
                trace_->last_read_source_offset = source_offset;
                trace_->last_read_requested = want;
                trace_->last_read_returned = 0;
                trace_->last_source_path = segment.path;
            }
            UInt32 read = 0;
            HRESULT result = S_OK;
            {
                ReadFileWallTimer timer(trace_);
                result = read_handles_.read_at(segment.path, source_offset, out, want, &read);
            }
            if (result != S_OK)
            {
                const DWORD error = GetLastError();
                if (trace_)
                {
                    trace_->read_error = true;
                    trace_->last_hresult = result;
                    trace_->last_win32_error = static_cast<int>(error);
                }
                return result;
            }
            if (read_out)
            {
                *read_out = read;
            }
            return S_OK;
        }

        LONG refs_ = 1;

        std::vector<PatchedInputSegment> segments_;

        UInt64 total_size_ = 0;

        UInt64 position_ = 0;

        ExtractInputTrace *trace_ = nullptr;

        // One long lived read handle per source file, not reopened per Read call.
        PathHandleCache read_handles_;

        bool valid_ = true;
    };

    ComPtr<IInStream> open_archive_stream(

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
