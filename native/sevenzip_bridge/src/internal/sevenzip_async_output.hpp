#pragma once

#include "sevenzip_paths.hpp"
#include "sevenzip_space_retry.hpp"
#include "sevenzip_volume_state.hpp"
#include "sevenzip_writer_meters.hpp"
#include "extraction_replay.hpp"
#include "decoder_memory.h"
#ifdef SUP7Z_DEBUG
#include "worker_pipeline_timing.hpp"
#endif

#ifdef _WIN32

#include <algorithm>
#include <atomic>
#include <cassert>
#include <condition_variable>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <limits>
#include <memory>
#include <mutex>
#include <new>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace sunpack::sevenzip
{
    struct ArchiveMetadataErrors
    {
        DWORD time = 0;
        DWORD attributes = 0;
        DWORD first_error() const noexcept { return time ? time : attributes; }
    };

    struct ArchiveItemMetadata
    {
        enum : unsigned char { Creation = 1, Access = 2, Modification = 4, Attributes = 8 };
        FILETIME creation{};
        FILETIME access{};
        FILETIME modification{};
        unsigned char defined = 0;
        DWORD attributes = 0;

        bool has_times() const noexcept { return (defined & (Creation | Access | Modification)) != 0; }

        ArchiveMetadataErrors restore(HANDLE handle) const noexcept
        {
            const DWORD flags = basic_attributes();
            if (flags && has_times())
            {
                FILE_BASIC_INFO info{};
                info.FileAttributes = flags;
                // Keep unusual FILETIME values on the original SetFileTime path.
                if (copy_time(Creation, creation, info.CreationTime) &&
                    copy_time(Access, access, info.LastAccessTime) &&
                    copy_time(Modification, modification, info.LastWriteTime))
                {
                    if (SetFileInformationByHandle(handle, FileBasicInfo, &info, sizeof(info))) return {};
                }
            }
            // Some filesystems reject the combined update. Preserve independent
            // restoration and error reporting for each part in that case.
            const DWORD time_error = set_times(handle);
            return {time_error, set_basic_attributes(handle, flags)};
        }

    private:
        bool copy_time(unsigned char flag, FILETIME time, LARGE_INTEGER &destination) const noexcept
        {
            if (!(defined & flag)) return true;
            if (time.dwHighDateTime & 0x80000000U) return false;
            destination.HighPart = static_cast<LONG>(time.dwHighDateTime);
            destination.LowPart = time.dwLowDateTime;
            return true;
        }

        DWORD set_times(HANDLE handle) const noexcept
        {
            if (!has_times() || SetFileTime(handle,
                    (defined & Creation) ? &creation : nullptr,
                    (defined & Access) ? &access : nullptr,
                    (defined & Modification) ? &modification : nullptr))
                return ERROR_SUCCESS;
            return GetLastError();
        }

        DWORD basic_attributes() const noexcept
        {
            if (!(defined & Attributes)) return 0;
            // Only basic writable attributes; never copy type,
            // reparse, compression, encryption or POSIX mode bits into Windows.
            constexpr DWORD mask = FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN |
                FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_TEMPORARY |
                FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED;
            const DWORD value = attributes & mask;
            // Zero time fields leave the timestamps unchanged. NORMAL clears
            // writable flags; zero attributes would instead leave them unchanged.
            return value ? value : FILE_ATTRIBUTE_NORMAL;
        }

        static DWORD set_basic_attributes(HANDLE handle, DWORD flags) noexcept
        {
            if (!flags) return ERROR_SUCCESS;
            FILE_BASIC_INFO info{};
            info.FileAttributes = flags;
            if (SetFileInformationByHandle(handle, FileBasicInfo, &info, sizeof(info)))
                return ERROR_SUCCESS;
            return GetLastError();
        }
    };

    class AsyncFileWriter final
    {
    public:
        struct JobState
        {
            explicit JobState(
                std::size_t budget,
                std::shared_ptr<std::atomic<bool>> external_cancel = nullptr
#ifdef SUP7Z_DEBUG
                , PipelineTiming *pipeline_timing = nullptr
#endif
                )
                : max_inflight_bytes(budget),
                  cancel_token(std::move(external_cancel))
#ifdef SUP7Z_DEBUG
                  , pipeline_timing(pipeline_timing)
#endif
                  {}

            // 必须是 atomic：gate 的 wait() 在 writer mutex_ 之外无锁读它。
            // 每个令本 job 终局的地方都要同步置 true；空间错误不得置位（那是暂停语义的前提）。
            std::atomic<bool> terminal_requested{false};

            // 详细错误结果，由本 writer 的 mutex_ 保护。
            HRESULT first_error = S_OK;
            int first_win32_error = 0;
            std::size_t inflight_bytes = 0;
            std::size_t pending_jobs = 0;
            bool cancelled = false;
            const std::size_t max_inflight_bytes;
            std::shared_ptr<std::atomic<bool>> cancel_token;
#ifdef SUP7Z_DEBUG
            PipelineTiming *pipeline_timing = nullptr;
#endif
        };

        using JobStatePtr = std::shared_ptr<JobState>;

        struct Buffer;
        struct FileState;
        using FileStatePtr = std::shared_ptr<FileState>;

        struct FileSnapshot
        {
            UInt64 written_bytes = 0;
            Int32 operation_result = 0;
            HRESULT hresult = S_OK;
            int win32_error = 0;
            ArchiveMetadataErrors metadata_errors;
            bool operation_result_set = false;
            bool has_mtime_ns = false;
            UInt64 mtime_ns = 0;
            std::vector<unsigned char> magic;
            bool failed = false;
            bool closed = false;
#ifdef SUP7Z_TEST_IO_FAULTS
            UInt64 accepted_bytes = 0;
            std::size_t peak_active_data_writes = 0;
#endif
        };

#ifdef SUP7Z_TEST_IO_FAULTS
        struct WriterMeterSnapshot
        {
            std::uint64_t accepted_bytes;
            std::uint64_t written_bytes;
            std::uint64_t discarded_bytes;
            std::uint64_t pending_bytes;
            std::uint64_t completed_files;
            std::uint64_t completed_jobs;
        };

        WriterMeterSnapshot snapshot_meters() const noexcept
        {
            return {test_accepted_bytes_.load(std::memory_order_relaxed),
                    test_written_bytes_.load(std::memory_order_relaxed),
                    test_discarded_bytes_.load(std::memory_order_relaxed),
                    test_pending_bytes_.load(std::memory_order_relaxed),
                    test_completed_files_.load(std::memory_order_relaxed),
                    test_completed_jobs_.load(std::memory_order_relaxed)};
        }

        const AsyncWriterConfig &config() const noexcept { return config_; }
#endif

        const VolumeStatePtr &volume_state() const noexcept { return state_; }

        // writer 是否已停止接收/推进工作，供 gate 的 terminal predicate 在非 atomic 上下文使用。
        bool stopping() const noexcept { return stopping_.load(std::memory_order_acquire); }

        const std::string &volume_key() const noexcept { return state_->key; }

        struct WorkItem
        {
            enum class Kind
            {
                Data,
                Close
            };

            static WorkItem data(Buffer *value, UInt64 offset)
            {
                WorkItem item;
                item.kind = Kind::Data;
                item.buffer = value;
                item.output_offset = offset;
                return item;
            }

            static WorkItem close(FileStatePtr value)
            {
                WorkItem item;
                item.kind = Kind::Close;
                item.file = std::move(value);
                return item;
            }

            Kind kind = Kind::Data;
            Buffer *buffer = nullptr;
            FileStatePtr file;
            UInt64 output_offset = 0;
            unsigned long retry_error = 0;
        };

        struct FileState
        {
            FileState(
                JobStatePtr state,
                std::wstring file_path,
                std::wstring archive_path,
                UInt32 archive_index,
                std::size_t trace,
                const ArchiveItemMetadata &file_metadata)
                : item_path(std::move(archive_path)),
                  item_index(archive_index),
                  trace_index(trace),
                  job(std::move(state)),
                  path(std::move(file_path)),
                  metadata(file_metadata) {}

            const std::wstring item_path;
            const UInt32 item_index = 0;
            const std::size_t trace_index = 0;

            // 本文件所属卷的空间 gate，可能为 nullptr（功能关闭 / 无卷身份）。
            // 在 make_file() 时快照进来，writer 线程不再取 state_。
            VolumeSpaceGate *volume_space_gate() const noexcept { return space_gate.get(); }
            const WrittenRanges &previous_writes() const noexcept {
                static const WrittenRanges empty;
                return replay ? replay->written : empty;
            }

        private:
            friend class AsyncFileWriter;

            JobStatePtr job;
            std::wstring path;
            const ArchiveItemMetadata metadata;
            std::shared_ptr<VolumeSpaceGate> space_gate;
            std::atomic<UInt64> accepted_bytes{0};
            std::atomic<UInt64> next_write_offset{0};
            std::mutex producer_mutex;
            Buffer *staging_buffer = nullptr;
            std::size_t inflight_bytes = 0;
            std::size_t outstanding_data = 0;
#ifdef SUP7Z_TEST_IO_FAULTS
            std::size_t active_data_writes = 0;
            std::size_t peak_active_data_writes = 0;
#endif
            UInt64 written_bytes = 0;
            Int32 operation_result = 0;
            HRESULT hresult = S_OK;
            int win32_error = 0;
            ArchiveMetadataErrors metadata_errors;
            bool operation_result_set = false;
            bool has_mtime_ns = false;
            UInt64 mtime_ns = 0;
            std::vector<unsigned char> magic;
            bool failed = false;
            bool closed = false;
            bool close_requested = false;
            bool close_enqueued = false;
            std::size_t active_index = 0;
            // Only open attempts for this file serialize. Never acquire this
            // mutex while holding the writer mutex (including on close).
            std::mutex open_mutex;
            HANDLE handle = INVALID_HANDLE_VALUE;
            bool open_attempted = false;
            bool new_writes = false;
            bool output_created = false;
            ReplayFile *replay = nullptr;
            bool track_replay = false;
            WrittenRanges written_ranges_;
        };

        struct IoRequest
        {
            OVERLAPPED overlapped{};
            Buffer *buffer = nullptr;
        };
        static_assert(offsetof(IoRequest, overlapped) == 0);

        struct Buffer
        {
            Buffer() { request.buffer = this; }

            void reserve_payload(std::size_t required)
            {
                // Keep the logical 1 MiB staging limit. Small files only pay
                // for a small allocation, which can grow once if needed.
                constexpr std::size_t small_capacity = 16U << 10;
                const auto new_capacity = required <= small_capacity ? small_capacity : kBufferSize;
                std::unique_ptr<unsigned char[]> payload(new unsigned char[new_capacity]);
                if (size) std::memcpy(payload.get(), data.get(), size);
                data = std::move(payload);
                capacity = new_capacity;
            }

            std::unique_ptr<unsigned char[]> data;
            std::size_t capacity = 0;
            IoRequest request;
            // Completion can be dequeued before WriteFile returns. Serialize
            // that handoff, including synchronous success, before recycling.
            std::mutex io_mutex;
            UInt64 output_offset = 0;
            UInt32 transferred = 0;
            ProbeLease probe_lease;
            FileStatePtr file;
            UInt32 size = 0;
        };

        static constexpr std::size_t kBufferSize = 1U << 20;
        static constexpr std::size_t kDefaultWriterCount = 4;
        static constexpr std::size_t kMaxWriterCount = 8;
        static constexpr std::size_t kDefaultJobInFlightBytes = 32U << 20;
        static constexpr std::size_t kDefaultFileInFlightBytes = 8U << 20;

        AsyncFileWriter(
            VolumeStatePtr state,
            AsyncWriterConfig config = {})
            : state_(state ? std::move(state) : make_volume_state(std::string{}, false)),
              config_(config),
              writer_count_((std::max)(std::size_t{1}, config.threads_per_volume)),
              buffer_count_((std::max)(std::size_t{4}, config.buffer_count)),
              queue_limit_((std::max)(std::size_t{1}, config.queue_limit))
        {
            initialize();
        }

        AsyncFileWriter()
            : AsyncFileWriter(
                  make_volume_state(std::string{}, false),
                  configured_async_writer_config()) {}

        ~AsyncFileWriter() { finish(); }

        AsyncFileWriter(const AsyncFileWriter &) = delete;
        AsyncFileWriter &operator=(const AsyncFileWriter &) = delete;

        JobStatePtr make_job(
            std::size_t max_inflight_bytes = 0,
            std::shared_ptr<std::atomic<bool>> cancel_token = nullptr
#ifdef SUP7Z_DEBUG
            , PipelineTiming *pipeline_timing = nullptr
#endif
            )
        {
            if (max_inflight_bytes == 0)
            {
                max_inflight_bytes = kDefaultJobInFlightBytes;
            }
            auto job = std::make_shared<JobState>(
                max_inflight_bytes,
                std::move(cancel_token)
#ifdef SUP7Z_DEBUG
                , pipeline_timing
#endif
                );
            std::lock_guard<std::mutex> lock(mutex_);
            synchronize_cancellation_locked(job);
            active_jobs_.push_back(job);
            return job;
        }

        FileStatePtr make_file(
            const JobStatePtr &job,
            std::wstring path,
            std::wstring item_path,
            UInt32 item_index,
            std::size_t trace_index,
            const ArchiveItemMetadata &metadata = {}
            , ReplayFile *replay = nullptr
            )
        {
            auto file = std::make_shared<FileState>(
                job ? job : make_job(),
                std::move(path), std::move(item_path), item_index, trace_index, metadata);
            file->replay = replay;
            file->track_replay = replay || current_extraction_replay;
            if (replay) {
                file->written_ranges_ = replay->written;
                file->written_bytes = replay->written.bytes();
                file->has_mtime_ns = replay->has_mtime;
                file->mtime_ns = replay->mtime;
            }
            std::lock_guard<std::mutex> lock(mutex_);
            // 快照本卷的空间 gate；功能关闭 / 空 key 时为 nullptr。
            file->space_gate = state_ ? state_->space_gate : nullptr;
            file->active_index = active_files_.size();
            active_files_.push_back(file);
            return file;
        }

        // Seal staging before a replay crosses confirmed bytes. Those bytes
        // advance the logical cursor without accepting another disk write.
        HRESULT skip_written(const FileStatePtr &file, UInt32 size) {
            std::lock_guard<std::mutex> producer_lock(file->producer_mutex);
            std::lock_guard<std::mutex> lock(mutex_);
            const auto error = terminal_result_locked(file->job);
            if (error != S_OK) return error;
            if (file->staging_buffer && file->staging_buffer->size && !enqueue_staging_locked(file, true))
                return terminal_result_locked(file->job);
            file->next_write_offset.fetch_add(size, std::memory_order_relaxed);
            file->accepted_bytes.fetch_add(size, std::memory_order_relaxed);
            return S_OK;
        }

        void capture_replay(const FileStatePtr &file, ExtractionReplay *saved = nullptr) {
            if (!file || (!file->replay && !saved)) return;
            std::lock_guard<std::mutex> lock(mutex_);
            auto &receipt = saved ? saved->files[file->item_index] : *file->replay;
            if (receipt.path.empty()) receipt.path = std::move(file->path);
            receipt.created = receipt.created || file->output_created;
            receipt.written = std::move(file->written_ranges_);
            receipt.complete = receipt.complete || (file->closed && !file->failed && file->operation_result_set && file->operation_result == 0);
            receipt.has_mtime = file->has_mtime_ns;
            receipt.mtime = file->mtime_ns;
        }

        std::size_t idle_memory_bytes() noexcept {
            std::lock_guard<std::mutex> lock(mutex_);
            std::size_t bytes = 0;
            for (const auto *buffer : free_buffers_) bytes += buffer->capacity;
            return bytes;
        }

        // The registry aggregates small pools before requesting coarse reclaim.
        // Only free buffers are touched; IOCP keeps ownership of in-flight data.
        void reclaim_idle_memory() noexcept {
            std::lock_guard<std::mutex> lock(mutex_);
            for (auto *buffer : free_buffers_)
            {
                buffer->data.reset();
                buffer->capacity = 0;
            }
        }

        HRESULT write(
            const FileStatePtr &file,
            const void *data,
            UInt32 size,
            UInt32 *processed_size)
        {
            if (processed_size)
            {
                *processed_size = 0;
            }
            if (!file || (size != 0 && data == nullptr))
            {
                return E_POINTER;
            }
            if (size == 0)
            {
                return S_OK;
            }

            const auto *source = static_cast<const unsigned char *>(data);
            UInt32 consumed = 0;
            const auto job = file->job;
            if (!job)
            {
                return E_FAIL;
            }

            std::unique_lock<std::mutex> producer_lock(file->producer_mutex);

            while (consumed < size)
            {
                bool queued_staging = false;
                bool newly_acquired_staging = false;
                UInt32 previous_size = 0;
                UInt32 chunk = 0;
                HRESULT setup_error = S_OK;
                {
                    std::unique_lock<std::mutex> lock(mutex_);

                    producer_cv_.wait(lock, [this, &job, &file]
                                      { return terminal_result_locked(job) != S_OK || file->close_requested ||
                                               can_accept_locked(job, file); });

                    const HRESULT error = terminal_result_locked(job);
                    if (error != S_OK || file->close_requested)
                    {
                        if (processed_size)
                        {
                            *processed_size = consumed;
                        }
                        return error == S_OK ? E_ABORT : error;
                    }

                    if (file->staging_buffer && file->staging_buffer->size == kBufferSize)
                    {
                        queued_staging = enqueue_staging_locked(file, false);
                        if (!queued_staging)
                        {
                            const HRESULT enqueue_error = terminal_result_locked(job);
                            if (enqueue_error != S_OK)
                            {
                                if (processed_size)
                                {
                                    *processed_size = consumed;
                                }
                                return enqueue_error;
                            }
                            continue;
                        }
                    }

                    Buffer *buffer = file->staging_buffer;
                    if (!buffer && free_buffers_.empty()) continue;
                    previous_size = buffer ? buffer->size : 0;
                    const std::size_t job_available = job->max_inflight_bytes -
                        (std::min)(job->inflight_bytes, job->max_inflight_bytes);
                    const std::size_t file_available = kDefaultFileInFlightBytes -
                        (std::min)(file->inflight_bytes, kDefaultFileInFlightBytes);
                    const std::size_t chunk_size = (std::min)({
                        static_cast<std::size_t>(size - consumed),
                        kBufferSize - previous_size,
                        job_available,
                        file_available,
                    });
                    if (chunk_size == 0) continue;

                    if (!buffer) buffer = free_buffers_.back();
                    try
                    {
                        if (buffer->capacity < previous_size + chunk_size)
                        {
                            buffer->reserve_payload(previous_size + chunk_size);
                        }
                        if (!file->staging_buffer)
                        {
                            free_buffers_.pop_back();
                            buffer->file = file;
                            buffer->size = 0;
                            file->staging_buffer = buffer;
                            newly_acquired_staging = true;
                        }
                        chunk = static_cast<UInt32>(chunk_size);
                        job->inflight_bytes += chunk_size;
                        file->inflight_bytes += chunk_size;
                    }
                    catch (...)
                    {
                        mark_file_failure_locked(file, E_OUTOFMEMORY, ERROR_OUTOFMEMORY);
                        set_job_error_locked(job, E_OUTOFMEMORY, ERROR_OUTOFMEMORY);
                        setup_error = E_OUTOFMEMORY;
                    }
                }

                if (setup_error != S_OK)
                {
                    producer_cv_.notify_all();
                    if (processed_size)
                    {
                        *processed_size = consumed;
                    }
                    return setup_error;
                }

                std::memcpy(
                    file->staging_buffer->data.get() + previous_size,
                    source + consumed,
                    chunk);

                HRESULT enqueue_result = S_OK;
                {
                    std::unique_lock<std::mutex> lock(mutex_);
                    const HRESULT error = terminal_result_locked(job);
                    Buffer *buffer = file->staging_buffer;
                    if (error != S_OK || file->close_requested || !buffer)
                    {
                        job->inflight_bytes -= chunk;
                        file->inflight_bytes -= chunk;
                        if (newly_acquired_staging && buffer && buffer->size == previous_size)
                        {
                            file->staging_buffer = nullptr;
                            buffer->file.reset();
                            buffer->size = 0;
                            free_buffers_.push_back(buffer);
                        }
                        if (processed_size)
                        {
                            *processed_size = consumed;
                        }
                        enqueue_result = error == S_OK ? E_ABORT : error;
                    }
                    else
                    {
                        buffer->size = previous_size + chunk;
                        if (previous_size == 0)
                        {
                            ++job->pending_jobs;
                            ++file->outstanding_data;
                        }
                        file->accepted_bytes.fetch_add(chunk, std::memory_order_relaxed);
                        file->new_writes = true;
#ifdef SUP7Z_TEST_IO_FAULTS
                        test_accepted_bytes_.fetch_add(chunk, std::memory_order_relaxed);
                        test_pending_bytes_.fetch_add(chunk, std::memory_order_relaxed);
#endif
                        consumed += chunk;
                        if (buffer->size == kBufferSize)
                        {
                            queued_staging = enqueue_staging_locked(file, false);
                            if (!queued_staging && terminal_result_locked(job) == S_OK)
                            {
                                enqueue_result = E_FAIL;
                            }
                            else if (!queued_staging)
                            {
                                enqueue_result = terminal_result_locked(job);
                            }
                        }
                    }
                }
                if (enqueue_result != S_OK)
                {
                    producer_cv_.notify_all();
                    if (processed_size)
                    {
                        *processed_size = consumed;
                    }
                    return enqueue_result;
                }
            }

            if (processed_size)
            {
                *processed_size = consumed;
            }
            return S_OK;
        }

        void close_file(
            const FileStatePtr &file,
            std::vector<unsigned char> magic) noexcept
        {
            if (!file)
            {
                return;
            }

            std::unique_lock<std::mutex> producer_lock(file->producer_mutex);
            bool direct_close = false;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                if (file->close_requested)
                {
                    return;
                }
                synchronize_cancellation_locked(file->job);
                file->close_requested = true;
                file->magic = std::move(magic);
                if (file->job)
                {
                    ++file->job->pending_jobs;
                }
                if (terminal_result_locked(file->job) != S_OK)
                {
                    discard_staging_locked(file);
                }
                else if (file->staging_buffer)
                {
                    enqueue_staging_locked(file, true);
                }
                if (file->outstanding_data == 0)
                {
                    enqueue_close_locked(file, &direct_close);
                }
            }
            if (direct_close)
            {
                process_close(file);
            }
            producer_cv_.notify_all();
        }

        HRESULT finish_job(const JobStatePtr &job) noexcept
        {
            if (!job)
            {
                return E_FAIL;
            }
            {
                std::lock_guard<std::mutex> lock(mutex_);
                synchronize_cancellation_locked(job);
            }
            // Seal all files even if an error arrives after this call starts,
            // or the caller never reached the stream's Close().
            seal_job_files(job);
            drain_cancelled_retries();
            if (job->terminal_requested.load(std::memory_order_acquire) && state_->space_gate)
                state_->space_gate->wake_waiters();

            std::unique_lock<std::mutex> lock(mutex_);

            producer_cv_.wait(lock, [&job]
                              { return job->pending_jobs == 0; });

            const HRESULT result = terminal_result_locked(job);
            unregister_job_locked(job);
#ifdef SUP7Z_TEST_IO_FAULTS
            if (result == S_OK)
            {
                test_completed_jobs_.fetch_add(1, std::memory_order_relaxed);
            }
#endif
            return result;
        }

        void cancel_job(const JobStatePtr &job) noexcept
        {
            if (!job)
            {
                return;
            }
            {
                std::lock_guard<std::mutex> lock(mutex_);
                cancel_job_locked(job);
            }
            // Release a producer's capacity wait before acquiring its file
            // mutex to seal it; the producer holds that mutex during Write().
            producer_cv_.notify_all();
            if (state_->space_gate) state_->space_gate->wake_waiters();
            seal_job_files(job);
            drain_cancelled_retries();
        }

        void wake_waiters() noexcept
        {
            {
                std::lock_guard<std::mutex> lock(mutex_);
                for (auto it = active_jobs_.begin(); it != active_jobs_.end();)
                {
                    if (const auto job = it->lock())
                    {
                        synchronize_cancellation_locked(job);
                        ++it;
                    }
                    else
                    {
                        it = active_jobs_.erase(it);
                    }
                }
            }
            drain_cancelled_retries();
            // 取消必须能穿透"因满盘而暂停"：卷 gate 的等待者也要被唤醒。
            if (state_ && state_->space_gate)
            {
                state_->space_gate->wake_waiters();
            }
            producer_cv_.notify_all();
        }

        HRESULT current_error(const JobStatePtr &job) noexcept
        {
            if (!job)
            {
                return E_FAIL;
            }
            std::lock_guard<std::mutex> lock(mutex_);
            synchronize_cancellation_locked(job);
            return terminal_result_locked(job);
        }

        int current_win32_error(const JobStatePtr &job) noexcept
        {
            if (!job)
            {
                return ERROR_INVALID_STATE;
            }
            std::lock_guard<std::mutex> lock(mutex_);
            synchronize_cancellation_locked(job);
            return current_win32_error_locked(job);
        }

        UInt64 accepted_bytes(const FileStatePtr &file) const noexcept
        {
            return file ? file->accepted_bytes.load(std::memory_order_relaxed) : 0;
        }

        bool is_quiescent() const noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (queued_jobs_ != 0 || !active_files_.empty())
            {
                return false;
            }
            for (const auto &weak_job : active_jobs_)
            {
                if (!weak_job.expired())
                {
                    return false;
                }
            }
            return true;
        }

#ifdef SUP7Z_TEST_IO_FAULTS
        bool has_active_jobs() const noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            for (const auto &weak_job : active_jobs_)
            {
                if (!weak_job.expired())
                {
                    return true;
                }
            }
            return false;
        }
#endif

        void record_operation_result(const FileStatePtr &file, Int32 operation_result) noexcept
        {
            if (!file)
            {
                return;
            }
            std::lock_guard<std::mutex> lock(mutex_);
            file->operation_result = operation_result;
            file->operation_result_set = true;
        }

        FileSnapshot snapshot_file(const FileStatePtr &file) const
        {
            FileSnapshot snapshot;
            if (!file)
            {
                return snapshot;
            }
            std::lock_guard<std::mutex> lock(mutex_);
            snapshot.written_bytes = file->written_bytes;
            snapshot.operation_result = file->operation_result;
            snapshot.hresult = file->hresult;
            snapshot.win32_error = file->win32_error;
            snapshot.metadata_errors = file->metadata_errors;
            snapshot.operation_result_set = file->operation_result_set;
            snapshot.has_mtime_ns = file->has_mtime_ns;
            snapshot.mtime_ns = file->mtime_ns;
            snapshot.magic = file->magic;
            snapshot.failed = file->failed;
            snapshot.closed = file->closed;
#ifdef SUP7Z_TEST_IO_FAULTS
            snapshot.accepted_bytes = file->accepted_bytes.load(std::memory_order_relaxed);
            snapshot.peak_active_data_writes = file->peak_active_data_writes;
#endif
            return snapshot;
        }

        void finish() noexcept
        {
            std::lock_guard<std::mutex> finish_lock(finish_mutex_);
            if (!completion_port_) return;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                stopping_.store(true, std::memory_order_release);
                for (const auto &weak : active_jobs_)
                    if (auto job = weak.lock()) cancel_job_locked(job);
            }
            producer_cv_.notify_all();
            if (state_->space_gate) state_->space_gate->wake_waiters();
            seal_job_files(nullptr);
            if (state_ && state_->space_gate) state_->space_gate->wake_waiters();
            producer_cv_.notify_all();
            drain_cancelled_retries();
            {
                std::unique_lock<std::mutex> lock(mutex_);
                producer_cv_.wait(lock, [this] { return queued_jobs_ == 0 && active_files_.empty(); });
            }
            // No packet can reference a recycled buffer or a closed file now.
            space_wake_->disable();
            for (std::size_t i = 0; i < workers_.size(); ++i)
                PostQueuedCompletionStatus(completion_port_, 0, kStopPacket, nullptr);
            for (auto &worker : workers_) if (worker.joinable()) worker.join();
            CloseHandle(completion_port_);
            completion_port_ = nullptr;
        }

    private:
        void unregister_file_locked(const FileStatePtr &file) noexcept
        {
            // Callbacks retain closed files for final snapshots. Registry
            // membership follows I/O lifetime rather than shared_ptr lifetime.
            const auto index = file->active_index;
            assert(index < active_files_.size() && active_files_[index] == file);
            if (index + 1 != active_files_.size())
            {
                active_files_[index] = std::move(active_files_.back());
                active_files_[index]->active_index = index;
            }
            active_files_.pop_back();
        }

        void initialize()
        {
            buffers_.reserve(buffer_count_);
            free_buffers_.reserve(buffer_count_);
            for (std::size_t index = 0; index < buffer_count_; ++index)
            {
                auto buffer = std::make_unique<Buffer>();
                free_buffers_.push_back(buffer.get());
                buffers_.push_back(std::move(buffer));
            }
            completion_port_ = CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0,
                                                       static_cast<DWORD>(writer_count_));
            if (!completion_port_) throw std::bad_alloc();
            try
            {
                space_wake_ = std::make_shared<CompletionWake>(completion_port_);
                if (state_->space_gate) state_->space_gate->subscribe(space_wake_);
                workers_.reserve(writer_count_);
                for (std::size_t index = 0; index < writer_count_; ++index)
                {
                    workers_.emplace_back([this]
                                          { writer_loop(); });
                }
            }
            catch (...)
            {
                {
                    std::lock_guard<std::mutex> lock(mutex_);
                    stopping_.store(true, std::memory_order_release);
                }
                for (std::size_t i = 0; i < workers_.size(); ++i)
                    PostQueuedCompletionStatus(completion_port_, 0, kStopPacket, nullptr);
                for (auto &worker : workers_)
                {
                    if (worker.joinable())
                    {
                        worker.join();
                    }
                }
                if (space_wake_) space_wake_->disable();
                CloseHandle(completion_port_);
                completion_port_ = nullptr;
                throw;
            }
        }

        bool write_through() const noexcept { return config_.write_through; }

#ifdef SUP7Z_TEST_IO_FAULTS
        void account_discarded(std::size_t bytes) noexcept
        {
            test_discarded_bytes_.fetch_add(bytes, std::memory_order_relaxed);
            test_pending_bytes_.fetch_sub(bytes, std::memory_order_relaxed);
        }
#endif

        void set_job_error_locked(const JobStatePtr &job, HRESULT hr, int win32_error) noexcept
        {
            if (job && job->first_error == S_OK)
            {
                job->first_error = hr;
                job->first_win32_error = win32_error;
                job->terminal_requested.store(true, std::memory_order_release);
            }
        }

        void cancel_job_locked(const JobStatePtr &job) noexcept
        {
            if (!job)
            {
                return;
            }
            job->cancelled = true;
            job->terminal_requested.store(true, std::memory_order_release);
            set_job_error_locked(job, E_ABORT, ERROR_OPERATION_ABORTED);
        }

        void synchronize_cancellation_locked(const JobStatePtr &job) noexcept
        {
            if (job && job->cancel_token && job->cancel_token->load(std::memory_order_acquire))
            {
                cancel_job_locked(job);
            }
        }

        HRESULT terminal_result_locked(const JobStatePtr &job) const noexcept
        {
            if (!job)
            {
                return E_FAIL;
            }
            if (job->first_error != S_OK)
            {
                return job->first_error;
            }
            return (job->cancelled || stopping_.load(std::memory_order_acquire)) ? E_ABORT : S_OK;
        }

        int current_win32_error_locked(const JobStatePtr &job) const noexcept
        {
            if (!job)
            {
                return ERROR_INVALID_STATE;
            }
            if (job->first_win32_error != 0)
            {
                return job->first_win32_error;
            }
            return (job->cancelled || stopping_.load(std::memory_order_acquire))
                       ? ERROR_OPERATION_ABORTED
                       : 0;
        }

        bool can_accept_locked(const JobStatePtr &job, const FileStatePtr &file) const noexcept
        {
            if (!job || !file || file->close_requested ||
                job->inflight_bytes >= job->max_inflight_bytes ||
                file->inflight_bytes >= kDefaultFileInFlightBytes)
            {
                return file && file->staging_buffer &&
                       file->staging_buffer->size == kBufferSize &&
                       queued_jobs_ < queue_limit_;
            }
            if (file->staging_buffer)
            {
                return file->staging_buffer->size < kBufferSize;
            }
            return !free_buffers_.empty();
        }

        void unregister_job_locked(const JobStatePtr &job) noexcept
        {
            for (auto it = active_jobs_.begin(); it != active_jobs_.end();)
            {
                const auto candidate = it->lock();
                if (!candidate || candidate.get() == job.get())
                {
                    it = active_jobs_.erase(it);
                }
                else
                {
                    ++it;
                }
            }
        }

        void seal_job_files(const JobStatePtr &job) noexcept
        {
            // Scan backwards: unregister_file_locked swaps the tail into an
            // erased slot, so removals can only move already-visited files.
            // No snapshot allocation is safe here: cleanup must work under OOM.
            // A null job seals the entire facility during shutdown.
            std::size_t remaining = (std::numeric_limits<std::size_t>::max)();
            for (;;)
            {
                FileStatePtr file;
                {
                    std::lock_guard<std::mutex> lock(mutex_);
                    remaining = (std::min)(remaining, active_files_.size());
                    while (remaining != 0)
                    {
                        const auto &candidate = active_files_[--remaining];
                        if ((!job || candidate->job == job) && !candidate->close_requested)
                        {
                            file = candidate;
                            break;
                        }
                    }
                }
                if (!file) return;
                // Callers need not have reached Close(). Keep the file alive
                // until submitted I/O drains and its handle closes.
                close_file(file, {});
            }
        }

        void discard_staging_locked(const FileStatePtr &file) noexcept
        {
            if (!file || !file->staging_buffer)
            {
                return;
            }
            Buffer *buffer = file->staging_buffer;
            file->staging_buffer = nullptr;
            if (buffer->size != 0)
            {
#ifdef SUP7Z_TEST_IO_FAULTS
                account_discarded(buffer->size);
#endif
                if (file->inflight_bytes >= buffer->size)
                {
                    file->inflight_bytes -= buffer->size;
                }
                else
                {
                    file->inflight_bytes = 0;
                }
                if (file->outstanding_data != 0)
                {
                    --file->outstanding_data;
                }
                if (file->job)
                {
                    if (file->job->inflight_bytes >= buffer->size)
                    {
                        file->job->inflight_bytes -= buffer->size;
                    }
                    else
                    {
                        file->job->inflight_bytes = 0;
                    }
                    if (file->job->pending_jobs != 0)
                    {
                        --file->job->pending_jobs;
                    }
                }
            }
            buffer->file.reset();
            buffer->size = 0;
            free_buffers_.push_back(buffer);
        }

        bool enqueue_staging_locked(
            const FileStatePtr &file,
            bool force_queue) noexcept
        {
            if (!file || !file->staging_buffer || file->staging_buffer->size == 0)
            {
                return false;
            }
            if (!force_queue && queued_jobs_ >= queue_limit_)
            {
                return false;
            }

            Buffer *buffer = file->staging_buffer;
            const UInt64 output_offset = file->next_write_offset.load(std::memory_order_relaxed);
            if (output_offset > (std::numeric_limits<UInt64>::max)() - buffer->size)
            {
                discard_staging_locked(file);
                mark_file_failure_locked(file, E_FAIL, ERROR_ARITHMETIC_OVERFLOW);
                set_job_error_locked(file->job, E_FAIL, ERROR_ARITHMETIC_OVERFLOW);
                return false;
            }
            try
            {
                work_queue_.emplace_back(WorkItem::data(buffer, output_offset));
                const DWORD error = post_work_locked();
                if (error != ERROR_SUCCESS)
                {
                    work_queue_.pop_back();
                    discard_staging_locked(file);
                    mark_file_failure_locked(file, HRESULT_FROM_WIN32(error), error);
                    set_job_error_locked(file->job, HRESULT_FROM_WIN32(error), error);
                    return false;
                }
            }
            catch (...)
            {
                discard_staging_locked(file);
                mark_file_failure_locked(file, E_OUTOFMEMORY, ERROR_OUTOFMEMORY);
                set_job_error_locked(file->job, E_OUTOFMEMORY, ERROR_OUTOFMEMORY);
                return false;
            }
            file->staging_buffer = nullptr;
            file->next_write_offset.store(
                output_offset + buffer->size, std::memory_order_relaxed);
            ++queued_jobs_;
            return true;
        }

        bool enqueue_close_locked(const FileStatePtr &file, bool *direct_close) noexcept
        {
            if (!file || !file->close_requested || file->close_enqueued || file->closed ||
                file->outstanding_data != 0)
            {
                return false;
            }
            file->close_enqueued = true;
            try
            {
                work_queue_.push_back(WorkItem::close(file));
                const DWORD error = post_work_locked();
                if (error != ERROR_SUCCESS)
                {
                    work_queue_.pop_back();
                    mark_file_failure_locked(file, HRESULT_FROM_WIN32(error), error);
                    set_job_error_locked(file->job, HRESULT_FROM_WIN32(error), error);
                    if (direct_close) *direct_close = true;
                    return false;
                }
                ++queued_jobs_;
                return true;
            }
            catch (...)
            {
                mark_file_failure_locked(file, E_OUTOFMEMORY, ERROR_OUTOFMEMORY);
                set_job_error_locked(file->job, E_OUTOFMEMORY, ERROR_OUTOFMEMORY);
                if (direct_close)
                {
                    *direct_close = true;
                }
                return false;
            }
        }

        static constexpr ULONG_PTR kWorkPacket = 1;
        static constexpr ULONG_PTR kStopPacket = 2;
        static constexpr ULONG_PTR kRetryPacket = 3;

        class CompletionWake final : public SpaceWakeTarget
        {
        public:
            explicit CompletionWake(HANDLE port) : port_(port) {}
            void wake() noexcept override
            {
                std::lock_guard<std::mutex> lock(mutex_);
                if (port_ && !posted_)
                    posted_ = PostQueuedCompletionStatus(port_, 0, kRetryPacket, nullptr) != FALSE;
            }
            void acknowledge() noexcept { std::lock_guard<std::mutex> lock(mutex_); posted_ = false; }
            void disable() noexcept { std::lock_guard<std::mutex> lock(mutex_); port_ = nullptr; }
        private:
            std::mutex mutex_;
            HANDLE port_;
            bool posted_ = false;
        };

        DWORD post_work_locked() noexcept
        {
            // The live port is owned by this facility until all files drain.
            if (PostQueuedCompletionStatus(completion_port_, 0, kWorkPacket, nullptr)) return ERROR_SUCCESS;
            return GetLastError();
        }

        void writer_loop() noexcept
        {
            for (;;)
            {
                DWORD bytes = 0;
                ULONG_PTR key = 0;
                OVERLAPPED *overlapped = nullptr;
                const BOOL ok = GetQueuedCompletionStatus(completion_port_, &bytes, &key, &overlapped, INFINITE);
                const DWORD error = ok ? ERROR_SUCCESS : GetLastError();
                if (key == kRetryPacket)
                {
                    space_wake_->acknowledge();
                    dispatch_space_retries();
                    continue;
                }
                if (overlapped)
                {
                    auto *request = reinterpret_cast<IoRequest *>(overlapped);
                    complete_data_write(request->buffer, bytes, error);
                    continue;
                }
                if (key == kStopPacket || (!ok && error == ERROR_ABANDONED_WAIT_0)) break;
                if (key != kWorkPacket) continue;
                WorkItem item;
                bool wake_producers = false;
                {
                    std::lock_guard<std::mutex> lock(mutex_);
                    if (work_queue_.empty()) continue;
                    item = std::move(work_queue_.front());
                    work_queue_.pop_front();
                    --queued_jobs_;
                    wake_producers = queued_jobs_ == queue_limit_ - 1 ||
                        (queued_jobs_ == 0 && active_files_.empty());
                }
                // Dequeue changes only queue capacity. Data completion wakes
                // producers when it returns buffers or releases byte budgets.
                if (wake_producers) producer_cv_.notify_all();
                if (item.kind == WorkItem::Kind::Close)
                {
                    process_close(item.file);
                    continue;
                }
                Buffer *buffer = item.buffer;
                const auto file = buffer->file;
                buffer->output_offset = item.output_offset;
                buffer->transferred = 0;
                dispatch_data(buffer);
            }
        }

        void dispatch_data(Buffer *buffer) noexcept
        {
            bool submitted = false;
            const auto result = attempt_data_write(buffer->file, buffer, submitted);
            // Once submitted, ONLY the completion packet owns this buffer.
            if (!submitted)
            {
                finish_data_attempt(buffer, result);
            }
        }

        void finish_data_attempt(Buffer *buffer, AttemptResult result) noexcept
        {
            const auto file = buffer->file;
            const bool held_probe = buffer->probe_lease.valid();
            settle_space_attempt(buffer->probe_lease, result, file->path);
            if (result.kind == AttemptResult::Kind::SpaceFailure && file->space_gate)
            {
                auto item = WorkItem::data(buffer, buffer->output_offset);
                item.retry_error = held_probe ? 0 : result.win32_error;
                defer_space_work(std::move(item));
                return;
            }
            if (result.kind == AttemptResult::Kind::SpaceFailure)
                record_failure(file, HRESULT_FROM_WIN32(result.win32_error), result.win32_error);
#ifdef SUP7Z_TEST_IO_FAULTS
            if (result.kind != AttemptResult::Kind::Succeeded && buffer->size > buffer->transferred)
                account_discarded(buffer->size - buffer->transferred);
#endif
            release_buffer(buffer);
        }

        void complete_data_write(Buffer *buffer, DWORD bytes, DWORD error) noexcept
        {
            AttemptResult result;
            {
                std::lock_guard<std::mutex> io_lock(buffer->io_mutex);
                const auto file = buffer->file;
#ifdef SUP7Z_DEBUG
                if (file && file->job->pipeline_timing)
                    file->job->pipeline_timing->end(PipelineStage::Output);
#endif
#ifdef SUP7Z_TEST_IO_FAULTS
                end_data_write(file);
#endif
                if (error != ERROR_SUCCESS)
                    result = classify_data_failure(file, error);
                else if (bytes == 0 || bytes > buffer->size - buffer->transferred)
                {
                    record_failure(file, HRESULT_FROM_WIN32(ERROR_WRITE_FAULT), ERROR_WRITE_FAULT);
                    result = {AttemptResult::Kind::PermanentFailure, ERROR_WRITE_FAULT};
                }
                else
                {
                    add_written_bytes(file, bytes, buffer->output_offset + buffer->transferred);
                    buffer->transferred += bytes;
                }
            }
            if (result.kind == AttemptResult::Kind::Succeeded && buffer->transferred < buffer->size)
                dispatch_data(buffer); // short write continues at the confirmed prefix
            else
                finish_data_attempt(buffer, result);
        }

        // No waiter thread: the monitor/gate posts one coalesced IOCP packet.
        // Queue publication and admission share mutex_, so a transition cannot
        // be lost between testing Pending and leaving the item in this queue.
        void defer_space_work(WorkItem item) noexcept
        {
            const auto file = item.kind == WorkItem::Kind::Data ? item.buffer->file : item.file;
            if (item.retry_error)
                report_retry_space_failure(file->space_gate.get(), item.retry_error, file->path);
            try
            {
                std::lock_guard<std::mutex> lock(mutex_);
                retry_queue_.push_back(std::move(item));
            }
            catch (...)
            {
                record_failure(file, E_OUTOFMEMORY, ERROR_OUTOFMEMORY);
                if (item.kind == WorkItem::Kind::Data)
                    finish_data_attempt(item.buffer, {AttemptResult::Kind::PermanentFailure, ERROR_OUTOFMEMORY});
                else process_close(file);
            }
            space_wake_->wake();
        }

        void dispatch_space_retries() noexcept
        {
            for (;;)
            {
                WorkItem item;
                ProbeLease lease;
                bool found = false;
                {
                    std::lock_guard<std::mutex> lock(mutex_);
                    for (auto it = retry_queue_.begin(); it != retry_queue_.end(); ++it)
                    {
                        const auto file = it->kind == WorkItem::Kind::Data ? it->buffer->file : it->file;
                        synchronize_cancellation_locked(file->job);
                        auto decision = file->space_gate->try_wait(writer_terminal_predicate(file->job));
                        if (decision.kind == VolumeSpaceGate::WaitResult::Kind::Pending) continue;
                        lease = std::move(decision.lease);
                        item = std::move(*it);
                        retry_queue_.erase(it);
                        found = true;
                        break;
                    }
                }
                if (!found) return;
                if (item.kind == WorkItem::Kind::Data)
                {
                    item.buffer->probe_lease = std::move(lease);
                    dispatch_data(item.buffer);
                }
                else process_close(item.file, std::move(lease));
            }
        }

        void drain_cancelled_retries() noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!retry_queue_.empty()) space_wake_->wake();
        }

        // Publish the handle under mutex_, but keep filesystem calls outside
        // that per-volume lock. Outstanding data prevents close during opening.
        // Space failures remain retryable through the existing IOCP queue.
        AttemptResult try_open_file(const FileStatePtr &file, bool has_data = true) noexcept
        {
            if (!file) return {AttemptResult::Kind::PermanentFailure, ERROR_INVALID_STATE};
            {
                std::lock_guard<std::mutex> lock(mutex_);
                if (file->failed)
                    return {AttemptResult::Kind::PermanentFailure, ERROR_INVALID_STATE};
                if (file->handle != INVALID_HANDLE_VALUE)
                    return {AttemptResult::Kind::Succeeded, 0};
                if (file->open_attempted)
                    return {AttemptResult::Kind::PermanentFailure, ERROR_OPEN_FAILED};
            }
            std::lock_guard<std::mutex> open_lock(file->open_mutex);
            {
                std::lock_guard<std::mutex> lock(mutex_);
                if (file->failed)
                    return {AttemptResult::Kind::PermanentFailure, ERROR_INVALID_STATE};
                if (file->handle != INVALID_HANDLE_VALUE)
                    return {AttemptResult::Kind::Succeeded, 0};
                if (file->open_attempted)
                    return {AttemptResult::Kind::PermanentFailure, ERROR_OPEN_FAILED};
            }

            DWORD creation_flags = FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED;
            if (write_through())
            {
                creation_flags |= FILE_FLAG_WRITE_THROUGH;
            }
#ifdef SUP7Z_TEST_IO_FAULTS
            // 整个 FileState 生命周期内 CreateFileW 只应被调用一次。
            if (open_probe_)
            {
                open_probe_(file->path);
            }
#endif

            const HANDLE handle = CreateFileW(
                win32_extended_path(file->path).c_str(),
                GENERIC_WRITE,
                0,
                nullptr,
                file->replay && file->replay->created ? OPEN_EXISTING : CREATE_NEW,
                creation_flags,
                nullptr);
            const DWORD open_error = handle == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
            if (handle == INVALID_HANDLE_VALUE)
            {
                std::lock_guard<std::mutex> lock(mutex_);
                const DWORD error = open_error;
                if (is_output_space_failure(error))
                {
                    if (!file->space_gate)
                    {
                        // gate 关闭时任何错误都置 open_attempted = true，即不再尝试。
                        file->open_attempted = true;
                    }
                    // 不置 open_attempted 与 file/job 失败，重试可达且 job 不终局。
                    return {AttemptResult::Kind::SpaceFailure,
                            static_cast<unsigned long>(error)};
                }
                file->open_attempted = true;
                mark_file_failure_locked(
                    file, HRESULT_FROM_WIN32(error), static_cast<int>(error));
                set_job_error_locked(
                    file->job, HRESULT_FROM_WIN32(error), static_cast<int>(error));
                return {AttemptResult::Kind::PermanentFailure,
                        static_cast<unsigned long>(error)};
            }
            DWORD registration_error = ERROR_SUCCESS;
            if (has_data && !CreateIoCompletionPort(handle, completion_port_, 0, static_cast<DWORD>(writer_count_)))
            {
                registration_error = GetLastError();
            }
            if (registration_error) CloseHandle(handle);
            std::lock_guard<std::mutex> lock(mutex_);
            file->output_created = true;
            if (file->replay) file->replay->created = true;
            file->open_attempted = true;
            if (registration_error)
            {
                mark_file_failure_locked(file, HRESULT_FROM_WIN32(registration_error), registration_error);
                set_job_error_locked(file->job, HRESULT_FROM_WIN32(registration_error), registration_error);
                return {AttemptResult::Kind::PermanentFailure, registration_error};
            }
            file->handle = handle;
            return {AttemptResult::Kind::Succeeded, 0};
        }

        // gate 的终态谓词：只读 atomic，并在冷路径上才被求值。
        TerminalPredicate writer_terminal_predicate(const JobStatePtr &job) const
        {
            return [this, job]
            {
                return stopping_.load(std::memory_order_acquire) || !job ||
                       job->terminal_requested.load(std::memory_order_acquire) ||
                       (job->cancel_token &&
                        job->cancel_token->load(std::memory_order_acquire));
            };
        }

        bool begin_data_write(const FileStatePtr &file) noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!file || file->failed || terminal_result_locked(file->job) != S_OK)
            {
                return false;
            }
#ifdef SUP7Z_TEST_IO_FAULTS
            ++file->active_data_writes;
            file->peak_active_data_writes = (std::max)(file->peak_active_data_writes, file->active_data_writes);
#endif
            return true;
        }

#ifdef SUP7Z_TEST_IO_FAULTS
        void end_data_write(const FileStatePtr &file) noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (file && file->active_data_writes != 0)
            {
                --file->active_data_writes;
            }
        }
#endif

        void add_written_bytes(const FileStatePtr &file, DWORD written, UInt64 offset = 0) noexcept
        {
#ifdef SUP7Z_TEST_IO_FAULTS
            test_written_bytes_.fetch_add(written, std::memory_order_relaxed);
            test_pending_bytes_.fetch_sub(written, std::memory_order_relaxed);
#endif
            std::lock_guard<std::mutex> lock(mutex_);
            if (file)
            {
                file->written_bytes += written;
                if (file->track_replay) {
                    try { file->written_ranges_.add(offset, offset + written); }
                    catch (...) { set_job_error_locked(file->job, E_OUTOFMEMORY, ERROR_OUTOFMEMORY); }
                }
            }
        }

        // Submit exactly one request. A successful submit (including TRUE)
        // is NOT a completed write: IOCP owns its memory until dequeued.
        AttemptResult attempt_data_write(const FileStatePtr &file,
                                         Buffer *buffer,
                                         bool &submitted) noexcept
        {
            std::lock_guard<std::mutex> io_lock(buffer->io_mutex);
            submitted = false;
            const auto job = file->job;
            const auto global_error = current_error(job);
            if (global_error != S_OK)
            {
                record_failure(file, global_error, current_win32_error(job));
                return {AttemptResult::Kind::Terminal, 0};
            }
            const auto opened = try_open_file(file);
            if (opened.kind != AttemptResult::Kind::Succeeded) return opened;
            if (!begin_data_write(file)) return {AttemptResult::Kind::Terminal, 0};
#ifdef SUP7Z_TEST_IO_FAULTS
            unsigned long injected = 0;
            if (write_fault_.consume(injected))
            {
                end_data_write(file);
                return classify_data_failure(file, injected);
            }
#endif
            const UInt64 offset = buffer->output_offset + buffer->transferred;
            buffer->request.overlapped = {};
            buffer->request.overlapped.Offset = static_cast<DWORD>(offset);
            buffer->request.overlapped.OffsetHigh = static_cast<DWORD>(offset >> 32U);
            DWORD size = buffer->size - buffer->transferred;
#ifdef SUP7Z_TEST_IO_FAULTS
            const auto chunk = max_write_chunk_.load(std::memory_order_relaxed);
            if (chunk && size > chunk) size = chunk;
#endif
#ifdef SUP7Z_DEBUG
            if (job->pipeline_timing) job->pipeline_timing->begin(PipelineStage::Output);
#endif
            const BOOL started = WriteFile(file->handle, buffer->data.get() + buffer->transferred,
                                           size, nullptr, &buffer->request.overlapped);
            const DWORD error = started ? ERROR_SUCCESS : GetLastError();
            if (!started && error != ERROR_IO_PENDING)
            {
#ifdef SUP7Z_DEBUG
                if (job->pipeline_timing) job->pipeline_timing->end(PipelineStage::Output);
#endif
#ifdef SUP7Z_TEST_IO_FAULTS
                end_data_write(file);
#endif
                return classify_data_failure(file, error);
            }
            submitted = true;
            return {};
        }

        bool is_output_space_failure(DWORD error) const noexcept
        {
#ifdef SUP7Z_TEST_IO_FAULTS
            if (failure_classifier_) return failure_classifier_(error);
#endif
            return is_space_exhaustion_error(error);
        }

        // 空间类错误必须走 SpaceFailure 交给骨架重试，绝不能在这里调用 record_failure
        // （那会把 pending 记成 discarded 并把 file/job 标记成永久失败）。
        AttemptResult classify_data_failure(const FileStatePtr &file, DWORD error) noexcept
        {
            if (is_output_space_failure(error))
            {
                return {AttemptResult::Kind::SpaceFailure, static_cast<unsigned long>(error)};
            }
            record_failure(file, HRESULT_FROM_WIN32(error), static_cast<int>(error));
            return {AttemptResult::Kind::PermanentFailure, static_cast<unsigned long>(error)};
        }

        bool flush_file(HANDLE handle, DWORD &error) noexcept
        {
#ifdef SUP7Z_TEST_IO_FAULTS
            if (flush_fault_.consume(error)) return false;
#endif
            if (FlushFileBuffers(handle)) return true;
            error = GetLastError();
            return false;
        }

        void process_close(const FileStatePtr &file, ProbeLease lease = {}) noexcept
        {
            if (!file)
            {
                return;
            }
            const auto job = file->job;
            const HRESULT global_error = current_error(job);
            if (global_error != S_OK)
            {
                record_failure(file, global_error, current_win32_error(job));
            }

            bool should_open = false;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                should_open = !file->failed && file->handle == INVALID_HANDLE_VALUE &&
                              !file->open_attempted && !(file->replay && file->replay->complete && !file->new_writes);
            }
            AttemptResult result;
            // This is a close-only open. The file has no outstanding data
            // and no future write can require a completion packet.
            if (should_open) result = try_open_file(file, false);
            HANDLE handle;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                handle = file->handle;
            }
            if (result.kind == AttemptResult::Kind::Succeeded && handle != INVALID_HANDLE_VALUE && write_through())
            {
                DWORD error = ERROR_SUCCESS;
                if (!flush_file(handle, error))
                {
                    result = {is_space_exhaustion_error(error) ? AttemptResult::Kind::SpaceFailure
                               : AttemptResult::Kind::PermanentFailure, error};
                }
            }
            const bool held_probe = lease.valid();
            // A terminal job cannot prove recovery even if its cleanup flush succeeds.
            if (current_error(job) != S_OK) result = {AttemptResult::Kind::Terminal, 0};
            settle_space_attempt(lease, result, file->path);
            if (result.kind == AttemptResult::Kind::SpaceFailure && file->space_gate)
            {
                auto item = WorkItem::close(file);
                item.retry_error = held_probe ? 0 : result.win32_error;
                defer_space_work(std::move(item));
                return;
            }
            if (result.kind == AttemptResult::Kind::SpaceFailure || result.kind == AttemptResult::Kind::PermanentFailure)
                record_failure(file, HRESULT_FROM_WIN32(result.win32_error), result.win32_error);
            bool restore_times = false;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                restore_times = !file->failed && result.kind == AttemptResult::Kind::Succeeded;
                file->handle = INVALID_HANDLE_VALUE;
            }
            ArchiveMetadataErrors metadata_errors;
            if (handle != INVALID_HANDLE_VALUE)
            {
                // All data writes have drained. Stream release can precede
                // SetOperationResult, so timestamp restoration must not depend on it.
                if (restore_times)
                {
                    metadata_errors = file->metadata.restore(handle);
                }
                FILETIME last_write{};
                if (GetFileTime(handle, nullptr, nullptr, &last_write))
                {
                    ULARGE_INTEGER ticks{};
                    ticks.LowPart = last_write.dwLowDateTime;
                    ticks.HighPart = last_write.dwHighDateTime;
                    constexpr UInt64 unix_epoch_100ns = 116444736000000000ULL;
                    if (ticks.QuadPart >= unix_epoch_100ns &&
                        ticks.QuadPart - unix_epoch_100ns <= (std::numeric_limits<UInt64>::max)() / 100ULL)
                    {
                        std::lock_guard<std::mutex> lock(mutex_);
                        file->mtime_ns = (ticks.QuadPart - unix_epoch_100ns) * 100ULL;
                        file->has_mtime_ns = true;
                    }
                }

                const BOOL closed = CloseHandle(handle);
                const DWORD close_error = closed ? ERROR_SUCCESS : GetLastError();
                if (!closed)
                {
                    const DWORD error = close_error;
                    record_failure(file, HRESULT_FROM_WIN32(error), static_cast<int>(error));
                }
            }
            {
                std::lock_guard<std::mutex> lock(mutex_);
                file->metadata_errors = metadata_errors;
                file->closed = true;
#ifdef SUP7Z_TEST_IO_FAULTS
                if (!file->failed)
                {
                    test_completed_files_.fetch_add(1, std::memory_order_relaxed);
                }
#endif
                if (job && job->pending_jobs != 0)
                {
                    --job->pending_jobs;
                }
                unregister_file_locked(file);
            }
            producer_cv_.notify_all();
        }

        void release_buffer(Buffer *buffer) noexcept
        {
            if (!buffer)
            {
                return;
            }
            const auto file = buffer->file;
            const auto job = file ? file->job : nullptr;
            bool direct_close = false;
            {

                std::lock_guard<std::mutex> lock(mutex_);

                if (file)
                {
                    file->inflight_bytes -= buffer->size;
                    if (file->outstanding_data != 0)
                    {
                        --file->outstanding_data;
                    }
                }
                if (job)
                {
                    job->inflight_bytes -= buffer->size;
                    if (job->pending_jobs != 0)
                    {
                        --job->pending_jobs;
                    }
                }
                buffer->file.reset();
                buffer->size = 0;
                free_buffers_.push_back(buffer);
                if (file && file->close_requested && file->outstanding_data == 0)
                {
                    enqueue_close_locked(file, &direct_close);
                }
            }
            if (direct_close)
            {
                process_close(file);
            }
            producer_cv_.notify_all();
        }

        void record_failure(
            const FileStatePtr &file,
            HRESULT hr,
            int win32_error) noexcept
        {
            {
                std::lock_guard<std::mutex> lock(mutex_);
                mark_file_failure_locked(file, hr, win32_error);
                if (file)
                {
                    set_job_error_locked(file->job, hr, win32_error);
                }
            }
            if (file && file->space_gate) file->space_gate->wake_waiters();
            producer_cv_.notify_all();
        }

        static void mark_file_failure_locked(const FileStatePtr &file, HRESULT hr, int win32_error) noexcept
        {
            if (!file || file->failed)
            {
                return;
            }
            file->failed = true;
            file->hresult = hr;
            file->win32_error = win32_error;
        }

        std::vector<std::unique_ptr<Buffer>> buffers_;
        // Every entry belongs to buffers_; returning one must never allocate.
        std::vector<Buffer *> free_buffers_;
        std::vector<std::thread> workers_;
        std::deque<WorkItem> work_queue_;
        std::vector<std::weak_ptr<JobState>> active_jobs_;
        std::vector<FileStatePtr> active_files_;
        mutable std::mutex mutex_;
        std::condition_variable producer_cv_;
        HANDLE completion_port_ = nullptr;
        std::mutex finish_mutex_;
        std::deque<WorkItem> retry_queue_;
        std::shared_ptr<CompletionWake> space_wake_;
        const VolumeStatePtr state_;
        const AsyncWriterConfig config_;
        const std::size_t writer_count_;
        const std::size_t buffer_count_;
        const std::size_t queue_limit_;
        std::size_t queued_jobs_ = 0;
        // 必须是 atomic：gate 的 terminal predicate 会无锁读它。
        std::atomic<bool> stopping_{false};

#ifdef SUP7Z_TEST_IO_FAULTS
        std::atomic<std::uint64_t> test_accepted_bytes_{0};
        std::atomic<std::uint64_t> test_written_bytes_{0};
        std::atomic<std::uint64_t> test_discarded_bytes_{0};
        std::atomic<std::uint64_t> test_pending_bytes_{0};
        std::atomic<std::uint64_t> test_completed_files_{0};
        std::atomic<std::uint64_t> test_completed_jobs_{0};

    public:
        // 测试专用：
        //   A：failure_classifier 可注入，用真实的其他错误码驱动空间失败路径。
        //   B：CreateFileW 调用探针，每个 FileState 的 CreateFileW 调用次数必须恒为 1。
        //   D：WriteFile / FlushFileBuffers 故障注入。
        using FailureClassifier = std::function<bool(unsigned long win32_error)>;
        using OpenProbe = std::function<void(const std::wstring &path)>;

        void set_failure_classifier_for_test(FailureClassifier classifier) noexcept
        {
            failure_classifier_ = std::move(classifier);
        }

        void set_open_probe_for_test(OpenProbe probe) noexcept { open_probe_ = std::move(probe); }

        // WriteFile 故障注入，在调用真实 WriteFile 之前生效。
        // 放过 skip 次调用后，连续 faults 次以 win32_error 失败，之后恢复。
        void set_write_fault_for_test(unsigned long win32_error, int faults, int skip = 0) noexcept
        {
            write_fault_.set(win32_error, faults, skip);
        }

        // FlushFileBuffers 故障注入，同样在真实调用之前生效。
        void set_flush_fault_for_test(unsigned long win32_error, int faults, int skip = 0) noexcept
        {
            flush_fault_.set(win32_error, faults, skip);
        }

        // 限制单次 WriteFile 的最大字节数（0 = 不限制），强制制造 partial write，
        // 否则 transferred 跨 retry 的语义无法被测试。
        void set_max_write_chunk_for_test(UInt32 bytes) noexcept
        {
            max_write_chunk_.store(bytes, std::memory_order_relaxed);
        }

    private:
        FailureClassifier failure_classifier_;
        OpenProbe open_probe_;
        std::atomic<UInt32> max_write_chunk_{0};

        struct InjectedFault
        {
            std::atomic<unsigned long> error{0};
            std::atomic<int> remaining{0};
            std::atomic<int> skip{0};

            void set(unsigned long win32_error, int faults, int skip_count) noexcept
            {
                error.store(win32_error, std::memory_order_relaxed);
                remaining.store(faults, std::memory_order_relaxed);
                skip.store(skip_count, std::memory_order_relaxed);
            }

            // 返回 true 表示本次系统调用被注入的故障取代。
            bool consume(unsigned long &win32_error) noexcept
            {
                if (remaining.load(std::memory_order_relaxed) <= 0)
                {
                    return false;
                }
                int pending_skip = skip.load(std::memory_order_relaxed);
                while (pending_skip > 0)
                {
                    if (skip.compare_exchange_weak(pending_skip, pending_skip - 1,
                                                   std::memory_order_relaxed))
                    {
                        return false;
                    }
                }
                int pending = remaining.load(std::memory_order_relaxed);
                do
                {
                    if (pending <= 0) return false;
                } while (!remaining.compare_exchange_weak(pending, pending - 1,
                                                           std::memory_order_relaxed));
                win32_error = error.load(std::memory_order_relaxed);
                return true;
            }
        } write_fault_, flush_fault_;
#endif
    };

}

#endif
