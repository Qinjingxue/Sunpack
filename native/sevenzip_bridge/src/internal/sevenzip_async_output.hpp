#pragma once

#include "sevenzip_paths.hpp"
#include "sevenzip_space_retry.hpp"
#include "sevenzip_volume_state.hpp"
#include "sevenzip_writer_meters.hpp"
#include "sevenzip_writer_probe.hpp"
#ifdef SUP7Z_ENABLE_PIPELINE_TIMING
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

    class AsyncFileWriter final
    {
    public:
        struct JobState
        {
            explicit JobState(
                std::size_t budget,
                std::shared_ptr<std::atomic<bool>> external_cancel = nullptr
#ifdef SUP7Z_ENABLE_PIPELINE_TIMING
                , PipelineTiming *pipeline_timing = nullptr
#endif
                )
                : max_inflight_bytes(budget),
                  cancel_token(std::move(external_cancel))
#ifdef SUP7Z_ENABLE_PIPELINE_TIMING
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
#ifdef SUP7Z_ENABLE_PIPELINE_TIMING
            PipelineTiming *pipeline_timing = nullptr;
#endif
#ifdef SUP7Z_ENABLE_WRITER_PROBE
            WriterProbe probe;
#endif
        };

        using JobStatePtr = std::shared_ptr<JobState>;

        struct Buffer;
        struct FileState;
        using FileStatePtr = std::shared_ptr<FileState>;

        struct FileSnapshot
        {
            UInt64 accepted_bytes = 0;
            UInt64 written_bytes = 0;
            Int32 operation_result = 0;
            HRESULT hresult = S_OK;
            int win32_error = 0;
            bool operation_result_set = false;
            bool has_mtime_ns = false;
            UInt64 mtime_ns = 0;
            std::vector<unsigned char> magic;
            bool failed = false;
            bool closed = false;
            std::size_t peak_active_data_writes = 0;
        };

        struct Metrics
        {
            std::uint64_t accepted_bytes = 0;
            std::uint64_t written_bytes = 0;
            std::uint64_t discarded_bytes = 0;
            std::uint64_t pending_bytes = 0;
            std::uint64_t completed_files = 0;
            std::uint64_t completed_jobs = 0;
        };

        WriterMeterSnapshot snapshot_global_meters() const noexcept
        {
            return snapshot_counters(meters_->counters);
        }

        WriterMeterSnapshot snapshot_volume_meters() const noexcept
        {
            return state_ ? snapshot_counters(state_->counters) : WriterMeterSnapshot{};
        }

        const AsyncWriterConfig &config() const noexcept { return config_; }

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
                std::size_t trace)
                : item_path(std::move(archive_path)),
                  item_index(archive_index),
                  trace_index(trace),
                  job(std::move(state)),
                  path(std::move(file_path)) {}

            const std::wstring item_path;
            const UInt32 item_index = 0;
            const std::size_t trace_index = 0;

            // 本文件所属卷的空间 gate，可能为 nullptr（功能关闭 / 无卷身份）。
            // 在 make_file() 时快照进来，writer 线程不再取 state_。
            VolumeSpaceGate *volume_space_gate() const noexcept { return space_gate.get(); }

        private:
            friend class AsyncFileWriter;

            JobStatePtr job;
            std::wstring path;
            std::shared_ptr<VolumeSpaceGate> space_gate;
            std::atomic<UInt64> accepted_bytes{0};
            std::atomic<UInt64> next_write_offset{0};
            std::mutex producer_mutex;
            Buffer *staging_buffer = nullptr;
            std::size_t inflight_bytes = 0;
            std::size_t outstanding_data = 0;
            std::size_t active_data_writes = 0;
            std::size_t peak_active_data_writes = 0;
            UInt64 written_bytes = 0;
            Int32 operation_result = 0;
            HRESULT hresult = S_OK;
            int win32_error = 0;
            bool operation_result_set = false;
            bool has_mtime_ns = false;
            UInt64 mtime_ns = 0;
            std::vector<unsigned char> magic;
            bool failed = false;
            bool closed = false;
            bool close_requested = false;
            bool close_enqueued = false;
            bool inflight_released = false;
            HANDLE handle = INVALID_HANDLE_VALUE;
            bool open_attempted = false;
#ifdef SUP7Z_ENABLE_WRITER_PROBE
            UInt64 probe_expected_size = 0;
#endif
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

            std::unique_ptr<unsigned char[]> data;
            IoRequest request;
            // Completion can be dequeued before WriteFile returns. Serialize
            // that handoff, including synchronous success, before recycling.
            std::mutex io_mutex;
            UInt64 output_offset = 0;
            UInt32 transferred = 0;
            ProbeLease probe_lease;
            FileStatePtr file;
            UInt32 size = 0;
#ifdef SUP7Z_ENABLE_WRITER_PROBE
            unsigned long long probe_queued_at = 0;
#endif
        };

        static constexpr std::size_t kBufferSize = 1U << 20;
        static constexpr std::size_t kDefaultWriterCount = 4;
        static constexpr std::size_t kMaxWriterCount = 8;
        static constexpr std::size_t kDefaultJobInFlightBytes = 32U << 20;
        static constexpr std::size_t kDefaultFileInFlightBytes = 8U << 20;

        AsyncFileWriter(
            std::shared_ptr<WriterMeters> meters,
            VolumeStatePtr state,
            AsyncWriterConfig config = {})
            : meters_(meters ? std::move(meters) : std::make_shared<WriterMeters>()),
              state_(state ? std::move(state) : make_volume_state(std::string{}, false)),
              config_(config),
              writer_count_((std::max)(std::size_t{1}, config.threads_per_volume)),
              buffer_count_((std::max)(std::size_t{4}, config.buffer_count)),
              queue_limit_((std::max)(std::size_t{1}, config.queue_limit))
        {
            initialize();
        }

        AsyncFileWriter()
            : AsyncFileWriter(
                  std::make_shared<WriterMeters>(),
                  make_volume_state(std::string{}, false),
                  configured_async_writer_config()) {}

        ~AsyncFileWriter() { finish(); }

        AsyncFileWriter(const AsyncFileWriter &) = delete;
        AsyncFileWriter &operator=(const AsyncFileWriter &) = delete;

        JobStatePtr make_job(
            std::size_t max_inflight_bytes = 0,
            std::shared_ptr<std::atomic<bool>> cancel_token = nullptr
#ifdef SUP7Z_ENABLE_PIPELINE_TIMING
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
#ifdef SUP7Z_ENABLE_PIPELINE_TIMING
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
            std::size_t trace_index
#ifdef SUP7Z_ENABLE_WRITER_PROBE
            , UInt64 expected_size = 0
#endif
            )
        {
            auto file = std::make_shared<FileState>(
                job ? job : make_job(),
                std::move(path), std::move(item_path), item_index, trace_index);
            std::lock_guard<std::mutex> lock(mutex_);
#ifdef SUP7Z_ENABLE_WRITER_PROBE
            file->probe_expected_size = expected_size;
#endif
            // 快照本卷的空间 gate；功能关闭 / 空 key 时为 nullptr。
            file->space_gate = state_ ? state_->space_gate : nullptr;
            active_files_.push_back(file);
            ++inflight_file_count_;
            if (active_files_.size() >= 1024 &&
                active_files_.size() > inflight_file_count_ * 2 + 256)
            {
                prune_expired_files_locked();
            }
            return file;
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

#ifdef SUP7Z_ENABLE_WRITER_PROBE
                WriterProbeSpan probe_producer(job->probe, WriterProbePhase::Producer);
#endif

#ifdef SUP7Z_ENABLE_WRITER_PROBE
                WriterProbeSpan probe_filelock(job->probe, WriterProbePhase::FileLock);
#endif
            std::unique_lock<std::mutex> producer_lock(file->producer_mutex);
#ifdef SUP7Z_ENABLE_WRITER_PROBE
                probe_filelock.finish();
#endif

            while (consumed < size)
            {
                bool queued_staging = false;
                bool newly_acquired_staging = false;
                UInt32 previous_size = 0;
                UInt32 chunk = 0;
                HRESULT setup_error = S_OK;
                {

#ifdef SUP7Z_ENABLE_WRITER_PROBE
                WriterProbeSpan probe_setup(job->probe, WriterProbePhase::SetupLock);
#endif
                    std::unique_lock<std::mutex> lock(mutex_);
#ifdef SUP7Z_ENABLE_WRITER_PROBE
                probe_setup.finish();
#endif

#ifdef SUP7Z_ENABLE_WRITER_PROBE
                    if (!can_accept_locked(job, file)) {
                        if (file->inflight_bytes >= kDefaultFileInFlightBytes) job->probe.file_full++;
                        if (job->inflight_bytes >= job->max_inflight_bytes) job->probe.job_full++;
                        if (free_buffers_.empty()) job->probe.buffers_empty++;
                    }
#endif

#ifdef SUP7Z_ENABLE_WRITER_PROBE
                WriterProbeSpan probe_capacity(job->probe, WriterProbePhase::CapacityWait);
#endif
                    producer_cv_.wait(lock, [this, &job, &file]
                                      { return terminal_result_locked(job) != S_OK || file->close_requested ||
                                               can_accept_locked(job, file); });
#ifdef SUP7Z_ENABLE_WRITER_PROBE
                probe_capacity.finish();
#endif

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
                    if (!buffer)
                    {
                        if (free_buffers_.empty())
                        {
                            continue;
                        }

                        buffer = free_buffers_.back();
                        free_buffers_.pop_back();
                        try
                        {
                            if (!buffer->data)
                            {
                                buffer->data = std::make_unique<unsigned char[]>(kBufferSize);
                            }
                            buffer->file = file;
                            buffer->size = 0;
                            file->staging_buffer = buffer;
                            newly_acquired_staging = true;
                        }
                        catch (...)
                        {
                            free_buffers_.push_back(buffer);
                            mark_file_failure_locked(file, E_OUTOFMEMORY, ERROR_OUTOFMEMORY);
                            set_job_error_locked(job, E_OUTOFMEMORY, ERROR_OUTOFMEMORY);
                            setup_error = E_OUTOFMEMORY;
                        }
                    }
                    if (setup_error != S_OK)
                    {
                    }
                    else
                    {
                        previous_size = buffer->size;
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
                        if (chunk_size == 0)
                        {
                            if (newly_acquired_staging)
                            {
                                file->staging_buffer = nullptr;
                                buffer->file.reset();
                                free_buffers_.push_back(buffer);
                            }
                            continue;
                        }
                        chunk = static_cast<UInt32>(chunk_size);
                        job->inflight_bytes += chunk_size;
                        file->inflight_bytes += chunk_size;
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


#ifdef SUP7Z_ENABLE_WRITER_PROBE
                WriterProbeSpan probe_copy(job->probe, WriterProbePhase::Copy);
#endif
#ifdef SUP7Z_ENABLE_WRITER_PROBE
                if (std::strcmp(writer_probe_mode(), "memory-nocopy") != 0)
#endif
                std::memcpy(
                    file->staging_buffer->data.get() + previous_size,
                    source + consumed,
                    chunk);
#ifdef SUP7Z_ENABLE_WRITER_PROBE
                probe_copy.finish();
#endif

                HRESULT enqueue_result = S_OK;
                {

#ifdef SUP7Z_ENABLE_WRITER_PROBE
                WriterProbeSpan probe_commit(job->probe, WriterProbePhase::CommitLock);
#endif
                    std::unique_lock<std::mutex> lock(mutex_);
#ifdef SUP7Z_ENABLE_WRITER_PROBE
                probe_commit.finish();
#endif
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
                        account_accepted(chunk);
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

#ifdef SUP7Z_ENABLE_WRITER_PROBE
                WriterProbeSpan probe_finishlock(job->probe, WriterProbePhase::FinishLock);
#endif
            std::unique_lock<std::mutex> lock(mutex_);
#ifdef SUP7Z_ENABLE_WRITER_PROBE
                probe_finishlock.finish();
#endif

#ifdef SUP7Z_ENABLE_WRITER_PROBE
                WriterProbeSpan probe_finishwait(job->probe, WriterProbePhase::FinishWait);
#endif
            producer_cv_.wait(lock, [&job]
                              { return job->pending_jobs == 0; });
#ifdef SUP7Z_ENABLE_WRITER_PROBE
                probe_finishwait.finish();
#endif

            const HRESULT result = terminal_result_locked(job);
            unregister_job_locked(job);
            prune_expired_files_locked();
            if (result == S_OK)
            {
                meters_->counters.completed_jobs.fetch_add(1, std::memory_order_relaxed);
                state_->counters.completed_jobs.fetch_add(1, std::memory_order_relaxed);
            }
#ifdef SUP7Z_ENABLE_WRITER_PROBE
            lock.unlock();
            job->probe.dump();
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

        Metrics snapshot_metrics() const noexcept
        {
            const auto meters = snapshot_counters(meters_->counters);
            return Metrics{
                meters.accepted_bytes,
                meters.written_bytes,
                meters.discarded_bytes,
                meters.pending_bytes,
                meters.completed_files,
                meters.completed_jobs,
            };
        }

        bool is_quiescent() const noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (queued_jobs_ != 0 || inflight_file_count_ != 0)
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
            snapshot.accepted_bytes = file->accepted_bytes.load(std::memory_order_relaxed);
            snapshot.written_bytes = file->written_bytes;
            snapshot.operation_result = file->operation_result;
            snapshot.hresult = file->hresult;
            snapshot.win32_error = file->win32_error;
            snapshot.operation_result_set = file->operation_result_set;
            snapshot.has_mtime_ns = file->has_mtime_ns;
            snapshot.mtime_ns = file->mtime_ns;
            snapshot.magic = file->magic;
            snapshot.failed = file->failed;
            snapshot.closed = file->closed;
            snapshot.peak_active_data_writes = file->peak_active_data_writes;
            return snapshot;
        }

        void finish() noexcept
        {
            std::lock_guard<std::mutex> finish_lock(finish_mutex_);
            if (!completion_port_) return;
            std::vector<JobStatePtr> jobs;
            std::vector<FileStatePtr> files;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                stopping_.store(true, std::memory_order_release);
                for (const auto &weak : active_jobs_)
                    if (auto job = weak.lock()) { cancel_job_locked(job); jobs.push_back(job); }
                for (const auto &weak : active_files_)
                    if (auto file = weak.lock()) files.push_back(file);
            }
            producer_cv_.notify_all();
            if (state_->space_gate) state_->space_gate->wake_waiters();
            for (const auto &job : jobs) seal_job_files(job);
            for (const auto &file : files) close_file(file, {});
            if (state_ && state_->space_gate) state_->space_gate->wake_waiters();
            producer_cv_.notify_all();
            drain_cancelled_retries();
            {
                std::unique_lock<std::mutex> lock(mutex_);
                producer_cv_.wait(lock, [this] { return queued_jobs_ == 0 && inflight_file_count_ == 0; });
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
        void prune_expired_files_locked() noexcept
        {
            active_files_.erase(
                std::remove_if(
                    active_files_.begin(),
                    active_files_.end(),
                    [](const auto &file) { return file.expired(); }),
                active_files_.end());
        }

        void initialize()
        {
            buffers_.reserve(buffer_count_);
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

        void account_accepted(std::size_t bytes) noexcept
        {
            const std::uint64_t value = static_cast<std::uint64_t>(bytes);
            meters_->counters.accepted_bytes.fetch_add(value, std::memory_order_relaxed);
            meters_->counters.pending_bytes.fetch_add(value, std::memory_order_relaxed);
            state_->counters.accepted_bytes.fetch_add(value, std::memory_order_relaxed);
            state_->counters.pending_bytes.fetch_add(value, std::memory_order_relaxed);
        }

        void account_written(std::size_t bytes) noexcept
        {
            const std::uint64_t value = static_cast<std::uint64_t>(bytes);
            meters_->counters.written_bytes.fetch_add(value, std::memory_order_relaxed);
            state_->counters.written_bytes.fetch_add(value, std::memory_order_relaxed);
            account_pending_release(bytes);
        }

        void account_discarded(std::size_t bytes) noexcept
        {
            if (bytes == 0)
            {
                return;
            }
            const std::uint64_t value = static_cast<std::uint64_t>(bytes);
            meters_->counters.discarded_bytes.fetch_add(value, std::memory_order_relaxed);
            state_->counters.discarded_bytes.fetch_add(value, std::memory_order_relaxed);
            account_pending_release(bytes);
        }

        void account_pending_release(std::size_t bytes) noexcept
        {
            release_pending(meters_->counters.pending_bytes, *state_, bytes);
            release_pending(state_->counters.pending_bytes, *state_, bytes);
        }

        static void release_pending(
            std::atomic<std::uint64_t> &pending,
            VolumeState &volume,
            std::size_t bytes) noexcept
        {
            const std::uint64_t value = static_cast<std::uint64_t>(bytes);
#ifndef NDEBUG
            const std::uint64_t previous = pending.fetch_sub(value, std::memory_order_relaxed);
            assert(previous >= value && "pending gauge over-released: a byte was accounted twice");
#else
            std::uint64_t current = pending.load(std::memory_order_relaxed);
            for (;;)
            {
                if (current < value)
                {
                    volume.accounting_violations.fetch_add(1, std::memory_order_relaxed);
                }
                const std::uint64_t next = current > value ? current - value : 0;
                if (pending.compare_exchange_weak(
                        current, next, std::memory_order_relaxed, std::memory_order_relaxed))
                {
                    return;
                }
            }
#endif
        }

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
            if (!job)
            {
                return;
            }
            std::vector<FileStatePtr> files;
            try
            {
                std::lock_guard<std::mutex> lock(mutex_);
                for (auto it = active_files_.begin(); it != active_files_.end();)
                {
                    if (const auto file = it->lock())
                    {
                        if (file->job.get() == job.get() && !file->close_requested)
                        {
                            files.push_back(file);
                        }
                        ++it;
                    }
                    else
                    {
                        it = active_files_.erase(it);
                    }
                }
            }
            catch (...)
            {
                return;
            }

            for (const auto &file : files)
            {
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
                account_discarded(buffer->size);
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
#ifdef SUP7Z_ENABLE_WRITER_PROBE
                buffer->probe_queued_at = file->job->probe.enabled ? writer_probe_clock() : 0;
                if (buffer->probe_queued_at)
                {
                    file->job->probe.begin_inflight();
                    file->job->probe.observe_queue_depth(queued_jobs_ + 1);
                }
#endif
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
                {
                    std::lock_guard<std::mutex> lock(mutex_);
                    if (work_queue_.empty()) continue;
                    item = std::move(work_queue_.front());
                    work_queue_.pop_front();
                    --queued_jobs_;
                }
                producer_cv_.notify_all();
                if (item.kind == WorkItem::Kind::Close)
                {
                    process_close(item.file);
                    continue;
                }
                Buffer *buffer = item.buffer;
                const auto file = buffer->file;
#ifdef SUP7Z_ENABLE_WRITER_PROBE
                if (file && file->job->probe.enabled && buffer->probe_queued_at)
                    file->job->probe.add(WriterProbePhase::Queue, writer_probe_clock() - buffer->probe_queued_at);
#endif
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
            if (result.kind != AttemptResult::Kind::Succeeded && buffer->size > buffer->transferred)
                account_discarded(buffer->size - buffer->transferred);
            release_buffer(buffer);
        }

        void complete_data_write(Buffer *buffer, DWORD bytes, DWORD error) noexcept
        {
            AttemptResult result;
            {
                std::lock_guard<std::mutex> io_lock(buffer->io_mutex);
                const auto file = buffer->file;
#ifdef SUP7Z_ENABLE_PIPELINE_TIMING
                if (file && file->job->pipeline_timing)
                    file->job->pipeline_timing->end(PipelineStage::Output);
#endif
                end_data_write(file);
                if (error != ERROR_SUCCESS)
                    result = classify_data_failure(file, error);
                else if (bytes == 0 || bytes > buffer->size - buffer->transferred)
                {
                    record_failure(file, HRESULT_FROM_WIN32(ERROR_WRITE_FAULT), ERROR_WRITE_FAULT, 0);
                    result = {AttemptResult::Kind::PermanentFailure, ERROR_WRITE_FAULT};
                }
                else
                {
                    buffer->transferred += bytes;
                    add_written_bytes(file, bytes);
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

        // 一次 CreateFileW 尝试：在 writer mutex_ 内且只做一次，绝不等待。
        // 同一 FileState 的多个 Data WorkItem 会被多个 writer 线程并发处理，去锁后
        // 两个线程可能同时 CreateFileW(CREATE_NEW)，后者得到 ERROR_FILE_EXISTS 而把 job 标成永久失败；
        // 空间失败由调用方排入 IOCP 恢复队列，绝不在这里等待。
        // open_attempted 的语义是"已建立 handle 或已永久失败"，空间错误不置位。
        // 空间错误无需清理残留：0 字节可用时 CreateFileW(CREATE_NEW) 仍成功，
        // 错误实际发生在随后的 WriteFile，因此整个 FileState 生命周期内只调用一次 CreateFileW。
        AttemptResult try_open_file_locked(const FileStatePtr &file) noexcept
        {

#ifdef SUP7Z_ENABLE_WRITER_PROBE
                WriterProbeSpan probe_openlock(file ? &file->job->probe : nullptr, WriterProbePhase::OpenLock);
#endif
            std::lock_guard<std::mutex> lock(mutex_);

#ifdef SUP7Z_ENABLE_WRITER_PROBE
                probe_openlock.finish();
#endif
            if (!file || file->failed)
            {
                return {AttemptResult::Kind::PermanentFailure, ERROR_INVALID_STATE};
            }
            if (file->handle != INVALID_HANDLE_VALUE)
            {
                return {AttemptResult::Kind::Succeeded, 0}; // 已被本卷其他 writer 线程打开
            }
            if (file->open_attempted)
            {
                // 已尝试过且未成功，不再尝试。
                return {AttemptResult::Kind::PermanentFailure, ERROR_OPEN_FAILED};
            }

            DWORD creation_flags = FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED;
            if (write_through())
            {
                creation_flags |= FILE_FLAG_WRITE_THROUGH;
            }
            // 整个 FileState 生命周期内 CreateFileW 只应被调用一次。
            if (open_probe_)
            {
                open_probe_(file->path);
            }

#ifdef SUP7Z_ENABLE_WRITER_PROBE
                WriterProbeSpan probe_open(file->job->probe, WriterProbePhase::Open);
#endif
            const HANDLE handle = CreateFileW(
                win32_extended_path(file->path).c_str(),
                GENERIC_WRITE,
                0,
                nullptr,
                CREATE_NEW,
                creation_flags,
                nullptr);
            const DWORD open_error = handle == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
#ifdef SUP7Z_ENABLE_WRITER_PROBE
                probe_open.finish();
#endif
            if (handle == INVALID_HANDLE_VALUE)
            {
                const DWORD error = open_error;
                if (failure_classifier_(static_cast<unsigned long>(error)))
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
#ifdef SUP7Z_ENABLE_WRITER_PROBE
            if (file->probe_expected_size && std::strcmp(writer_probe_mode(), "eof") == 0) {
                WriterProbeSpan preallocate(file->job->probe, WriterProbePhase::Preallocate);
                FILE_END_OF_FILE_INFO info{};
                info.EndOfFile.QuadPart = file->probe_expected_size;
                if (!SetFileInformationByHandle(handle, FileEndOfFileInfo, &info, sizeof(info))) {
                    const DWORD error = GetLastError();
                    CloseHandle(handle);
                    return {AttemptResult::Kind::PermanentFailure, error};
                }
            }
#endif
            if (!CreateIoCompletionPort(handle, completion_port_, 0, static_cast<DWORD>(writer_count_)))
            {
                const DWORD error = GetLastError();
                CloseHandle(handle);
                file->open_attempted = true;
                mark_file_failure_locked(file, HRESULT_FROM_WIN32(error), error);
                set_job_error_locked(file->job, HRESULT_FROM_WIN32(error), error);
                return {AttemptResult::Kind::PermanentFailure, error};
            }
            file->handle = handle;
            file->open_attempted = true;
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
            ++file->active_data_writes;
            file->peak_active_data_writes = (std::max)(file->peak_active_data_writes, file->active_data_writes);
            return true;
        }

        void end_data_write(const FileStatePtr &file) noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (file && file->active_data_writes != 0)
            {
                --file->active_data_writes;
            }
        }

        void add_written_bytes(const FileStatePtr &file, DWORD written) noexcept
        {
            account_written(written);
            std::lock_guard<std::mutex> lock(mutex_);
            if (file)
            {
                file->written_bytes += written;
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
#ifdef SUP7Z_ENABLE_WRITER_PROBE
            WriterProbeSpan probe_dispatch(job->probe, WriterProbePhase::Dispatch);
#endif
            const auto global_error = current_error(job);
            if (global_error != S_OK)
            {
                record_failure(file, global_error, current_win32_error(job));
                return {AttemptResult::Kind::Terminal, 0};
            }
#ifdef SUP7Z_ENABLE_WRITER_PROBE
            if (writer_probe_memory())
            {
                add_written_bytes(file, buffer->size - buffer->transferred);
                buffer->transferred = buffer->size;
                return {};
            }
#endif
            const auto opened = try_open_file_locked(file);
            if (opened.kind != AttemptResult::Kind::Succeeded) return opened;
            if (!begin_data_write(file)) return {AttemptResult::Kind::Terminal, 0};
            unsigned long injected = 0;
            if (consume_injected_write_fault(&injected))
            {
                end_data_write(file);
                return classify_data_failure(file, injected);
            }
            const UInt64 offset = buffer->output_offset + buffer->transferred;
            buffer->request.overlapped = {};
            buffer->request.overlapped.Offset = static_cast<DWORD>(offset);
            buffer->request.overlapped.OffsetHigh = static_cast<DWORD>(offset >> 32U);
            DWORD size = buffer->size - buffer->transferred;
            const auto chunk = max_write_chunk_.load(std::memory_order_relaxed);
            if (chunk && size > chunk) size = chunk;
#ifdef SUP7Z_ENABLE_PIPELINE_TIMING
            if (job->pipeline_timing) job->pipeline_timing->begin(PipelineStage::Output);
#endif
#ifdef SUP7Z_ENABLE_WRITER_PROBE
            WriterProbeSpan probe_writefile(job->probe, WriterProbePhase::WriteFile);
#endif
            const BOOL started = WriteFile(file->handle, buffer->data.get() + buffer->transferred,
                                           size, nullptr, &buffer->request.overlapped);
            const DWORD error = started ? ERROR_SUCCESS : GetLastError();
            if (!started && error != ERROR_IO_PENDING)
            {
#ifdef SUP7Z_ENABLE_PIPELINE_TIMING
                if (job->pipeline_timing) job->pipeline_timing->end(PipelineStage::Output);
#endif
                end_data_write(file);
                return classify_data_failure(file, error);
            }
            submitted = true;
            return {};
        }

        // 空间类错误必须走 SpaceFailure 交给骨架重试，绝不能在这里调用 record_failure
        // （那会把 pending 记成 discarded 并把 file/job 标记成永久失败）。
        AttemptResult classify_data_failure(const FileStatePtr &file, DWORD error) noexcept
        {
            if (failure_classifier_(static_cast<unsigned long>(error)))
            {
                return {AttemptResult::Kind::SpaceFailure, static_cast<unsigned long>(error)};
            }
            record_failure(file, HRESULT_FROM_WIN32(error), static_cast<int>(error), 0);
            return {AttemptResult::Kind::PermanentFailure, static_cast<unsigned long>(error)};
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
                              !file->open_attempted;
#ifdef SUP7Z_ENABLE_WRITER_PROBE
                if (writer_probe_memory()) should_open = false;
#endif
            }
            AttemptResult result;
            if (should_open) result = try_open_file_locked(file);
            HANDLE handle;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                handle = file->handle;
            }
            if (result.kind == AttemptResult::Kind::Succeeded && handle != INVALID_HANDLE_VALUE && write_through())
            {
                unsigned long injected = 0;
                const bool fault = consume_injected_flush_fault(&injected);
                if (fault || !FlushFileBuffers(handle))
                {
                    const DWORD error = fault ? injected : GetLastError();
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
            {
                std::lock_guard<std::mutex> lock(mutex_);
                file->handle = INVALID_HANDLE_VALUE;
            }
            if (handle != INVALID_HANDLE_VALUE)
            {
                FILETIME last_write{};
                if (GetFileTime(handle, nullptr, nullptr, &last_write))
                {
                    ULARGE_INTEGER ticks{};
                    ticks.LowPart = last_write.dwLowDateTime;
                    ticks.HighPart = last_write.dwHighDateTime;
                    constexpr UInt64 unix_epoch_100ns = 116444736000000000ULL;
                    if (ticks.QuadPart >= unix_epoch_100ns)
                    {
                        std::lock_guard<std::mutex> lock(mutex_);
                        file->mtime_ns = (ticks.QuadPart - unix_epoch_100ns) * 100ULL;
                        file->has_mtime_ns = true;
                    }
                }

#ifdef SUP7Z_ENABLE_WRITER_PROBE
                WriterProbeSpan probe_close(job->probe, WriterProbePhase::Close);
#endif
                const BOOL closed = CloseHandle(handle);
                const DWORD close_error = closed ? ERROR_SUCCESS : GetLastError();
#ifdef SUP7Z_ENABLE_WRITER_PROBE
                probe_close.finish();
#endif
                if (!closed)
                {
                    const DWORD error = close_error;
                    record_failure(file, HRESULT_FROM_WIN32(error), static_cast<int>(error));
                }
            }
            bool completed_successfully = false;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                file->closed = true;
                completed_successfully = !file->failed;
                if (job && job->pending_jobs != 0)
                {
                    --job->pending_jobs;
                }
                if (!file->inflight_released)
                {
                    file->inflight_released = true;
                    if (inflight_file_count_ != 0)
                    {
                        --inflight_file_count_;
                    }
                }
            }
            if (completed_successfully)
            {
                meters_->counters.completed_files.fetch_add(1, std::memory_order_relaxed);
                state_->counters.completed_files.fetch_add(1, std::memory_order_relaxed);
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
#ifdef SUP7Z_ENABLE_WRITER_PROBE
            if (job && buffer->probe_queued_at)
            {
                job->probe.end_inflight(buffer->probe_queued_at);
                buffer->probe_queued_at = 0;
            }
#endif
            bool direct_close = false;
            {

#ifdef SUP7Z_ENABLE_WRITER_PROBE
                WriterProbeSpan probe_release(job ? &job->probe : nullptr, WriterProbePhase::ReleaseLock);
#endif
                std::lock_guard<std::mutex> lock(mutex_);

#ifdef SUP7Z_ENABLE_WRITER_PROBE
                probe_release.finish();
#endif
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
            int win32_error,
            std::size_t discarded_bytes = 0) noexcept
        {
            // discarded_bytes 是调用方持有的剩余字节；空间/终态路径一律传 0 ——
            // 已 dequeue 的 buffer 剩余字节只由 writer_loop 收尾负责，
            // staging 中的 buffer 由 discard_staging_locked() 负责，两者不重叠。
            account_discarded(discarded_bytes);
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
        std::deque<Buffer *> free_buffers_;
        std::vector<std::thread> workers_;
        std::deque<WorkItem> work_queue_;
        std::vector<std::weak_ptr<JobState>> active_jobs_;
        std::vector<std::weak_ptr<FileState>> active_files_;
        mutable std::mutex mutex_;
        std::condition_variable producer_cv_;
        HANDLE completion_port_ = nullptr;
        std::mutex finish_mutex_;
        std::deque<WorkItem> retry_queue_;
        std::shared_ptr<CompletionWake> space_wake_;
        const std::shared_ptr<WriterMeters> meters_;
        const VolumeStatePtr state_;
        const AsyncWriterConfig config_;
        const std::size_t writer_count_;
        const std::size_t buffer_count_;
        const std::size_t queue_limit_;
        std::size_t inflight_file_count_ = 0;
        std::size_t queued_jobs_ = 0;
        // 必须是 atomic：gate 的 terminal predicate 会无锁读它。
        std::atomic<bool> stopping_{false};

    public:
        // 测试专用，生产代码永不设置：
        //   A：failure_classifier 可注入，用真实的其他错误码驱动空间失败路径。
        //   B：CreateFileW 调用探针，每个 FileState 的 CreateFileW 调用次数必须恒为 1。
        //   D：WriteFile / FlushFileBuffers 故障注入。
        using FailureClassifier = std::function<bool(unsigned long win32_error)>;
        using OpenProbe = std::function<void(const std::wstring &path)>;

        void set_failure_classifier_for_test(FailureClassifier classifier) noexcept
        {
            failure_classifier_ = classifier ? std::move(classifier) : default_failure_classifier();
        }

        void set_open_probe_for_test(OpenProbe probe) noexcept { open_probe_ = std::move(probe); }

        // WriteFile 故障注入，在调用真实 WriteFile 之前生效。
        // 放过 skip 次调用后，连续 faults 次以 win32_error 失败，之后恢复。
        void set_write_fault_for_test(unsigned long win32_error, int faults, int skip = 0) noexcept
        {
            write_fault_error_.store(win32_error, std::memory_order_relaxed);
            write_fault_remaining_.store(faults, std::memory_order_relaxed);
            write_fault_skip_.store(skip, std::memory_order_relaxed);
        }

        // FlushFileBuffers 故障注入，同样在真实调用之前生效。
        void set_flush_fault_for_test(unsigned long win32_error, int faults, int skip = 0) noexcept
        {
            flush_fault_error_.store(win32_error, std::memory_order_relaxed);
            flush_fault_remaining_.store(faults, std::memory_order_relaxed);
            flush_fault_skip_.store(skip, std::memory_order_relaxed);
        }

        // 限制单次 WriteFile 的最大字节数（0 = 不限制），强制制造 partial write，
        // 否则 transferred 跨 retry 的语义无法被测试。
        void set_max_write_chunk_for_test(UInt32 bytes) noexcept
        {
            max_write_chunk_.store(bytes, std::memory_order_relaxed);
        }

    private:
        static FailureClassifier default_failure_classifier()
        {
            return [](unsigned long win32_error) { return is_space_exhaustion_error(win32_error); };
        }

        FailureClassifier failure_classifier_ = default_failure_classifier();
        OpenProbe open_probe_;
        std::atomic<unsigned long> write_fault_error_{0};
        std::atomic<int> write_fault_remaining_{0};
        std::atomic<int> write_fault_skip_{0};
        std::atomic<unsigned long> flush_fault_error_{0};
        std::atomic<int> flush_fault_remaining_{0};
        std::atomic<int> flush_fault_skip_{0};
        std::atomic<UInt32> max_write_chunk_{0};

        // 返回 true 表示本次系统调用被注入的故障取代。
        template <typename Remaining, typename Skip>
        static bool consume_fault(Remaining &remaining, Skip &skip, unsigned long *win32_error) noexcept
        {
            if (remaining.load(std::memory_order_relaxed) <= 0)
            {
                return false;
            }
            int pending_skip = skip.load(std::memory_order_relaxed);
            while (pending_skip > 0)
            {
                if (skip.compare_exchange_weak(pending_skip, pending_skip - 1,
                                               std::memory_order_relaxed,
                                               std::memory_order_relaxed))
                {
                    return false; // 本次调用被放过
                }
            }
            int pending = remaining.load(std::memory_order_relaxed);
            do
            {
                if (pending <= 0) return false;
            } while (!remaining.compare_exchange_weak(pending, pending - 1,
                                                       std::memory_order_relaxed));
            if (win32_error)
            {
                *win32_error = 0;
            }
            return true;
        }

        bool consume_injected_write_fault(unsigned long *win32_error) noexcept
        {
            if (!consume_fault(write_fault_remaining_, write_fault_skip_, nullptr))
            {
                return false;
            }
            if (win32_error)
            {
                *win32_error = write_fault_error_.load(std::memory_order_relaxed);
            }
            return true;
        }

        bool consume_injected_flush_fault(unsigned long *win32_error) noexcept
        {
            if (!consume_fault(flush_fault_remaining_, flush_fault_skip_, nullptr))
            {
                return false;
            }
            if (win32_error)
            {
                *win32_error = flush_fault_error_.load(std::memory_order_relaxed);
            }
            return true;
        }
    };

}

#endif
