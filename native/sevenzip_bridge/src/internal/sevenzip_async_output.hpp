#pragma once

#include "sevenzip_paths.hpp"
#include "sevenzip_space_retry.hpp"
#include "sevenzip_volume_state.hpp"
#include "sevenzip_writer_meters.hpp"

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
                std::shared_ptr<std::atomic<bool>> external_cancel = nullptr)
                : max_inflight_bytes(budget),
                  cancel_token(std::move(external_cancel)) {}

            // ★ 唤醒判据：**只由 atomic 组成**，gate 的 wait() 可以无锁读。
            //
            //   非 atomic 的 cancelled / first_error 由本 writer 的 mutex_ 保护，
            //   而 gate 的 wait() 不持那把锁 —— 直接读它们是 data race / UB，
            //   让谓词去 lock writer mutex 又会引入 gate -> writer 锁依赖（禁止）。
            //
            //   所有会令本 job 终局的地方都必须同步置 true：
            //       set_job_error_locked()   （首次永久错误）
            //       cancel_job_locked()      （取消 / token / executor shutdown）
            //       finish()                 （writer 整体停止 —— 走 cancel_job_locked）
            //
            //   ⚠️ 空间错误**不得**置位这一位（那正是暂停语义的前提）：
            //      空间路径不调用 set_job_error_locked / cancel_job_locked。
            std::atomic<bool> terminal_requested{false};

            // 详细错误结果：仍保留在 writer mutex_ 之下，仅供诊断与最终归类。
            HRESULT first_error = S_OK;
            int first_win32_error = 0;
            std::size_t inflight_bytes = 0;
            std::size_t pending_jobs = 0;
            bool cancelled = false;
            const std::size_t max_inflight_bytes;
            std::shared_ptr<std::atomic<bool>> cancel_token;
        };

        using JobStatePtr = std::shared_ptr<JobState>;

        struct Buffer;
        struct FileState;
        using FileStatePtr = std::shared_ptr<FileState>;

        struct FileSnapshot
        {
            UInt64 accepted_bytes = 0;
            UInt64 written_bytes = 0;
            UInt32 output_crc32 = 0;
            Int32 operation_result = 0;
            HRESULT hresult = S_OK;
            int win32_error = 0;
            bool operation_result_set = false;
            bool has_output_crc32 = false;
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

        // writer 是否已停止接收/推进工作。供 writer 之外的调用点（根输出目录创建、
        // 条目目录创建、GetStream）构造 gate 的 terminal predicate 使用：
        // 这两项合起来覆盖每一个 gate waiter —— executor stop() 置真 cancel_tokens_，
        // registry shutdown → finish() 置真本 writer 的 stopping_。
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

            // 本文件所属卷的空间 gate（**可能为 nullptr**：功能关闭 / 无卷身份）。
            // 在 make_file() 时从 VolumeState 快照进来，因此 writer 线程不需要
            // 再取 state_（gate 的存活期长于 writer，但拿到的指针在整个尝试期间稳定）。
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
            UInt32 output_crc32 = 0;
            Int32 operation_result = 0;
            HRESULT hresult = S_OK;
            int win32_error = 0;
            bool operation_result_set = false;
            bool has_output_crc32 = false;
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
        };

        struct Buffer
        {
            Buffer()
                : completion_event(CreateEventW(nullptr, TRUE, FALSE, nullptr))
            {
                if (completion_event == nullptr)
                {
                    throw std::bad_alloc();
                }
            }

            ~Buffer()
            {
                if (completion_event != nullptr)
                {
                    CloseHandle(completion_event);
                }
            }

            std::unique_ptr<unsigned char[]> data;
            HANDLE completion_event = nullptr;
            FileStatePtr file;
            UInt32 size = 0;
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
            std::shared_ptr<std::atomic<bool>> cancel_token = nullptr)
        {
            if (max_inflight_bytes == 0)
            {
                max_inflight_bytes = kDefaultJobInFlightBytes;
            }
            auto job = std::make_shared<JobState>(max_inflight_bytes, std::move(cancel_token));
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
            std::size_t trace_index)
        {
            auto file = std::make_shared<FileState>(
                job ? job : make_job(),
                std::move(path), std::move(item_path), item_index, trace_index);
            std::lock_guard<std::mutex> lock(mutex_);
            // 快照本卷的空间 gate。功能关闭 / 空 key 的兜底 writer 时为 nullptr，
            // 于是 retry_with_space_gate 走 gate == nullptr 的**完全现状**分支。
            file->space_gate = state_ ? state_->space_gate : nullptr;
            active_files_.push_back(file);
            ++inflight_file_count_;
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
                if (queued_staging)
                {
                    work_cv_.notify_one();
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
            UInt32 output_crc32,
            bool has_output_crc32,
            std::vector<unsigned char> magic) noexcept
        {
            if (!file)
            {
                return;
            }

            std::unique_lock<std::mutex> producer_lock(file->producer_mutex);
            bool queued_close = false;
            bool queued_data = false;
            bool direct_close = false;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                if (file->close_requested)
                {
                    return;
                }
                synchronize_cancellation_locked(file->job);
                file->close_requested = true;
                file->output_crc32 = output_crc32;
                file->has_output_crc32 = has_output_crc32;
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
                    queued_data = enqueue_staging_locked(file, true);
                }
                if (file->outstanding_data == 0)
                {
                    queued_close = enqueue_close_locked(file, &direct_close);
                }
            }
            if (queued_data)
            {
                work_cv_.notify_one();
            }
            if (queued_close)
            {
                work_cv_.notify_one();
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
            bool cancelled = false;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                synchronize_cancellation_locked(job);
                cancelled = terminal_result_locked(job) != S_OK;
            }
            if (cancelled)
            {
                cleanup_cancelled_staging(job);
            }
            std::unique_lock<std::mutex> lock(mutex_);
            producer_cv_.wait(lock, [&job]
                              { return job->pending_jobs == 0; });
            const HRESULT result = terminal_result_locked(job);
            unregister_job_locked(job);
            if (result == S_OK)
            {
                meters_->counters.completed_jobs.fetch_add(1, std::memory_order_relaxed);
                state_->counters.completed_jobs.fetch_add(1, std::memory_order_relaxed);
            }
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
            cleanup_cancelled_staging(job);
            // 取消必须能穿透"因满盘而暂停"：置 terminal_requested 之后还要唤醒
            // 卡在卷 gate 上的 writer 线程，否则它只能等 wait_tick 超时才察觉取消。
            if (state_ && state_->space_gate)
            {
                state_->space_gate->wake_waiters();
            }
            work_cv_.notify_all();
            producer_cv_.notify_all();
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
            // 卷空间 gate 的等待者也要被唤醒：取消必须能穿透"因满盘而暂停"。
            // gate 的 wait() 会重新求值调用方传入的 terminal predicate（读 cancel_token）。
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
            snapshot.output_crc32 = file->output_crc32;
            snapshot.operation_result = file->operation_result;
            snapshot.hresult = file->hresult;
            snapshot.win32_error = file->win32_error;
            snapshot.operation_result_set = file->operation_result_set;
            snapshot.has_output_crc32 = file->has_output_crc32;
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
            std::vector<JobStatePtr> jobs;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                stopping_.store(true, std::memory_order_release);
                for (const auto &weak_job : active_jobs_)
                {
                    if (const auto job = weak_job.lock())
                    {
                        cancel_job_locked(job);
                        jobs.push_back(job);
                    }
                }
            }
            for (const auto &job : jobs)
            {
                cleanup_cancelled_staging(job);
            }
            // ★ 唤醒（**不是** abort）：本 writer 的 stopping_ 已经置位、且所有 active job
            //   都已被 cancel_job_locked 置 terminal_requested，所以谓词此刻为真，
            //   卡在卷 gate 上的 writer 线程会返回 Terminal 并正常退出。
            //   gate 的状态**不因关停而改变**（没有 aborted_ 永久闩锁）——
            //   否则 persistent volume 的 gate 会被 idle reap 永久毒死。
            if (state_ && state_->space_gate)
            {
                state_->space_gate->wake_waiters();
            }
            work_cv_.notify_all();
            producer_cv_.notify_all();
            for (auto &worker : workers_)
            {
                if (worker.joinable())
                {
                    worker.join();
                }
            }
        }

    private:
        void initialize()
        {
            buffers_.reserve(buffer_count_);
            for (std::size_t index = 0; index < buffer_count_; ++index)
            {
                auto buffer = std::make_unique<Buffer>();
                free_buffers_.push_back(buffer.get());
                buffers_.push_back(std::move(buffer));
            }
            workers_.reserve(writer_count_);
            try
            {
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
                work_cv_.notify_all();
                for (auto &worker : workers_)
                {
                    if (worker.joinable())
                    {
                        worker.join();
                    }
                }
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

        void cleanup_cancelled_staging(const JobStatePtr &job) noexcept
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
                        if (file->job.get() == job.get())
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
                std::unique_lock<std::mutex> producer_lock(file->producer_mutex);
                bool queued_close = false;
                {
                    std::lock_guard<std::mutex> lock(mutex_);
                    if (terminal_result_locked(job) == S_OK)
                    {
                        continue;
                    }
                    discard_staging_locked(file);
                    if (file->close_requested && file->outstanding_data == 0)
                    {
                        queued_close = enqueue_close_locked(file, nullptr);
                    }
                }
                if (queued_close)
                {
                    work_cv_.notify_one();
                }
                producer_cv_.notify_all();
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
                work_queue_.emplace_back(WorkItem::data(buffer, output_offset));
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

        void writer_loop() noexcept
        {
            for (;;)
            {
                WorkItem item;
                {
                    std::unique_lock<std::mutex> lock(mutex_);
                    work_cv_.wait(lock, [this]
                                  { return stopping_.load(std::memory_order_acquire) ||
                                           !work_queue_.empty(); });
                    if (work_queue_.empty())
                    {
                        if (stopping_.load(std::memory_order_acquire))
                        {
                            break;
                        }
                        continue;
                    }
                    item = std::move(work_queue_.front());
                    work_queue_.pop_front();
                    --queued_jobs_;
                }
                producer_cv_.notify_all();

                if (item.kind == WorkItem::Kind::Data)
                {
                    // buffer 的所有权在本循环内。只有真正终结时才 release，
                    // 因此"暂停"期间 buffer 天然保持 inflight，producer 反压成立。
                    Buffer *buffer = item.buffer;
                    const FileStatePtr file = buffer ? buffer->file : nullptr;

                    // ★ 谓词**只读 atomic**（stopping_ 是 writer 私有 atomic；
                    //   job->terminal_requested / cancel_token 同样是 atomic）。
                    //   job 必须**按值**捕获 shared_ptr —— 谓词可能活过局部作用域。
                    const JobStatePtr job = file ? file->job : nullptr;
                    const TerminalPredicate terminal_pred = writer_terminal_predicate(job);

                    // transferred 跨重试保留：空间失败时已经落盘的前缀不能被重复记账，
                    // 重试也从 output_offset + transferred 继续（同 handle、同 offset 语义）。
                    UInt32 transferred = 0;

                    // ★★ writer_loop **不认识 ProbeLease**，也不调用任何 gate 状态接口。
                    //     全部空间状态交互发生在骨架内部（唯一权威实现）。
                    const AttemptResult result = retry_with_space_gate(
                        file ? file->volume_space_gate() : nullptr,
                        terminal_pred,
                        file ? std::wstring_view(file->path) : std::wstring_view{},
                        [&] {
                            // 一次真实尝试：只返回 AttemptResult，绝不碰 gate、绝不记账
                            return attempt_data_write(file, buffer, item.output_offset, transferred);
                        });

                    // ★ 收尾记账：dequeue 的 buffer 剩余字节**只在这里**结算。
                    if (result.kind == AttemptResult::Kind::SpaceFailure)
                    {
                        // 只可能在这里出现：gate == nullptr（骨架内部已吃掉
                        // gate != nullptr 的情形）。执行旧版永久失败语义。
                        record_legacy_space_failure(file, buffer, transferred, result.win32_error);
                        release_buffer(buffer);
                        continue;
                    }
                    switch (result.kind)
                    {
                    case AttemptResult::Kind::Succeeded:
                        break; // remaining == 0，无需记
                    case AttemptResult::Kind::PermanentFailure:
                    case AttemptResult::Kind::Terminal:
                        if (buffer && buffer->size > transferred)
                        {
                            account_discarded(buffer->size - transferred);
                        }
                        break;
                    }

                    release_buffer(buffer);
                }
                else
                {
                    process_close(item.file);
                }
            }
        }

        // ---------------------------------------------------------------------
        // 一次 CreateFileW 尝试（**在 writer mutex_ 内**，只做一次，绝不等待）。
        //
        // ★ 保留 writer mutex 对 CreateFile 尝试的**串行化**：同一个 FileState 的
        //   多个 Data WorkItem 会被多个 per-volume writer 线程并发处理
        //   （active_data_writes / peak_active_data_writes 就是证据）。去掉锁后两个
        //   线程可能同时 CreateFileW(CREATE_NEW)：T1 成功、T2 得到 ERROR_FILE_EXISTS
        //   → T2 把整个 job 标成永久失败。
        //
        // ★ 真正禁止的是「持 writer mutex **等磁盘恢复**」，而不是「持 writer mutex
        //   **调一次 CreateFileW**」。等待由调用方在**锁外**做（retry_with_space_gate）。
        //
        // ★ open_attempted 的语义修正：从"尝试过一次就永不再试"改为
        //   "**已建立 handle 或已永久失败**"。空间错误**不置位** → 重试可达。
        //
        // ★ 空间错误**不需要任何残留清理**：T-WIN-1b 实测证明可以在同一个 handle 上
        //   续写；而且 CreateFileW(CREATE_NEW) 在 0 字节可用时依然成功（NTFS 不预分配），
        //   空间错误实际发生在随后的 WriteFile。因此整个 FileState 生命周期内
        //   CreateFileW 只调用一次，**没有** OPEN_EXISTING 分支、没有 ownership 字段、
        //   没有 remove_space_failure_residue()。
        // ---------------------------------------------------------------------
        AttemptResult try_open_file_locked(const FileStatePtr &file) noexcept
        {
            std::lock_guard<std::mutex> lock(mutex_);
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
                // 旧语义：已尝试过且未成功 → 不再尝试。
                return {AttemptResult::Kind::PermanentFailure, ERROR_OPEN_FAILED};
            }

            DWORD creation_flags = FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED;
            if (write_through())
            {
                creation_flags |= FILE_FLAG_WRITE_THROUGH;
            }
            // 缝隙 B：这一行是"同 handle 续写"的回归防线所在。
            // （整个 FileState 生命周期内 CreateFileW 只应被调用一次。）
            if (open_probe_)
            {
                open_probe_(file->path);
            }
            const HANDLE handle = CreateFileW(
                win32_extended_path(file->path).c_str(),
                GENERIC_WRITE,
                0,
                nullptr,
                CREATE_NEW,
                creation_flags,
                nullptr);
            if (handle == INVALID_HANDLE_VALUE)
            {
                const DWORD error = GetLastError();
                if (failure_classifier_(static_cast<unsigned long>(error)))
                {
                    if (!file->space_gate)
                    {
                        // 开关关闭：逐语义对齐旧 open_file()（它在**任何**错误上都先置
                        // open_attempted = true 再标记失败，即"不再尝试"）。
                        file->open_attempted = true;
                    }
                    // ★ 不置 open_attempted → 重试可达；不置 file/job 失败 → job 不终局。
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
            file->handle = handle;
            file->open_attempted = true;
            return {AttemptResult::Kind::Succeeded, 0};
        }

        // 打开文件（**锁外等待**版本）：一次真实尝试 = 一次 try_open_file_locked。
        // gate == nullptr 时只尝试一次并**原样外泄** SpaceFailure，由这里执行 Open
        // 路径的旧语义（§4.5.0.1：mark_file_failure + set_job_error +
        // **置 open_attempted = true**；与 Data 路径的 record_legacy_space_failure
        // 不同，后者需要 buffer / transferred 语义）。
        AttemptResult open_file_with_space_gate(const FileStatePtr &file,
                                                const TerminalPredicate &terminal) noexcept
        {
            const AttemptResult result = retry_with_space_gate(
                file ? file->space_gate.get() : nullptr,
                terminal,
                file ? std::wstring_view(file->path) : std::wstring_view{},
                [this, &file] { return try_open_file_locked(file); });

            if (result.kind == AttemptResult::Kind::SpaceFailure)
            {
                std::lock_guard<std::mutex> lock(mutex_);
                if (file && !file->failed)
                {
                    file->open_attempted = true;
                    mark_file_failure_locked(
                        file,
                        HRESULT_FROM_WIN32(static_cast<DWORD>(result.win32_error)),
                        static_cast<int>(result.win32_error));
                    set_job_error_locked(
                        file->job,
                        HRESULT_FROM_WIN32(static_cast<DWORD>(result.win32_error)),
                        static_cast<int>(result.win32_error));
                }
                producer_cv_.notify_all();
            }
            return result;
        }

        bool open_file(const FileStatePtr &file, const TerminalPredicate &terminal) noexcept
        {
            return open_file_with_space_gate(file, terminal).kind ==
                   AttemptResult::Kind::Succeeded;
        }

        // gate 的终态谓词：**只读 atomic**（stopping_ / terminal_requested / cancel_token）。
        // job 按值捕获 shared_ptr —— 谓词可能活过局部作用域。
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

        // ---------------------------------------------------------------------
        // 一次真实的 WriteFile 尝试。**只返回结果，绝不碰 gate、绝不记 discarded。**
        //
        // `transferred` 是 in/out：进入时是本次 buffer 已经落盘的前缀（跨重试保留），
        // 退出时是新的前缀。这样：
        //   * add_written_bytes 只对**新**写入的字节调用 → 重试不会重复记账；
        //   * 空间失败时重试从 output_offset + transferred 继续
        //     （同 handle、同偏移语义，§17.4 的实测结论）。
        //
        // 不变量校验：
        //   * 成功路径上 add_written_bytes 只对应真实 GetOverlappedResult 成功；
        //   * 所有失败路径都配对 end_data_write，active_data_writes 归零；
        //   * 空间失败路径**不**调用 record_failure（否则记账与 job 终态都被破坏）。
        // ---------------------------------------------------------------------
        AttemptResult attempt_data_write(const FileStatePtr &file,
                                         Buffer *buffer,
                                         UInt64 output_offset,
                                         UInt32 &transferred) noexcept
        {
            transferred = 0;
            if (!file || !buffer || !buffer->data)
            {
                return {AttemptResult::Kind::PermanentFailure, ERROR_INVALID_STATE};
            }

            const auto job = file->job;
            const HRESULT global_error = current_error(job);
            if (global_error != S_OK)
            {
                // 已经是终态（取消 / 其他文件已永久失败 / writer 停止）。
                // 仍然要标记本文件失败，否则 process_close 的
                // completed_successfully = !file->failed 会把失败文件计入 completed_files。
                // 剩余字节的 discarded 由 writer_loop 收尾（此处传 0）。
                record_failure(file, global_error, current_win32_error(job), 0);
                return {AttemptResult::Kind::Terminal, 0};
            }

            // ★ 打开文件：**只做一次锁内尝试**，绝不在这里嵌套 retry_with_space_gate。
            //   外层（Data 骨架）可能正持有 probe 许可，内层 wait() 会在 Probing 上
            //   永久阻塞。SpaceFailure 直接上抛，由外层骨架重试整次尝试 ——
            //   open_attempted 未被置位，因此重试会真正再调一次 CreateFileW。
            const AttemptResult open_result = try_open_file_locked(file);
            if (open_result.kind != AttemptResult::Kind::Succeeded)
            {
                return open_result;
            }

            if (!begin_data_write(file))
            {
                const HRESULT error = current_error(job);
                if (error != S_OK)
                {
                    record_failure(file, error, current_win32_error(job), 0);
                }
                return {AttemptResult::Kind::Terminal, 0};
            }

            while (transferred < buffer->size)
            {
                unsigned long injected_error = 0;
                if (consume_injected_write_fault(&injected_error))
                {
                    end_data_write(file);
                    return classify_data_failure(file, static_cast<DWORD>(injected_error));
                }

                const UInt64 request_offset = output_offset + transferred;
                OVERLAPPED overlapped{};
                overlapped.Offset = static_cast<DWORD>(request_offset);
                overlapped.OffsetHigh = static_cast<DWORD>(request_offset >> 32U);
                overlapped.hEvent = buffer->completion_event;
                ResetEvent(buffer->completion_event);

                const DWORD request_size = buffer->size - transferred;
                const BOOL started = WriteFile(
                    file->handle,
                    buffer->data.get() + transferred,
                    request_size,
                    nullptr,
                    &overlapped);
                if (!started && GetLastError() != ERROR_IO_PENDING)
                {
                    const DWORD error = GetLastError();
                    end_data_write(file);
                    return classify_data_failure(file, error);
                }

                DWORD written = 0;
                if (!GetOverlappedResult(file->handle, &overlapped, &written, TRUE))
                {
                    const DWORD error = GetLastError();
                    end_data_write(file);
                    return classify_data_failure(file, error);
                }
                if (written == 0)
                {
                    end_data_write(file);
                    record_failure(
                        file, HRESULT_FROM_WIN32(ERROR_WRITE_FAULT), ERROR_WRITE_FAULT, 0);
                    return {AttemptResult::Kind::PermanentFailure, ERROR_WRITE_FAULT};
                }
                transferred += written;
                add_written_bytes(file, written);
            }
            end_data_write(file);
            return {AttemptResult::Kind::Succeeded, 0};
        }

        // 写入失败的分类：**空间类错误必须走 SpaceFailure**，由骨架决定重试，
        // 绝不能在这里调用 record_failure（那会立刻把 pending 记成 discarded、
        // 把 file/job 标记成永久失败）。
        AttemptResult classify_data_failure(const FileStatePtr &file, DWORD error) noexcept
        {
            if (failure_classifier_(static_cast<unsigned long>(error)))
            {
                return {AttemptResult::Kind::SpaceFailure, static_cast<unsigned long>(error)};
            }
            record_failure(file, HRESULT_FROM_WIN32(error), static_cast<int>(error), 0);
            return {AttemptResult::Kind::PermanentFailure, static_cast<unsigned long>(error)};
        }

        void process_close(const FileStatePtr &file) noexcept
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
            }
            if (should_open)
            {
                // close 阶段的 open 走同一骨架（在 writer 线程上，不持有 probe 许可，
                // 因此不会与外层重试冲突）。
                open_file(file, writer_terminal_predicate(job));
            }

            HANDLE handle = INVALID_HANDLE_VALUE;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                handle = file->handle;
                file->handle = INVALID_HANDLE_VALUE;
            }
            if (handle != INVALID_HANDLE_VALUE)
            {
                if (write_through())
                {
                    // ★ flush 必须走**同一个骨架**：早期设计只有
                    //   "FlushFileBuffers → space error → gate->wait() → retry"，
                    //   缺 report_space_failure / ProbeLease / probe 结算。若 gate 原本
                    //   是 Ready，直接 wait() 会立刻返回（Ready 快路径）→ flush 变成
                    //   **忙重试**，而且 probe 许可从未被结算。
                    //
                    //   仅 write-through 路径（B4）：非 write-through 时 CloseHandle
                    //   本身就会 flush，不需要额外的可暂停等待。
                    //
                    // ⚠️ handle 在骨架外面被摘下来了（file->handle = INVALID_HANDLE_VALUE），
                    //   因此 attempt 里的 FlushFileBuffers 用的是**同一个** handle，
                    //   暂停期间它不会被关闭（同 handle 续写语义的一部分）。
                    const TerminalPredicate flush_terminal = writer_terminal_predicate(job);
                    const AttemptResult flush_result = retry_with_space_gate(
                        file->space_gate.get(),
                        flush_terminal,
                        file->path,
                        [this, handle]() noexcept -> AttemptResult
                        {
                            unsigned long injected = 0;
                            if (consume_injected_flush_fault(&injected))
                            {
                                const DWORD error = static_cast<DWORD>(injected);
                                if (is_space_exhaustion_error(static_cast<unsigned long>(error)))
                                {
                                    return {AttemptResult::Kind::SpaceFailure,
                                            static_cast<unsigned long>(error)};
                                }
                                return {AttemptResult::Kind::PermanentFailure,
                                        static_cast<unsigned long>(error)};
                            }
                            if (FlushFileBuffers(handle))
                            {
                                return {AttemptResult::Kind::Succeeded, 0};
                            }
                            const DWORD error = GetLastError();
                            if (is_space_exhaustion_error(static_cast<unsigned long>(error)))
                            {
                                return {AttemptResult::Kind::SpaceFailure,
                                        static_cast<unsigned long>(error)};
                            }
                            return {AttemptResult::Kind::PermanentFailure,
                                    static_cast<unsigned long>(error)};
                        });

                    if (flush_result.kind != AttemptResult::Kind::Succeeded)
                    {
                        // ★ 逐路径的旧语义（§4.5.0.1）：Flush 用 record_failure 且
                        //   discarded_bytes = 0（剩余字节由 writer_loop 收尾负责）。
                        //   注意 SpaceFailure 只可能在 gate == nullptr 时外泄。
                        record_failure(
                            file,
                            HRESULT_FROM_WIN32(static_cast<DWORD>(flush_result.win32_error)),
                            static_cast<int>(flush_result.win32_error),
                            0);
                    }
                }
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
                if (!CloseHandle(handle))
                {
                    const DWORD error = GetLastError();
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
            bool queued_close = false;
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
                    queued_close = enqueue_close_locked(file, &direct_close);
                }
            }
            if (queued_close)
            {
                work_cv_.notify_one();
            }
            if (direct_close)
            {
                process_close(file);
            }
            producer_cv_.notify_all();
        }

        // ---------------------------------------------------------------------
        // gate == nullptr（功能关闭 / 无卷身份）时的**旧语义收尾**。
        //
        // 必须逐条对应改动前的 record_failure(file, hr, err, buffer->size - transferred)：
        //      1) account_discarded(pending -> discarded)
        //      2) file 终局失败
        //      3) job 终局失败（set_job_error_locked 同时置 terminal_requested）
        //      4) 唤醒 producer
        //
        // ⚠️ 只适用于 **Data** 路径（它需要 buffer / transferred 语义）。
        //    Open / Flush / Directory 三条路径的旧语义各不相同，各自处理：
        //      Open      → mark_file_failure_locked + set_job_error_locked + open_attempted = true
        //      Flush     → record_failure(file, hr, err, 0)
        //      Directory → 返回 false + 原始 std::error_code
        //    把四条路径合并成一个 helper 会破坏"开关关闭 = 逐语义回到现状"这条合并门禁。
        // ---------------------------------------------------------------------
        void record_legacy_space_failure(const FileStatePtr &file,
                                         const Buffer *buffer,
                                         UInt32 transferred,
                                         unsigned long win32_error) noexcept
        {
            if (buffer && buffer->size > transferred)
            {
                account_discarded(buffer->size - transferred);
            }
            {
                std::lock_guard<std::mutex> lock(mutex_);
                mark_file_failure_locked(
                    file, HRESULT_FROM_WIN32(win32_error), static_cast<int>(win32_error));
                if (file)
                {
                    set_job_error_locked(
                        file->job, HRESULT_FROM_WIN32(win32_error), static_cast<int>(win32_error));
                }
            }
            producer_cv_.notify_all();
        }

        void record_failure(
            const FileStatePtr &file,
            HRESULT hr,
            int win32_error,
            std::size_t discarded_bytes = 0) noexcept
        {
            // ``discarded_bytes`` is the caller's remainder: bytes that reached the
            // writer thread but will never be written.
            //
            // ★ 空间/终态路径一律传 0：**已 dequeue 的 buffer 剩余字节只由
            //   writer_loop 的收尾负责**（§4.5.3.1 的唯一不变量）。这样 discarded
            //   对"已 dequeue 的 buffer"只有一个写入点，不变量可以一眼证明。
            //   仍在 staging 的 buffer 由 discard_staging_locked() 负责，两者不重叠。
            account_discarded(discarded_bytes);
            {
                std::lock_guard<std::mutex> lock(mutex_);
                mark_file_failure_locked(file, hr, win32_error);
                if (file)
                {
                    set_job_error_locked(file->job, hr, win32_error);
                }
            }
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
        std::condition_variable work_cv_;
        const std::shared_ptr<WriterMeters> meters_;
        const VolumeStatePtr state_;
        const AsyncWriterConfig config_;
        const std::size_t writer_count_;
        const std::size_t buffer_count_;
        const std::size_t queue_limit_;
        std::size_t inflight_file_count_ = 0;
        std::size_t queued_jobs_ = 0;
        // ★ 必须是 atomic：gate 的 terminal predicate 会**无锁**读它
        //   （AsyncFileWriter::stopping_ 与 NativeJobExecutor::stopping_ 是两个
        //    互不可见的量，不能互相顶替）。
        std::atomic<bool> stopping_{false};

    public:
        // ------------------------------------------------------------------
        // 测试缝隙（生产代码永不设置）
        //
        // 缝隙 A：failure_classifier 可注入。C++ 单测无法制造真实的 ERROR_DISK_FULL，
        //         于是用"真实的其它错误码"驱动同一条代码路径：把 classifier 配成
        //         "ERROR_ACCESS_DENIED(5) 视为空间类"，对只读目录写 → CreateFileW /
        //         WriteFile 返回 5 → writer 进入等待 → 测试改回权限 → 重试成功。
        //         断言 gate 记录的必须是**原始码**（5，而不是 112）。
        // 缝隙 B：CreateFileW 调用探针。"同 handle 续写"的回归防线：正常恢复期间
        //         每个 FileState 的 CreateFileW 调用次数必须恒为 1。
        // 缝隙 D：WriteFile 故障注入（见下）。
        // ------------------------------------------------------------------
        using FailureClassifier = std::function<bool(unsigned long win32_error)>;
        using OpenProbe = std::function<void(const std::wstring &path)>;

        void set_failure_classifier_for_test(FailureClassifier classifier) noexcept
        {
            failure_classifier_ = classifier ? std::move(classifier) : default_failure_classifier();
        }

        void set_open_probe_for_test(OpenProbe probe) noexcept { open_probe_ = std::move(probe); }

        // 缝隙 D：WriteFile 故障注入（在调用真实 WriteFile **之前**生效）。
        //   skip 次调用被放过，随后 faults 次连续以 win32_error 失败，之后恢复。
        //
        //   ⚠️ 为什么需要它（而不是只用缝隙 C 的"只读目录"路线）：
        //      只读目录只会让 CreateFileW 返回 ERROR_ACCESS_DENIED，**打不到
        //      WriteFile**；而本阶段要覆盖的恰恰是 WriteFile 重试、probe 结算、
        //      暂停期间的记账不变量。C++ 单测无法制造真实的 ERROR_DISK_FULL，
        //      因此把"真实系统调用"这一步替换掉，其余代码路径全部是真实的。
        void set_write_fault_for_test(unsigned long win32_error, int faults, int skip = 0) noexcept
        {
            write_fault_error_.store(win32_error, std::memory_order_relaxed);
            write_fault_remaining_.store(faults, std::memory_order_relaxed);
            write_fault_skip_.store(skip, std::memory_order_relaxed);
        }

        // 缝隙 D2：FlushFileBuffers 故障注入（同样在真实调用之前生效）。
        //   write-through 路径的 flush 走的是同一个重试骨架，必须能被独立驱动。
        void set_flush_fault_for_test(unsigned long win32_error, int faults, int skip = 0) noexcept
        {
            flush_fault_error_.store(win32_error, std::memory_order_relaxed);
            flush_fault_remaining_.store(faults, std::memory_order_relaxed);
            flush_fault_skip_.store(skip, std::memory_order_relaxed);
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
            remaining.fetch_sub(1, std::memory_order_relaxed);
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
