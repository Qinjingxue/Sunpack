#pragma once

#include "sevenzip_paths.hpp"
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

namespace sunpack::sevenzip {

class AsyncFileWriter final {
public:
    struct JobState {
        explicit JobState(
            std::size_t budget,
            std::shared_ptr<std::atomic<bool>> external_cancel = nullptr)
            : max_inflight_bytes(budget),
              cancel_token(std::move(external_cancel)) {}

        // All scheduler state is protected by AsyncFileWriter::mutex_.
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

    struct FileSnapshot {
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

    struct Metrics {
        std::uint64_t accepted_bytes = 0;
        std::uint64_t written_bytes = 0;
        // Bytes that entered the writer but will never reach the disk (cancelled
        // or permanently failed).  Together with pending_bytes this keeps the
        // accounting identity below exact:
        //   accepted = written + discarded + pending
        std::uint64_t discarded_bytes = 0;
        // Gauge: bytes accepted but neither written nor discarded yet.
        std::uint64_t pending_bytes = 0;
        std::uint64_t completed_files = 0;
        std::uint64_t completed_jobs = 0;
    };

    // Latest process-wide meters, as sampled by the owner for the controller.
    // The counters live in WriterMeters, not here: a reclaimed writer must not
    // take the aggregate with it.
    WriterMeterSnapshot snapshot_global_meters() const noexcept {
        return snapshot_counters(meters_->counters);
    }

    // Per-volume meters for diagnostics.
    WriterMeterSnapshot snapshot_volume_meters() const noexcept {
        return state_ ? snapshot_counters(state_->counters) : WriterMeterSnapshot{};
    }

    const AsyncWriterConfig& config() const noexcept { return config_; }

    const VolumeStatePtr& volume_state() const noexcept { return state_; }

    // Routing key this facility was built for.  The lease uses it to release the
    // right registry entry without a reverse lookup.
    const std::string& volume_key() const noexcept { return state_->key; }

    struct WorkItem {
        enum class Kind { Data, Close };

        static WorkItem data(Buffer* value, UInt64 offset) {
            WorkItem item;
            item.kind = Kind::Data;
            item.buffer = value;
            item.output_offset = offset;
            return item;
        }

        static WorkItem close(FileStatePtr value) {
            WorkItem item;
            item.kind = Kind::Close;
            item.file = std::move(value);
            return item;
        }

        Kind kind = Kind::Data;
        Buffer* buffer = nullptr;
        FileStatePtr file;
        UInt64 output_offset = 0;
    };

    struct FileState {
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

        // These fields are immutable after construction and may be used as output identity.
        const std::wstring item_path;
        const UInt32 item_index = 0;
        const std::size_t trace_index = 0;

    private:
        friend class AsyncFileWriter;

        JobStatePtr job;
        std::wstring path;
        std::atomic<UInt64> accepted_bytes{0};
        std::atomic<UInt64> next_write_offset{0};
        // Serializes producers for this file while allowing different files to
        // fill their staging buffers concurrently.  The writer mutex still
        // protects scheduler/accounting state.
        std::mutex producer_mutex;
        Buffer* staging_buffer = nullptr;
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
        // Guards the inflight_file_count_ release so a repeated close cannot
        // double-decrement the reclamation counter.
        bool inflight_released = false;
        HANDLE handle = INVALID_HANDLE_VALUE;
        bool open_attempted = false;
    };

    struct Buffer {
        Buffer()
            : completion_event(CreateEventW(nullptr, TRUE, FALSE, nullptr)) {
            if (completion_event == nullptr) {
                throw std::bad_alloc();
            }
        }

        ~Buffer() {
            if (completion_event != nullptr) {
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

    // Volume-scoped facility.  ``meters`` is process-wide and owned by whoever
    // outlives every writer; ``state`` carries the volume's own counters and the
    // future disk-full gate.  Both are shared_ptr rather than a registry-map raw
    // pointer so an unordered_map rehash can never dangle them (§3.2).
    AsyncFileWriter(
        std::shared_ptr<WriterMeters> meters,
        VolumeStatePtr state,
        AsyncWriterConfig config = {})
        : meters_(meters ? std::move(meters) : std::make_shared<WriterMeters>()),
          state_(state ? std::move(state) : make_volume_state(std::string{}, false)),
          config_(config),
          writer_count_((std::max)(std::size_t{1}, config.threads_per_volume)),
          buffer_count_((std::max)(std::size_t{4}, config.buffer_count)),
          queue_limit_((std::max)(std::size_t{1}, config.queue_limit)) {
        initialize();
    }

    // Convenience construction for tests and for callers that do not take part in
    // the per-volume registry yet.  Uses the environment snapshot.
    AsyncFileWriter()
        : AsyncFileWriter(
              std::make_shared<WriterMeters>(),
              make_volume_state(std::string{}, false),
              configured_async_writer_config()) {}

    ~AsyncFileWriter() { finish(); }

    AsyncFileWriter(const AsyncFileWriter&) = delete;
    AsyncFileWriter& operator=(const AsyncFileWriter&) = delete;

    JobStatePtr make_job(
        std::size_t max_inflight_bytes = 0,
        std::shared_ptr<std::atomic<bool>> cancel_token = nullptr
    ) {
        if (max_inflight_bytes == 0) {
            max_inflight_bytes = kDefaultJobInFlightBytes;
        }
        auto job = std::make_shared<JobState>(max_inflight_bytes, std::move(cancel_token));
        std::lock_guard<std::mutex> lock(mutex_);
        synchronize_cancellation_locked(job);
        active_jobs_.push_back(job);
        return job;
    }

    FileStatePtr make_file(
        const JobStatePtr& job,
        std::wstring path,
        std::wstring item_path,
        UInt32 item_index,
        std::size_t trace_index
    ) {
        auto file = std::make_shared<FileState>(
            job ? job : make_job(),
            std::move(path), std::move(item_path), item_index, trace_index);
        std::lock_guard<std::mutex> lock(mutex_);
        active_files_.push_back(file);
        ++inflight_file_count_;
        return file;
    }

    HRESULT write(
        const FileStatePtr& file,
        const void* data,
        UInt32 size,
        UInt32* processed_size
    ) {
        if (processed_size) {
            *processed_size = 0;
        }
        if (!file || (size != 0 && data == nullptr)) {
            return E_POINTER;
        }
        if (size == 0) {
            return S_OK;
        }

        const auto* source = static_cast<const unsigned char*>(data);
        UInt32 consumed = 0;
        const auto job = file->job;
        if (!job) {
            return E_FAIL;
        }
        // 7-Zip normally calls an output stream serially, but keeping this
        // lock here makes the writer API safe for concurrent callers of the
        // same file without serializing producers for other files.
        std::unique_lock<std::mutex> producer_lock(file->producer_mutex);
        while (consumed < size) {
            bool queued_staging = false;
            bool newly_acquired_staging = false;
            UInt32 previous_size = 0;
            UInt32 chunk = 0;
            HRESULT setup_error = S_OK;
            {
                std::unique_lock<std::mutex> lock(mutex_);
                producer_cv_.wait(lock, [this, &job, &file] {
                    return terminal_result_locked(job) != S_OK || file->close_requested ||
                        can_accept_locked(job, file);
                });
                const HRESULT error = terminal_result_locked(job);
                if (error != S_OK || file->close_requested) {
                    if (processed_size) {
                        *processed_size = consumed;
                    }
                    return error == S_OK ? E_ABORT : error;
                }

                // A full staging buffer is not writable.  Move ownership to
                // the queue before obtaining the next pool buffer.
                if (file->staging_buffer && file->staging_buffer->size == kBufferSize) {
                    queued_staging = enqueue_staging_locked(file, false);
                    if (!queued_staging) {
                        const HRESULT enqueue_error = terminal_result_locked(job);
                        if (enqueue_error != S_OK) {
                            if (processed_size) {
                                *processed_size = consumed;
                            }
                            return enqueue_error;
                        }
                        continue;
                    }
                }

                Buffer* buffer = file->staging_buffer;
                if (!buffer) {
                    if (free_buffers_.empty()) {
                        continue;
                    }
                    // Reuse the most recently completed buffer first.  This
                    // keeps the lazily allocated pool working set bounded by
                    // the actual in-flight concurrency instead of touching
                    // every buffer in the FIFO pool over time.
                    buffer = free_buffers_.back();
                    free_buffers_.pop_back();
                    try {
                        if (!buffer->data) {
                            buffer->data = std::make_unique<unsigned char[]>(kBufferSize);
                        }
                        buffer->file = file;
                        buffer->size = 0;
                        file->staging_buffer = buffer;
                        newly_acquired_staging = true;
                    } catch (...) {
                        free_buffers_.push_back(buffer);
                        mark_file_failure_locked(file, E_OUTOFMEMORY, ERROR_OUTOFMEMORY);
                        set_job_error_locked(job, E_OUTOFMEMORY, ERROR_OUTOFMEMORY);
                        setup_error = E_OUTOFMEMORY;
                    }
                }
                if (setup_error != S_OK) {
                    // The buffer was returned to the pool and is not visible
                    // from FileState after an allocation failure.
                } else {
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
                    if (chunk_size == 0) {
                        if (newly_acquired_staging) {
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

            if (setup_error != S_OK) {
                producer_cv_.notify_all();
                if (processed_size) {
                    *processed_size = consumed;
                }
                return setup_error;
            }

            // The pool Buffer is the staging buffer itself.  There is no
            // temporary callback-sized allocation or second staging copy.
            std::memcpy(
                file->staging_buffer->data.get() + previous_size,
                source + consumed,
                chunk);

            HRESULT enqueue_result = S_OK;
            {
                std::unique_lock<std::mutex> lock(mutex_);
                const HRESULT error = terminal_result_locked(job);
                Buffer* buffer = file->staging_buffer;
                if (error != S_OK || file->close_requested || !buffer) {
                    job->inflight_bytes -= chunk;
                    file->inflight_bytes -= chunk;
                    if (newly_acquired_staging && buffer && buffer->size == previous_size) {
                        file->staging_buffer = nullptr;
                        buffer->file.reset();
                        buffer->size = 0;
                        free_buffers_.push_back(buffer);
                    }
                    if (processed_size) {
                        *processed_size = consumed;
                    }
                    enqueue_result = error == S_OK ? E_ABORT : error;
                } else {
                    buffer->size = previous_size + chunk;
                    if (previous_size == 0) {
                        ++job->pending_jobs;
                        ++file->outstanding_data;
                    }
                    file->accepted_bytes.fetch_add(chunk, std::memory_order_relaxed);
                    account_accepted(chunk);
                    consumed += chunk;
                    if (buffer->size == kBufferSize) {
                        queued_staging = enqueue_staging_locked(file, false);
                        if (!queued_staging && terminal_result_locked(job) == S_OK) {
                            enqueue_result = E_FAIL;
                        } else if (!queued_staging) {
                            enqueue_result = terminal_result_locked(job);
                        }
                    }
                }
            }
            if (enqueue_result != S_OK) {
                producer_cv_.notify_all();
                if (processed_size) {
                    *processed_size = consumed;
                }
                return enqueue_result;
            }
            if (queued_staging) {
                work_cv_.notify_one();
            }
        }

        if (processed_size) {
            *processed_size = consumed;
        }
        return S_OK;
    }

    void close_file(
        const FileStatePtr& file,
        UInt32 output_crc32,
        bool has_output_crc32,
        std::vector<unsigned char> magic
    ) noexcept {
        if (!file) {
            return;
        }

        std::unique_lock<std::mutex> producer_lock(file->producer_mutex);
        bool queued_close = false;
        bool queued_data = false;
        bool direct_close = false;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (file->close_requested) {
                return;
            }
            synchronize_cancellation_locked(file->job);
            file->close_requested = true;
            file->output_crc32 = output_crc32;
            file->has_output_crc32 = has_output_crc32;
            file->magic = std::move(magic);
            if (file->job) {
                // Reserve the close before the last data completion can wake finish_job().
                ++file->job->pending_jobs;
            }
            if (terminal_result_locked(file->job) != S_OK) {
                discard_staging_locked(file);
            } else if (file->staging_buffer) {
                // Closing is a producer-side flush boundary.  It must not be
                // blocked by the normal queue watermark.
                queued_data = enqueue_staging_locked(file, true);
            }
            if (file->outstanding_data == 0) {
                queued_close = enqueue_close_locked(file, &direct_close);
            }
        }
        if (queued_data) {
            work_cv_.notify_one();
        }
        if (queued_close) {
            work_cv_.notify_one();
        }
        if (direct_close) {
            process_close(file);
        }
        producer_cv_.notify_all();
    }

    HRESULT finish_job(const JobStatePtr& job) noexcept {
        if (!job) {
            return E_FAIL;
        }
        bool cancelled = false;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            synchronize_cancellation_locked(job);
            cancelled = terminal_result_locked(job) != S_OK;
        }
        if (cancelled) {
            cleanup_cancelled_staging(job);
        }
        std::unique_lock<std::mutex> lock(mutex_);
        producer_cv_.wait(lock, [&job] {
            return job->pending_jobs == 0;
        });
        const HRESULT result = terminal_result_locked(job);
        unregister_job_locked(job);
        if (result == S_OK) {
            meters_->counters.completed_jobs.fetch_add(1, std::memory_order_relaxed);
            state_->counters.completed_jobs.fetch_add(1, std::memory_order_relaxed);
        }
        return result;
    }

    void cancel_job(const JobStatePtr& job) noexcept {
        if (!job) {
            return;
        }
        {
            std::lock_guard<std::mutex> lock(mutex_);
            cancel_job_locked(job);
        }
        cleanup_cancelled_staging(job);
        work_cv_.notify_all();
        producer_cv_.notify_all();
    }

    void wake_waiters() noexcept {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            for (auto it = active_jobs_.begin(); it != active_jobs_.end();) {
                if (const auto job = it->lock()) {
                    synchronize_cancellation_locked(job);
                    ++it;
                } else {
                    it = active_jobs_.erase(it);
                }
            }
        }
        producer_cv_.notify_all();
    }

    HRESULT current_error(const JobStatePtr& job) noexcept {
        if (!job) {
            return E_FAIL;
        }
        std::lock_guard<std::mutex> lock(mutex_);
        synchronize_cancellation_locked(job);
        return terminal_result_locked(job);
    }

    int current_win32_error(const JobStatePtr& job) noexcept {
        if (!job) {
            return ERROR_INVALID_STATE;
        }
        std::lock_guard<std::mutex> lock(mutex_);
        synchronize_cancellation_locked(job);
        return current_win32_error_locked(job);
    }

    UInt64 accepted_bytes(const FileStatePtr& file) const noexcept {
        return file ? file->accepted_bytes.load(std::memory_order_relaxed) : 0;
    }

    Metrics snapshot_metrics() const noexcept {
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

    // True when this facility holds no outstanding work: no queued items, no
    // open or in-flight files and no registered job.
    //
    // "Open" rather than "referenced": extraction callbacks legitimately keep
    // strong FileState references for the whole job (they snapshot file results at
    // finalize), so counting live references would make a facility unreclaimable
    // forever.  What matters for reclamation is that no write work remains.
    bool is_quiescent() const noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        if (queued_jobs_ != 0 || inflight_file_count_ != 0) {
            return false;
        }
        for (const auto& weak_job : active_jobs_) {
            if (!weak_job.expired()) {
                return false;
            }
        }
        return true;
    }

    // True while any job is still registered, i.e. finish_job() has not completed
    // for every make_job().  The pending gauge alone is not an idle signal: a job
    // can legitimately drain to zero bytes between chunks while its extraction is
    // still running.
    bool has_active_jobs() const noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& weak_job : active_jobs_) {
            if (!weak_job.expired()) {
                return true;
            }
        }
        return false;
    }

    void record_operation_result(const FileStatePtr& file, Int32 operation_result) noexcept {
        if (!file) {
            return;
        }
        std::lock_guard<std::mutex> lock(mutex_);
        file->operation_result = operation_result;
        file->operation_result_set = true;
    }

    FileSnapshot snapshot_file(const FileStatePtr& file) const {
        FileSnapshot snapshot;
        if (!file) {
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

    void finish() noexcept {
        std::vector<JobStatePtr> jobs;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            stopping_ = true;
            for (const auto& weak_job : active_jobs_) {
                if (const auto job = weak_job.lock()) {
                    cancel_job_locked(job);
                    jobs.push_back(job);
                }
            }
        }
        for (const auto& job : jobs) {
            cleanup_cancelled_staging(job);
        }
        // Writer threads still drain queued data and deferred Close work before exiting.
        work_cv_.notify_all();
        producer_cv_.notify_all();
        for (auto& worker : workers_) {
            if (worker.joinable()) {
                worker.join();
            }
        }
    }

private:
    void initialize() {
        buffers_.reserve(buffer_count_);
        for (std::size_t index = 0; index < buffer_count_; ++index) {
            auto buffer = std::make_unique<Buffer>();
            free_buffers_.push_back(buffer.get());
            buffers_.push_back(std::move(buffer));
        }
        workers_.reserve(writer_count_);
        try {
            for (std::size_t index = 0; index < writer_count_; ++index) {
                workers_.emplace_back([this] { writer_loop(); });
            }
        } catch (...) {
            {
                std::lock_guard<std::mutex> lock(mutex_);
                stopping_ = true;
            }
            work_cv_.notify_all();
            for (auto& worker : workers_) {
                if (worker.joinable()) {
                    worker.join();
                }
            }
            throw;
        }
    }

    bool write_through() const noexcept { return config_.write_through; }

    // The only writers of the byte counters.  Keeping every byte through exactly
    // one of these three paths is what makes the accounting identity hold:
    //   accepted = written + discarded + pending
    // Do not add fetch_add calls on the counters anywhere else.  Each path feeds
    // two sinks: the volume's own meters (diagnostics) and the process-wide meters
    // (the controller's only input).
    void account_accepted(std::size_t bytes) noexcept {
        const std::uint64_t value = static_cast<std::uint64_t>(bytes);
        meters_->counters.accepted_bytes.fetch_add(value, std::memory_order_relaxed);
        meters_->counters.pending_bytes.fetch_add(value, std::memory_order_relaxed);
        state_->counters.accepted_bytes.fetch_add(value, std::memory_order_relaxed);
        state_->counters.pending_bytes.fetch_add(value, std::memory_order_relaxed);
    }

    void account_written(std::size_t bytes) noexcept {
        const std::uint64_t value = static_cast<std::uint64_t>(bytes);
        meters_->counters.written_bytes.fetch_add(value, std::memory_order_relaxed);
        state_->counters.written_bytes.fetch_add(value, std::memory_order_relaxed);
        account_pending_release(bytes);
    }

    void account_discarded(std::size_t bytes) noexcept {
        if (bytes == 0) {
            return;
        }
        const std::uint64_t value = static_cast<std::uint64_t>(bytes);
        meters_->counters.discarded_bytes.fetch_add(value, std::memory_order_relaxed);
        state_->counters.discarded_bytes.fetch_add(value, std::memory_order_relaxed);
        account_pending_release(bytes);
    }

    void account_pending_release(std::size_t bytes) noexcept {
        release_pending(meters_->counters.pending_bytes, *state_, bytes);
        release_pending(state_->counters.pending_bytes, *state_, bytes);
    }

    static void release_pending(
        std::atomic<std::uint64_t>& pending,
        VolumeState& volume,
        std::size_t bytes
    ) noexcept {
        const std::uint64_t value = static_cast<std::uint64_t>(bytes);
        // Saturating release: the gauge must never wrap, so a bug degrades into a
        // stuck gauge instead of an enormous one.  Saturation would also hide an
        // over-release -- freeing more than was ever pending reads as "idle" to
        // the controller -- so debug builds assert it and release builds count it
        // per volume for the diagnostics.
#ifndef NDEBUG
        const std::uint64_t previous = pending.fetch_sub(value, std::memory_order_relaxed);
        assert(previous >= value && "pending gauge over-released: a byte was accounted twice");
#else
        std::uint64_t current = pending.load(std::memory_order_relaxed);
        for (;;) {
            if (current < value) {
                volume.accounting_violations.fetch_add(1, std::memory_order_relaxed);
            }
            const std::uint64_t next = current > value ? current - value : 0;
            if (pending.compare_exchange_weak(
                    current, next, std::memory_order_relaxed, std::memory_order_relaxed)) {
                return;
            }
        }
#endif
    }

    void set_job_error_locked(const JobStatePtr& job, HRESULT hr, int win32_error) noexcept {
        if (job && job->first_error == S_OK) {
            job->first_error = hr;
            job->first_win32_error = win32_error;
        }
    }

    void cancel_job_locked(const JobStatePtr& job) noexcept {
        if (!job) {
            return;
        }
        job->cancelled = true;
        set_job_error_locked(job, E_ABORT, ERROR_OPERATION_ABORTED);
    }

    void synchronize_cancellation_locked(const JobStatePtr& job) noexcept {
        if (job && job->cancel_token && job->cancel_token->load(std::memory_order_acquire)) {
            cancel_job_locked(job);
        }
    }

    HRESULT terminal_result_locked(const JobStatePtr& job) const noexcept {
        if (!job) {
            return E_FAIL;
        }
        if (job->first_error != S_OK) {
            return job->first_error;
        }
        return (job->cancelled || stopping_) ? E_ABORT : S_OK;
    }

    int current_win32_error_locked(const JobStatePtr& job) const noexcept {
        if (!job) {
            return ERROR_INVALID_STATE;
        }
        if (job->first_win32_error != 0) {
            return job->first_win32_error;
        }
        return (job->cancelled || stopping_) ? ERROR_OPERATION_ABORTED : 0;
    }

    bool can_accept_locked(const JobStatePtr& job, const FileStatePtr& file) const noexcept {
        if (!job || !file || file->close_requested ||
            job->inflight_bytes >= job->max_inflight_bytes ||
            file->inflight_bytes >= kDefaultFileInFlightBytes) {
            // A full staging buffer can still make progress by being queued,
            // even though it cannot accept another byte.
            return file && file->staging_buffer &&
                file->staging_buffer->size == kBufferSize &&
                queued_jobs_ < queue_limit_;
        }
        if (file->staging_buffer) {
            return file->staging_buffer->size < kBufferSize;
        }
        return !free_buffers_.empty();
    }

    void unregister_job_locked(const JobStatePtr& job) noexcept {
        for (auto it = active_jobs_.begin(); it != active_jobs_.end();) {
            const auto candidate = it->lock();
            if (!candidate || candidate.get() == job.get()) {
                it = active_jobs_.erase(it);
            } else {
                ++it;
            }
        }
    }

    void cleanup_cancelled_staging(const JobStatePtr& job) noexcept {
        if (!job) {
            return;
        }
        std::vector<FileStatePtr> files;
        try {
            std::lock_guard<std::mutex> lock(mutex_);
            for (auto it = active_files_.begin(); it != active_files_.end();) {
                if (const auto file = it->lock()) {
                    if (file->job.get() == job.get()) {
                        files.push_back(file);
                    }
                    ++it;
                } else {
                    it = active_files_.erase(it);
                }
            }
        } catch (...) {
            return;
        }

        for (const auto& file : files) {
            std::unique_lock<std::mutex> producer_lock(file->producer_mutex);
            bool queued_close = false;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                if (terminal_result_locked(job) == S_OK) {
                    continue;
                }
                discard_staging_locked(file);
                if (file->close_requested && file->outstanding_data == 0) {
                    queued_close = enqueue_close_locked(file, nullptr);
                }
            }
            if (queued_close) {
                work_cv_.notify_one();
            }
            producer_cv_.notify_all();
        }
    }

    void discard_staging_locked(const FileStatePtr& file) noexcept {
        if (!file || !file->staging_buffer) {
            return;
        }
        Buffer* buffer = file->staging_buffer;
        file->staging_buffer = nullptr;
        if (buffer->size != 0) {
            // The whole staging buffer never entered process_data(), so every byte
            // is discarded here.  Buffers that did reach process_data() settle
            // their remainder there, which keeps a partially written buffer from
            // being counted twice.
            account_discarded(buffer->size);
            if (file->inflight_bytes >= buffer->size) {
                file->inflight_bytes -= buffer->size;
            } else {
                file->inflight_bytes = 0;
            }
            if (file->outstanding_data != 0) {
                --file->outstanding_data;
            }
            if (file->job) {
                if (file->job->inflight_bytes >= buffer->size) {
                    file->job->inflight_bytes -= buffer->size;
                } else {
                    file->job->inflight_bytes = 0;
                }
                if (file->job->pending_jobs != 0) {
                    --file->job->pending_jobs;
                }
            }
        }
        buffer->file.reset();
        buffer->size = 0;
        free_buffers_.push_back(buffer);
    }

    bool enqueue_staging_locked(
        const FileStatePtr& file,
        bool force_queue
    ) noexcept {
        if (!file || !file->staging_buffer || file->staging_buffer->size == 0) {
            return false;
        }
        if (!force_queue && queued_jobs_ >= queue_limit_) {
            return false;
        }

        Buffer* buffer = file->staging_buffer;
        const UInt64 output_offset = file->next_write_offset.load(std::memory_order_relaxed);
        if (output_offset > (std::numeric_limits<UInt64>::max)() - buffer->size) {
            discard_staging_locked(file);
            mark_file_failure_locked(file, E_FAIL, ERROR_ARITHMETIC_OVERFLOW);
            set_job_error_locked(file->job, E_FAIL, ERROR_ARITHMETIC_OVERFLOW);
            return false;
        }
        try {
            // Queue allocation happens before publishing the new logical
            // offset, so an allocation failure cannot create an offset hole.
            work_queue_.emplace_back(WorkItem::data(buffer, output_offset));
        } catch (...) {
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

    bool enqueue_close_locked(const FileStatePtr& file, bool* direct_close) noexcept {
        if (!file || !file->close_requested || file->close_enqueued || file->closed ||
            file->outstanding_data != 0) {
            return false;
        }
        file->close_enqueued = true;
        try {
            work_queue_.push_back(WorkItem::close(file));
            ++queued_jobs_;
            return true;
        } catch (...) {
            mark_file_failure_locked(file, E_OUTOFMEMORY, ERROR_OUTOFMEMORY);
            set_job_error_locked(file->job, E_OUTOFMEMORY, ERROR_OUTOFMEMORY);
            if (direct_close) {
                *direct_close = true;
            }
            return false;
        }
    }

    void writer_loop() noexcept {
        for (;;) {
            WorkItem item;
            {
                std::unique_lock<std::mutex> lock(mutex_);
                work_cv_.wait(lock, [this] { return stopping_ || !work_queue_.empty(); });
                if (work_queue_.empty()) {
                    if (stopping_) {
                        break;
                    }
                    continue;
                }
                item = std::move(work_queue_.front());
                work_queue_.pop_front();
                --queued_jobs_;
            }
            producer_cv_.notify_all();

            if (item.kind == WorkItem::Kind::Data) {
                process_data(item.buffer, item.output_offset);
                release_buffer(item.buffer);
            } else {
                process_close(item.file);
            }
        }
    }

    bool open_file(const FileStatePtr& file) noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!file || file->failed) {
            return false;
        }
        if (file->handle != INVALID_HANDLE_VALUE) {
            return true;
        }
        if (file->open_attempted) {
            return false;
        }
        file->open_attempted = true;
        DWORD creation_flags = FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED;
        if (write_through()) {
            creation_flags |= FILE_FLAG_WRITE_THROUGH;
        }
        file->handle = CreateFileW(
            win32_extended_path(file->path).c_str(),
            GENERIC_WRITE,
            0,
            nullptr,
            CREATE_NEW,
            creation_flags,
            nullptr);
        if (file->handle == INVALID_HANDLE_VALUE) {
            const DWORD error = GetLastError();
            mark_file_failure_locked(file, HRESULT_FROM_WIN32(error), static_cast<int>(error));
            set_job_error_locked(file->job, HRESULT_FROM_WIN32(error), static_cast<int>(error));
            return false;
        }
        return true;
    }

    bool begin_data_write(const FileStatePtr& file) noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!file || file->failed || terminal_result_locked(file->job) != S_OK) {
            return false;
        }
        ++file->active_data_writes;
        file->peak_active_data_writes = (std::max)(
            file->peak_active_data_writes, file->active_data_writes);
        return true;
    }

    void end_data_write(const FileStatePtr& file) noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        if (file && file->active_data_writes != 0) {
            --file->active_data_writes;
        }
    }

    void add_written_bytes(const FileStatePtr& file, DWORD written) noexcept {
        // Lock-free accounting: the three account_* helpers are the only writers of
        // the byte counters, so they must not depend on mutex_ being held or free.
        account_written(written);
        std::lock_guard<std::mutex> lock(mutex_);
        if (file) {
            file->written_bytes += written;
        }
    }

    void process_data(Buffer* buffer, UInt64 output_offset) noexcept {
        if (!buffer || !buffer->file) {
            return;
        }
        const auto& file = buffer->file;
        const auto job = file->job;
        const HRESULT global_error = current_error(job);
        if (global_error != S_OK) {
            record_failure(file, global_error, current_win32_error(job), buffer->size);
            return;
        }
        if (!open_file(file) || !begin_data_write(file)) {
            const HRESULT error = current_error(job);
            if (error != S_OK) {
                record_failure(
                    file, error, current_win32_error(job), buffer->size);
            }
            return;
        }

        UInt32 transferred = 0;
        while (transferred < buffer->size) {
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
            // A failure part way through a buffer must discard only the bytes that
            // did not reach the disk; the successfully written prefix is already
            // accounted by add_written_bytes below.
            if (!started && GetLastError() != ERROR_IO_PENDING) {
                const DWORD error = GetLastError();
                end_data_write(file);
                record_failure(
                    file,
                    HRESULT_FROM_WIN32(error),
                    static_cast<int>(error),
                    buffer->size - transferred);
                return;
            }

            DWORD written = 0;
            if (!GetOverlappedResult(file->handle, &overlapped, &written, TRUE)) {
                const DWORD error = GetLastError();
                end_data_write(file);
                record_failure(
                    file,
                    HRESULT_FROM_WIN32(error),
                    static_cast<int>(error),
                    buffer->size - transferred);
                return;
            }
            if (written == 0) {
                end_data_write(file);
                record_failure(
                    file,
                    HRESULT_FROM_WIN32(ERROR_WRITE_FAULT),
                    ERROR_WRITE_FAULT,
                    buffer->size - transferred);
                return;
            }
            transferred += written;
            add_written_bytes(file, written);
        }
        end_data_write(file);
    }

    void process_close(const FileStatePtr& file) noexcept {
        if (!file) {
            return;
        }
        const auto job = file->job;
        const HRESULT global_error = current_error(job);
        if (global_error != S_OK) {
            record_failure(file, global_error, current_win32_error(job));
        }

        bool should_open = false;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            should_open = !file->failed && file->handle == INVALID_HANDLE_VALUE &&
                !file->open_attempted;
        }
        if (should_open) {
            open_file(file);
        }

        HANDLE handle = INVALID_HANDLE_VALUE;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            handle = file->handle;
            file->handle = INVALID_HANDLE_VALUE;
        }
        if (handle != INVALID_HANDLE_VALUE) {
            if (write_through() && !FlushFileBuffers(handle)) {
                const DWORD error = GetLastError();
                record_failure(file, HRESULT_FROM_WIN32(error), static_cast<int>(error));
            }
            FILETIME last_write{};
            if (GetFileTime(handle, nullptr, nullptr, &last_write)) {
                ULARGE_INTEGER ticks{};
                ticks.LowPart = last_write.dwLowDateTime;
                ticks.HighPart = last_write.dwHighDateTime;
                constexpr UInt64 unix_epoch_100ns = 116444736000000000ULL;
                if (ticks.QuadPart >= unix_epoch_100ns) {
                    std::lock_guard<std::mutex> lock(mutex_);
                    file->mtime_ns = (ticks.QuadPart - unix_epoch_100ns) * 100ULL;
                    file->has_mtime_ns = true;
                }
            }
            if (!CloseHandle(handle)) {
                const DWORD error = GetLastError();
                record_failure(file, HRESULT_FROM_WIN32(error), static_cast<int>(error));
            }
        }
        bool completed_successfully = false;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            file->closed = true;
            completed_successfully = !file->failed;
            if (job && job->pending_jobs != 0) {
                --job->pending_jobs;
            }
            if (!file->inflight_released) {
                file->inflight_released = true;
                if (inflight_file_count_ != 0) {
                    --inflight_file_count_;
                }
            }
        }
        if (completed_successfully) {
            meters_->counters.completed_files.fetch_add(1, std::memory_order_relaxed);
            state_->counters.completed_files.fetch_add(1, std::memory_order_relaxed);
        }
        producer_cv_.notify_all();
    }

    void release_buffer(Buffer* buffer) noexcept {
        if (!buffer) {
            return;
        }
        const auto file = buffer->file;
        const auto job = file ? file->job : nullptr;
        bool queued_close = false;
        bool direct_close = false;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (file) {
                file->inflight_bytes -= buffer->size;
                if (file->outstanding_data != 0) {
                    --file->outstanding_data;
                }
            }
            if (job) {
                job->inflight_bytes -= buffer->size;
                if (job->pending_jobs != 0) {
                    --job->pending_jobs;
                }
            }
            buffer->file.reset();
            buffer->size = 0;
            free_buffers_.push_back(buffer);
            if (file && file->close_requested && file->outstanding_data == 0) {
                queued_close = enqueue_close_locked(file, &direct_close);
            }
        }
        if (queued_close) {
            work_cv_.notify_one();
        }
        if (direct_close) {
            process_close(file);
        }
        producer_cv_.notify_all();
    }

    void record_failure(
        const FileStatePtr& file,
        HRESULT hr,
        int win32_error,
        std::size_t discarded_bytes = 0
    ) noexcept {
        // ``discarded_bytes`` is the caller's remainder: bytes that reached
        // process_data() but will never be written.  Callers that did not take a
        // buffer out of the queue pass 0 and let release_buffer() settle it.
        account_discarded(discarded_bytes);
        {
            std::lock_guard<std::mutex> lock(mutex_);
            mark_file_failure_locked(file, hr, win32_error);
            if (file) {
                set_job_error_locked(file->job, hr, win32_error);
            }
        }
        producer_cv_.notify_all();
    }

    static void mark_file_failure_locked(const FileStatePtr& file, HRESULT hr, int win32_error) noexcept {
        if (!file || file->failed) {
            return;
        }
        file->failed = true;
        file->hresult = hr;
        file->win32_error = win32_error;
    }

    std::vector<std::unique_ptr<Buffer>> buffers_;
    std::deque<Buffer*> free_buffers_;
    std::vector<std::thread> workers_;
    std::deque<WorkItem> work_queue_;
    std::vector<std::weak_ptr<JobState>> active_jobs_;
    std::vector<std::weak_ptr<FileState>> active_files_;
    mutable std::mutex mutex_;
    std::condition_variable producer_cv_;
    std::condition_variable work_cv_;
    // Process-wide meters.  Owned elsewhere; the writer only contributes to them.
    const std::shared_ptr<WriterMeters> meters_;
    // Volume meters and the future disk-full gate for this facility's volume.
    const VolumeStatePtr state_;
    const AsyncWriterConfig config_;
    const std::size_t writer_count_;
    const std::size_t buffer_count_;
    const std::size_t queue_limit_;
    // Live FileState count, maintained by the writer itself.  The reclaim path
    // must never have to walk the weak_ptr vector to answer this (§5.4).
    std::size_t inflight_file_count_ = 0;
    std::size_t queued_jobs_ = 0;
    bool stopping_ = false;
};

}  // namespace sunpack::sevenzip

#endif
