#pragma once

#include "sevenzip_sdk.hpp"

#ifdef _WIN32

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>

namespace sunpack::sevenzip
{
    struct WriterCounters
    {
        // 每个字节只走 AsyncFileWriter 的一个 account_* 助手：
        // accepted_bytes = written_bytes + discarded_bytes + pending_bytes（pending 为 gauge）。
        std::atomic<std::uint64_t> accepted_bytes{0};
        std::atomic<std::uint64_t> written_bytes{0};
        std::atomic<std::uint64_t> discarded_bytes{0};
        std::atomic<std::uint64_t> pending_bytes{0};
        std::atomic<std::uint64_t> completed_files{0};
        std::atomic<std::uint64_t> completed_jobs{0};

        void reset() noexcept
        {
            accepted_bytes.store(0, std::memory_order_relaxed);
            written_bytes.store(0, std::memory_order_relaxed);
            discarded_bytes.store(0, std::memory_order_relaxed);
            pending_bytes.store(0, std::memory_order_relaxed);
            completed_files.store(0, std::memory_order_relaxed);
            completed_jobs.store(0, std::memory_order_relaxed);
        }
    };

    struct WriterMeters
    {
        WriterCounters counters;
    };

    using WriterMetersPtr = std::shared_ptr<WriterMeters>;

    struct WriterMeterSnapshot
    {
        std::uint64_t accepted_bytes = 0;
        std::uint64_t written_bytes = 0;
        std::uint64_t discarded_bytes = 0;
        std::uint64_t pending_bytes = 0;
        std::uint64_t completed_files = 0;
        std::uint64_t completed_jobs = 0;

        bool operator==(const WriterMeterSnapshot &other) const noexcept
        {
            return accepted_bytes == other.accepted_bytes &&
                   written_bytes == other.written_bytes &&
                   discarded_bytes == other.discarded_bytes &&
                   pending_bytes == other.pending_bytes &&
                   completed_files == other.completed_files &&
                   completed_jobs == other.completed_jobs;
        }
    };

    inline WriterMeterSnapshot snapshot_counters(const WriterCounters &counters) noexcept
    {
        WriterMeterSnapshot snapshot;
        snapshot.accepted_bytes = counters.accepted_bytes.load(std::memory_order_relaxed);
        snapshot.written_bytes = counters.written_bytes.load(std::memory_order_relaxed);
        snapshot.discarded_bytes = counters.discarded_bytes.load(std::memory_order_relaxed);
        snapshot.pending_bytes = counters.pending_bytes.load(std::memory_order_relaxed);
        snapshot.completed_files = counters.completed_files.load(std::memory_order_relaxed);
        snapshot.completed_jobs = counters.completed_jobs.load(std::memory_order_relaxed);
        return snapshot;
    }

    inline std::uint64_t pending_bytes_of(const WriterCounters &counters) noexcept
    {
        return counters.pending_bytes.load(std::memory_order_relaxed);
    }

    struct AsyncWriterConfig
    {
        std::size_t threads_per_volume = 4;
        std::size_t buffer_count = 64;
        std::size_t queue_limit = 4096;
        bool write_through = false;
        std::chrono::milliseconds idle_timeout{20000};

        // 空间 gate 总开关：环境变量未设置时保持此默认值。
        bool space_gate_enabled = true;
        std::chrono::milliseconds space_poll_interval{1000};
        std::chrono::milliseconds space_status_report_interval{15000};
    };

    AsyncWriterConfig configured_async_writer_config() noexcept;

}

#endif
