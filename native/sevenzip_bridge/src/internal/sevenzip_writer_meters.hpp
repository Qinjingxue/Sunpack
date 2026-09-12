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

    // ⚠️ 这里曾有一个 `enum class VolumeSpaceState { Ready, SpaceBlocked }`。
    //    它与 `VolumeState::space_state` 原子量**全项目零读取零写入**，已删除。
    //    唯一状态定义是 sevenzip_space_gate.hpp 的 `VolumeSpacePhase`
    //    （Ready / Blocked / Probing）—— 保留两个会造成"两个真相"。
    struct AsyncWriterConfig
    {
        std::size_t threads_per_volume = 4;
        std::size_t buffer_count = 64;
        std::size_t queue_limit = 4096;
        bool write_through = false;
        std::chrono::milliseconds idle_timeout{20000};

        // --- 空间不足自动暂停/恢复（C5：只留一个总开关）---
        // ★ 默认 **true** —— 这是 Phase 6（PR-6）的最后一步（§3.13）。
        //
        //   翻转默认值的**前置条件**在合并前已全部满足：
        //     Phase 4（根输出目录纳入 gate，P0）+ Phase 5（controller rebase）
        //     + Phase 6a（native 事件）+ Phase 6b（Python space_waiting + UI）
        //     且 L4 真实满盘端到端全部通过
        //     （tests/integration/test_disk_full_pause_resume.py：
        //       T-WIN-2 / 12 / 13 / 15 / 17 / 20 / 21）。
        //
        //   R22（"默认值忘改 → 功能永不生效"）的防线是 tests/space_retry.cpp 的
        //   "Phase 6c 默认开启验收" 用例：它断言"未设置 SUNPACK_VOLUME_SPACE_GATE
        //   时必须为 true"，并同时断言 `=0` 仍能一键回退。
        bool space_gate_enabled = true;
        std::chrono::milliseconds space_poll_interval{1000};
        std::chrono::milliseconds space_status_report_interval{15000};
    };

    AsyncWriterConfig configured_async_writer_config() noexcept;

}

#endif
