#pragma once

// Metering and configuration types for the volume-scoped write path.
//
// These are split out of sevenzip_async_output.hpp because they outlive an
// individual AsyncFileWriter: the volume meters belong to the volume and the
// process-wide meters belong to the worker, while the writer itself is a
// reclaimable resource (see docs/sevenzip_worker_per_volume_write.zh.md §3).

#include "sevenzip_sdk.hpp"

#ifdef _WIN32

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>

namespace sunpack::sevenzip {

// One set of write meters.  ``accepted``, ``written`` and ``discarded`` are
// monotonic counters; ``pending`` is a gauge.  They are maintained so that the
// identity below always holds, and that is only guaranteed because every byte
// goes through exactly one of the three account_* helpers in AsyncFileWriter:
//
//     accepted_bytes = written_bytes + discarded_bytes + pending_bytes
//
// The identity is what makes ``pending_bytes`` a usable idle signal, including
// while a future disk-full pause holds bytes without writing or discarding them.
struct WriterCounters {
    std::atomic<std::uint64_t> accepted_bytes{0};
    std::atomic<std::uint64_t> written_bytes{0};
    std::atomic<std::uint64_t> discarded_bytes{0};
    std::atomic<std::uint64_t> pending_bytes{0};
    std::atomic<std::uint64_t> completed_files{0};
    std::atomic<std::uint64_t> completed_jobs{0};

    void reset() noexcept {
        accepted_bytes.store(0, std::memory_order_relaxed);
        written_bytes.store(0, std::memory_order_relaxed);
        discarded_bytes.store(0, std::memory_order_relaxed);
        pending_bytes.store(0, std::memory_order_relaxed);
        completed_files.store(0, std::memory_order_relaxed);
        completed_jobs.store(0, std::memory_order_relaxed);
    }
};

// Process-wide write meters.
//
// The controller reads these, so they must never regress: they are owned by
// whoever outlives every writer (the registry/executor) and only ever grow.
// Every writer updates its own volume meters *and* these, which is one extra
// relaxed atomic add per account call - irrelevant next to a 1 MiB buffer.
struct WriterMeters {
    WriterCounters counters;
};

using WriterMetersPtr = std::shared_ptr<WriterMeters>;

// Immutable snapshot handed to the controller and to diagnostics.
struct WriterMeterSnapshot {
    std::uint64_t accepted_bytes = 0;
    std::uint64_t written_bytes = 0;
    std::uint64_t discarded_bytes = 0;
    std::uint64_t pending_bytes = 0;
    std::uint64_t completed_files = 0;
    std::uint64_t completed_jobs = 0;

    bool operator==(const WriterMeterSnapshot& other) const noexcept {
        return accepted_bytes == other.accepted_bytes &&
            written_bytes == other.written_bytes &&
            discarded_bytes == other.discarded_bytes &&
            pending_bytes == other.pending_bytes &&
            completed_files == other.completed_files &&
            completed_jobs == other.completed_jobs;
    }
};

inline WriterMeterSnapshot snapshot_counters(const WriterCounters& counters) noexcept {
    WriterMeterSnapshot snapshot;
    snapshot.accepted_bytes = counters.accepted_bytes.load(std::memory_order_relaxed);
    snapshot.written_bytes = counters.written_bytes.load(std::memory_order_relaxed);
    snapshot.discarded_bytes = counters.discarded_bytes.load(std::memory_order_relaxed);
    snapshot.pending_bytes = counters.pending_bytes.load(std::memory_order_relaxed);
    snapshot.completed_files = counters.completed_files.load(std::memory_order_relaxed);
    snapshot.completed_jobs = counters.completed_jobs.load(std::memory_order_relaxed);
    return snapshot;
}

// Future disk-full gate.  Declared here so VolumeState owns the right slot from
// the start; nothing acts on it during the per-volume writer refactor (§8).
enum class VolumeSpaceState {
    Ready = 0,
    SpaceBlocked = 1,
};

// Write facility parameters, snapshotted once when the registry is constructed.
//
// The writer must not read the environment itself: every volume's writer has to
// be built from the same values by construction, not by "they all happen to read
// the same variables".
struct AsyncWriterConfig {
    // Threads per volume facility.  Note this is per volume, not per process:
    // SUNPACK_ASYNC_WRITER_THREADS_PER_VOLUME took over from the old global
    // SUNPACK_ASYNC_WRITER_THREADS name (§5.1).
    std::size_t threads_per_volume = 4;
    // Buffer slots.  The 1 MiB backing store is allocated lazily, so this bounds
    // the staging window rather than resident memory (§5.1.1).
    std::size_t buffer_count = 64;
    // Hard cap on queued work items.
    std::size_t queue_limit = 4096;
    bool write_through = false;
    // How long a persistent physical volume keeps its facility after its last
    // lease is released.  A non-positive value means "never reclaim", which is
    // deliberately not the same as "reclaim immediately"; synthetic per-job
    // volumes ignore this setting and are reclaimable as soon as their lease
    // drops (§5.4).
    std::chrono::milliseconds idle_timeout{20000};
};

// Environment-derived defaults.  Called once by the registry/executor.
AsyncWriterConfig configured_async_writer_config() noexcept;

}  // namespace sunpack::sevenzip

#endif
