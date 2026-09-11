#pragma once

// Per-output-volume write facilities.
//
// The registry routes a job to the facility for its output volume, keeps one
// AsyncFileWriter per volume, and owns the persistent per-volume state.  A job
// holds a VolumeWriterRegistry::Lease for its whole run; that lease is the only
// lifetime mechanism for a writer (docs/sevenzip_worker_per_volume_write.zh.md
// §5.3), which is a much stronger condition to prove than "every JobState and
// FileState was counted correctly".
//
// C++ must not resolve volume identity here: the worker does not link the Rust
// volume resolver, so the key always arrives in the request (§2.2).

#include "sevenzip_async_output.hpp"
#include "sevenzip_volume_state.hpp"
#include "sevenzip_writer_meters.hpp"

#ifdef _WIN32

#include <chrono>
#include <cstddef>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace sunpack::sevenzip {

class VolumeWriterRegistry final {
public:
    // RAII handle for one job's use of a volume facility.  Move-only: two jobs
    // must never share one lease, because the lease count is what keeps a writer
    // alive.
    class Lease final {
    public:
        Lease() = default;
        Lease(VolumeWriterRegistry* registry, std::shared_ptr<AsyncFileWriter> writer)
            : registry_(registry), writer_(std::move(writer)) {}

        Lease(const Lease&) = delete;
        Lease& operator=(const Lease&) = delete;

        Lease(Lease&& other) noexcept
            : registry_(other.registry_), writer_(std::move(other.writer_)) {
            other.registry_ = nullptr;
        }

        Lease& operator=(Lease&& other) noexcept {
            if (this != &other) {
                reset();
                registry_ = other.registry_;
                writer_ = std::move(other.writer_);
                other.registry_ = nullptr;
            }
            return *this;
        }

        ~Lease() { reset(); }

        bool valid() const noexcept { return writer_ != nullptr; }
        AsyncFileWriter& writer() const noexcept { return *writer_; }
        std::shared_ptr<AsyncFileWriter> writer_pointer() const noexcept { return writer_; }
        // True when this acquire call built the facility.  Reported by the caller
        // rather than logged from inside acquire(), so no callback runs while the
        // registry mutex is held.
        bool created_facility() const noexcept { return created_facility_; }
        const VolumeStatePtr& volume() const noexcept {
            return writer_ ? writer_->volume_state() : empty_state();
        }

        void reset() noexcept;

    private:
        static const VolumeStatePtr& empty_state() noexcept;

        VolumeWriterRegistry* registry_ = nullptr;
        std::shared_ptr<AsyncFileWriter> writer_;
        bool created_facility_ = false;

        friend class VolumeWriterRegistry;
    };

    VolumeWriterRegistry(WriterMetersPtr meters, AsyncWriterConfig config);
    ~VolumeWriterRegistry();

    VolumeWriterRegistry(const VolumeWriterRegistry&) = delete;
    VolumeWriterRegistry& operator=(const VolumeWriterRegistry&) = delete;

    // Returns a facility for ``key``, creating it on first use.
    //
    // Never blocks on volume readiness: a caller waiting here would pin a worker
    // thread and let one blocked volume starve the others (§6.2).  The only
    // synchronisation is the brief window in which an existing entry's writer is
    // being replaced.
    Lease acquire(const std::string& key);

    // True when no facility exists.  Used by shutdown self-checks.
    bool empty() const noexcept;

    // Volume keys with a live facility.  Diagnostics only.
    std::vector<std::string> volume_keys() const;

    // Aggregated view across every live facility.
    //
    // The controller consumes this instead of a single writer: the process-wide
    // meters already aggregate the byte counters continuously, and the per-job
    // flags have to be reduced over the facilities because one may still be
    // draining while another is idle (§6.5).
    struct Aggregate {
        WriterMeterSnapshot meters;
        std::size_t live_facilities = 0;
        bool any_active_jobs = false;
    };

    Aggregate snapshot() const;

    // Destroys facilities whose leases have all been released and whose reclaim
    // deadline has passed.
    //
    // Leases, not internal state counting, are the lifetime mechanism (§5.3): a
    // writer is only ever destroyed after the last lease on its volume is gone,
    // and the move out of the registry map happens under the lock while the
    // destruction happens after it is released, so a join never blocks the
    // registry (§6.6).  ``is_quiescent()`` is checked as a defensive assertion.
    //
    // Returns the volumes reclaimed, for logging.
    std::vector<std::string> reap_idle();

    // Earliest pending reclaim deadline, or nullopt when nothing is pending.
    // The controller parks until this instant instead of sleeping forever, so
    // reclamation keeps running while the adaptive controller is idle (§5.5).
    std::optional<std::chrono::steady_clock::time_point> next_reap_deadline() const;

    // Number of facilities reclaimed so far.  Diagnostics and tests.
    std::size_t reclaimed_count() const noexcept;

    // Drops every facility.  Writers are moved out of the map under the lock and
    // destroyed after it is released, so no join ever happens while holding the
    // registry mutex (§6.6).
    void shutdown() noexcept;

private:
    // Persistent per-volume state plus its (optional) reclaimable facility.
    // ``idle_since`` and ``reap_deadline`` are reserved for the reclamation step;
    // nothing reaps yet.
    struct Entry {
        VolumeStatePtr state;
        std::shared_ptr<AsyncFileWriter> writer;
        std::size_t leases = 0;
        std::chrono::steady_clock::time_point idle_since{};
        std::chrono::steady_clock::time_point reap_deadline{};
    };

    void release(const std::string& key) noexcept;

    const WriterMetersPtr meters_;
    const AsyncWriterConfig config_;
    mutable std::mutex mutex_;
    std::unordered_map<std::string, Entry> entries_;
    std::size_t reclaimed_count_ = 0;
    bool stopping_ = false;
};

using VolumeWriterRegistryPtr = std::shared_ptr<VolumeWriterRegistry>;

}  // namespace sunpack::sevenzip

#endif
