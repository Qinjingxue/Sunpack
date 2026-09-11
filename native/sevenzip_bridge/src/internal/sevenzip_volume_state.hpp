#pragma once

// Volume-scoped write state.
//
// VolumeState lifetime is the worker's, not a writer's: meters, the future
// disk-full gate and (later) free-space watching belong to the volume, while the
// AsyncFileWriter that does the work is a reclaimable resource.  Splitting the two
// is what keeps the process-wide meters continuous across writer reclamation
// (docs/sevenzip_worker_per_volume_write.zh.md §3.1/§3.3).

#include "sevenzip_writer_meters.hpp"

#ifdef _WIN32

#include <atomic>
#include <memory>
#include <string>

namespace sunpack::sevenzip {

using VolumeKey = std::string;

// Persistent state for one output volume.
//
// ``persistent`` distinguishes a real physical volume from a synthetic per-job
// key produced when volume resolution failed (§2.3): physical state is kept for
// the worker's lifetime, synthetic state is deleted together with its writer
// because the key can never be reused.
struct VolumeState {
    explicit VolumeState(VolumeKey volume_key, bool is_persistent)
        : key(std::move(volume_key)), persistent(is_persistent) {}

    const VolumeKey key;
    const bool persistent = true;

    // Per-volume meters.  Diagnostics and future per-volume policy; the
    // controller reads the process-wide WriterMeters instead.
    WriterCounters counters;

    // Future disk-full gate (§8).  Nothing acts on this yet.
    std::atomic<VolumeSpaceState> space_state{VolumeSpaceState::Ready};
};

using VolumeStatePtr = std::shared_ptr<VolumeState>;

inline VolumeStatePtr make_volume_state(VolumeKey key, bool persistent) {
    return std::make_shared<VolumeState>(std::move(key), persistent);
}

}  // namespace sunpack::sevenzip

#endif
