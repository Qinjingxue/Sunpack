#include "sevenzip_volume_registry.hpp"

#ifdef _WIN32

#include <chrono>
#include <utility>

namespace sunpack::sevenzip {

namespace {

const VolumeStatePtr& empty_volume_state() noexcept {
    static const VolumeStatePtr empty;
    return empty;
}

}  // namespace

const VolumeStatePtr& VolumeWriterRegistry::Lease::empty_state() noexcept {
    return empty_volume_state();
}

void VolumeWriterRegistry::Lease::reset() noexcept {
    VolumeWriterRegistry* registry = registry_;
    registry_ = nullptr;
    if (registry != nullptr && writer_) {
        // Releasing the lease may arm the volume's reclaim deadline, which is why
        // the caller must reset the lease *before* it reports the job finished
        // (§6.4): active_jobs_ == 0 then implies every lease is already released.
        registry->release(writer_->volume_key());
    }
    writer_.reset();
}

VolumeWriterRegistry::VolumeWriterRegistry(WriterMetersPtr meters, AsyncWriterConfig config)
    : meters_(meters ? std::move(meters) : std::make_shared<WriterMeters>()),
      config_(config) {}

VolumeWriterRegistry::~VolumeWriterRegistry() { shutdown(); }

VolumeWriterRegistry::Lease VolumeWriterRegistry::acquire(const std::string& key) {
    std::shared_ptr<AsyncFileWriter> writer;
    bool created = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto found = entries_.find(key);
        if (found == entries_.end()) {
            // A key that never resolved is a synthetic per-job key: it can never
            // be reused, so its state must not outlive its writer (§3.3).
            const bool persistent = !key.empty() && key.rfind("job:", 0) != 0;
            Entry entry;
            entry.state = make_volume_state(key, persistent);
            found = entries_.emplace(key, std::move(entry)).first;
        }
        Entry& entry = found->second;
        if (!entry.writer) {
            // Construction spawns the facility's threads; a failure propagates to
            // the worker loop, which turns it into a job failure.
            entry.writer = std::make_shared<AsyncFileWriter>(meters_, entry.state, config_);
            created = true;
        }
        ++entry.leases;
        entry.idle_since = std::chrono::steady_clock::time_point{};
        entry.reap_deadline = std::chrono::steady_clock::time_point{};
        writer = entry.writer;
    }
    Lease lease(this, std::move(writer));
    lease.created_facility_ = created;
    return lease;
}

void VolumeWriterRegistry::release(const std::string& key) noexcept {
    std::shared_ptr<AsyncFileWriter> retired;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto found = entries_.find(key);
        if (found == entries_.end()) {
            return;
        }
        Entry& entry = found->second;
        if (entry.leases != 0) {
            --entry.leases;
        }
        if (entry.leases == 0) {
            entry.idle_since = std::chrono::steady_clock::now();
            if (entry.state && entry.state->persistent) {
                // A non-positive idle timeout means "keep this facility forever",
                // which is not the same as "reclaim on the next tick": leave the
                // deadline default so neither the reaper nor next_reap_deadline()
                // considers the entry (§5.4).
                entry.reap_deadline = config_.idle_timeout > std::chrono::milliseconds::zero()
                    ? entry.idle_since + config_.idle_timeout
                    : std::chrono::steady_clock::time_point{};
            } else {
                // A synthetic per-job key can never be reused, so it becomes
                // reclaimable as soon as its lease is gone, regardless of the
                // configured idle timeout.
                entry.reap_deadline = entry.idle_since;
            }
        }
    }
    (void)retired;
}

VolumeWriterRegistry::Aggregate VolumeWriterRegistry::snapshot() const {
    std::vector<std::shared_ptr<AsyncFileWriter>> writers;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        writers.reserve(entries_.size());
        for (const auto& item : entries_) {
            if (item.second.writer) {
                writers.push_back(item.second.writer);
            }
        }
    }
    Aggregate aggregate;
    // The byte counters come from the process-wide meters, which the writers keep
    // continuous across facility reclamation; only the per-job flags need the
    // per-facility view.
    aggregate.meters = snapshot_counters(meters_->counters);
    aggregate.live_facilities = writers.size();
    for (const auto& writer : writers) {
        if (writer->has_active_jobs()) {
            aggregate.any_active_jobs = true;
        }
    }
    return aggregate;
}

std::vector<std::string> VolumeWriterRegistry::reap_idle() {
    std::vector<std::string> reclaimed;
    std::vector<std::shared_ptr<AsyncFileWriter>> retired;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto now = std::chrono::steady_clock::now();
        for (auto it = entries_.begin(); it != entries_.end();) {
            Entry& entry = it->second;
            const bool armed = entry.reap_deadline != std::chrono::steady_clock::time_point{};
            if (entry.leases != 0 || !entry.writer || !armed ||
                now < entry.reap_deadline ||
                !entry.writer->is_quiescent()) {
                ++it;
                continue;
            }
            reclaimed.push_back(it->first);
            retired.push_back(std::move(entry.writer));
            if (entry.state && entry.state->persistent) {
                // A physical volume keeps its state and its counters for the
                // worker's lifetime; only the facility is reclaimed.
                entry.writer.reset();
                entry.idle_since = std::chrono::steady_clock::time_point{};
                entry.reap_deadline = std::chrono::steady_clock::time_point{};
                ++it;
            } else {
                // A synthetic per-job key can never be reused, so its state goes
                // with its writer instead of accumulating tombstones (§3.3).
                it = entries_.erase(it);
            }
            ++reclaimed_count_;
        }
    }
    // Destructors run here, with the registry mutex released.
    retired.clear();
    return reclaimed;
}

std::optional<std::chrono::steady_clock::time_point> VolumeWriterRegistry::next_reap_deadline() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::optional<std::chrono::steady_clock::time_point> earliest;
    for (const auto& item : entries_) {
        const Entry& entry = item.second;
        if (entry.leases != 0 || !entry.writer ||
            entry.reap_deadline == std::chrono::steady_clock::time_point{}) {
            continue;
        }
        if (!earliest || entry.reap_deadline < *earliest) {
            earliest = entry.reap_deadline;
        }
    }
    return earliest;
}

std::size_t VolumeWriterRegistry::reclaimed_count() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return reclaimed_count_;
}

bool VolumeWriterRegistry::empty() const noexcept {    std::lock_guard<std::mutex> lock(mutex_);
    return entries_.empty();
}

std::vector<std::string> VolumeWriterRegistry::volume_keys() const {
    std::vector<std::string> keys;
    std::lock_guard<std::mutex> lock(mutex_);
    keys.reserve(entries_.size());
    for (const auto& item : entries_) {
        keys.push_back(item.first);
    }
    return keys;
}

void VolumeWriterRegistry::shutdown() noexcept {
    std::vector<std::shared_ptr<AsyncFileWriter>> writers;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        stopping_ = true;
        for (auto& item : entries_) {
            if (item.second.writer) {
                writers.push_back(std::move(item.second.writer));
            }
        }
        entries_.clear();
    }
    // Every finish()/join happens with the registry mutex released.
    writers.clear();
}

}  // namespace sunpack::sevenzip

#endif
