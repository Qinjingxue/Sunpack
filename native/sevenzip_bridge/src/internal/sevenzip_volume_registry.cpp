#include "sevenzip_volume_registry.hpp"
#include "sevenzip_space_gate.hpp"

#ifdef _WIN32

#include <algorithm>
#include <chrono>
#include <optional>
#include <utility>

namespace sunpack::sevenzip
{

    const VolumeStatePtr &VolumeWriterRegistry::Lease::empty_state() noexcept
    {
        static const VolumeStatePtr empty;
        return empty;
    }

    void VolumeWriterRegistry::Lease::reset() noexcept
    {
        VolumeWriterRegistry *registry = registry_;
        registry_ = nullptr;
        created_facility_ = false;
        if (registry != nullptr && writer_)
        {
            registry->release(writer_->volume_key());
        }
        writer_.reset();
    }

    VolumeWriterRegistry::VolumeWriterRegistry(WriterMetersPtr meters,
                                               AsyncWriterConfig config,
                                               VolumeSpaceChangeSink sink)
        : meters_(meters ? std::move(meters) : std::make_shared<WriterMeters>()),
          config_(config),
          sink_(std::move(sink)) {}

    VolumeWriterRegistry::~VolumeWriterRegistry() { shutdown(); }

    VolumeWriterRegistry::Lease VolumeWriterRegistry::acquire(const std::string &key)
    {
        std::shared_ptr<AsyncFileWriter> writer;
        bool created = false;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto found = entries_.find(key);
            // Publish a new volume only after its facility is fully constructed.
            // Failed construction otherwise leaves an entry with no reap deadline.
            Entry pending;
            Entry &entry = found == entries_.end() ? pending : found->second;
            if (found == entries_.end())
            {
                const bool persistent = !key.empty() && key.rfind("job:", 0) != 0;
                entry.state = make_volume_state(key, persistent);
            }

            if (!entry.state->space_gate && !key.empty())
            {
                std::weak_ptr<VolumeState> weak_state = entry.state;
                const VolumeSpaceChangeSink inner = sink_;
                entry.state->space_gate = std::make_shared<VolumeSpaceGate>(
                    key,
                    std::string{},
                    [weak_state, inner](const VolumeSpaceTransition &transition)
                    {
                        if (!inner)
                        {
                            return;
                        }
                        VolumeSpaceTransition enriched = transition;
                        if (const auto state = weak_state.lock())
                        {
                            enriched.pending_bytes = pending_bytes_of(state->counters);
                        }
                        inner(enriched);
                    });
            }

            if (!entry.writer)
            {
                entry.writer = std::make_shared<AsyncFileWriter>(
                    meters_, entry.state, config_);
                created = true;
            }
            ++entry.leases;
            entry.reap_deadline = std::chrono::steady_clock::time_point{};
            writer = entry.writer;
            if (found == entries_.end())
            {
                entries_.emplace(key, std::move(pending));
            }
        }
        Lease lease(this, std::move(writer));
        lease.created_facility_ = created;
        return lease;
    }

    void VolumeWriterRegistry::release(const std::string &key) noexcept
    {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto found = entries_.find(key);
            if (found == entries_.end())
            {
                return;
            }
            Entry &entry = found->second;
            if (entry.leases != 0)
            {
                --entry.leases;
            }
            if (entry.leases == 0)
            {
                const auto now = std::chrono::steady_clock::now();
                if (entry.state && entry.state->persistent)
                {
                    entry.reap_deadline = config_.idle_timeout > std::chrono::milliseconds::zero()
                                              ? now + config_.idle_timeout
                                              : std::chrono::steady_clock::time_point{};
                }
                else
                {
                    entry.reap_deadline = now;
                }
            }
        }
    }

    std::vector<std::string> VolumeWriterRegistry::reap_idle()
    {
        std::vector<std::string> reclaimed;
        std::vector<std::shared_ptr<AsyncFileWriter>> retired;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            const auto previous_size = entries_.size();
            const auto now = std::chrono::steady_clock::now();
            std::size_t retained_states = 0;
            for (auto it = entries_.begin(); it != entries_.end();)
            {
                Entry &entry = it->second;
                // Only persistent entries survive without a writer.
                if (!entry.writer)
                {
                    ++retained_states;
                    ++it;
                    continue;
                }
                const bool armed = entry.reap_deadline != std::chrono::steady_clock::time_point{};
                if (entry.leases != 0 || !armed ||
                    now < entry.reap_deadline ||
                    !entry.writer->is_quiescent())
                {
                    ++it;
                    continue;
                }
                reclaimed.push_back(it->first);
                retired.push_back(std::move(entry.writer));
                if (entry.state && entry.state->persistent)
                {
                    entry.reap_deadline = std::chrono::steady_clock::time_point{};
                    ++retained_states;
                    ++it;
                }
                else
                {
                    it = entries_.erase(it);
                }
            }

            if (retained_states > kMaxRetainedVolumeStates)
            {
                std::size_t to_remove = retained_states - kMaxRetainedVolumeStates;
                for (auto it = entries_.begin(); it != entries_.end() && to_remove != 0;)
                {
                    if (!it->second.writer)
                    {
                        it = entries_.erase(it);
                        --to_remove;
                    }
                    else
                    {
                        ++it;
                    }
                }
            }
            if (entries_.size() < previous_size &&
                entries_.bucket_count() > (std::max)(kMaxRetainedVolumeStates, entries_.size() * 4))
            {
                entries_.rehash(0);
            }
        }

        retired.clear();
        return reclaimed;
    }

    std::optional<std::chrono::steady_clock::time_point> VolumeWriterRegistry::next_reap_deadline() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        std::optional<std::chrono::steady_clock::time_point> earliest;
        for (const auto &item : entries_)
        {
            const Entry &entry = item.second;
            if (entry.leases != 0 || !entry.writer ||
                entry.reap_deadline == std::chrono::steady_clock::time_point{})
            {
                continue;
            }
            if (!earliest || entry.reap_deadline < *earliest)
            {
                earliest = entry.reap_deadline;
            }
        }
        return earliest;
    }

    std::size_t VolumeWriterRegistry::volume_count() const noexcept
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return entries_.size();
    }

    std::vector<VolumeStatePtr> VolumeWriterRegistry::blocked_volumes(bool require_affected_jobs) const
    {
        std::vector<VolumeStatePtr> blocked;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            blocked.reserve(entries_.size());
            for (const auto &item : entries_)
            {
                const VolumeStatePtr &state = item.second.state;
                // 锁内只取 shared_ptr 快照，绝不调用 gate（blocked() 自身要取 gate mutex_）。
                if (state && state->space_gate)
                {
                    blocked.push_back(state);
                }
            }
        }

        // 锁外过滤，锁序 registry -> gate。
        blocked.erase(
            std::remove_if(blocked.begin(), blocked.end(),
                           [require_affected_jobs](const VolumeStatePtr &state)
                           {
                               return !state->space_gate->blocked() ||
                                      (require_affected_jobs &&
                                       !state->space_gate->has_affected_jobs());
                           }),
            blocked.end());
        return blocked;
    }

    void VolumeWriterRegistry::reclaim_idle_memory()
    {
        std::vector<std::shared_ptr<AsyncFileWriter>> writers;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            for (const auto &entry : entries_) if (entry.second.writer) writers.push_back(entry.second.writer);
        }
        std::size_t bytes = 0;
        for (const auto &writer : writers) bytes += writer->idle_memory_bytes();
        if (bytes >= (8U << 20))
            for (const auto &writer : writers) writer->reclaim_idle_memory();
    }

    void VolumeWriterRegistry::abort_all_space_gates() noexcept
    {
        // 关停路径：只唤醒被 blocked 的 gate，不改变任何 gate 状态。
        for (const auto &state : blocked_volumes(false))
        {
            state->space_gate->wake_waiters();
        }
    }

    void VolumeWriterRegistry::shutdown() noexcept
    {
        std::vector<std::shared_ptr<AsyncFileWriter>> writers;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            for (auto &item : entries_)
            {
                if (item.second.writer)
                {
                    writers.push_back(std::move(item.second.writer));
                }
            }
            entries_.clear();
        }
        writers.clear();
    }

}

#endif
