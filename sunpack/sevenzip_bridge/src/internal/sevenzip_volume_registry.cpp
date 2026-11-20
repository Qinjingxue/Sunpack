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
        if (registry != nullptr && writer_)
        {
            registry->release(writer_->volume_key());
        }
        writer_.reset();
    }

    VolumeWriterRegistry::VolumeWriterRegistry(AsyncWriterConfig config,
                                               VolumeSpaceChangeSink sink,
                                               std::function<void()> on_reap_change)
        : config_(config),
          sink_(std::move(sink)),
          on_reap_change_(std::move(on_reap_change)) {}

    VolumeWriterRegistry::~VolumeWriterRegistry() { shutdown(); }

    VolumeWriterRegistry::Lease VolumeWriterRegistry::acquire(const std::string &key)
    {
        std::unique_lock<std::mutex> lock(mutex_);
        for (;;)
        {
            auto found = entries_.find(key);
            const bool new_volume = found == entries_.end();
            if (new_volume)
            {
                const bool persistent = !key.empty() && key.rfind("job:", 0) != 0;
                auto gate = key.empty() ? nullptr : std::make_shared<VolumeSpaceGate>(key, std::string{}, sink_);
                auto state = std::make_shared<VolumeState>(key, persistent, std::move(gate));
                found = entries_.emplace(key, Entry{std::move(state)}).first;
            }
            Entry &entry = found->second;
            if (entry.writer)
            {
                ++entry.leases;
                entry.reap_deadline = {};
                return Lease(this, entry.writer);
            }
            if (entry.leases != 0)
            {
                writer_ready_.wait(lock);
                continue;
            }

            // The provisional lease keeps this entry alive and lets other
            // volumes acquire writers while we start threads and create IOCP.
            entry.leases = 1;
            lock.unlock();
            std::shared_ptr<AsyncFileWriter> writer;
            try
            {
                writer = std::make_shared<AsyncFileWriter>(entry.state, config_);
            }
            catch (...)
            {
                lock.lock();
                if (new_volume) entries_.erase(key);
                else entry.leases = 0;
                lock.unlock();
                writer_ready_.notify_all();
                throw;
            }
            lock.lock();
            entry.writer = writer;
            lock.unlock();
            writer_ready_.notify_all();
            return Lease(this, std::move(writer));
        }
    }

    void VolumeWriterRegistry::release(const std::string &key) noexcept
    {
        std::shared_ptr<AsyncFileWriter> writer;
        std::chrono::steady_clock::time_point released_at;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            const auto found = entries_.find(key);
            if (found == entries_.end()) return;
            Entry &entry = found->second;
            if (entry.leases == 0 || --entry.leases != 0) return;
            if (!entry.state->persistent)
            {
                // The caller still owns the writer until Lease::reset returns.
                entries_.erase(found);
                if (!index_needs_compaction_locked()) return;
            }
            else if (config_.idle_timeout == std::chrono::milliseconds::zero())
            {
                // Keep the physical volume's gate history with no warm writer.
                entry.writer.reset();
            }
            else
            {
                released_at = std::chrono::steady_clock::now();
                entry.reap_deadline = released_at + config_.idle_timeout;
                writer = entry.writer;
            }
        }
        if (writer) writer->trim_completed_batch(released_at, config_.idle_timeout);
        if (on_reap_change_) on_reap_change_();
    }

    bool VolumeWriterRegistry::index_needs_compaction_locked() const noexcept
    {
        return entries_.bucket_count() > (std::max)(kMaxRetainedVolumeStates, entries_.size() * 4);
    }

    std::optional<std::chrono::steady_clock::time_point>
    VolumeWriterRegistry::reap_idle(std::chrono::steady_clock::time_point now)
    {
        std::vector<std::shared_ptr<AsyncFileWriter>> retired;
        std::optional<std::chrono::steady_clock::time_point> earliest;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            std::size_t retained_states = 0;
            for (auto it = entries_.begin(); it != entries_.end();)
            {
                Entry &entry = it->second;
                if (!entry.writer)
                {
                    // An initialization in progress has a provisional lease.
                    if (entry.leases == 0) ++retained_states;
                    ++it;
                    continue;
                }
                const bool armed = entry.reap_deadline != std::chrono::steady_clock::time_point{};
                if (entry.leases != 0 || !armed)
                {
                    ++it;
                    continue;
                }
                if (now < entry.reap_deadline || !entry.writer->is_quiescent())
                {
                    if (!earliest || entry.reap_deadline < *earliest) earliest = entry.reap_deadline;
                    ++it;
                    continue;
                }
                retired.push_back(std::move(entry.writer));
                entry.reap_deadline = {};
                ++retained_states;
                ++it;
            }

            if (retained_states > kMaxRetainedVolumeStates)
            {
                std::size_t to_remove = retained_states - kMaxRetainedVolumeStates;
                for (auto it = entries_.begin(); it != entries_.end() && to_remove != 0;)
                {
                    if (!it->second.writer && it->second.leases == 0)
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
            // Synthetic entries disappear in release(), before this pass.
            if (index_needs_compaction_locked())
            {
                try
                {
                    // MSVC's rehash never shrinks. Transfer the nodes so a
                    // provisional writer initialization keeps its Entry reference.
                    decltype(entries_) compact;
                    compact.reserve(entries_.size());
                    compact.merge(entries_);
                    entries_.swap(compact);
                }
                catch (const std::bad_alloc &) { /* Trimming is best effort. */ }
            }
        }

        return earliest;
    }

#ifdef SUP7Z_DEBUG
    std::size_t VolumeWriterRegistry::volume_count() const noexcept
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return entries_.size();
    }

    std::size_t VolumeWriterRegistry::volume_bucket_count() const noexcept
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return entries_.bucket_count();
    }
#endif

    std::vector<VolumeStatePtr> VolumeWriterRegistry::blocked_volumes(bool require_affected_jobs) const
    {
        std::vector<VolumeStatePtr> blocked;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            for (const auto &item : entries_)
            {
                if (require_affected_jobs && item.second.leases == 0) continue;
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
                               return !state->space_gate->blocked(require_affected_jobs);
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
            std::unique_lock<std::mutex> lock(mutex_);
            writer_ready_.wait(lock, [this] {
                return std::none_of(entries_.begin(), entries_.end(), [](const auto &item) {
                    return !item.second.writer && item.second.leases != 0;
                });
            });
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
