#include "sevenzip_volume_registry.hpp"

#ifdef _WIN32

#include <chrono>
#include <utility>

namespace sunpack::sevenzip
{

    namespace
    {

        const VolumeStatePtr &empty_volume_state() noexcept
        {
            static const VolumeStatePtr empty;
            return empty;
        }

    } // namespace

    const VolumeStatePtr &VolumeWriterRegistry::Lease::empty_state() noexcept
    {
        return empty_volume_state();
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

    VolumeWriterRegistry::VolumeWriterRegistry(WriterMetersPtr meters, AsyncWriterConfig config)
        : meters_(meters ? std::move(meters) : std::make_shared<WriterMeters>()),
          config_(config) {}

    VolumeWriterRegistry::~VolumeWriterRegistry() { shutdown(); }

    VolumeWriterRegistry::Lease VolumeWriterRegistry::acquire(const std::string &key)
    {
        std::shared_ptr<AsyncFileWriter> writer;
        bool created = false;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto found = entries_.find(key);
            if (found == entries_.end())
            {

                const bool persistent = !key.empty() && key.rfind("job:", 0) != 0;
                Entry entry;
                entry.state = make_volume_state(key, persistent);
                found = entries_.emplace(key, std::move(entry)).first;
            }
            Entry &entry = found->second;
            if (!entry.writer)
            {

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

    void VolumeWriterRegistry::release(const std::string &key) noexcept
    {
        std::shared_ptr<AsyncFileWriter> retired;
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
                entry.idle_since = std::chrono::steady_clock::now();
                if (entry.state && entry.state->persistent)
                {

                    entry.reap_deadline = config_.idle_timeout > std::chrono::milliseconds::zero()
                                              ? entry.idle_since + config_.idle_timeout
                                              : std::chrono::steady_clock::time_point{};
                }
                else
                {

                    entry.reap_deadline = entry.idle_since;
                }
            }
        }
        (void)retired;
    }

    VolumeWriterRegistry::Aggregate VolumeWriterRegistry::snapshot() const
    {
        std::vector<std::shared_ptr<AsyncFileWriter>> writers;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            writers.reserve(entries_.size());
            for (const auto &item : entries_)
            {
                if (item.second.writer)
                {
                    writers.push_back(item.second.writer);
                }
            }
        }
        Aggregate aggregate;

        aggregate.meters = snapshot_counters(meters_->counters);
        aggregate.live_facilities = writers.size();
        for (const auto &writer : writers)
        {
            if (writer->has_active_jobs())
            {
                aggregate.any_active_jobs = true;
            }
        }
        return aggregate;
    }

    std::vector<std::string> VolumeWriterRegistry::reap_idle()
    {
        std::vector<std::string> reclaimed;
        std::vector<std::shared_ptr<AsyncFileWriter>> retired;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            const auto now = std::chrono::steady_clock::now();
            for (auto it = entries_.begin(); it != entries_.end();)
            {
                Entry &entry = it->second;
                const bool armed = entry.reap_deadline != std::chrono::steady_clock::time_point{};
                if (entry.leases != 0 || !entry.writer || !armed ||
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

                    entry.writer.reset();
                    entry.idle_since = std::chrono::steady_clock::time_point{};
                    entry.reap_deadline = std::chrono::steady_clock::time_point{};
                    ++it;
                }
                else
                {

                    it = entries_.erase(it);
                }
                ++reclaimed_count_;
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

    std::size_t VolumeWriterRegistry::reclaimed_count() const noexcept
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return reclaimed_count_;
    }

    bool VolumeWriterRegistry::empty() const noexcept
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return entries_.empty();
    }

    std::vector<std::string> VolumeWriterRegistry::volume_keys() const
    {
        std::vector<std::string> keys;
        std::lock_guard<std::mutex> lock(mutex_);
        keys.reserve(entries_.size());
        for (const auto &item : entries_)
        {
            keys.push_back(item.first);
        }
        return keys;
    }

    void VolumeWriterRegistry::shutdown() noexcept
    {
        std::vector<std::shared_ptr<AsyncFileWriter>> writers;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            stopping_ = true;
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
