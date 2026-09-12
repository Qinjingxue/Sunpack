#include "sevenzip_volume_registry.hpp"
#include "sevenzip_space_gate.hpp"

#ifdef _WIN32

#include <algorithm>
#include <chrono>
#include <optional>
#include <winioctl.h>
#include <utility>

namespace sunpack::sevenzip
{

    namespace
    {

        std::optional<bool> query_volume_seek_penalty(const std::string &key)
        {
            std::wstring wide_key;
            wide_key.reserve(key.size());
            for (const unsigned char value : key)
            {
                wide_key.push_back(static_cast<wchar_t>(value));
            }
            if (!is_volume_guid_key(wide_key))
            {
                // Synthetic keys and non-volume paths keep the existing configuration.
                return std::nullopt;
            }

            // CreateFileW opens the volume device itself only without a trailing slash;
            // the slash form names the volume root directory.
            const HANDLE volume = CreateFileW(
                wide_key.c_str(),
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                nullptr,
                OPEN_EXISTING,
                0,
                nullptr);
            if (volume == INVALID_HANDLE_VALUE)
            {
                return std::nullopt;
            }

            STORAGE_PROPERTY_QUERY query{};
            query.PropertyId = StorageDeviceSeekPenaltyProperty;
            query.QueryType = PropertyStandardQuery;
            DEVICE_SEEK_PENALTY_DESCRIPTOR descriptor{};
            DWORD bytes_returned = 0;
            const BOOL success = DeviceIoControl(
                volume,
                IOCTL_STORAGE_QUERY_PROPERTY,
                &query,
                sizeof(query),
                &descriptor,
                sizeof(descriptor),
                &bytes_returned,
                nullptr);
            CloseHandle(volume);

            if (!success || bytes_returned < sizeof(descriptor))
            {
                return std::nullopt;
            }
            return descriptor.IncursSeekPenalty != FALSE;
        }

        AsyncWriterConfig config_for_volume(
            const std::string &key,
            AsyncWriterConfig config)
        {
            if (query_volume_seek_penalty(key).value_or(false))
            {
                config.threads_per_volume = 1;
            }
            return config;
        }

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
            if (found == entries_.end())
            {
                const bool persistent = !key.empty() && key.rfind("job:", 0) != 0;
                Entry entry;
                entry.state = make_volume_state(key, persistent);
                found = entries_.emplace(key, std::move(entry)).first;
            }
            Entry &entry = found->second;

            // gate 懒创建且只在这里注入 sink，已有 entry 的 gate 绝不重设；
            // 功能关闭或空 key 时必须保持 nullptr，让空间判定短路。
            if (!entry.state->space_gate && !key.empty() && config_.space_gate_enabled)
            {
                // pending_bytes 是 gate 唯一拿不到的展示字段（gate 不认识 VolumeState，
                // 依赖方向必须单向）。用 weak_ptr 在 sink 包装里补齐，不能捕获
                // shared_ptr（VolumeState → gate → lambda → VolumeState = 泄漏）。
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
                    meters_, entry.state, config_for_volume(key, config_));
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

    std::vector<VolumeStatePtr> VolumeWriterRegistry::blocked_volumes() const
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
                           [](const VolumeStatePtr &state)
                           { return !state->space_gate->blocked(); }),
            blocked.end());
        return blocked;
    }

    void VolumeWriterRegistry::abort_all_space_gates() noexcept
    {
        // 关停路径：只唤醒被 blocked 的 gate，不改变任何 gate 状态。
        for (const auto &state : blocked_volumes())
        {
            state->space_gate->wake_waiters();
        }
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
