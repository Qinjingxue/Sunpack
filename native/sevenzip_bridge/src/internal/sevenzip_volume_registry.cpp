#include "sevenzip_volume_registry.hpp"

#ifdef _WIN32

#include <algorithm>
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

            // ★ gate 懒创建 + 只在这里注入 sink。已有 entry 的 gate 绝不重设
            //   （persistent gate 的回调在 writer 回收 / 重建期间保持不变）。
            //   ★ 只在**功能开启**时创建：space_gate_enabled = false 时
            //     VolumeState::space_gate 必须保持 nullptr，让所有空间判定短路、
            //     走完全现状的永久失败路径（§7.3）。这也是"每次 acquire() 零新增
            //     开销"的保证（writer_construction_cost 是回归红线）。
            //   空 key 的兜底 writer（无真实卷身份）同样不创建 gate。
            if (!entry.state->space_gate && !key.empty() && config_.space_gate_enabled)
            {
                // pending_bytes 是 gate 唯一拿不到的展示字段（gate 不认识 VolumeState，
                // 依赖方向必须单向）。用 weak_ptr 在 sink 包装里补齐，**不能**捕获
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

    std::vector<VolumeStatePtr> VolumeWriterRegistry::blocked_volumes() const
    {
        std::vector<VolumeStatePtr> blocked;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            blocked.reserve(entries_.size());
            for (const auto &item : entries_)
            {
                const VolumeStatePtr &state = item.second.state;
                // 只做 shared_ptr 快照，**不在锁内调用 gate**（那会引入 registry → gate
                // 之外的额外持锁时间；blocked() 自身要取 gate mutex_）。
                if (state && state->space_gate)
                {
                    blocked.push_back(state);
                }
            }
        }

        // 锁外过滤：锁序 registry → 释放 → gate，与 reap_idle() 同序。
        blocked.erase(
            std::remove_if(blocked.begin(), blocked.end(),
                           [](const VolumeStatePtr &state)
                           { return !state->space_gate->blocked(); }),
            blocked.end());
        return blocked;
    }

    void VolumeWriterRegistry::abort_all_space_gates() noexcept
    {
        // 关停路径：只唤醒，**不改变任何 gate 状态**。
        // 被唤醒的 writer 用自己传入的 terminal predicate 决定去留；因为
        // NativeJobExecutor::stop() 已经先把所有 cancel_token 置真，谓词此刻为真。
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
