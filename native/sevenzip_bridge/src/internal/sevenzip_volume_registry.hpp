#pragma once

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

namespace sunpack::sevenzip
{

    class VolumeWriterRegistry final
    {
    public:
        class Lease final
        {
        public:
            Lease() = default;
            Lease(VolumeWriterRegistry *registry, std::shared_ptr<AsyncFileWriter> writer)
                : registry_(registry), writer_(std::move(writer)) {}

            Lease(const Lease &) = delete;
            Lease &operator=(const Lease &) = delete;

            Lease(Lease &&other) noexcept
                : registry_(other.registry_), writer_(std::move(other.writer_))
            {
                other.registry_ = nullptr;
            }

            Lease &operator=(Lease &&other) noexcept
            {
                if (this != &other)
                {
                    reset();
                    registry_ = other.registry_;
                    writer_ = std::move(other.writer_);
                    other.registry_ = nullptr;
                }
                return *this;
            }

            ~Lease() { reset(); }

            bool valid() const noexcept { return writer_ != nullptr; }
            AsyncFileWriter &writer() const noexcept { return *writer_; }
            std::shared_ptr<AsyncFileWriter> writer_pointer() const noexcept { return writer_; }
            bool created_facility() const noexcept { return created_facility_; }
            const VolumeStatePtr &volume() const noexcept
            {
                return writer_ ? writer_->volume_state() : empty_state();
            }

            void reset() noexcept;

        private:
            static const VolumeStatePtr &empty_state() noexcept;

            VolumeWriterRegistry *registry_ = nullptr;
            std::shared_ptr<AsyncFileWriter> writer_;
            bool created_facility_ = false;

            friend class VolumeWriterRegistry;
        };

        VolumeWriterRegistry(WriterMetersPtr meters,
                             AsyncWriterConfig config,
                             VolumeSpaceChangeSink sink = {});
        ~VolumeWriterRegistry();

        VolumeWriterRegistry(const VolumeWriterRegistry &) = delete;
        VolumeWriterRegistry &operator=(const VolumeWriterRegistry &) = delete;

        Lease acquire(const std::string &key);

        bool empty() const noexcept;

        std::vector<std::string> volume_keys() const;

        struct Aggregate
        {
            WriterMeterSnapshot meters;
            std::size_t live_facilities = 0;
            bool any_active_jobs = false;
        };

        Aggregate snapshot() const;

        std::vector<std::string> reap_idle();

        std::optional<std::chrono::steady_clock::time_point> next_reap_deadline() const;

        std::size_t reclaimed_count() const noexcept;

        // 当前处于 Blocked / Probing 的卷。**快照式**：锁内拷贝 shared_ptr，
        // 锁外返回，调用方在 registry mutex_ 之外使用返回值。
        // 没有 dedup_key / facility_key / SpaceGroup / BlockedVolume 结构 ——
        // 卷身份就是 VolumeState::key。
        std::vector<VolumeStatePtr> blocked_volumes() const;

        // 关停用：对所有 blocked gate 调用 wake_waiters()。
        // **不改变任何 gate 状态**（没有 aborted_ 永久闩锁）。
        void abort_all_space_gates() noexcept;

        void shutdown() noexcept;

    private:
        struct Entry
        {
            VolumeStatePtr state;
            std::shared_ptr<AsyncFileWriter> writer;
            std::size_t leases = 0;
            std::chrono::steady_clock::time_point idle_since{};
            std::chrono::steady_clock::time_point reap_deadline{};
        };

        void release(const std::string &key) noexcept;

        const WriterMetersPtr meters_;
        const AsyncWriterConfig config_;
        // ★ ChangeSink 的唯一所有者链：
        //     NativeJobExecutor → VolumeWriterRegistry(meters, config, sink)
        //         → VolumeSpaceGate(volume_key, query_root_hint, sink)
        //   gate 只在**新建 entry** 时创建并注入 sink；已有 entry 的 gate 绝不重设。
        const VolumeSpaceChangeSink sink_;
        mutable std::mutex mutex_;
        std::unordered_map<std::string, Entry> entries_;
        std::size_t reclaimed_count_ = 0;
        bool stopping_ = false;
    };

    using VolumeWriterRegistryPtr = std::shared_ptr<VolumeWriterRegistry>;

    // ---------------------------------------------------------------------
    // `affected_jobs_` 的注册点必须在 **volume lease scope**（§4.7.1 的 P0）。
    //
    // 早期设计把 register/unregister 放在 make_job() / finish_job()，而根输出目录
    // 创建（archive_extract.cpp，满盘最常见的入口）发生在 make_job 之前 ——
    // 那次满盘会开启 episode 并发出 space_blocked 给 **0 个 job**，Python 因此
    // 不知道 job 正在合法暂停，看门狗仍按 no-progress 计时并把它杀掉。
    //
    // ⚠️ 声明顺序要求：必须写在 `auto lease = writer_registry_->acquire(key);`
    //    **之后**，这样它**先于** lease 析构（C++ 逆序析构）—— 保证"注销发生在
    //    lease 释放之前"，避免 gate 已被回收却仍在注销。
    // ---------------------------------------------------------------------
    class SpaceJobRegistration final
    {
    public:
        SpaceJobRegistration(const VolumeWriterRegistry::Lease &lease,
                             const std::string &job_id) noexcept
        {
            if (job_id.empty())
            {
                return;
            }
            const VolumeStatePtr &state = lease.volume();
            if (state && state->space_gate)
            {
                gate_ = state->space_gate;
                job_id_ = job_id;
                gate_->register_job(job_id_);
            }
        }

        ~SpaceJobRegistration()
        {
            if (gate_)
            {
                gate_->unregister_job(job_id_);
            }
        }

        SpaceJobRegistration(const SpaceJobRegistration &) = delete;
        SpaceJobRegistration &operator=(const SpaceJobRegistration &) = delete;

        bool registered() const noexcept { return gate_ != nullptr; }

    private:
        std::shared_ptr<VolumeSpaceGate> gate_;
        std::string job_id_;
    };

}

#endif
