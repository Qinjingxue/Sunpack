#pragma once

#include "sevenzip_async_output.hpp"
#include "sevenzip_volume_state.hpp"
#include "sevenzip_writer_meters.hpp"

#ifdef _WIN32

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
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
                : registry_(std::exchange(other.registry_, nullptr)),
                  writer_(std::move(other.writer_)) {}

            Lease &operator=(Lease &&other) noexcept
            {
                if (this != &other)
                {
                    reset();
                    registry_ = std::exchange(other.registry_, nullptr);
                    writer_ = std::move(other.writer_);
                }
                return *this;
            }

            ~Lease() { reset(); }

#ifdef SUP7Z_DEBUG
            bool valid() const noexcept { return writer_ != nullptr; }
            AsyncFileWriter &writer() const noexcept { return *writer_; }
#endif
            const std::shared_ptr<AsyncFileWriter> &writer_pointer() const noexcept { return writer_; }
            const VolumeStatePtr &volume() const noexcept
            {
                return writer_ ? writer_->volume_state() : empty_state();
            }

            void reset() noexcept;

        private:
            static const VolumeStatePtr &empty_state() noexcept;

            VolumeWriterRegistry *registry_ = nullptr;
            std::shared_ptr<AsyncFileWriter> writer_;
        };

        explicit VolumeWriterRegistry(AsyncWriterConfig config,
                                      VolumeSpaceChangeSink sink = {},
                                      std::function<void()> on_reap_change = {});
        ~VolumeWriterRegistry();

        VolumeWriterRegistry(const VolumeWriterRegistry &) = delete;
        VolumeWriterRegistry &operator=(const VolumeWriterRegistry &) = delete;

        Lease acquire(const std::string &key);

#ifdef SUP7Z_DEBUG
        std::size_t volume_count() const noexcept;
        std::size_t volume_bucket_count() const noexcept;
#endif

        std::optional<std::chrono::steady_clock::time_point> reap_idle(std::chrono::steady_clock::time_point now);

        // 默认只返回仍有 affected job 的 Blocked / Probing 卷，供空间监控采样。
        // 关停路径可传 false，以便唤醒没有 job id 的 gate waiter。
        std::vector<VolumeStatePtr> blocked_volumes(bool require_affected_jobs = true) const;

        // 关停用：唤醒所有等待者，不改变任何 gate 状态。
        void abort_all_space_gates() noexcept;
        void reclaim_idle_memory();

        void shutdown() noexcept;

    private:
        static constexpr std::size_t kMaxRetainedVolumeStates = 64;

        struct Entry
        {
            VolumeStatePtr state;
            std::shared_ptr<AsyncFileWriter> writer;
            // A lease without a writer belongs to the thread initializing it.
            std::size_t leases = 0;
            std::chrono::steady_clock::time_point reap_deadline{};
        };

        void release(const std::string &key) noexcept;
        bool index_needs_compaction_locked() const noexcept;

        const AsyncWriterConfig config_;
        // gate 只在新建 entry 时创建并注入 sink；已有 entry 的 gate 不得重设。
        const VolumeSpaceChangeSink sink_;
        const std::function<void()> on_reap_change_;
        mutable std::mutex mutex_;
        std::condition_variable writer_ready_;
        std::unordered_map<std::string, Entry> entries_;
    };

    // The writer lease and the immutable job ID outlive this registration.
    class SpaceJobRegistration final
    {
    public:
        SpaceJobRegistration(const VolumeWriterRegistry::Lease &lease,
                             std::string_view job_id) noexcept
        {
            if (job_id.empty())
            {
                return;
            }
            const VolumeStatePtr &state = lease.volume();
            if (state && state->space_gate && state->space_gate->register_job(job_id))
            {
                gate_ = state->space_gate.get();
                job_id_ = job_id;
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

    private:
        VolumeSpaceGate *gate_ = nullptr;
        std::string_view job_id_;
    };

}

#endif
