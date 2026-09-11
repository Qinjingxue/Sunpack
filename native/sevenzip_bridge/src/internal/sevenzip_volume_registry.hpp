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

        VolumeWriterRegistry(WriterMetersPtr meters, AsyncWriterConfig config);
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
        mutable std::mutex mutex_;
        std::unordered_map<std::string, Entry> entries_;
        std::size_t reclaimed_count_ = 0;
        bool stopping_ = false;
    };

    using VolumeWriterRegistryPtr = std::shared_ptr<VolumeWriterRegistry>;

}

#endif
