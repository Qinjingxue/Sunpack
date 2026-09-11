#pragma once

#include "sevenzip_writer_meters.hpp"

#ifdef _WIN32

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>

namespace sunpack::sevenzip
{

    using VolumeKey = std::string;
    struct VolumeState
    {
        explicit VolumeState(VolumeKey volume_key, bool is_persistent)
            : key(std::move(volume_key)), persistent(is_persistent) {}

        const VolumeKey key;
        const bool persistent = true;

        WriterCounters counters;

        std::atomic<std::uint64_t> accounting_violations{0};

        std::atomic<VolumeSpaceState> space_state{VolumeSpaceState::Ready};
    };

    using VolumeStatePtr = std::shared_ptr<VolumeState>;

    inline VolumeStatePtr make_volume_state(VolumeKey key, bool persistent)
    {
        return std::make_shared<VolumeState>(std::move(key), persistent);
    }

}

#endif
