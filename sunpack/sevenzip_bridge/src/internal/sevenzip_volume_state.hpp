#pragma once

#include "sevenzip_space_gate.hpp"

#ifdef _WIN32

#include <memory>
#include <string>
#include <utility>

namespace sunpack::sevenzip
{

    using VolumeKey = std::string;
    struct VolumeState
    {
        explicit VolumeState(VolumeKey volume_key, bool is_persistent,
                             std::shared_ptr<VolumeSpaceGate> gate = {})
            : key(std::move(volume_key)), persistent(is_persistent), space_gate(std::move(gate)) {}

        const VolumeKey key;
        const bool persistent = true;

        // The gate belongs to the volume and can outlive a writer facility.
        const std::shared_ptr<VolumeSpaceGate> space_gate;
    };

    using VolumeStatePtr = std::shared_ptr<VolumeState>;

}

#endif
