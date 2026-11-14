#pragma once

#include "sevenzip_sdk.hpp"

#ifdef _WIN32

#include <chrono>
#include <cstddef>

namespace sunpack::sevenzip
{
    struct AsyncWriterConfig
    {
        std::size_t threads_per_volume = 4;
        std::size_t buffer_count = 64;
        std::size_t queue_limit = 4096;
        bool write_through = false;
        std::chrono::milliseconds idle_timeout{20000};

        std::chrono::milliseconds space_poll_interval{1000};
        std::chrono::milliseconds space_status_report_interval{15000};
    };

    AsyncWriterConfig configured_async_writer_config() noexcept;

}

#endif
