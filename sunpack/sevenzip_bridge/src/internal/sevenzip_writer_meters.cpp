#include "sevenzip_writer_meters.hpp"

#ifdef _WIN32

#include <algorithm>
#include <cstdlib>
#include <cwchar>

namespace sunpack::sevenzip
{

    namespace
    {

        constexpr std::size_t kDefaultBufferCount = 64;
        constexpr std::size_t kMaxBufferCount = 256;

        std::size_t configured_size(
            const wchar_t *name,
            std::size_t fallback,
            std::size_t minimum,
            std::size_t maximum) noexcept
        {
            wchar_t text[32]{};
            const DWORD length = GetEnvironmentVariableW(name, text, static_cast<DWORD>(std::size(text)));
            if (length == 0 || length >= std::size(text))
            {
                return fallback;
            }
            wchar_t *end = nullptr;
            const unsigned long long parsed = std::wcstoull(text, &end, 10);
            if (end == text || *end != L'\0' || parsed < minimum || parsed > maximum)
            {
                return fallback;
            }
            return static_cast<std::size_t>(parsed);
        }

        bool configured_flag(const wchar_t *name) noexcept
        {
            wchar_t text[8]{};
            const DWORD length = GetEnvironmentVariableW(name, text, static_cast<DWORD>(std::size(text)));
            if (length != 1)
            {
                return false;
            }
            return text[0] == L'1' || text[0] == L'y' || text[0] == L'Y';
        }

    } // namespace

    AsyncWriterConfig configured_async_writer_config() noexcept
    {
        AsyncWriterConfig config;
        config.buffer_count = configured_size(
            L"SUNPACK_ASYNC_WRITER_BUFFERS", kDefaultBufferCount, 4, kMaxBufferCount);
        config.write_through = configured_flag(L"SUNPACK_ASYNC_WRITER_WRITE_THROUGH");
        const auto idle_seconds = configured_size(
            L"SUNPACK_ASYNC_WRITER_IDLE_SECONDS",
            static_cast<std::size_t>(std::chrono::duration_cast<std::chrono::seconds>(config.idle_timeout).count()),
            0, 24 * 60 * 60);
        config.idle_timeout = std::chrono::seconds(idle_seconds);

        config.space_poll_interval = std::chrono::milliseconds(configured_size(
            L"SUNPACK_VOLUME_SPACE_POLL_MS", 1000, 50, 60000));
        config.space_status_report_interval = std::chrono::milliseconds(configured_size(
            L"SUNPACK_VOLUME_SPACE_STATUS_REPORT_MS", 15000, 1000, 600000));
        return config;
    }

}

#endif
