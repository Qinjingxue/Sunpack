#include "sevenzip_writer_meters.hpp"

#ifdef _WIN32

#include <algorithm>
#include <cstdlib>
#include <cwchar>
#include <optional>

namespace sunpack::sevenzip
{

    namespace
    {

        constexpr std::size_t kDefaultThreadsPerVolume = 4;
        constexpr std::size_t kMaxThreadsPerVolume = 8;
        constexpr std::size_t kDefaultBufferCount = 64;
        constexpr std::size_t kMaxBufferCount = 256;
        constexpr std::size_t kDefaultQueueLimit = 4096;
        constexpr std::size_t kMaxQueueLimit = 1U << 20;
        constexpr unsigned long long kDefaultIdleTimeoutMs = 20000;
        constexpr unsigned long long kMaxIdleTimeoutMs = 24ULL * 60ULL * 60ULL * 1000ULL;

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

        unsigned long long configured_ull(
            const wchar_t *name,
            unsigned long long fallback,
            unsigned long long maximum) noexcept
        {
            wchar_t text[32]{};
            const DWORD length = GetEnvironmentVariableW(name, text, static_cast<DWORD>(std::size(text)));
            if (length == 0 || length >= std::size(text))
            {
                return fallback;
            }
            wchar_t *end = nullptr;
            const unsigned long long parsed = std::wcstoull(text, &end, 10);
            if (end == text || *end != L'\0' || parsed > maximum)
            {
                return fallback;
            }
            return parsed;
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

        // 三态：nullopt 表示"未设置"，与"显式设为假"必须可区分。
        std::optional<bool> configured_flag_value(const wchar_t *name) noexcept
        {
            wchar_t text[8]{};
            const DWORD length = GetEnvironmentVariableW(name, text, static_cast<DWORD>(std::size(text)));
            if (length == 0 || length >= std::size(text))
            {
                return std::nullopt;
            }
            return length == 1 && (text[0] == L'1' || text[0] == L'y' || text[0] == L'Y');
        }

    } // namespace

    AsyncWriterConfig configured_async_writer_config() noexcept
    {
        AsyncWriterConfig config;
        config.threads_per_volume = configured_size(
            L"SUNPACK_ASYNC_WRITER_THREADS_PER_VOLUME",
            kDefaultThreadsPerVolume,
            1,
            kMaxThreadsPerVolume);
        config.buffer_count = configured_size(
            L"SUNPACK_ASYNC_WRITER_BUFFERS", kDefaultBufferCount, 4, kMaxBufferCount);
        config.queue_limit = configured_size(
            L"SUNPACK_ASYNC_WRITER_QUEUE_LIMIT", kDefaultQueueLimit, 1, kMaxQueueLimit);
        config.write_through = configured_flag(L"SUNPACK_ASYNC_WRITER_WRITE_THROUGH");
        const unsigned long long idle_seconds = configured_ull(
            L"SUNPACK_ASYNC_WRITER_IDLE_SECONDS",
            kDefaultIdleTimeoutMs / 1000ULL,
            kMaxIdleTimeoutMs / 1000ULL);
        config.idle_timeout = std::chrono::milliseconds(idle_seconds * 1000ULL);

        // 环境变量未设置时保持结构体默认值，显式设置才覆盖。
        if (const auto flag = configured_flag_value(L"SUNPACK_VOLUME_SPACE_GATE"))
        {
            config.space_gate_enabled = *flag;
        }
        config.space_poll_interval = std::chrono::milliseconds(configured_size(
            L"SUNPACK_VOLUME_SPACE_POLL_MS", 1000, 50, 60000));
        config.space_status_report_interval = std::chrono::milliseconds(configured_size(
            L"SUNPACK_VOLUME_SPACE_STATUS_REPORT_MS", 15000, 1000, 600000));
        return config;
    }

}

#endif
