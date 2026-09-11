// Measures AsyncFileWriter construction cost, which decides whether building a
// facility while holding the registry mutex is acceptable.
//
// Construction spawns threads_per_volume threads plus the buffer/event shells, so
// the question is whether that is microseconds (leave acquire() simple) or
// milliseconds (move construction out of the lock).
#include "internal/sevenzip_async_output.hpp"
#include "internal/sevenzip_volume_registry.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <string>
#include <vector>

#ifdef _WIN32

namespace {

using sunpack::sevenzip::AsyncFileWriter;
using sunpack::sevenzip::AsyncWriterConfig;
using sunpack::sevenzip::WriterMeters;
using sunpack::sevenzip::VolumeWriterRegistry;

double median(std::vector<double>& values) {
    if (values.empty()) {
        return 0.0;
    }
    std::sort(values.begin(), values.end());
    return values[values.size() / 2];
}

}  // namespace

int main() {
    constexpr int kRounds = 40;
    AsyncWriterConfig config;
    config.threads_per_volume = 4;
    config.buffer_count = 64;

    // 1. Raw construction, no registry involved.
    std::vector<double> direct;
    for (int round = 0; round < kRounds; ++round) {
        auto meters = std::make_shared<WriterMeters>();
        const auto started = std::chrono::steady_clock::now();
        {
            AsyncFileWriter writer(
                meters,
                sunpack::sevenzip::make_volume_state("probe:", true),
                config);
        }
        const auto finished = std::chrono::steady_clock::now();
        direct.push_back(
            std::chrono::duration<double, std::micro>(finished - started).count());
    }

    // 2. First acquire per volume, i.e. the path that constructs under the lock,
    //    measured across distinct volumes so each one is a cold construction.
    std::vector<double> acquire_first;
    {
        auto meters = std::make_shared<WriterMeters>();
        VolumeWriterRegistry registry(meters, config);
        for (int round = 0; round < kRounds; ++round) {
            const std::string key = "vol-" + std::to_string(round);
            const auto started = std::chrono::steady_clock::now();
            auto lease = registry.acquire(key);
            const auto finished = std::chrono::steady_clock::now();
            acquire_first.push_back(
                std::chrono::duration<double, std::micro>(finished - started).count());
        }
        registry.shutdown();
    }

    // 3. Warm acquire of an existing facility (the common case).
    std::vector<double> acquire_warm;
    {
        auto meters = std::make_shared<WriterMeters>();
        VolumeWriterRegistry registry(meters, config);
        auto warm = registry.acquire("warm");
        for (int round = 0; round < kRounds; ++round) {
            const auto started = std::chrono::steady_clock::now();
            auto lease = registry.acquire("warm");
            const auto finished = std::chrono::steady_clock::now();
            acquire_warm.push_back(
                std::chrono::duration<double, std::micro>(finished - started).count());
        }
        registry.shutdown();
    }

    std::printf("construction cost, median of %d rounds:\n", kRounds);
    std::printf("  direct AsyncFileWriter ctor        : %8.1f us\n", median(direct));
    std::printf("  registry.acquire, cold (creates)   : %8.1f us\n", median(acquire_first));
    std::printf("  registry.acquire, warm (reuses)    : %8.1f us\n", median(acquire_warm));
    std::printf(
        "  verdict: %s\n",
        median(acquire_first) < 1000.0
            ? "sub-millisecond; constructing under the registry lock is acceptable"
            : "millisecond-scale; move construction out of the registry lock");
    return 0;
}

#else

int main() { return 0; }

#endif
