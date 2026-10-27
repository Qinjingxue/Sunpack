// Manual allocator benchmark: bounded, untouched commitments; no host pressure.
#include "internal/native_memory.hpp"
#include <Psapi.h>
#include <chrono>
#include <cstdio>
#include <future>
#include <vector>

using namespace sunpack::sevenzip;
using Clock = std::chrono::steady_clock;
int main() {
    SetProcessAffinityMask(GetCurrentProcess(), 3);
    for (const auto lanes : {1, 8}) {
        std::atomic<unsigned> queries{0};
        NativeMemoryManager manager(0, [&] {
            ++queries;
            return NativeMemoryManager::query_windows(0);
        });
        std::vector<std::unique_ptr<NativeMemoryJob>> jobs;
        for (int i = 0; i < lanes; ++i) {
            jobs.push_back(std::make_unique<NativeMemoryJob>(manager));
            manager.begin(*jobs.back());
        }
        const auto start = Clock::now();
        std::vector<std::future<void>> futures;
        for (const auto &job : jobs) futures.push_back(std::async(std::launch::async, [&, job = job.get()] {
            for (int i = 0; i < 200; ++i) {
                auto *p = manager.allocate(*job, 4 << 20);
                if (!p) ExitProcess(2);
                sunpack_memory_free(p);
            }
        }));
        for (auto &future : futures) future.get();
        const auto elapsed = std::chrono::duration<double>(Clock::now() - start).count();
        for (const auto &job : jobs) manager.end(*job);
        manager.stop();
        std::printf("{\"lanes\":%d,\"allocations\":%d,\"seconds\":%.6f,\"queries\":%u}\n",
            lanes, lanes * 200, elapsed, queries.load());
    }
}
