// Test executable only. Observe exact managed commits without adding counters,
// polling or a test mode to the production allocator.
#include <Windows.h>
#include <Psapi.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <thread>
#include "memory_windows.hpp"

namespace memory_probe {
std::mutex mutex;
std::uint64_t committed = 0;
FILE *file = nullptr;
HANDLE stop = nullptr;
std::thread thread;

void sample_locked(char phase) {
    PROCESS_MEMORY_COUNTERS_EX info{};
    if (file && GetProcessMemoryInfo(GetCurrentProcess(), reinterpret_cast<PROCESS_MEMORY_COUNTERS *>(&info), sizeof(info))) {
        std::fprintf(file, "%llu,%c,%llu,%llu\n", GetTickCount64(), phase,
            static_cast<unsigned long long>(info.PrivateUsage), static_cast<unsigned long long>(committed));
        std::fflush(file);
    }
}
LPVOID WINAPI allocate(LPVOID address, SIZE_T bytes, DWORD type, DWORD protect) {
    std::lock_guard<std::mutex> lock(mutex);
    const auto result = ::VirtualAlloc(address, bytes, type, protect);
    if (result) committed += (bytes + 4095) & ~std::uint64_t{4095};
    sample_locked('A');
    return result;
}
BOOL WINAPI release(LPVOID address, SIZE_T bytes, DWORD type) {
    std::lock_guard<std::mutex> lock(mutex);
    MEMORY_BASIC_INFORMATION region{};
    VirtualQuery(address, &region, sizeof(region));
    const auto result = ::VirtualFree(address, bytes, type);
    if (result) committed -= region.RegionSize;
    sample_locked('F');
    return result;
}
}

// Only this translation unit replaces the core allocator's implementation.
// The static library's ordinary native_memory.obj is not pulled by the linker.
#define VirtualAlloc memory_probe::allocate
#define VirtualFree memory_probe::release
#include "../src/internal/native_memory.cpp"
#undef VirtualFree
#undef VirtualAlloc

namespace memory_probe {
struct Lifetime {
    Lifetime() {
        const auto path = std::getenv("SUNPACK_TEST_MEMORY_TRACE");
        if (!path) return;
        file = std::fopen(path, "w");
        if (!file) return;
        stop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        thread = std::thread([] {
            do {
                std::lock_guard<std::mutex> lock(mutex);
                sample_locked('S');
            } while (WaitForSingleObject(stop, 2) == WAIT_TIMEOUT);
        });
    }
    ~Lifetime() {
        if (!file) return;
        SetEvent(stop);
        thread.join();
        CloseHandle(stop);
        std::fclose(file);
        file = nullptr;
    }
} lifetime;
}
