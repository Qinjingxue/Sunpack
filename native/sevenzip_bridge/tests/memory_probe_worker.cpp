// Test executable only: exercise server-sized CPU budgets without requiring
// that many physical processors or changing production resource detection.
#include <Windows.h>
#include <cstdlib>

namespace memory_probe {
DWORD active_processor_count(WORD group) {
    const char *value = std::getenv("SUNPACK_TEST_LOGICAL_PROCESSORS");
    if (value && *value) {
        char *end = nullptr;
        const auto count = std::strtoul(value, &end, 10);
        if (*end == '\0' && count > 0 && count <= 1024)
            return static_cast<DWORD>(count);
    }
    return ::GetActiveProcessorCount(group);
}
}

#define GetActiveProcessorCount memory_probe::active_processor_count
#include "../src/worker.cpp"
#undef GetActiveProcessorCount
