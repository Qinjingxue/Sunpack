// Link the identical allocator against a test-only Windows availability query.
#include "memory_windows.hpp"
#include "../src/internal/decoder_memory.h"
#include <cstdint>
#include <cstdlib>

namespace {
// Existing resource tests miss global-new/delete calls outside the registry's
// lifetime. Check both process edges in the worker they already launch, with
// no additional archive, process or timing-dependent repetition.
struct AllocationLifetimeProbe {
    static void check() {
        // An aligned address need not belong to our VirtualAlloc registry.
        auto *unmanaged = reinterpret_cast<void *>(std::uintptr_t{65536});
        if (sunpack_memory_size(unmanaged) != 0 || sunpack_memory_free(unmanaged) != 0)
            std::abort();
    }
    AllocationLifetimeProbe() { check(); }
    ~AllocationLifetimeProbe() { check(); }
} allocation_lifetime_probe;
}

#include "../src/internal/native_memory.cpp"
