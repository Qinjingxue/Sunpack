// Worker executable only. Large C++ containers (SDK headers, inventories and
// decode adapters) share the same admission as the C decoder allocators.
// Small allocations keep the CRT path; no global-new policy enters Python.
#include "internal/decoder_memory.h"
#include <cstdlib>
#include <malloc.h>
#include <new>

namespace {
void *allocate(std::size_t size, std::size_t alignment = 0) {
    if (!size) size = 1;
    void *pointer;
    if (size >= SUNPACK_LARGE_ALLOCATION && alignment <= 65536 && sunpack_memory_current_context())
        pointer = sunpack_memory_alloc(size);
    else pointer = alignment ? _aligned_malloc(size, alignment) : std::malloc(size);
    if (!pointer) throw std::bad_alloc();
    return pointer;
}
void release(void *pointer, bool aligned = false) noexcept {
    if (sunpack_memory_free(pointer)) return;
    if (aligned) _aligned_free(pointer); else std::free(pointer);
}
}
void *operator new(std::size_t size) { return allocate(size); }
void *operator new[](std::size_t size) { return allocate(size); }
void operator delete(void *p) noexcept { release(p); }
void operator delete[](void *p) noexcept { release(p); }
void operator delete(void *p, std::size_t) noexcept { release(p); }
void operator delete[](void *p, std::size_t) noexcept { release(p); }
void *operator new(std::size_t size, const std::nothrow_t &) noexcept { try { return allocate(size); } catch (...) { return nullptr; } }
void *operator new[](std::size_t size, const std::nothrow_t &n) noexcept { return ::operator new(size, n); }
void operator delete(void *p, const std::nothrow_t &) noexcept { release(p); }
void operator delete[](void *p, const std::nothrow_t &) noexcept { release(p); }
void *operator new(std::size_t size, std::align_val_t alignment) { return allocate(size, static_cast<std::size_t>(alignment)); }
void *operator new[](std::size_t size, std::align_val_t alignment) { return ::operator new(size, alignment); }
void operator delete(void *p, std::align_val_t) noexcept { release(p, true); }
void operator delete[](void *p, std::align_val_t) noexcept { release(p, true); }
void operator delete(void *p, std::size_t, std::align_val_t) noexcept { release(p, true); }
void operator delete[](void *p, std::size_t, std::align_val_t) noexcept { release(p, true); }
void *operator new(std::size_t size, std::align_val_t alignment, const std::nothrow_t &) noexcept { try { return ::operator new(size, alignment); } catch (...) { return nullptr; } }
void *operator new[](std::size_t size, std::align_val_t alignment, const std::nothrow_t &n) noexcept { return ::operator new(size, alignment, n); }
void operator delete(void *p, std::align_val_t, const std::nothrow_t &) noexcept { release(p, true); }
void operator delete[](void *p, std::align_val_t, const std::nothrow_t &) noexcept { release(p, true); }
