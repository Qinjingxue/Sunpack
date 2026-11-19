#pragma once

#include <atomic>
#include <cstddef>

namespace sunpack::sevenzip
{

class NativeCpuBudget final
{
public:
    using CapacityAvailableCallback = void (*)(void *) noexcept;

    explicit NativeCpuBudget(
        std::size_t nominal_capacity,
        CapacityAvailableCallback capacity_available = nullptr,
        void *capacity_available_context = nullptr) noexcept;

    bool try_acquire_base() noexcept;
    std::size_t acquire_up_to(
        std::size_t wanted,
        std::size_t minimum_grant = 1) noexcept;
    void release(std::size_t count) noexcept;

    std::size_t reserved_credits() const noexcept;
    bool can_acquire_base() const noexcept;

private:
    const std::size_t nominal_capacity_;
    std::atomic<std::size_t> reserved_credits_{0};
    CapacityAvailableCallback capacity_available_;
    void *capacity_available_context_;
};

#ifdef SUP7Z_DEBUG
struct NativeCpuJobSnapshot
{
    std::size_t current_extra_credits = 0;
    std::size_t peak_extra_credits = 0;
};
#endif

class NativeCpuJobContext final
{
public:
    explicit NativeCpuJobContext(
        NativeCpuBudget &budget) noexcept;
    ~NativeCpuJobContext();

    std::size_t acquire_extra(
        std::size_t wanted,
        std::size_t minimum_grant = 1) noexcept;
    void release_extra(std::size_t count) noexcept;
#ifdef SUP7Z_DEBUG
    NativeCpuJobSnapshot snapshot() const noexcept;
#endif

private:
    NativeCpuBudget &budget_;
    std::atomic<std::size_t> current_extra_{0};
#ifdef SUP7Z_DEBUG
    std::atomic<std::size_t> peak_extra_{0};
#endif
};

class NativeCpuContextScope final
{
public:
    explicit NativeCpuContextScope(NativeCpuJobContext *context) noexcept;
    ~NativeCpuContextScope();

    NativeCpuContextScope(const NativeCpuContextScope &) = delete;
    NativeCpuContextScope &operator=(const NativeCpuContextScope &) = delete;

private:
    NativeCpuJobContext *previous_;
};

NativeCpuJobContext *current_native_cpu_job_context() noexcept;

} // namespace sunpack::sevenzip
