#pragma once

#include <atomic>
#include <cstddef>
#include <functional>

namespace sunpack::sevenzip
{

struct NativeCpuBudgetSnapshot
{
    std::size_t nominal_capacity = 1;
    std::size_t effective_capacity = 1;
    std::size_t reserved_credits = 0;
};

class NativeCpuBudget final
{
public:
    explicit NativeCpuBudget(
        std::size_t nominal_capacity,
        std::function<void()> capacity_available = {});

    bool try_acquire_base() noexcept;
    std::size_t acquire_up_to(
        std::size_t wanted,
        std::size_t minimum_grant = 1) noexcept;
    std::size_t acquire_all_available() noexcept;
    void release(std::size_t count) noexcept;

    void set_effective_capacity(std::size_t capacity) noexcept;

    std::size_t nominal_capacity() const noexcept;
    std::size_t effective_capacity() const noexcept;
    std::size_t reserved_credits() const noexcept;
    bool can_acquire_base() const noexcept;
    NativeCpuBudgetSnapshot snapshot() const noexcept;

private:
    const std::size_t nominal_capacity_;
    std::atomic<std::size_t> effective_capacity_;
    std::atomic<std::size_t> reserved_credits_{0};
    std::function<void()> capacity_available_;
};

struct NativeCpuJobSnapshot
{
    std::size_t current_extra_credits = 0;
    std::size_t peak_extra_credits = 0;
    std::size_t total_extra_credits_granted = 0;
};

class NativeCpuJobContext final
{
public:
    explicit NativeCpuJobContext(
        NativeCpuBudget &budget,
        std::function<void(NativeCpuJobSnapshot)> change_sink = {}) noexcept;
    ~NativeCpuJobContext();

    std::size_t acquire_extra(
        std::size_t wanted,
        std::size_t minimum_grant = 1) noexcept;
    std::size_t acquire_all_available() noexcept;
    void release_extra(std::size_t count) noexcept;
    NativeCpuJobSnapshot snapshot() const noexcept;

private:
    NativeCpuBudget *budget_;
    std::atomic<std::size_t> current_extra_{0};
    std::atomic<std::size_t> peak_extra_{0};
    std::atomic<std::size_t> total_extra_granted_{0};
    std::function<void(NativeCpuJobSnapshot)> change_sink_;
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
