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
    struct OutputDrainHandoff
    {
        void *context = nullptr;
        bool (*begin)(void *) noexcept = nullptr;
        void (*end)(void *) noexcept = nullptr;
        const std::atomic<bool> *backlog = nullptr;
    };

    explicit NativeCpuJobContext(NativeCpuBudget &budget) noexcept;
    NativeCpuJobContext(NativeCpuBudget &budget, OutputDrainHandoff handoff) noexcept;
    bool may_handoff_output_drain() const noexcept
    {
        return output_drain_.begin &&
            (!output_drain_.backlog || output_drain_.backlog->load(std::memory_order_relaxed)) &&
            !budget_.can_acquire_base() &&
            current_extra_.load(std::memory_order_relaxed) == 0;
    }
    bool begin_output_drain_wait() noexcept
    {
        // The original pressure sample armed the wait. Recheck queue state in the scheduler,
        // not capacity here: another lender may have just returned its CPU credit.
        return output_drain_.begin && output_drain_.begin(output_drain_.context);
    }
    void end_output_drain_wait() noexcept { output_drain_.end(output_drain_.context); }
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
    OutputDrainHandoff output_drain_;
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
