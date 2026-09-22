#include "native_cpu_budget.hpp"
#include "decoder_cpu_budget.h"

#include <algorithm>
#include <limits>
#include <utility>

namespace sunpack::sevenzip
{
namespace
{
thread_local NativeCpuJobContext *g_current_cpu_context = nullptr;
}

NativeCpuBudget::NativeCpuBudget(
    std::size_t nominal_capacity,
    std::function<void()> capacity_available)
    : nominal_capacity_((std::max)(std::size_t{1}, nominal_capacity)),
      effective_capacity_(nominal_capacity_),
      capacity_available_(std::move(capacity_available))
{
}

bool NativeCpuBudget::try_acquire_base() noexcept
{
    return acquire_up_to(1, 1) == 1;
}

std::size_t NativeCpuBudget::acquire_up_to(
    std::size_t wanted,
    std::size_t minimum_grant) noexcept
{
    if (wanted == 0)
        return 0;
    minimum_grant = (std::max)(std::size_t{1}, minimum_grant);
    if (minimum_grant > wanted)
        return 0;

    std::size_t reserved = reserved_credits_.load(std::memory_order_acquire);
    for (;;)
    {
        const std::size_t effective =
            effective_capacity_.load(std::memory_order_acquire);
        if (reserved >= effective)
            return 0;

        const std::size_t available = effective - reserved;
        const std::size_t grant = (std::min)(wanted, available);
        if (grant < minimum_grant)
            return 0;

        if (reserved_credits_.compare_exchange_weak(
                reserved,
                reserved + grant,
                std::memory_order_acq_rel,
                std::memory_order_acquire))
            return grant;
    }
}

std::size_t NativeCpuBudget::acquire_all_available() noexcept
{
    return acquire_up_to((std::numeric_limits<std::size_t>::max)(), 1);
}

void NativeCpuBudget::release(std::size_t count) noexcept
{
    if (count == 0)
        return;

    std::size_t reserved = reserved_credits_.load(std::memory_order_acquire);
    for (;;)
    {
        const std::size_t next = count >= reserved ? 0 : reserved - count;
        if (reserved_credits_.compare_exchange_weak(
                reserved,
                next,
                std::memory_order_acq_rel,
                std::memory_order_acquire))
            break;
    }

    if (capacity_available_)
        capacity_available_();
}

void NativeCpuBudget::set_effective_capacity(std::size_t capacity) noexcept
{
    const std::size_t next =
        (std::max)(std::size_t{1}, (std::min)(capacity, nominal_capacity_));
    const std::size_t previous =
        effective_capacity_.exchange(next, std::memory_order_acq_rel);
    if (next > previous && capacity_available_)
        capacity_available_();
}

std::size_t NativeCpuBudget::nominal_capacity() const noexcept
{
    return nominal_capacity_;
}

std::size_t NativeCpuBudget::effective_capacity() const noexcept
{
    return effective_capacity_.load(std::memory_order_acquire);
}

std::size_t NativeCpuBudget::reserved_credits() const noexcept
{
    return reserved_credits_.load(std::memory_order_acquire);
}

bool NativeCpuBudget::can_acquire_base() const noexcept
{
    return reserved_credits() < effective_capacity();
}

NativeCpuBudgetSnapshot NativeCpuBudget::snapshot() const noexcept
{
    return {
        nominal_capacity_,
        effective_capacity(),
        reserved_credits(),
    };
}

NativeCpuJobContext::NativeCpuJobContext(
    NativeCpuBudget &budget,
    std::function<void(NativeCpuJobSnapshot)> change_sink) noexcept
    : budget_(&budget),
      change_sink_(std::move(change_sink))
{
}

NativeCpuJobContext::~NativeCpuJobContext()
{
    const std::size_t remaining =
        current_extra_.exchange(0, std::memory_order_acq_rel);
    if (remaining != 0 && budget_)
        budget_->release(remaining);
}

std::size_t NativeCpuJobContext::acquire_extra(
    std::size_t wanted,
    std::size_t minimum_grant) noexcept
{
    if (!budget_)
        return 0;

    const std::size_t granted =
        budget_->acquire_up_to(wanted, minimum_grant);
    if (granted == 0)
        return 0;

    const std::size_t current =
        current_extra_.fetch_add(granted, std::memory_order_acq_rel) + granted;
    total_extra_granted_.fetch_add(granted, std::memory_order_relaxed);

    std::size_t peak = peak_extra_.load(std::memory_order_acquire);
    while (peak < current &&
           !peak_extra_.compare_exchange_weak(
               peak,
               current,
               std::memory_order_acq_rel,
               std::memory_order_acquire))
    {
    }
    if (change_sink_)
        change_sink_(snapshot());
    return granted;
}

std::size_t NativeCpuJobContext::acquire_all_available() noexcept
{
    if (!budget_)
        return 0;

    const std::size_t granted = budget_->acquire_all_available();
    if (granted == 0)
        return 0;

    const std::size_t current =
        current_extra_.fetch_add(granted, std::memory_order_acq_rel) + granted;
    total_extra_granted_.fetch_add(granted, std::memory_order_relaxed);

    std::size_t peak = peak_extra_.load(std::memory_order_acquire);
    while (peak < current &&
           !peak_extra_.compare_exchange_weak(
               peak,
               current,
               std::memory_order_acq_rel,
               std::memory_order_acquire))
    {
    }
    if (change_sink_)
        change_sink_(snapshot());
    return granted;
}

void NativeCpuJobContext::release_extra(std::size_t count) noexcept
{
    if (count == 0 || !budget_)
        return;

    std::size_t current = current_extra_.load(std::memory_order_acquire);
    std::size_t released = 0;
    for (;;)
    {
        released = (std::min)(count, current);
        if (current_extra_.compare_exchange_weak(
                current,
                current - released,
                std::memory_order_acq_rel,
                std::memory_order_acquire))
            break;
    }
    budget_->release(released);
    if (change_sink_)
        change_sink_(snapshot());
}

NativeCpuJobSnapshot NativeCpuJobContext::snapshot() const noexcept
{
    return {
        current_extra_.load(std::memory_order_acquire),
        peak_extra_.load(std::memory_order_acquire),
        total_extra_granted_.load(std::memory_order_acquire),
    };
}

NativeCpuContextScope::NativeCpuContextScope(
    NativeCpuJobContext *context) noexcept
    : previous_(g_current_cpu_context)
{
    g_current_cpu_context = context;
}

NativeCpuContextScope::~NativeCpuContextScope()
{
    g_current_cpu_context = previous_;
}

NativeCpuJobContext *current_native_cpu_job_context() noexcept
{
    return g_current_cpu_context;
}

} // namespace sunpack::sevenzip

extern "C"
{

void *sunpack_cpu_current_job_context(void)
{
    return static_cast<void *>(
        sunpack::sevenzip::current_native_cpu_job_context());
}

unsigned sunpack_cpu_acquire_extra_for_context(
    void *context,
    unsigned wanted,
    unsigned minimum_grant)
{
    auto *job = static_cast<sunpack::sevenzip::NativeCpuJobContext *>(context);
    if (!job)
        return wanted;
    return static_cast<unsigned>(
        job->acquire_extra(wanted, minimum_grant));
}

unsigned sunpack_cpu_acquire_all_available_for_context(
    void *context)
{
    auto *job = static_cast<sunpack::sevenzip::NativeCpuJobContext *>(context);
    if (!job)
        return 0;
    return static_cast<unsigned>(job->acquire_all_available());
}

void sunpack_cpu_release_extra_for_context(
    void *context,
    unsigned count)
{
    auto *job = static_cast<sunpack::sevenzip::NativeCpuJobContext *>(context);
    if (job)
        job->release_extra(count);
}

unsigned sunpack_cpu_acquire_extra(
    unsigned wanted,
    unsigned minimum_grant)
{
    return sunpack_cpu_acquire_extra_for_context(
        sunpack_cpu_current_job_context(),
        wanted,
        minimum_grant);
}

unsigned sunpack_cpu_acquire_all_available(void)
{
    return sunpack_cpu_acquire_all_available_for_context(
        sunpack_cpu_current_job_context());
}

void sunpack_cpu_release_extra(unsigned count)
{
    sunpack_cpu_release_extra_for_context(
        sunpack_cpu_current_job_context(),
        count);
}

} // extern "C"
