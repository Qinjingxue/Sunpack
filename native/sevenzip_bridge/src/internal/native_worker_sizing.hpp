#pragma once

#include <algorithm>
#include <cstddef>

namespace sunpack::sevenzip
{

    struct NativeMachineResources
    {
        std::size_t logical_processors = 2;
    };

    struct NativeSizingOverrides
    {
        std::size_t thread_capacity = 0;
        std::size_t initial_active_jobs = 0;
    };

    struct NativeSizingTuning
    {
        // Zero means no default cap beyond the machine's logical processors.
        std::size_t maximum_thread_capacity = 0;
        std::size_t foreground_cpu_divisor = 2;
    };

    struct NativeSizingPlan
    {
        std::size_t thread_capacity = 1;
        std::size_t initial_active_jobs = 1;
        bool thread_capacity_overridden = false;
        bool initial_active_jobs_overridden = false;
    };

    inline std::size_t native_sizing_ceil_div(std::size_t value, std::size_t divisor) noexcept
    {
        if (divisor == 0)
        {
            return value;
        }
        return value / divisor + (value % divisor == 0 ? 0 : 1);
    }

    inline NativeSizingPlan derive_native_sizing_plan(
        NativeMachineResources resources,
        const NativeSizingOverrides &overrides,
        NativeSizingTuning tuning = {}) noexcept
    {
        resources.logical_processors = (std::max)(std::size_t{1}, resources.logical_processors);
        const std::size_t maximum_thread_capacity = tuning.maximum_thread_capacity == 0
                                                        ? resources.logical_processors
                                                        : (std::max)(std::size_t{1}, tuning.maximum_thread_capacity);

        NativeSizingPlan plan;
        plan.thread_capacity_overridden = overrides.thread_capacity != 0;
        plan.initial_active_jobs_overridden = overrides.initial_active_jobs != 0;

        if (plan.thread_capacity_overridden)
        {
            plan.thread_capacity = (std::max)(std::size_t{1}, (std::min)(overrides.thread_capacity, maximum_thread_capacity));
        }
        else
        {
            plan.thread_capacity = (std::max)(std::size_t{1}, (std::min)({
                                                                  resources.logical_processors,
                                                                  maximum_thread_capacity,
                                                              }));
        }

        if (plan.initial_active_jobs_overridden)
        {
            plan.initial_active_jobs = (std::max)(std::size_t{1}, (std::min)(overrides.initial_active_jobs, plan.thread_capacity));
        }
        else
        {
            const std::size_t cpu_seed = native_sizing_ceil_div(
                resources.logical_processors,
                tuning.foreground_cpu_divisor);
            plan.initial_active_jobs = (std::max)(std::size_t{1}, (std::min)({
                                                                      cpu_seed,
                                                                      plan.thread_capacity,
                                                                  }));
        }
        return plan;
    }

} // namespace sunpack::sevenzip
