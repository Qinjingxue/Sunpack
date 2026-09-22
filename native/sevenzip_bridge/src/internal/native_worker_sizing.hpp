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
};

struct NativeSizingTuning
{
    // Zero means no default cap beyond the machine's logical processors.
    std::size_t maximum_thread_capacity = 0;
};

struct NativeSizingPlan
{
    std::size_t thread_capacity = 1;
    bool thread_capacity_overridden = false;
};

inline NativeSizingPlan derive_native_sizing_plan(
    NativeMachineResources resources,
    const NativeSizingOverrides &overrides,
    NativeSizingTuning tuning = {}) noexcept
{
    resources.logical_processors =
        (std::max)(std::size_t{1}, resources.logical_processors);
    const std::size_t maximum_thread_capacity =
        tuning.maximum_thread_capacity == 0
            ? resources.logical_processors
            : (std::max)(
                  std::size_t{1},
                  tuning.maximum_thread_capacity);

    NativeSizingPlan plan;
    plan.thread_capacity_overridden = overrides.thread_capacity != 0;
    plan.thread_capacity =
        plan.thread_capacity_overridden
            ? (std::max)(
                  std::size_t{1},
                  (std::min)(
                      overrides.thread_capacity,
                      maximum_thread_capacity))
            : (std::max)(
                  std::size_t{1},
                  (std::min)(
                      resources.logical_processors,
                      maximum_thread_capacity));
    return plan;
}

} // namespace sunpack::sevenzip
