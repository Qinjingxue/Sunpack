#pragma once

#include <algorithm>
#include <cstddef>

namespace sunpack::sevenzip
{

struct NativeMachineResources
{
    std::size_t logical_processors = 2;
};

struct NativeSizingPlan
{
    std::size_t thread_capacity = 1;
};

inline NativeSizingPlan derive_native_sizing_plan(
    NativeMachineResources resources) noexcept
{
    return {(std::max)(std::size_t{1}, resources.logical_processors)};
}

} // namespace sunpack::sevenzip
