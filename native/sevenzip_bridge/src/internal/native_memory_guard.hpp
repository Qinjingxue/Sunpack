#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>

namespace sunpack::sevenzip
{

struct NativeMemoryGuardConfig
{
    double minimum_available_ratio = 0.10;
};

struct NativeMemoryGuardSnapshot
{
    std::size_t nominal_cpu_budget = 1;
    std::size_t effective_cpu_budget = 1;
    std::size_t budget_step = 1;
    std::uint64_t total_physical_bytes = 0;
    std::uint64_t available_physical_bytes = 0;
    double available_ratio = 0.0;
    double minimum_available_ratio = 0.10;
    bool under_pressure = false;
};

class NativeMemoryGuard final
{
public:
    NativeMemoryGuard(
        std::size_t nominal_cpu_budget,
        NativeMemoryGuardConfig config = {}) noexcept
        : nominal_cpu_budget_((std::max)(std::size_t{1}, nominal_cpu_budget)),
          effective_cpu_budget_(nominal_cpu_budget_),
          budget_step_((std::max)(std::size_t{1}, nominal_cpu_budget_ / 8)),
          minimum_available_ratio_(
              (std::max)(0.01, (std::min)(0.95, config.minimum_available_ratio)))
    {
    }

    NativeMemoryGuard(const NativeMemoryGuard &) = delete;
    NativeMemoryGuard &operator=(const NativeMemoryGuard &) = delete;

    bool observe(
        std::uint64_t total_physical_bytes,
        std::uint64_t available_physical_bytes) noexcept
    {
        if (total_physical_bytes == 0)
            return false;

        total_physical_bytes_ = total_physical_bytes;
        available_physical_bytes_ =
            (std::min)(available_physical_bytes, total_physical_bytes);
        available_ratio_ =
            static_cast<double>(available_physical_bytes_) /
            static_cast<double>(total_physical_bytes_);

        const bool pressure = available_ratio_ < minimum_available_ratio_;
        under_pressure_ = pressure;

        const std::size_t previous = effective_cpu_budget_;
        if (pressure)
        {
            effective_cpu_budget_ =
                effective_cpu_budget_ > budget_step_
                    ? effective_cpu_budget_ - budget_step_
                    : std::size_t{1};
        }
        else if (effective_cpu_budget_ < nominal_cpu_budget_)
        {
            effective_cpu_budget_ =
                (std::min)(
                    nominal_cpu_budget_,
                    effective_cpu_budget_ + budget_step_);
        }

        return effective_cpu_budget_ != previous;
    }

    NativeMemoryGuardSnapshot snapshot() const noexcept
    {
        return {
            nominal_cpu_budget_,
            effective_cpu_budget_,
            budget_step_,
            total_physical_bytes_,
            available_physical_bytes_,
            available_ratio_,
            minimum_available_ratio_,
            under_pressure_,
        };
    }

    std::size_t effective_cpu_budget() const noexcept
    {
        return effective_cpu_budget_;
    }

private:
    const std::size_t nominal_cpu_budget_;
    std::size_t effective_cpu_budget_;
    const std::size_t budget_step_;
    const double minimum_available_ratio_;

    std::uint64_t total_physical_bytes_ = 0;
    std::uint64_t available_physical_bytes_ = 0;
    double available_ratio_ = 0.0;
    bool under_pressure_ = false;
};

} // namespace sunpack::sevenzip
