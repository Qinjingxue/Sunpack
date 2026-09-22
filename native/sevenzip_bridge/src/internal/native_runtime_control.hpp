#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>

namespace sunpack::sevenzip
{

struct NativeRuntimeSample
{
    double cpu_percent = 0.0;
    bool cpu_percent_valid = false;
};

struct NativeThroughputCounters
{
    std::uint64_t accepted_bytes = 0;
    std::uint64_t written_bytes = 0;
    std::uint64_t completed_files = 0;
    std::uint64_t completed_jobs = 0;
};

enum class NativeControllerDecision
{
    None,
    ActivityStarted,
    ActivityEnded,
    BaselineEstablished,
    BudgetReduced,
    BudgetRestored,
};

struct NativeRuntimeSnapshot
{
    std::size_t nominal_cpu_budget = 1;
    std::size_t effective_cpu_budget = 1;
    std::size_t budget_step = 1;
    std::size_t active_jobs = 0;
    NativeControllerDecision decision = NativeControllerDecision::None;
    double written_bytes_per_second = 0.0;
    double reference_bytes_per_second = 0.0;
    double observation_window_seconds = 0.0;
    std::uint64_t measurement_sequence = 0;
    bool resource_diagnostics_enabled = false;
    bool cpu_percent_valid = false;
    double cpu_percent = 0.0;
};

struct NativeRuntimeConfig
{
    bool adaptive_enabled = true;
    bool resource_diagnostics_enabled = false;
    bool measurement_diagnostics_enabled = false;
    double observation_window_seconds = 1.0;
    double throughput_change_ratio = 0.40;
};

class NativeRuntimeControl final
{
public:
    NativeRuntimeControl(
        std::size_t nominal_cpu_budget,
        NativeRuntimeConfig config = {})
        : nominal_cpu_budget_((std::max)(std::size_t{1}, nominal_cpu_budget)),
          effective_cpu_budget_(nominal_cpu_budget_),
          budget_step_((std::max)(std::size_t{1}, nominal_cpu_budget_ / 8)),
          adaptive_enabled_(config.adaptive_enabled),
          resource_diagnostics_enabled_(config.resource_diagnostics_enabled),
          measurement_diagnostics_enabled_(config.measurement_diagnostics_enabled),
          observation_window_seconds_((std::max)(0.1, config.observation_window_seconds)),
          lower_ratio_(1.0 - (std::min)(0.95, (std::max)(0.01, config.throughput_change_ratio))),
          upper_ratio_(1.0 + (std::min)(0.95, (std::max)(0.01, config.throughput_change_ratio)))
    {
    }

    NativeRuntimeControl(const NativeRuntimeControl &) = delete;
    NativeRuntimeControl &operator=(const NativeRuntimeControl &) = delete;

    bool begin_activity(const NativeThroughputCounters &counters) noexcept
    {
        effective_cpu_budget_ = nominal_cpu_budget_;
        previous_counters_ = counters;
        counters_primed_ = true;
        window_seconds_ = 0.0;
        window_written_bytes_ = 0;
        reference_bytes_per_second_ = 0.0;
        written_bytes_per_second_ = 0.0;
        reobserve_after_budget_change_ = false;
        saturation_primed_ = false;
        decision_ = NativeControllerDecision::ActivityStarted;
        active_ = true;
        return true;
    }

    bool end_activity(const NativeThroughputCounters &counters) noexcept
    {
        previous_counters_ = counters;
        counters_primed_ = true;
        window_seconds_ = 0.0;
        window_written_bytes_ = 0;
        reference_bytes_per_second_ = 0.0;
        written_bytes_per_second_ = 0.0;
        reobserve_after_budget_change_ = false;
        saturation_primed_ = false;
        decision_ = NativeControllerDecision::ActivityEnded;
        active_ = false;
        return true;
    }

    bool observe(
        const NativeRuntimeSample &sample,
        const NativeThroughputCounters &counters,
        std::size_t reserved_cpu_credits,
        double elapsed_seconds) noexcept
    {
        decision_ = NativeControllerDecision::None;
        cpu_percent_valid_ = resource_diagnostics_enabled_ && sample.cpu_percent_valid;
        cpu_percent_ = cpu_percent_valid_ ? sample.cpu_percent : 0.0;

        if (!active_ || elapsed_seconds <= 0.0)
        {
            previous_counters_ = counters;
            counters_primed_ = true;
            return false;
        }

        if (!counters_primed_)
        {
            previous_counters_ = counters;
            counters_primed_ = true;
            return false;
        }

        const std::uint64_t written_delta =
            counters.written_bytes >= previous_counters_.written_bytes
                ? counters.written_bytes - previous_counters_.written_bytes
                : 0;
        previous_counters_ = counters;

        // Throughput is meaningful for concurrency control only when the CPU
        // admission budget is exactly saturated. Under-filled intervals can
        // reflect too few runnable jobs or task-shape changes; over-filled
        // intervals can exist transiently after a non-preemptive derate. Both
        // are discarded so every learned window belongs to one exact budget.
        if (reserved_cpu_credits != effective_cpu_budget_)
        {
            window_seconds_ = 0.0;
            window_written_bytes_ = 0;
            saturation_primed_ = false;
            return false;
        }

        // The first sample that observes exact saturation only establishes the
        // start boundary. Its elapsed interval may include time before the
        // budget became full, so neither its duration nor byte delta belongs
        // to the observation window. Only subsequent continuously saturated
        // samples are accumulated.
        if (!saturation_primed_)
        {
            saturation_primed_ = true;
            window_seconds_ = 0.0;
            window_written_bytes_ = 0;
            return false;
        }

        window_seconds_ += elapsed_seconds;
        window_written_bytes_ += written_delta;

        if (window_seconds_ < observation_window_seconds_)
            return false;

        const double measured_seconds = window_seconds_;
        written_bytes_per_second_ =
            measured_seconds > 0.0
                ? static_cast<double>(window_written_bytes_) / measured_seconds
                : 0.0;
        window_seconds_ = 0.0;
        window_written_bytes_ = 0;
        ++measurement_sequence_;

        if (written_bytes_per_second_ <= 0.0)
            return false;

        if (reference_bytes_per_second_ <= 0.0 || reobserve_after_budget_change_)
        {
            reference_bytes_per_second_ = written_bytes_per_second_;
            reobserve_after_budget_change_ = false;
            decision_ = NativeControllerDecision::BaselineEstablished;
            return true;
        }

        if (!adaptive_enabled_)
            return false;

        const double ratio =
            written_bytes_per_second_ / reference_bytes_per_second_;

        if (ratio <= lower_ratio_ && effective_cpu_budget_ > 1)
        {
            effective_cpu_budget_ =
                effective_cpu_budget_ > budget_step_
                    ? effective_cpu_budget_ - budget_step_
                    : std::size_t{1};
            reobserve_after_budget_change_ = true;
            reference_bytes_per_second_ = 0.0;
            saturation_primed_ = false;
            decision_ = NativeControllerDecision::BudgetReduced;
            return true;
        }

        if (ratio >= upper_ratio_ &&
            effective_cpu_budget_ < nominal_cpu_budget_)
        {
            effective_cpu_budget_ =
                (std::min)(
                    nominal_cpu_budget_,
                    effective_cpu_budget_ + budget_step_);
            reobserve_after_budget_change_ = true;
            reference_bytes_per_second_ = 0.0;
            saturation_primed_ = false;
            decision_ = NativeControllerDecision::BudgetRestored;
            return true;
        }

        return false;
    }

    NativeRuntimeSnapshot snapshot(std::size_t active_jobs) const noexcept
    {
        return {
            nominal_cpu_budget_,
            effective_cpu_budget_,
            budget_step_,
            active_jobs,
            decision_,
            written_bytes_per_second_,
            reference_bytes_per_second_,
            observation_window_seconds_,
            measurement_sequence_,
            resource_diagnostics_enabled_,
            cpu_percent_valid_,
            cpu_percent_,
        };
    }

    std::size_t effective_cpu_budget() const noexcept
    {
        return effective_cpu_budget_;
    }

    bool resource_diagnostics_enabled() const noexcept
    {
        return resource_diagnostics_enabled_;
    }

    bool measurement_diagnostics_enabled() const noexcept
    {
        return measurement_diagnostics_enabled_;
    }

private:
    const std::size_t nominal_cpu_budget_;
    std::size_t effective_cpu_budget_;
    const std::size_t budget_step_;
    const bool adaptive_enabled_;
    const bool resource_diagnostics_enabled_;
    const bool measurement_diagnostics_enabled_;
    const double observation_window_seconds_;
    const double lower_ratio_;
    const double upper_ratio_;

    NativeControllerDecision decision_ = NativeControllerDecision::None;
    NativeThroughputCounters previous_counters_{};
    bool counters_primed_ = false;
    bool active_ = false;
    bool reobserve_after_budget_change_ = false;
    bool saturation_primed_ = false;
    double window_seconds_ = 0.0;
    std::uint64_t window_written_bytes_ = 0;
    double written_bytes_per_second_ = 0.0;
    double reference_bytes_per_second_ = 0.0;
    std::uint64_t measurement_sequence_ = 0;
    bool cpu_percent_valid_ = false;
    double cpu_percent_ = 0.0;
};

} // namespace sunpack::sevenzip
