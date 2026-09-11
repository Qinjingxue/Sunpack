#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>

namespace sunpack::sevenzip
{

    struct NativeRuntimeSample
    {
        std::size_t available_memory = 0;
        double cpu_percent = 0.0;
        bool cpu_percent_valid = false;
        std::uint64_t io_read_bytes = 0;
        std::uint64_t io_write_bytes = 0;
        bool io_counters_valid = false;
    };

    struct NativeThroughputCounters
    {
        std::uint64_t accepted_bytes = 0;
        std::uint64_t written_bytes = 0;
        std::uint64_t completed_files = 0;
        std::uint64_t completed_jobs = 0;
    };

    enum class NativeExplorationStrategy
    {
        Calibrated,
        Rapid,
        Full
    };
    enum class NativeThroughputMode
    {
        None,
        Bytes,
        Jobs,
        Files
    };
    enum class NativeControllerPhase
    {
        Baseline,
        Probe,
        Cooldown,
        Hold
    };
    enum class NativeLoadState
    {
        Idle,
        Unsaturated,
        Saturated
    };
    enum class NativeControllerDecision
    {
        None,
        ActivityStarted,
        ActivityEnded,
        SegmentStarted,
        SegmentInterrupted,
        BaselineReady,
        ProbeUp,
        ProbeDown,
        Accepted,
        RolledBack,
        Holding,
        MemoryPaused,
        MemoryResumed,
    };

    struct NativeRuntimeSnapshot
    {
        std::size_t active_limit = 1;
        std::size_t memory_budget = 0;
        std::size_t active_jobs = 0;
        std::size_t active_memory = 0;
        bool memory_admission_paused = false;
        NativeControllerPhase phase = NativeControllerPhase::Baseline;
        NativeLoadState load_state = NativeLoadState::Idle;
        NativeControllerDecision decision = NativeControllerDecision::None;
        NativeThroughputMode throughput_mode = NativeThroughputMode::None;
        double written_bytes_per_second = 0.0;
        double completed_jobs_per_second = 0.0;
        double completed_files_per_second = 0.0;
        std::uint64_t pending_write_bytes = 0;
        std::uint64_t activity_session = 0;
        std::uint64_t saturated_segment = 0;
        bool warm_start_used = false;
        bool resource_diagnostics_enabled = false;
        bool cpu_percent_valid = false;
        double cpu_percent = 0.0;
        double io_read_bytes_per_second = 0.0;
        double io_write_bytes_per_second = 0.0;
    };

    struct NativeRuntimeConfig
    {
        bool adaptive_enabled = true;
        bool resource_diagnostics_enabled = false;
        std::size_t initial_active_jobs = 0;
        NativeExplorationStrategy exploration_strategy = NativeExplorationStrategy::Calibrated;
        double minimum_window_seconds = 0.25;
        double maximum_window_seconds = 1.5;
        double settle_seconds = 0.10;
        std::uint64_t large_window_bytes = 32ULL << 20;
        std::size_t small_window_jobs = 4;
        std::size_t small_window_files = 16;
        double improvement_ratio = 1.03;
        double regression_ratio = 0.97;
        std::size_t aggressive_step = 4;
        std::size_t cooldown_windows = 2;
        std::size_t hold_windows = 8;
        std::size_t memory_pause_available = 1ULL << 30;
        std::size_t memory_resume_available = 2ULL << 30;
        double warm_start_decay_seconds = 0.0;
        std::size_t warm_start_confirmations = 2;
    };

    class NativeRuntimeControl final
    {
    public:
        NativeRuntimeControl(
            std::size_t max_active_jobs,
            std::size_t memory_budget,
            bool adaptive_enabled = true,
            std::size_t initial_active_jobs = 0)
            : NativeRuntimeControl(
                  max_active_jobs,
                  memory_budget,
                  NativeRuntimeConfig{adaptive_enabled, false, initial_active_jobs}) {}

        NativeRuntimeControl(
            std::size_t max_active_jobs,
            std::size_t memory_budget,
            NativeRuntimeConfig config)
            : max_active_jobs_((std::max)(std::size_t{1}, max_active_jobs)),
              memory_budget_(memory_budget),
              adaptive_enabled_(config.adaptive_enabled),
              resource_diagnostics_enabled_(config.resource_diagnostics_enabled),
              exploration_strategy_(config.exploration_strategy),
              minimum_window_seconds_((std::max)(0.05, config.minimum_window_seconds)),
              maximum_window_seconds_((std::max)(minimum_window_seconds_, config.maximum_window_seconds)),
              settle_seconds_((std::max)(0.0, config.settle_seconds)),
              large_window_bytes_((std::max)(std::uint64_t{1}, config.large_window_bytes)),
              small_window_jobs_((std::max)(std::size_t{1}, config.small_window_jobs)),
              small_window_files_((std::max)(std::size_t{1}, config.small_window_files)),
              improvement_ratio_((std::max)(1.0, config.improvement_ratio)),
              regression_ratio_((std::min)(1.0, (std::max)(0.01, config.regression_ratio))),
              configured_aggressive_step_((std::max)(std::size_t{1}, config.aggressive_step)),
              cooldown_windows_((std::max)(std::size_t{1}, config.cooldown_windows)),
              hold_windows_((std::max)(std::size_t{1}, config.hold_windows)),
              memory_pause_available_(config.memory_pause_available),
              memory_resume_available_((std::max)(config.memory_pause_available, config.memory_resume_available)),
              warm_start_decay_seconds_((std::max)(0.0, config.warm_start_decay_seconds)),
              warm_start_confirmations_((std::max)(std::size_t{1}, config.warm_start_confirmations))
        {
            const std::size_t configured_initial = config.initial_active_jobs == 0
                                                       ? (std::min)(max_active_jobs_, std::size_t{2})
                                                       : config.initial_active_jobs;
            initial_active_jobs_ = (std::max)(std::size_t{1}, (std::min)(configured_initial, max_active_jobs_));
            if (exploration_strategy_ == NativeExplorationStrategy::Full)
            {
                initial_active_jobs_ = max_active_jobs_;
            }
            active_limit_ = initial_active_jobs_;
            best_limit_ = active_limit_;
            last_good_limit_ = active_limit_;
            reset_probe_step();
            next_direction_ = active_limit_ == max_active_jobs_ ? -1 : 1;
        }

        NativeRuntimeControl(const NativeRuntimeControl &) = delete;
        NativeRuntimeControl &operator=(const NativeRuntimeControl &) = delete;

        bool can_admit(
            std::size_t active_jobs,
            std::size_t active_memory,
            std::size_t memory_reserve) const noexcept
        {
            if (active_jobs >= active_limit_)
            {
                return false;
            }
            if (memory_admission_paused_ && active_jobs != 0)
            {
                return false;
            }
            if (memory_budget_ == 0)
            {
                return true;
            }
            return active_memory <= memory_budget_ &&
                   memory_reserve <= memory_budget_ - (std::min)(active_memory, memory_budget_);
        }

        bool observe(
            const NativeRuntimeSample &runtime,
            const NativeThroughputCounters &counters,
            std::size_t queued_jobs,
            std::size_t active_jobs,
            std::size_t active_memory,
            double elapsed_seconds = 0.0) noexcept
        {
            decision_ = NativeControllerDecision::None;
            bool changed = false;
            if (load_state_ == NativeLoadState::Idle)
            {
                changed = begin_activity(counters, 0.0);
            }
            changed = observe_memory(runtime) || changed;
            observe_diagnostics(runtime, elapsed_seconds);
            const CounterDelta delta = counter_delta(counters);
            pending_write_bytes_ = counters.accepted_bytes >= counters.written_bytes
                                       ? counters.accepted_bytes - counters.written_bytes
                                       : 0;

            const bool concurrency_exposed = queued_jobs != 0 && active_jobs != 0 &&
                                             active_jobs + 1 >= active_limit_ && !memory_admission_paused_;
            if (!concurrency_exposed)
            {
                if (load_state_ == NativeLoadState::Saturated)
                {
                    changed = interrupt_saturated_segment() || changed;
                }
                else
                {
                    load_state_ = NativeLoadState::Unsaturated;
                    window_.clear();
                }
                return changed;
            }
            if (load_state_ != NativeLoadState::Saturated)
            {
                begin_saturated_segment();
                return true;
            }
            if (!adaptive_enabled_ || elapsed_seconds <= 0.0)
            {
                return changed;
            }
            if (settle_remaining_seconds_ > 0.0)
            {
                settle_remaining_seconds_ = (std::max)(0.0, settle_remaining_seconds_ - elapsed_seconds);
                window_.clear();
                return changed;
            }
            window_.add(delta, elapsed_seconds);
            if (!window_ready(window_))
            {
                return changed;
            }
            const Measurement measurement = window_.measurement(large_window_bytes_);
            window_.clear();
            last_measurement_ = measurement;
            return process_measurement(measurement) || changed;
        }

        NativeRuntimeSnapshot snapshot(
            std::size_t active_jobs,
            std::size_t active_memory) const noexcept
        {
            return NativeRuntimeSnapshot{
                active_limit_,
                memory_budget_,
                active_jobs,
                active_memory,
                memory_admission_paused_,
                phase_,
                load_state_,
                decision_,
                last_measurement_.mode,
                last_measurement_.bytes_per_second,
                last_measurement_.jobs_per_second,
                last_measurement_.files_per_second,
                pending_write_bytes_,
                activity_session_,
                saturated_segment_,
                warm_start_used_,
                resource_diagnostics_enabled_,
                diagnostic_cpu_valid_,
                diagnostic_cpu_percent_,
                diagnostic_io_read_rate_,
                diagnostic_io_write_rate_,
            };
        }

        bool resource_diagnostics_enabled() const noexcept
        {
            return resource_diagnostics_enabled_;
        }

        bool begin_activity(
            const NativeThroughputCounters &counters,
            double idle_seconds) noexcept
        {
            if (load_state_ != NativeLoadState::Idle)
            {
                return false;
            }
            if (warm_start_decay_seconds_ <= 0.0 || idle_seconds >= warm_start_decay_seconds_)
            {
                confirmed_limit_samples_ = 0;
                last_good_limit_ = initial_active_jobs_;
            }
            double retention = warm_start_decay_seconds_ <= 0.0
                                   ? 0.0
                                   : 1.0 - (std::min)(1.0, (std::max)(0.0, idle_seconds) /
                                                               warm_start_decay_seconds_);
            if (confirmed_limit_samples_ < warm_start_confirmations_)
            {
                retention = 0.0;
            }
            active_limit_ = interpolate_toward(
                initial_active_jobs_, last_good_limit_, retention);
            warm_start_used_ = active_limit_ != initial_active_jobs_;
            load_state_ = NativeLoadState::Unsaturated;
            ++activity_session_;
            prime_counters(counters);
            reset_learning_state();
            decision_ = NativeControllerDecision::ActivityStarted;
            return true;
        }

        bool end_activity(const NativeThroughputCounters &counters) noexcept
        {
            if (load_state_ == NativeLoadState::Idle)
            {
                prime_counters(counters);
                return false;
            }
            if (load_state_ == NativeLoadState::Saturated)
            {
                interrupt_saturated_segment();
            }
            load_state_ = NativeLoadState::Idle;
            warm_start_used_ = false;
            prime_counters(counters);
            reset_learning_state();
            decision_ = NativeControllerDecision::ActivityEnded;
            diagnostics_primed_ = false;
            return true;
        }

    private:
        struct CounterDelta
        {
            std::uint64_t accepted_bytes = 0;
            std::uint64_t written_bytes = 0;
            std::uint64_t completed_files = 0;
            std::uint64_t completed_jobs = 0;
        };

        struct Measurement
        {
            NativeThroughputMode mode = NativeThroughputMode::None;
            double bytes_per_second = 0.0;
            double jobs_per_second = 0.0;
            double files_per_second = 0.0;
            std::uint64_t written_bytes = 0;
            std::uint64_t completed_jobs = 0;
            std::uint64_t completed_files = 0;
        };

        struct Window
        {
            double seconds = 0.0;
            std::uint64_t written_bytes = 0;
            std::uint64_t completed_jobs = 0;
            std::uint64_t completed_files = 0;

            void add(const CounterDelta &delta, double elapsed) noexcept
            {
                seconds += elapsed;
                written_bytes += delta.written_bytes;
                completed_jobs += delta.completed_jobs;
                completed_files += delta.completed_files;
            }

            void clear() noexcept
            {
                seconds = 0.0;
                written_bytes = 0;
                completed_jobs = 0;
                completed_files = 0;
            }

            Measurement measurement(std::uint64_t large_bytes) const noexcept
            {
                Measurement result;
                if (seconds <= 0.0)
                {
                    return result;
                }
                result.written_bytes = written_bytes;
                result.completed_jobs = completed_jobs;
                result.completed_files = completed_files;
                result.bytes_per_second = static_cast<double>(written_bytes) / seconds;
                result.jobs_per_second = static_cast<double>(completed_jobs) / seconds;
                result.files_per_second = static_cast<double>(completed_files) / seconds;
                result.mode = written_bytes >= large_bytes
                                  ? NativeThroughputMode::Bytes
                              : completed_jobs != 0
                                  ? NativeThroughputMode::Jobs
                              : completed_files != 0
                                  ? NativeThroughputMode::Files
                                  : NativeThroughputMode::None;
                return result;
            }
        };

        static std::size_t interpolate_toward(
            std::size_t start,
            std::size_t target,
            double fraction) noexcept
        {
            const double clamped = (std::min)(1.0, (std::max)(0.0, fraction));
            if (start <= target)
            {
                return start + static_cast<std::size_t>(
                                   static_cast<double>(target - start) * clamped);
            }
            return start - static_cast<std::size_t>(
                               static_cast<double>(start - target) * clamped);
        }

        static std::uint64_t monotonic_delta(std::uint64_t now, std::uint64_t before) noexcept
        {
            return now >= before ? now - before : 0;
        }

        CounterDelta counter_delta(const NativeThroughputCounters &counters) noexcept
        {
            if (!counters_primed_)
            {
                previous_counters_ = counters;
                counters_primed_ = true;
                return {};
            }
            const CounterDelta delta{
                monotonic_delta(counters.accepted_bytes, previous_counters_.accepted_bytes),
                monotonic_delta(counters.written_bytes, previous_counters_.written_bytes),
                monotonic_delta(counters.completed_files, previous_counters_.completed_files),
                monotonic_delta(counters.completed_jobs, previous_counters_.completed_jobs),
            };
            previous_counters_ = counters;
            return delta;
        }

        void prime_counters(const NativeThroughputCounters &counters) noexcept
        {
            previous_counters_ = counters;
            counters_primed_ = true;
            pending_write_bytes_ = counters.accepted_bytes >= counters.written_bytes
                                       ? counters.accepted_bytes - counters.written_bytes
                                       : 0;
        }

        void begin_saturated_segment() noexcept
        {
            if (phase_ == NativeControllerPhase::Probe)
            {
                active_limit_ = best_limit_;
            }
            load_state_ = NativeLoadState::Saturated;
            ++saturated_segment_;
            reset_learning_state();
            decision_ = NativeControllerDecision::SegmentStarted;
        }

        bool interrupt_saturated_segment() noexcept
        {
            if (phase_ == NativeControllerPhase::Probe)
            {
                active_limit_ = best_limit_;
            }
            load_state_ = NativeLoadState::Unsaturated;
            reset_learning_state();
            decision_ = NativeControllerDecision::SegmentInterrupted;
            return true;
        }

        void remember_confirmed_limit(std::size_t limit) noexcept
        {
            if (last_good_limit_ == limit)
            {
                confirmed_limit_samples_ = (std::min)(warm_start_confirmations_, confirmed_limit_samples_ + 1);
            }
            else
            {
                last_good_limit_ = limit;
                confirmed_limit_samples_ = 1;
            }
        }

        bool observe_memory(const NativeRuntimeSample &runtime) noexcept
        {
            if (memory_budget_ == 0 || runtime.available_memory == 0)
            {
                return false;
            }
            if (!memory_admission_paused_ && runtime.available_memory < memory_pause_available_)
            {
                memory_admission_paused_ = true;
                decision_ = NativeControllerDecision::MemoryPaused;
                window_.clear();
                return true;
            }
            if (memory_admission_paused_ && runtime.available_memory > memory_resume_available_)
            {
                memory_admission_paused_ = false;
                decision_ = NativeControllerDecision::MemoryResumed;
                settle_remaining_seconds_ = settle_seconds_;
                return true;
            }
            return false;
        }

        void observe_diagnostics(const NativeRuntimeSample &runtime, double elapsed_seconds) noexcept
        {
            if (!resource_diagnostics_enabled_)
            {
                diagnostic_cpu_valid_ = false;
                diagnostic_cpu_percent_ = 0.0;
                diagnostic_io_read_rate_ = 0.0;
                diagnostic_io_write_rate_ = 0.0;
                return;
            }
            diagnostic_cpu_valid_ = runtime.cpu_percent_valid;
            diagnostic_cpu_percent_ = runtime.cpu_percent;
            if (!runtime.io_counters_valid || elapsed_seconds <= 0.0)
            {
                return;
            }
            if (diagnostics_primed_)
            {
                diagnostic_io_read_rate_ = static_cast<double>(monotonic_delta(
                                               runtime.io_read_bytes, previous_io_read_bytes_)) /
                                           elapsed_seconds;
                diagnostic_io_write_rate_ = static_cast<double>(monotonic_delta(
                                                runtime.io_write_bytes, previous_io_write_bytes_)) /
                                            elapsed_seconds;
            }
            previous_io_read_bytes_ = runtime.io_read_bytes;
            previous_io_write_bytes_ = runtime.io_write_bytes;
            diagnostics_primed_ = true;
        }

        bool window_ready(const Window &window) const noexcept
        {
            return window.seconds >= minimum_window_seconds_ &&
                   (window.written_bytes >= large_window_bytes_ ||
                    window.completed_jobs >= small_window_jobs_ ||
                    window.completed_files >= small_window_files_ ||
                    window.seconds >= maximum_window_seconds_);
        }

        static double measurement_rate(
            const Measurement &measurement,
            NativeThroughputMode mode) noexcept
        {
            switch (mode)
            {
            case NativeThroughputMode::Bytes:
                return measurement.bytes_per_second;
            case NativeThroughputMode::Jobs:
                return measurement.jobs_per_second;
            case NativeThroughputMode::Files:
                return measurement.files_per_second;
            default:
                return 0.0;
            }
        }

        NativeThroughputMode comparable_mode(
            const Measurement &baseline,
            const Measurement &probe) const noexcept
        {
            if (baseline.written_bytes >= large_window_bytes_ &&
                probe.written_bytes >= large_window_bytes_)
            {
                return NativeThroughputMode::Bytes;
            }
            if (baseline.completed_jobs >= small_window_jobs_ &&
                probe.completed_jobs >= small_window_jobs_)
            {
                return NativeThroughputMode::Jobs;
            }
            if (baseline.completed_files >= small_window_files_ &&
                probe.completed_files >= small_window_files_)
            {
                return NativeThroughputMode::Files;
            }
            return NativeThroughputMode::None;
        }

        bool process_measurement(const Measurement &measurement) noexcept
        {
            if (measurement.mode == NativeThroughputMode::None)
            {
                return false;
            }
            switch (phase_)
            {
            case NativeControllerPhase::Baseline:
                anchor_ = measurement;
                best_limit_ = active_limit_;
                decision_ = NativeControllerDecision::BaselineReady;
                return launch_next_probe();
            case NativeControllerPhase::Probe:
                return evaluate_probe(measurement);
            case NativeControllerPhase::Cooldown:
                if (++phase_windows_ >= cooldown_windows_)
                {
                    phase_windows_ = 0;
                    if (!launch_next_probe())
                    {
                        enter_hold();
                    }
                    return true;
                }
                return false;
            case NativeControllerPhase::Hold:
                if (++phase_windows_ >= hold_windows_)
                {
                    phase_windows_ = 0;
                    tried_up_ = false;
                    tried_down_ = false;
                    probe_step_ = 1;
                    phase_ = NativeControllerPhase::Baseline;
                    anchor_ = measurement;
                    decision_ = NativeControllerDecision::BaselineReady;
                    return launch_next_probe();
                }
                return false;
            }
            return false;
        }

        bool evaluate_probe(const Measurement &measurement) noexcept
        {
            const NativeThroughputMode mode = comparable_mode(anchor_, measurement);
            const double baseline_rate = measurement_rate(anchor_, mode);
            const double probe_rate = measurement_rate(measurement, mode);
            if (mode == NativeThroughputMode::None || baseline_rate <= 0.0 || probe_rate <= 0.0)
            {
                rollback_probe();
                return true;
            }
            const double ratio = probe_rate / baseline_rate;
            if (ratio >= improvement_ratio_)
            {
                best_limit_ = active_limit_;
                remember_confirmed_limit(best_limit_);
                anchor_ = measurement;
                decision_ = NativeControllerDecision::Accepted;
                tried_up_ = false;
                tried_down_ = false;
                if (ratio < improvement_ratio_ * 1.5)
                {
                    probe_step_ = 1;
                }
                return launch_probe(probe_direction_);
            }
            if (probe_direction_ < 0 && ratio >= regression_ratio_)
            {
                // Equal throughput at lower concurrency is a better operating point.
                best_limit_ = active_limit_;
                remember_confirmed_limit(best_limit_);
                decision_ = NativeControllerDecision::Accepted;
                tried_up_ = true;
                tried_down_ = false;
                probe_step_ = 1;
                return launch_probe(-1);
            }
            rollback_probe(true);
            return true;
        }

        void rollback_probe(bool confirm_best = false) noexcept
        {
            if (confirm_best)
            {
                remember_confirmed_limit(best_limit_);
            }
            if (probe_direction_ > 0)
            {
                tried_up_ = true;
                next_direction_ = -1;
            }
            else
            {
                tried_down_ = true;
                next_direction_ = 1;
            }
            active_limit_ = best_limit_;
            probe_step_ = 1;
            phase_ = NativeControllerPhase::Cooldown;
            phase_windows_ = 0;
            settle_remaining_seconds_ = settle_seconds_;
            decision_ = NativeControllerDecision::RolledBack;
        }

        bool launch_next_probe() noexcept
        {
            if (next_direction_ > 0 && !tried_up_ && launch_probe(1))
                return true;
            if (next_direction_ < 0 && !tried_down_ && launch_probe(-1))
                return true;
            if (!tried_up_ && launch_probe(1))
                return true;
            if (!tried_down_ && launch_probe(-1))
                return true;
            return false;
        }

        bool launch_probe(int direction) noexcept
        {
            const std::size_t step = (std::max)(std::size_t{1}, probe_step_);
            const std::size_t target = direction > 0
                                           ? (std::min)(max_active_jobs_, active_limit_ +
                                                                              (std::min)(step, max_active_jobs_ - active_limit_))
                                       : active_limit_ > step ? active_limit_ - step
                                                              : std::size_t{1};
            if (target == active_limit_)
            {
                if (direction > 0)
                    tried_up_ = true;
                else
                    tried_down_ = true;
                return false;
            }
            active_limit_ = target;
            probe_direction_ = direction;
            next_direction_ = direction;
            phase_ = NativeControllerPhase::Probe;
            settle_remaining_seconds_ = settle_seconds_;
            decision_ = direction > 0
                            ? NativeControllerDecision::ProbeUp
                            : NativeControllerDecision::ProbeDown;
            return true;
        }

        void enter_hold() noexcept
        {
            active_limit_ = best_limit_;
            phase_ = NativeControllerPhase::Hold;
            phase_windows_ = 0;
            settle_remaining_seconds_ = settle_seconds_;
            decision_ = NativeControllerDecision::Holding;
        }

        void reset_probe_step() noexcept
        {
            probe_step_ = exploration_strategy_ == NativeExplorationStrategy::Rapid
                              ? (std::min)(configured_aggressive_step_, (std::max)(std::size_t{1}, max_active_jobs_ / 4))
                              : std::size_t{1};
        }

        void reset_learning_state() noexcept
        {
            best_limit_ = active_limit_;
            phase_ = NativeControllerPhase::Baseline;
            decision_ = NativeControllerDecision::None;
            last_measurement_ = {};
            anchor_ = {};
            window_.clear();
            phase_windows_ = 0;
            tried_up_ = false;
            tried_down_ = false;
            next_direction_ = active_limit_ == max_active_jobs_ ? -1 : 1;
            reset_probe_step();
            settle_remaining_seconds_ = 0.0;
        }

        const std::size_t max_active_jobs_;
        const std::size_t memory_budget_;
        const bool adaptive_enabled_;
        const bool resource_diagnostics_enabled_;
        const NativeExplorationStrategy exploration_strategy_;
        const double minimum_window_seconds_;
        const double maximum_window_seconds_;
        const double settle_seconds_;
        const std::uint64_t large_window_bytes_;
        const std::size_t small_window_jobs_;
        const std::size_t small_window_files_;
        const double improvement_ratio_;
        const double regression_ratio_;
        const std::size_t configured_aggressive_step_;
        const std::size_t cooldown_windows_;
        const std::size_t hold_windows_;
        const std::size_t memory_pause_available_;
        const std::size_t memory_resume_available_;
        const double warm_start_decay_seconds_;
        const std::size_t warm_start_confirmations_;

        std::size_t initial_active_jobs_ = 1;
        std::size_t active_limit_ = 1;
        std::size_t best_limit_ = 1;
        bool memory_admission_paused_ = false;
        NativeControllerPhase phase_ = NativeControllerPhase::Baseline;
        NativeLoadState load_state_ = NativeLoadState::Idle;
        NativeControllerDecision decision_ = NativeControllerDecision::None;
        Measurement last_measurement_;
        Measurement anchor_;
        Window window_;
        bool counters_primed_ = false;
        NativeThroughputCounters previous_counters_;
        std::uint64_t pending_write_bytes_ = 0;
        int next_direction_ = 1;
        int probe_direction_ = 1;
        std::size_t probe_step_ = 1;
        bool tried_up_ = false;
        bool tried_down_ = false;
        std::size_t phase_windows_ = 0;
        double settle_remaining_seconds_ = 0.0;
        std::uint64_t activity_session_ = 0;
        std::uint64_t saturated_segment_ = 0;
        std::size_t last_good_limit_ = 1;
        std::size_t confirmed_limit_samples_ = 0;
        bool warm_start_used_ = false;

        bool diagnostic_cpu_valid_ = false;
        double diagnostic_cpu_percent_ = 0.0;
        bool diagnostics_primed_ = false;
        std::uint64_t previous_io_read_bytes_ = 0;
        std::uint64_t previous_io_write_bytes_ = 0;
        double diagnostic_io_read_rate_ = 0.0;
        double diagnostic_io_write_rate_ = 0.0;
    };

} // namespace sunpack::sevenzip
