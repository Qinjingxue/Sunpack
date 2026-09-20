#include "internal/worker_pipeline_timing.hpp"

#ifdef SUP7Z_ENABLE_PIPELINE_TIMING

#include <algorithm>
#include <limits>

namespace sunpack::sevenzip
{

namespace
{

unsigned long long elapsed_ns(PipelineTiming::Clock::time_point start,
                              PipelineTiming::Clock::time_point end) noexcept
{
    const auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
    return elapsed > 0 ? static_cast<unsigned long long>(elapsed) : 0ULL;
}

#ifdef _WIN32
unsigned long long filetime_100ns(const FILETIME &value) noexcept
{
    ULARGE_INTEGER ticks{};
    ticks.LowPart = value.dwLowDateTime;
    ticks.HighPart = value.dwHighDateTime;
    return ticks.QuadPart;
}
#endif

} // namespace

bool pipeline_timing_enabled() noexcept
{
    static const bool enabled = []
    {
        const char *value = std::getenv("SUNPACK_SEVENZIP_PROFILE_PIPELINE");
        return value && value[0] == '1';
    }();
    return enabled;
}

void PipelineTiming::start_pipeline() noexcept
{
    if (!enabled_)
    {
        return;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    if (!started_)
    {
        started_ = true;
        ended_ = false;
        started_at_ = Clock::now();
        last_update_ = started_at_;
    }
}

void PipelineTiming::advance_locked(Clock::time_point now) noexcept
{
    if (!started_)
    {
        return;
    }
    const unsigned long long elapsed = elapsed_ns(last_update_, now);
    unsigned int mask = 0;
    for (std::size_t index = 0; index < active_counts_.size(); ++index)
    {
        if (active_counts_[index] != 0)
        {
            mask |= 1U << static_cast<unsigned int>(index);
        }
    }
    mask_ns_[mask] += elapsed;
    last_update_ = now;
}

void PipelineTiming::begin(PipelineStage stage) noexcept
{
    if (!enabled_)
    {
        return;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    if (!started_)
    {
        ++active_counts_[stage_index(stage)];
        return;
    }
    const auto now = Clock::now();
    advance_locked(now);
    ++active_counts_[stage_index(stage)];
}

void PipelineTiming::end(PipelineStage stage) noexcept
{
    if (!enabled_)
    {
        return;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    const std::size_t index = stage_index(stage);
    if (active_counts_[index] == 0)
    {
        return;
    }
    if (!started_)
    {
        --active_counts_[index];
        return;
    }
    const auto now = Clock::now();
    advance_locked(now);
    --active_counts_[index];
    ended_ = true;
    ended_at_ = now;
}

void PipelineTiming::add_compute_cpu_ns(unsigned long long elapsed) noexcept
{
    if (!enabled_)
    {
        return;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    compute_cpu_ns_ += elapsed;
}

void PipelineTiming::add_prepare_ns(PipelinePreparePhase phase, unsigned long long elapsed) noexcept
{
    if (!enabled_)
    {
        return;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    prepare_ns_[static_cast<std::size_t>(phase)] += elapsed;
}

ExtractPipelineTiming PipelineTiming::snapshot() const noexcept
{
    ExtractPipelineTiming result;
    if (!enabled_)
    {
        return result;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    auto masks = mask_ns_;
    if (started_)
    {
        const auto now = Clock::now();
        const unsigned long long elapsed = elapsed_ns(last_update_, now);
        unsigned int mask = 0;
        for (std::size_t index = 0; index < active_counts_.size(); ++index)
        {
            if (active_counts_[index] != 0)
            {
                mask |= 1U << static_cast<unsigned int>(index);
            }
        }
        masks[mask] += elapsed;
    }

    result.pipeline_wall_ns = elapsed_ns(started_at_, ended_ ? ended_at_ : Clock::now());
    result.input_active_ns = masks[1] + masks[3] + masks[5] + masks[7];
    result.compute_active_ns = masks[2] + masks[3] + masks[6] + masks[7];
    result.output_active_ns = masks[4] + masks[5] + masks[6] + masks[7];
    result.input_compute_overlap_ns = masks[3] + masks[7];
    result.input_output_overlap_ns = masks[5] + masks[7];
    result.compute_output_overlap_ns = masks[6] + masks[7];
    result.all_overlap_ns = masks[7];
    result.any_overlap_ns = masks[3] + masks[5] + masks[6] + masks[7];
    result.idle_ns = masks[0];
    result.compute_cpu_ns = compute_cpu_ns_;
    result.prepare_output_directory_ns = prepare_ns_[0];
    result.prepare_format_candidates_ns = prepare_ns_[1];
    result.prepare_handler_create_ns = prepare_ns_[2];
    result.prepare_stream_open_ns = prepare_ns_[3];
    result.prepare_archive_open_ns = prepare_ns_[4];
    result.prepare_item_probe_ns = prepare_ns_[5];
    result.prepare_callback_setup_ns = prepare_ns_[6];
    result.prepare_output_finalize_ns = prepare_ns_[7];
    result.prepare_archive_close_ns = prepare_ns_[8];
    return result;
}

PipelineThreadCpuScope::PipelineThreadCpuScope(PipelineTiming *timing) noexcept
    : timing_(timing && timing->enabled() ? timing : nullptr)
{
#ifdef _WIN32
    if (timing_)
    {
        FILETIME creation{}, exit{}, kernel{}, user{};
        if (GetThreadTimes(GetCurrentThread(), &creation, &exit, &kernel, &user))
        {
            started_100ns_ = filetime_100ns(kernel) + filetime_100ns(user);
        }
        else
        {
            timing_ = nullptr;
        }
    }
#else
    timing_ = nullptr;
#endif
}

PipelineThreadCpuScope::~PipelineThreadCpuScope() noexcept
{
#ifdef _WIN32
    if (!timing_)
    {
        return;
    }
    FILETIME creation{}, exit{}, kernel{}, user{};
    if (!GetThreadTimes(GetCurrentThread(), &creation, &exit, &kernel, &user))
    {
        return;
    }
    const unsigned long long finished = filetime_100ns(kernel) + filetime_100ns(user);
    if (finished >= started_100ns_)
    {
        timing_->add_compute_cpu_ns((finished - started_100ns_) * 100ULL);
    }
#endif
}

} // namespace sunpack::sevenzip

#endif
