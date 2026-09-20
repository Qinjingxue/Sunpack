#pragma once

#include "sevenzip_bridge/bridge.hpp"

#ifdef SUP7Z_ENABLE_PIPELINE_TIMING

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdlib>
#include <mutex>

#ifdef _WIN32
#include <windows.h>
#endif

namespace sunpack::sevenzip
{

enum class PipelineStage : unsigned char
{
    Input = 0,
    Compute = 1,
    Output = 2,
};

bool pipeline_timing_enabled() noexcept;

class PipelineTiming final
{
public:
    using Clock = std::chrono::steady_clock;

    explicit PipelineTiming(bool enabled) noexcept : enabled_(enabled) {}

    bool enabled() const noexcept { return enabled_; }

    void start_pipeline() noexcept;
    void begin(PipelineStage stage) noexcept;
    void end(PipelineStage stage) noexcept;
    void add_compute_cpu_ns(unsigned long long elapsed_ns) noexcept;
    ExtractPipelineTiming snapshot() const noexcept;

private:
    static std::size_t stage_index(PipelineStage stage) noexcept
    {
        return static_cast<std::size_t>(stage);
    }

    void advance_locked(Clock::time_point now) noexcept;

    bool enabled_ = false;
    mutable std::mutex mutex_;
    bool started_ = false;
    bool ended_ = false;
    Clock::time_point started_at_{};
    Clock::time_point last_update_{};
    Clock::time_point ended_at_{};
    std::array<unsigned int, 3> active_counts_{};
    std::array<unsigned long long, 8> mask_ns_{};
    unsigned long long compute_cpu_ns_ = 0;
};

class PipelineStageScope final
{
public:
    PipelineStageScope(PipelineTiming *timing, PipelineStage stage) noexcept
        : timing_(timing), stage_(stage)
    {
        if (timing_ && timing_->enabled())
        {
            timing_->begin(stage_);
            active_ = true;
        }
    }

    ~PipelineStageScope() noexcept
    {
        finish();
    }

    PipelineStageScope(const PipelineStageScope &) = delete;
    PipelineStageScope &operator=(const PipelineStageScope &) = delete;

    void finish() noexcept
    {
        if (active_)
        {
            timing_->end(stage_);
            active_ = false;
        }
    }

private:
    PipelineTiming *timing_ = nullptr;
    PipelineStage stage_ = PipelineStage::Input;
    bool active_ = false;
};

class PipelineThreadCpuScope final
{
public:
    explicit PipelineThreadCpuScope(PipelineTiming *timing) noexcept;
    ~PipelineThreadCpuScope() noexcept;

    PipelineThreadCpuScope(const PipelineThreadCpuScope &) = delete;
    PipelineThreadCpuScope &operator=(const PipelineThreadCpuScope &) = delete;

private:
    PipelineTiming *timing_ = nullptr;
#ifdef _WIN32
    unsigned long long started_100ns_ = 0;
#endif
};

} // namespace sunpack::sevenzip

#else

namespace sunpack::sevenzip
{

inline bool pipeline_timing_enabled() noexcept { return false; }

} // namespace sunpack::sevenzip

#endif
