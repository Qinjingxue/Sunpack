#pragma once

#include "sevenzip_space_gate.hpp"
#include "sevenzip_volume_state.hpp"

#ifdef _WIN32

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace sunpack::sevenzip
{
    // 纯采样器：每次 tick 直接从 registry 拉 blocked volumes，不维护自己的 membership，
    // 不缓存、不 re-arm；全部水位规则在 gate.poll() 里（monitor 不做任何比较）。
    //
    // tick() 必须由 controller_loop 在 executor mutex_ 之外调用：它会取 registry mutex_ 并
    // 可能执行一次很慢的 GetDiskFreeSpaceExW（离线 UNC / 坏盘可能卡几秒），放在 mutex_ 内
    // 会把 submit() / cancel() / admission 全部堵住。
    class VolumeSpaceMonitor final
    {
    public:
        struct Options
        {
            std::chrono::milliseconds poll_interval{1000};
            std::chrono::milliseconds status_report_interval{15000};
        };

        using BlockedProvider = std::function<std::vector<VolumeStatePtr>()>;
        using StatusSink = std::function<void(const VolumeStatePtr &, std::uint64_t free_bytes,
                                              std::uint64_t pending_bytes, bool query_ok,
                                              unsigned long query_error)>;

        VolumeSpaceMonitor(Options options, BlockedProvider provider, StatusSink status)
            : options_(options),
              provider_(std::move(provider)),
              status_(std::move(status))
        {
            if (options_.poll_interval <= std::chrono::milliseconds::zero())
            {
                options_.poll_interval = std::chrono::milliseconds{1000};
            }
            if (options_.status_report_interval < options_.poll_interval)
            {
                options_.status_report_interval = options_.poll_interval;
            }
        }

        VolumeSpaceMonitor()
            : VolumeSpaceMonitor(Options{}, BlockedProvider{}, StatusSink{}) {}

        void tick(std::chrono::steady_clock::time_point now) noexcept
        {
            // sampling_ 只在"有卷进入 Blocked"（ChangeSink → note_blocked()）时置位，并且
            // 只在一次拉取返回空（确认当下没有任何 blocked 卷）时清零：从未满盘时每个 tick
            // 只有一条 relaxed 原子读，恢复之后最多再拉一次就彻底停下。
            //
            // 清零条件只能挂在"拉取返回空"上：多卷下 A 恢复时这次拉取返回的是 [B]（非空），
            // 采样必须继续、B 仍要被 poll。
            if (!sampling_.load(std::memory_order_relaxed))
            {
                return;
            }
            if (!provider_)
            {
                return;
            }

            std::vector<VolumeStatePtr> states;
            try
            {
                states = provider_();
            }
            catch (...)
            {
                return;
            }

            if (states.empty())
            {
                // 异常状态已完全消除：停止采样，并丢掉这个 episode 的全部历史 —— 诊断节流
                // 表不随 registry 已摘除的卷 key 无界增长，下一 episode 的第一拍也立即可采样。
                {
                    std::lock_guard<std::mutex> lock(mutex_);
                    last_status_at_.clear();
                    next_poll_at_ = std::chrono::steady_clock::time_point{};
                }
                sampling_.store(false, std::memory_order_relaxed);
                return;
            }

            {
                std::lock_guard<std::mutex> lock(mutex_);
                if (next_poll_at_ != std::chrono::steady_clock::time_point{} &&
                    now < next_poll_at_)
                {
                    return;
                }
                next_poll_at_ = now + options_.poll_interval;
            }

            for (const auto &state : states)
            {
                if (!state || !state->space_gate)
                {
                    continue;
                }
                VolumeSpaceGate &gate = *state->space_gate;

                std::uint64_t free_bytes = 0;
                std::uint64_t total_bytes = 0;
                if (!gate.query_free_bytes(&free_bytes, &total_bytes))
                {
                    // 卷暂时不可查询（拔盘 / UNC 断开 / 权限变化 / query_root 未解析）：
                    // 不转 Ready / Probing，只记录诊断并下轮重试。
                    const unsigned long error = gate.last_query_error();
                    gate.note_query_failure(error);
                    maybe_emit_status(state, 0, false, error, now);
                    continue;
                }

                gate.poll(free_bytes);
                maybe_emit_status(state, free_bytes, true, 0, now);
            }
        }

        // 采样是否处于"活跃"状态：note_blocked() 置位，一次拉取返回空则清零。
        // 用途只有 tick() 的常态早退与缩短 parked controller 的睡眠上限。
        bool sampling() const noexcept { return sampling_.load(std::memory_order_relaxed); }

        // 由 ChangeSink 在收到 space_blocked transition 时调用（开始采样的唯一驱动点）。
        void note_blocked() noexcept { sampling_.store(true, std::memory_order_relaxed); }

    private:
        void maybe_emit_status(const VolumeStatePtr &state,
                               std::uint64_t free_bytes,
                               bool query_ok,
                               unsigned long query_error,
                               std::chrono::steady_clock::time_point now) noexcept
        {
            if (!status_)
            {
                return;
            }
            {
                std::lock_guard<std::mutex> lock(mutex_);
                auto &last = last_status_at_[state->key];
                if (last != std::chrono::steady_clock::time_point{} &&
                    now - last < options_.status_report_interval)
                {
                    return;
                }
                last = now;
            }
            const std::uint64_t pending_bytes =
                state->counters.pending_bytes.load(std::memory_order_relaxed);
            try
            {
                status_(state, free_bytes, pending_bytes, query_ok, query_error);
            }
            catch (...)
            {
                // 诊断输出失败绝不影响采样循环。
            }
        }

        Options options_;
        BlockedProvider provider_;
        StatusSink status_;
        mutable std::mutex mutex_; // 只保护 next_poll_at_ / 诊断节流表
        std::atomic<bool> sampling_{false};
        std::chrono::steady_clock::time_point next_poll_at_{};
        std::unordered_map<std::string, std::chrono::steady_clock::time_point> last_status_at_;
    };

}

#endif
