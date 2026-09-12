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
    // ---------------------------------------------------------------------
    // 纯**采样器**。**不维护自己的 membership**：
    //     每次 tick 直接从 registry 拉 blocked volumes，不缓存、不 re-arm。
    //     全部水位规则在 gate.poll() 里（monitor 不做任何比较）。
    //
    // 这样直接删除：entries_ membership / rearmed_ 标志 / dormant 摘除与重加 /
    // set_wake_monitor()。现实中同一进程接触的物理输出卷数量通常就是个位数，
    // 异常路径扫描几个 VolumeState 的成本可以忽略。
    //
    // ⚠️ tick() **必须**由 controller_loop 在 executor mutex_ **之外**调用：
    //    它会取 registry mutex_ 并可能执行一次很慢的 GetDiskFreeSpaceExW
    //    （离线 UNC / 坏盘可能卡几秒）。放在 mutex_ 内会把 submit() / cancel() /
    //    admission 全部堵住。
    // ---------------------------------------------------------------------
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

            // 只有真的观测到 blocked 卷才点亮 sticky hint。
            //
            // ⚠️ 顺序很关键：早期骨架的第一行是 `if (!ever_had_blocked_) return;`，
            //    但**没有任何地方展示它如何变成 true** —— 照抄会让 monitor 永远不工作
            //    （与 §4.4.1 指出的 entries_ 缺陷同类）。因此这里先拉一次、再点亮、
            //    最后才做限速判断。
            if (states.empty())
            {
                return;
            }
            ever_had_blocked_.store(true, std::memory_order_relaxed);

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
                    // B5：卷暂时不可查询（拔盘 / UNC 断开 / 权限变化 / query_root 未解析）。
                    // 不转 Ready、不转 Probing、不新增状态；只记录诊断并下轮重试。
                    const unsigned long error = gate.last_query_error();
                    gate.note_query_failure(error);
                    maybe_emit_status(state, 0, false, error, now);
                    continue;
                }

                // ★ monitor 不做任何水位比较：一个采样值，交给 gate 自己裁决。
                gate.poll(free_bytes);
                maybe_emit_status(state, free_bytes, true, 0, now);
            }
        }

        // ★ sticky hint：进程第一次出现 blocked 卷后就**永远**为 true。
        //   **不是精确状态**，只用于"要不要缩短 parked controller 的睡眠"。
        //
        //   ⚠️ 绝不能用 has_blocked_ + note_ready() 那种精确 bool：多卷场景下
        //      "A 恢复 → 清零 → 仍 Blocked 的 B 永远不再被 poll"。
        //   ⚠️ 它也绝不参与"要不要 poll 哪些 gate"——那个决定每个 tick 都从
        //      registry.blocked_volumes() 重新拉。
        bool ever_had_blocked() const noexcept
        {
            return ever_had_blocked_.load(std::memory_order_relaxed);
        }

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
                // 低频诊断输出失败绝不影响采样循环。
            }
        }

        Options options_;
        BlockedProvider provider_;
        StatusSink status_;
        mutable std::mutex mutex_; // 只保护 next_poll_at_ / 诊断节流表
        std::atomic<bool> ever_had_blocked_{false};
        std::chrono::steady_clock::time_point next_poll_at_{};
        std::unordered_map<std::string, std::chrono::steady_clock::time_point> last_status_at_;
    };

}

#endif
