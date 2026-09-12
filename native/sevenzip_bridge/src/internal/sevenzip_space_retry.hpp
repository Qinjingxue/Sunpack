#pragma once

#include "sevenzip_space_gate.hpp"

#ifdef _WIN32

#include <string_view>
#include <utility>

namespace sunpack::sevenzip
{
    // ---------------------------------------------------------------------
    // 一次真实文件系统操作的结果。**四态**（早期三态枚举缺"空间失败"这第四条路径，
    // 并允许 attempt 自己上报空间失败 → 双重上报，已废弃）。
    //
    // ⚠️ vocabulary 约束：整条 native 空间错误链**只允许**出现
    //        AttemptResult / WaitResult / ProbeLease
    //    明确废弃并禁止重新引入：WriteOutcome / OpenOutcome / SpaceRetryResult /
    //    last_space_error() / out_space_error 出参。
    // ---------------------------------------------------------------------
    struct AttemptResult
    {
        enum class Kind
        {
            Succeeded,        // 一次真实操作成功
            SpaceFailure,     // 空间不足（gate 存在时可重试；**gate 为 null 时由调用方转旧语义**）
            PermanentFailure, // 确凿的非空间错误（不可重试）
            Terminal,         // 调用方要求终止（取消 / draining），未写入任何东西
        };

        Kind kind = Kind::Succeeded;
        unsigned long win32_error = 0; // 仅 SpaceFailure / PermanentFailure 有意义
    };

    // ---------------------------------------------------------------------
    // **唯一的重试骨架。它是全项目唯一有权调用 gate 空间状态接口的地方。**
    //
    // 返回值就是 AttemptResult —— **不存在 SpaceRetryResult**：少一个类型，并且让
    // "gate == nullptr 时 SpaceFailure 原样外泄"成为类型上可见的事实。
    //
    //   gate != nullptr : SpaceFailure 永远被骨架内部吃掉重试；
    //                     对外只可能 Succeeded / PermanentFailure / Terminal
    //   gate == nullptr : SpaceFailure **原样返回**，由调用方执行旧版永久失败副作用
    //                     （§4.5.0 / §4.5.0.1 逐路径定义）
    //
    // attempt 的契约（必须遵守）：
    //   1. 只做一次真实文件系统操作。
    //   2. **绝不**调用 gate 或 lease 的任何状态接口。
    //   3. 空间类错误的判定用 is_space_exhaustion_error()，把 Win32 码放进 win32_error。
    //   4. 绝不记账（discarded 由 writer_loop 独占）。
    //   5. 不得抛出异常（骨架是 noexcept）。
    // ---------------------------------------------------------------------
    template <typename AttemptFn>
    AttemptResult retry_with_space_gate(VolumeSpaceGate *gate,
                                        const TerminalPredicate &terminal,
                                        std::wstring_view failed_path,
                                        AttemptFn &&attempt) noexcept
    {
        if (gate == nullptr)
        {
            // 功能关闭 / 无卷身份：**只试一次，原样返回结果**。
            // 这里不做任何 classify —— gate 关闭时的旧语义副作用由调用方负责。
            return attempt();
        }

        for (;;)
        {
            ProbeLease lease;
            // ⚠️ lease 必须声明在循环**内部**：每轮迭代结束即析构。一轮里若 report_*
            //    没被走到，析构会把状态推回 Blocked（安全）。提到循环外面会让
            //    report_space_failure 在持有许可时被调用，状态机会错乱。
            auto decision = gate->wait(terminal);

            if (decision.kind == VolumeSpaceGate::WaitResult::Kind::Terminal)
            {
                return {AttemptResult::Kind::Terminal, 0};
            }
            if (decision.kind == VolumeSpaceGate::WaitResult::Kind::Probe)
            {
                lease = std::move(decision.lease); // 持有许可，**必须**结算
            }

            AttemptResult result = attempt();

            switch (result.kind)
            {
            case AttemptResult::Kind::Succeeded:
                if (lease.valid())
                {
                    lease.report_success();
                }
                return result;

            case AttemptResult::Kind::SpaceFailure:
                // ★ 唯一的空间失败上报点。attempt 绝不允许自己上报。
                if (lease.valid())
                {
                    lease.report_space_failure(result.win32_error, failed_path);
                }
                else
                {
                    gate->report_space_failure(result.win32_error, failed_path);
                }
                continue; // 回到 wait() 重新裁决

            case AttemptResult::Kind::PermanentFailure:
                // 非空间错误**不能证明卷可写** → probe inconclusive（绝不 Ready）。
                if (lease.valid())
                {
                    lease.report_inconclusive();
                }
                return result;

            case AttemptResult::Kind::Terminal:
                if (lease.valid())
                {
                    lease.report_inconclusive();
                }
                return result;
            }
        }
    }

}

#endif
