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
            SpaceFailure,     // 空间不足（gate 存在时进入冷路径重试；gate 为 null 时由调用方转旧语义）
            PermanentFailure, // 确凿的非空间错误（不可重试）
            Terminal,         // 调用方要求终止（取消 / draining）；**本次 attempt 未产生任何副作用**
        };

        Kind kind = Kind::Succeeded;
        unsigned long win32_error = 0; // 仅 SpaceFailure / PermanentFailure 有意义
    };

    // ---------------------------------------------------------------------
    // **唯一的重试骨架。它是全项目唯一有权调用 gate 空间状态接口的地方。**
    //
    // 语义是**异常驱动的冷路径**（架构师第十二轮 P1："正常路径零开销"）：
    //
    //        attempt()                        ← 每一次都先做**真实操作**
    //          ├─ 不是 SpaceFailure ─────────→ 立即返回；**gate 自始至终未被触碰**
    //          └─ SpaceFailure
    //               ├─ gate == nullptr ─────→ 原样外泄（调用方执行旧版永久失败副作用）
    //               └─ gate != nullptr ─────→ 冷路径：report → wait → attempt → 结算
    //
    //   于是"没有满盘时这个功能不存在"是**结构性**成立的，而不是靠"gate 的快路径足够快"：
    //     * 正常写路径**不取 gate mutex、不做 shared_ptr 引用计数、不构造终态谓词**；
    //     * 磁盘自己就是检测器 —— 第一次真实失败才把居间调停唤醒。
    //   代价被严格限制在异常路径：满盘那一刻，同卷每个 writer 线程各撞一次真实的
    //   ERROR_DISK_FULL 之后才进门排队。这恰好就是"磁盘满"本来的样子，而且必须如此：
    //   writer 停止尝试的唯一依据只能是**真实失败**，不能是 gate 的猜测。
    //
    //   ⚠️ 反向推论（写在这里防止将来有人"优化"回来）：**写成功不回报 gate**。
    //      卷恢复的唯一裁决者是 monitor 采样 + 一次真实 probe（铁律一）。让成功路径
    //      回报 gate，等于把热路径重新接回 gate，本函数的全部意义立即消失。
    //
    // attempt 的契约（必须遵守）：
    //   1. 只做一次真实文件系统操作。
    //   2. **绝不**调用 gate 或 lease 的任何状态接口。
    //   3. 空间类错误的判定用 is_space_exhaustion_error()，把 Win32 码放进 win32_error。
    //   4. 绝不记账（discarded 由 writer_loop 独占）。
    //   5. 不得抛出异常（骨架是 noexcept）。
    //   6. **终态自作**：调用方已要求终止时，attempt 必须**在产生任何副作用之前**
    //      返回 Terminal。热路径上骨架不再替调用方预先求值终态谓词 —— 那已经属于
    //      gate 路径的职责（而 gate 路径只在真的满盘之后才存在）。
    //      `attempt_data_write()` 正是这么做的：入口先查 current_error(job)。
    //
    // make_terminal 的契约：产出一个供 gate 使用的终态谓词。
    //   ★ 它**只在第一次真实空间失败之后被调用一次**（惰性）。因此热路径上
    //     `std::function` 的构造（可能堆分配 + shared_ptr 引用计数）根本不会发生。
    //   ⚠️ 它在 noexcept 上下文里被调用：若构造真的抛出 bad_alloc，行为与改造前
    //      （writer_loop 内构造谓词）完全一致 —— 都是 terminate，没有回归。
    // ---------------------------------------------------------------------
    template <typename TerminalFactory, typename AttemptFn>
    AttemptResult retry_with_space_gate(VolumeSpaceGate *gate,
                                        TerminalFactory &&make_terminal,
                                        std::wstring_view failed_path,
                                        AttemptFn &&attempt) noexcept
    {
        // ── ① 热路径：一次真实操作。这一行之前没有任何 gate 相关指令。 ──────────
        AttemptResult result = attempt();
        if (result.kind != AttemptResult::Kind::SpaceFailure)
        {
            return result; // Succeeded / PermanentFailure / Terminal 三者都到此为止
        }

        if (gate == nullptr)
        {
            // 功能关闭 / 无卷身份：**只试一次，原样返回结果**。
            // 这里不做任何 classify —— gate 关闭时的旧语义副作用由调用方负责。
            return result;
        }

        // ── ② 冷路径：第一次真实的空间失败。从这里开始才存在 VolumeSpaceGate。 ──
        //
        // ★ 失败证据**必须**先上报，且必须在 wait() 之前：wait() 只做裁决、不产生证据，
        //   "卷进入 Blocked / 其他 writer 停止尝试 / space_blocked 事件"全部源于这一行。
        gate->report_space_failure(result.win32_error, failed_path);

        // ★ 终态谓词的构造被推迟到冷路径（见上）。
        const TerminalPredicate terminal = make_terminal();

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

            result = attempt();

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
