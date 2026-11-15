#pragma once

#include "sevenzip_space_gate.hpp"

#ifdef _WIN32

#include <string_view>
#include <utility>

namespace sunpack::sevenzip
{
    // 一次真实文件系统操作的结果（四态）。
    struct AttemptResult
    {
        enum class Kind
        {
            Succeeded,        // 一次真实操作成功
            SpaceFailure,     // 空间不足（有 gate 时恢复；无 gate 时由调用方记录失败）
            PermanentFailure, // 确凿的非空间错误（不可重试）
            Terminal,         // 调用方要求终止（取消 / draining）；本次 attempt 未产生任何副作用
        };

        Kind kind = Kind::Succeeded;
        unsigned long win32_error = 0; // 仅 SpaceFailure / PermanentFailure 有意义
    };

    // Async completions must publish failure evidence before handing off to
    // their IOCP retry queue. Delaying it until dequeue can incorrectly open
    // a new blocked episode after another request has already recovered.
    inline void report_retry_space_failure(VolumeSpaceGate *gate,
                                           unsigned long error,
                                           std::wstring_view failed_path) noexcept
    {
        if (gate) gate->report_space_failure(error, failed_path);
    }

    inline void settle_space_attempt(ProbeLease &lease, const AttemptResult &result,
                                     std::wstring_view path) noexcept
    {
        if (!lease.valid()) return;
        if (result.kind == AttemptResult::Kind::Succeeded) lease.report_success();
        else if (result.kind == AttemptResult::Kind::SpaceFailure)
            lease.report_space_failure(result.win32_error, path);
        else lease.report_inconclusive();
    }

    // 目录操作的阻塞重试骨架；与 IOCP 共享 gate 裁决及许可结算。语义是异常驱动的
    // 冷路径：先做一次真实操作，只有真的返回 SpaceFailure 才触碰 gate；gate == nullptr 时
    // 原样外泄结果。写成功不回报 gate —— 卷恢复的唯一裁决者是 monitor 采样 + 一次真实 probe。
    //
    // attempt 的契约：
    //   1. 只做一次真实文件系统操作；绝不调用 gate / lease 的任何接口，绝不记账。
    //   2. 空间类错误用 is_space_exhaustion_error() 判定，把 Win32 码放进 win32_error。
    //   3. 不得抛出异常（骨架是 noexcept）。
    //   4. 终态自作：调用方已要求终止时，必须在产生任何副作用之前返回 Terminal。
    //
    // make_terminal 的契约：产出一个供 gate 使用的终态谓词，只在第一次真实空间失败之后被
    // 调用一次（惰性），因此热路径上根本不会构造 std::function。
    template <typename TerminalFactory, typename AttemptFn>
    AttemptResult retry_with_space_gate(VolumeSpaceGate *gate,
                                        TerminalFactory &&make_terminal,
                                        std::wstring_view failed_path,
                                        AttemptFn &&attempt) noexcept
    {
        AttemptResult result = attempt();
        if (result.kind != AttemptResult::Kind::SpaceFailure)
        {
            return result;
        }

        if (gate == nullptr)
        {
            // 没有恢复 gate：只试一次，由调用方记录失败。
            return result;
        }

        // 失败证据必须先于 wait() 上报：wait() 只做裁决，不产生证据。
        report_retry_space_failure(gate, result.win32_error, failed_path);

        const TerminalPredicate terminal = make_terminal();

        for (;;)
        {
            ProbeLease lease;
            // lease 必须每轮迭代析构：提到循环外会让下一轮在持有许可时上报失败，状态机错乱。
            auto decision = gate->wait(terminal);

            if (decision.kind == VolumeSpaceGate::WaitResult::Kind::Terminal)
            {
                return {AttemptResult::Kind::Terminal, 0};
            }
            if (decision.kind == VolumeSpaceGate::WaitResult::Kind::Probe)
            {
                lease = std::move(decision.lease); // 持有许可，必须结算
            }

            result = attempt();

            const bool held_probe = lease.valid();
            settle_space_attempt(lease, result, failed_path);
            if (result.kind != AttemptResult::Kind::SpaceFailure) return result;
            if (!held_probe) report_retry_space_failure(gate, result.win32_error, failed_path);

        }
    }

}

#endif
