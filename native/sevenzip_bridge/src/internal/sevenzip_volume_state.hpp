#pragma once

#include "sevenzip_space_gate.hpp"
#include "sevenzip_writer_meters.hpp"

#ifdef _WIN32

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>

namespace sunpack::sevenzip
{

    using VolumeKey = std::string;
    struct VolumeState
    {
        explicit VolumeState(VolumeKey volume_key, bool is_persistent)
            : key(std::move(volume_key)), persistent(is_persistent) {}

        const VolumeKey key;
        const bool persistent = true;

        WriterCounters counters;

        std::atomic<std::uint64_t> accounting_violations{0};

        // 懒创建：dry-run job 与 shared_writer == nullptr 的兜底 writer 没有真实卷身份
        // （key 为空），此时 gate 保持 nullptr，让这些路径语义完全不变。
        //
        // ⚠️ 生命周期：gate 的存活期 = VolumeState 的存活期，**长于 writer facility**。
        //    因此 gate 里绝不能保存任何指向 writer 成员的指针/引用，AsyncFileWriter
        //    也绝不持有 / 重设 ChangeSink（否则 facility 被 reap / 重建时会覆盖
        //    persistent gate 的回调）。
        //
        // ⚠️ 这里**不需要** query_root / dedup_key / facility_key 字段：
        //    查询路径是 VolumeSpaceGate 的私有惰性缓存，不是卷元数据。
        //
        // ⚠️ 这里曾有一个 `std::atomic<VolumeSpaceState> space_state`（零使用，已删除）。
        std::shared_ptr<VolumeSpaceGate> space_gate;
    };

    using VolumeStatePtr = std::shared_ptr<VolumeState>;

    inline VolumeStatePtr make_volume_state(VolumeKey key, bool persistent)
    {
        return std::make_shared<VolumeState>(std::move(key), persistent);
    }

}

#endif
