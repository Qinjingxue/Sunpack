#pragma once

#include "sevenzip_sdk.hpp"

#ifdef _WIN32

#include <system_error>

namespace sunpack::sevenzip
{
    // 卷空间不足类的**唯一判定入口**。任何"空间不足类"的瞬时卷错误都必须经由这里，
    // 不允许在调用点重新列举错误码（否则多处判定逻辑必然漂移）。
    //
    // 数值已用 Windows SDK 10.0.26100.0 的 shared\winerror.h 逐条核对。
    //
    // ⚠️ 曾写错过的两个码（务必不要写回）：
    //     ERROR_DISK_RESOURCES_EXHAUSTED  = 314  (0x13A)
    //     ERROR_NONPAGED_SYSTEM_RESOURCES = 1451 (0x5AB)   ← 不是磁盘错误！
    //   把 1451 放进本函数会让"系统 nonpaged 资源不足"被当成磁盘满，
    //   于是任务进入永不结束的"等待释放磁盘空间"。
    //
    // 刻意不纳入的错误码：
    //   ERROR_FILE_TOO_LARGE (223)              —— 单文件上限，释放空间不会改变结果
    //   ERROR_NONPAGED_SYSTEM_RESOURCES (1451)  —— 系统资源，与磁盘无关
    //   ERROR_CRC (23) / ERROR_WRITE_FAULT (29) —— 非空间类，属既有永久失败
    inline bool is_space_exhaustion_error(unsigned long win32_error) noexcept
    {
        switch (win32_error)
        {
        case ERROR_DISK_FULL:                // 112  介质已满
        case ERROR_HANDLE_DISK_FULL:         // 39   等价语义；网络/过滤驱动可能返回它
        case ERROR_DISK_RESOURCES_EXHAUSTED: // 314  磁盘物理资源耗尽（NTFS 元数据 / MFT 空间）
        case ERROR_DISK_QUOTA_EXCEEDED:      // 1295 配额耗尽，用户释放配额后可恢复
            return true;
        default:
            return false;
        }
    }

    // std::filesystem 的 non-throwing overload 把 Win32 码放进 std::error_code，
    // 其 category() 在 MSVC 上是 system_category()、value() 即 Win32 码。
    // 没有这个重载，根输出目录 / 条目目录创建路径无法与本函数共用判定。
    inline bool is_space_exhaustion_error(const std::error_code &error) noexcept
    {
        if (!error)
        {
            return false;
        }
        if (error.category() == std::system_category())
        {
            return is_space_exhaustion_error(static_cast<unsigned long>(error.value()));
        }
        return error == std::errc::no_space_on_device;
    }

    inline bool is_space_exhaustion_hresult(long hresult) noexcept
    {
        return HRESULT_FACILITY(hresult) == FACILITY_WIN32 &&
               is_space_exhaustion_error(static_cast<unsigned long>(HRESULT_CODE(hresult)));
    }

}

#endif
