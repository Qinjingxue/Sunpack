#pragma once

#include "sevenzip_space_retry.hpp"

#ifdef _WIN32

#include <filesystem>
#include <functional>
#include <system_error>
#include <utility>

namespace sunpack::sevenzip
{
    // 测试专用：目录创建的空间类错误判定器可注入（默认 is_space_exhaustion_error）。
    // 生产代码永不设置它；单测用真实错误码（把普通文件挡在目标目录位置上 →
    // ERROR_ALREADY_EXISTS）驱动同一代码路径，只把"是否算空间类"这一步换成可注入判定。
    using DirectoryFailureClassifier = std::function<bool(const std::error_code &)>;

    inline DirectoryFailureClassifier &directory_failure_classifier_for_test() noexcept
    {
        static DirectoryFailureClassifier classifier;
        return classifier;
    }

    inline void set_directory_failure_classifier_for_test(
        DirectoryFailureClassifier classifier) noexcept
    {
        directory_failure_classifier_for_test() = std::move(classifier);
    }

    inline bool is_directory_space_failure(const std::error_code &error) noexcept
    {
        const DirectoryFailureClassifier &injected = directory_failure_classifier_for_test();
        if (injected)
        {
            try
            {
                return injected(error);
            }
            catch (...)
            {
                return false;
            }
        }
        return is_space_exhaustion_error(error);
    }

    // 可暂停的目录创建，全项目唯一的目录创建入口（archive_extract.cpp 的根输出目录创建、
    // sevenzip_callbacks.hpp 的 ensure_directory 都必须调用它，不允许各自写一份重试逻辑）。
    //
    // 内部只用 non-throwing overload create_directories(path, ec)：会抛 filesystem_error 的
    // 重载从 noexcept helper 里穿出来等于 std::terminate()。
    //
    // 返回 true 表示目录已可用；返回 false 时 *out_error 已填充。
    // ensure_no_reparse_ancestors() 仍会抛 filesystem_error，必须由调用方在本 helper 之外
    // 用 try/catch 包住，不能让它穿进这里的 noexcept。
    inline bool create_directories_with_space_gate(
        const std::filesystem::path &directory,
        VolumeSpaceGate *gate,
        const TerminalPredicate &terminal,
        std::error_code *out_error) noexcept
    {
        if (out_error)
        {
            out_error->clear();
        }
        if (directory.empty())
        {
            if (out_error)
            {
                *out_error = std::make_error_code(std::errc::invalid_argument);
            }
            return false;
        }

        // 终态前置检查（调用方语义，不是骨架的一部分）：取消 / draining 时绝不能真的去创建
        // 目录。只在 gate 存在时检查 —— gate == nullptr 必须保持"只尝试一次、绝不出于终态
        // 跳过"的旧语义。
        if (gate != nullptr && terminal && terminal())
        {
            if (out_error)
            {
                *out_error = std::make_error_code(std::errc::operation_canceled);
            }
            return false;
        }

        unsigned long failure_code = 0;
        const AttemptResult result = retry_with_space_gate(
            gate,
            [&terminal] { return terminal; }, // 惰性：正常创建目录时根本不构造谓词
            directory.native(),
            [&directory, &failure_code]() noexcept -> AttemptResult
            {
                std::error_code ec;
                std::filesystem::create_directories(directory, ec);
                if (!ec)
                {
                    return {AttemptResult::Kind::Succeeded, 0};
                }
                // system_category() 的 value() 就是 Win32 码。
                failure_code = static_cast<unsigned long>(ec.value());
                return {is_directory_space_failure(ec) ? AttemptResult::Kind::SpaceFailure
                                                       : AttemptResult::Kind::PermanentFailure,
                        failure_code};
            });

        if (result.kind == AttemptResult::Kind::Succeeded)
        {
            return true;
        }
        if (out_error)
        {
            if (result.kind == AttemptResult::Kind::Terminal)
            {
                // attempt 未被调用，failure_code 仍是 0 —— 不能把它当成"成功"的 ec。
                *out_error = std::make_error_code(std::errc::operation_canceled);
            }
            else
            {
                *out_error =
                    std::error_code(static_cast<int>(failure_code), std::system_category());
            }
        }
        return false;
    }

}

#endif
