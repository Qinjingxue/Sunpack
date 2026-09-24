#pragma once

#include "sevenzip_bridge/bridge.hpp"
#include "sevenzip_sdk.hpp"

#ifdef _WIN32
#include <string>
#include <vector>
#endif

namespace sunpack::sevenzip {

#ifdef _WIN32

struct ArchiveOpenPlan {
    std::vector<ExtractInputRange> ranges;
    std::vector<GUID> formats;
    UInt64 archive_offset = 0;
    std::wstring archive_type;
    std::string source;

    bool uses_ranges() const { return !ranges.empty(); }
};

std::vector<ArchiveOpenPlan> embedded_archive_open_plans(
    const std::wstring& archive_path,
    const std::vector<std::wstring>& part_paths
);

std::vector<ArchiveOpenPlan> embedded_seven_zip_open_plans(
    const std::wstring& archive_path,
    const std::vector<std::wstring>& part_paths
);

std::vector<ArchiveOpenPlan> password_test_open_plans(
    const std::wstring& archive_path,
    const std::vector<std::wstring>& part_paths,
    const std::vector<GUID>& formats,
    const std::vector<ExtractInputRange>& input_ranges,
    bool format_hint_known = false
);

CMyComPtr<IInStream> open_stream_for_plan(
    const ArchiveOpenPlan& plan,
    const std::wstring& archive_path,
    const std::vector<std::wstring>& part_paths,
    bool& stream_opened
);

void apply_plan_metadata(PasswordTestResult& result, const ArchiveOpenPlan& plan);

#endif

}  // namespace sunpack::sevenzip
