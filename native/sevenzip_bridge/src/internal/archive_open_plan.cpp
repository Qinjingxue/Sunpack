#include "archive_open_plan.hpp"

#include "embedded_7z.hpp"
#include "sevenzip_formats.hpp"
#include "sevenzip_paths.hpp"
#include "sevenzip_streams.hpp"

#ifdef _WIN32
#include <utility>
#endif

namespace sunpack::sevenzip {

#ifdef _WIN32

std::vector<ArchiveOpenPlan> embedded_archive_open_plans(
    const std::wstring& archive_path,
    const std::vector<std::wstring>& part_paths
) {
    std::vector<ArchiveOpenPlan> plans;
    for (const auto& candidate : find_embedded_archive_candidates(archive_path, part_paths)) {
        ExtractInputRange range;
        range.path = candidate.path;
        range.start = candidate.offset;
        range.has_end = false;

        ArchiveOpenPlan plan;
        plan.ranges = {range};
        plan.formats = {format_guid(candidate.format_id)};
        plan.archive_offset = candidate.offset;
        plan.archive_type = candidate.archive_type;
        plan.source = "embedded_carrier";
        plans.push_back(std::move(plan));
    }
    return plans;
}

std::vector<ArchiveOpenPlan> embedded_seven_zip_open_plans(
    const std::wstring& archive_path,
    const std::vector<std::wstring>& part_paths
) {
    std::vector<ArchiveOpenPlan> plans;
    for (auto& plan : embedded_archive_open_plans(archive_path, part_paths)) {
        if (plan.archive_type == L"7z") {
            plan.source = "embedded_7z";
            plans.push_back(std::move(plan));
        }
    }
    return plans;
}

std::vector<ArchiveOpenPlan> password_test_open_plans(
    const std::wstring& archive_path,
    const std::vector<std::wstring>& part_paths,
    const std::vector<GUID>& formats,
    const std::vector<ExtractInputRange>& input_ranges,
    bool format_hint_known
) {
    ArchiveOpenPlan base;
    base.ranges = input_ranges;
    base.formats = formats;
    const std::wstring base_type = archive_type_for_path(archive_path);
    base.archive_type = base_type;
    base.source = input_ranges.empty() ? "whole_file" : "provided_ranges";

    if (!input_ranges.empty() || format_hint_known) {
        return {base};
    }
    if (!base_type.empty() && base_type != L"pe") {
        return {base};
    }

    std::vector<ArchiveOpenPlan> embedded = embedded_archive_open_plans(archive_path, part_paths);
    if (embedded.empty()) {
        return {base};
    }
    if (is_standard_seven_zip_path(archive_path)) {
        embedded.insert(embedded.begin(), std::move(base));
        return embedded;
    }
    embedded.push_back(std::move(base));
    return embedded;
}

CMyComPtr<IInStream> open_stream_for_plan(
    const ArchiveOpenPlan& plan,
    const std::wstring& archive_path,
    const std::vector<std::wstring>& part_paths,
    bool& stream_opened
) {
    if (plan.uses_ranges()) {
        auto* range_stream = new MultiRangeInStream(plan.ranges);
        stream_opened = range_stream->is_open();
        CMyComPtr<IInStream> owner(range_stream);

        return owner.Detach();
    }
    return open_archive_stream(archive_path, part_paths, stream_opened);
}

void apply_plan_metadata(PasswordTestResult& result, const ArchiveOpenPlan& plan) {
    result.archive_offset = plan.archive_offset;
    if (!plan.archive_type.empty()) {
        result.archive_type = plan.archive_type;
    }
}

#endif

}  // namespace sunpack::sevenzip
