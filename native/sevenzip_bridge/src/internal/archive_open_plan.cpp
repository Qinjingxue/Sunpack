#include "archive_open_plan.hpp"

#include "sevenzip_streams.hpp"

namespace sunpack::sevenzip {

#ifdef _WIN32

std::vector<ArchiveOpenPlan> password_test_open_plans(
    const std::vector<GUID>& formats,
    const std::vector<ExtractInputRange>& input_ranges,
    const std::wstring& format_hint
) {
    ArchiveOpenPlan plan;
    plan.ranges = input_ranges;
    plan.formats = formats;
    plan.archive_offset = input_ranges.empty() ? 0 : input_ranges.front().start;
    plan.format_hint = format_hint;
    plan.source = input_ranges.empty() ? "whole_file" : "provided_ranges";
    return {plan};
}

CMyComPtr<IInStream> open_stream_for_plan(
    const ArchiveOpenPlan& plan,
    const std::wstring& archive_path,
    const std::vector<std::wstring>& part_paths,
    bool& stream_opened,
    bool structured_order
) {
    if (plan.uses_ranges()) {
        auto* range_stream = new MultiRangeInStream(plan.ranges);
        stream_opened = range_stream->is_open();
        return CMyComPtr<IInStream>(range_stream);
    }
    // Structured (canonically named) volumes are already ordered by
    // Relations; re-sorting by physical filename would drop a disguised head.
    return open_archive_stream(archive_path, part_paths, stream_opened, nullptr, structured_order);
}

void apply_plan_metadata(PasswordTestResult& result, const ArchiveOpenPlan& plan) {
    result.archive_offset = plan.archive_offset;
    if (!plan.format_hint.empty()) {
        result.archive_type = plan.format_hint;
    }
}

#endif

}  // namespace sunpack::sevenzip
