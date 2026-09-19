#include "sevenzip_bridge/bridge.hpp"
#include "internal/sevenzip_paths.hpp"
#include "internal/sevenzip_formats.hpp"
#include "internal/password_probe_policy.hpp"
#include "internal/sevenzip_status.hpp"
#include "internal/native_runtime_control.hpp"
#include "internal/native_worker_sizing.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#ifdef _WIN32
namespace {

bool check_numbered_volume_paths() {
    const std::vector<std::wstring> zip_parts = {
        L"payload.zip.0002",
        L"payload.zip.0000",
        L"payload.zip.0001",
    };
    const auto sorted = sunpack::sevenzip::sorted_data_volume_paths(zip_parts);
    if (sorted.size() != 3 ||
        std::filesystem::path(sorted[0]).filename() != L"payload.zip.0000" ||
        std::filesystem::path(sorted[1]).filename() != L"payload.zip.0001" ||
        std::filesystem::path(sorted[2]).filename() != L"payload.zip.0002" ||
        sunpack::sevenzip::parse_volume_number(sorted[0]).value_or(-1) != 0) {
        return false;
    }

    const std::vector<std::wstring> seven_zip_parts = {
        L"payload.7z.002",
        L"payload.7z.001",
    };
    const auto seven_zip_sorted = sunpack::sevenzip::sorted_data_volume_paths(seven_zip_parts);
    return seven_zip_sorted.size() == 2 &&
        std::filesystem::path(seven_zip_sorted[0]).filename() == L"payload.7z.001" &&
        std::filesystem::path(seven_zip_sorted[1]).filename() == L"payload.7z.002";
}

bool check_rar_hint_prefers_signature_handler() {
    using sunpack::sevenzip::candidate_formats_for_hint;

    const auto root = std::filesystem::temp_directory_path() /
        (L"sunpack-rar-signature-" + std::to_wstring(GetCurrentProcessId()));
    std::error_code error;
    std::filesystem::remove_all(root, error);
    error.clear();
    std::filesystem::create_directories(root, error);
    if (error) {
        return false;
    }

    const auto check_signature = [&](const wchar_t* name,
                                     const std::vector<unsigned char>& signature,
                                     unsigned char expected_id) {
        const auto path = root / name;
        std::ofstream stream(path, std::ios::binary | std::ios::trunc);
        if (!stream) {
            return false;
        }
        stream.write(reinterpret_cast<const char*>(signature.data()),
                     static_cast<std::streamsize>(signature.size()));
        stream.close();
        if (!stream) {
            return false;
        }

        const auto formats = candidate_formats_for_hint(L"rar", path.wstring(), {});
        return formats.size() == 1 && formats.front().Data4[5] == expected_id;
    };

    const bool rar4_ok = check_signature(
        L"rar4.rar",
        {'R', 'a', 'r', '!', 0x1A, 0x07, 0x00},
        0x03);
    const bool rar5_ok = check_signature(
        L"rar5.rar",
        {'R', 'a', 'r', '!', 0x1A, 0x07, 0x01, 0x00},
        0xCC);

    const auto unknown_path = root / L"unknown.rar";
    {
        std::ofstream stream(unknown_path, std::ios::binary | std::ios::trunc);
        stream << "not-rar";
    }
    const auto fallback = candidate_formats_for_hint(L"rar", unknown_path.wstring(), {});
    const bool fallback_ok =
        fallback.size() == 2 &&
        fallback[0].Data4[5] == 0x03 &&
        fallback[1].Data4[5] == 0xCC;

    std::filesystem::remove_all(root, error);
    return rar4_ok && rar5_ok && fallback_ok;
}

bool check_wrong_password_evidence() {
    using sunpack::sevenzip::looks_wrong_password;
    using namespace sunpack::sevenzip;
    return
        looks_wrong_password(S_OK, kOpWrongPassword, false) &&
        !looks_wrong_password(S_FALSE, kOpOk, false) &&
        !looks_wrong_password(S_OK, kOpDataError, false) &&
        !looks_wrong_password(S_OK, kOpCrcError, false) &&
        looks_wrong_password(S_FALSE, kOpOk, true) &&
        looks_wrong_password(S_OK, kOpDataError, true) &&
        looks_wrong_password(S_OK, kOpCrcError, true);
}

bool check_password_probe_status_names() {
    return std::string(sunpack::sevenzip::status_name(
        sunpack::sevenzip::PasswordTestStatus::NeedsVolumeOrTailDamaged
    )) == "needs_volume_or_tail_damaged";
}

sunpack::sevenzip::NativeRuntimeConfig deterministic_runtime_config(std::size_t initial) {
    using namespace sunpack::sevenzip;
    NativeRuntimeConfig config;
    config.initial_active_jobs = initial;
    config.exploration_strategy = NativeExplorationStrategy::Calibrated;
    config.minimum_window_seconds = 0.1;
    config.maximum_window_seconds = 0.1;
    config.settle_seconds = 0.0;
    config.large_window_bytes = 500;
    config.small_window_jobs = 2;
    config.small_window_files = 2;
    config.cooldown_windows = 1;
    config.hold_windows = 2;
    return config;
}

bool check_empty_bounded_password_probe_requires_positive_evidence() {
    using sunpack::sevenzip::EmptyBoundedPasswordProbeDisposition;
    using sunpack::sevenzip::empty_bounded_password_probe_disposition;
    return
        empty_bounded_password_probe_disposition(false, 0, false) ==
            EmptyBoundedPasswordProbeDisposition::RejectInconclusive &&
        empty_bounded_password_probe_disposition(true, 0, false) ==
            EmptyBoundedPasswordProbeDisposition::RejectInconclusive &&
        empty_bounded_password_probe_disposition(true, 0, true) ==
            EmptyBoundedPasswordProbeDisposition::AcceptOpenProof &&
        empty_bounded_password_probe_disposition(true, 3, false) ==
            EmptyBoundedPasswordProbeDisposition::TestAllItems;
}

bool check_runtime_control_uses_only_limit_and_hard_memory_for_admission() {
    using namespace sunpack::sevenzip;
    auto config = deterministic_runtime_config(3);
    config.adaptive_enabled = false;
    NativeRuntimeControl controller(8, 1'024, config);
    return controller.can_admit(2, 512, 512) &&
        !controller.can_admit(3, 0, 1) &&
        !controller.can_admit(2, 800, 300);
}

bool check_runtime_control_rolls_back_large_window_regression() {
    using namespace sunpack::sevenzip;
    NativeRuntimeControl controller(8, 0, deterministic_runtime_config(4));
    NativeRuntimeSample runtime;
    NativeThroughputCounters counters;
    controller.observe(runtime, counters, 100, 4, 0, 0.1);
    counters.accepted_bytes = counters.written_bytes = 1'000;
    counters.completed_jobs = 2;
    controller.observe(runtime, counters, 100, 4, 0, 0.1);
    if (controller.snapshot(4, 0).active_limit != 5) {
        return false;
    }
    counters.accepted_bytes = counters.written_bytes = 1'800;
    counters.completed_jobs = 4;
    controller.observe(runtime, counters, 100, 5, 0, 0.1);
    const auto snapshot = controller.snapshot(5, 0);
    return snapshot.active_limit == 4 &&
        snapshot.decision == NativeControllerDecision::RolledBack &&
        snapshot.throughput_mode == NativeThroughputMode::Bytes;
}

bool check_runtime_control_accepts_large_window_improvement() {
    using namespace sunpack::sevenzip;
    NativeRuntimeControl controller(8, 0, deterministic_runtime_config(4));
    NativeRuntimeSample runtime;
    NativeThroughputCounters counters;
    controller.observe(runtime, counters, 100, 4, 0, 0.1);
    counters.accepted_bytes = counters.written_bytes = 1'000;
    counters.completed_jobs = 2;
    controller.observe(runtime, counters, 100, 4, 0, 0.1);
    counters.accepted_bytes = counters.written_bytes = 2'200;
    counters.completed_jobs = 4;
    controller.observe(runtime, counters, 100, 5, 0, 0.1);
    return controller.snapshot(5, 0).active_limit == 6;
}

bool check_runtime_control_uses_small_job_window() {
    using namespace sunpack::sevenzip;
    auto config = deterministic_runtime_config(4);
    config.large_window_bytes = 1ULL << 30;
    NativeRuntimeControl controller(8, 0, config);
    NativeRuntimeSample runtime;
    NativeThroughputCounters counters;
    controller.observe(runtime, counters, 100, 4, 0, 0.1);
    counters.completed_jobs = 4;
    controller.observe(runtime, counters, 100, 4, 0, 0.1);
    counters.completed_jobs = 7;
    controller.observe(runtime, counters, 100, 5, 0, 0.1);
    const auto snapshot = controller.snapshot(5, 0);
    return snapshot.active_limit == 4 &&
        snapshot.throughput_mode == NativeThroughputMode::Jobs;
}

bool check_runtime_control_pauses_only_on_memory_emergency() {
    using namespace sunpack::sevenzip;
    auto config = deterministic_runtime_config(4);
    config.adaptive_enabled = false;
    config.memory_pause_available = 100;
    config.memory_resume_available = 200;
    NativeRuntimeControl controller(8, 1'024, config);
    NativeRuntimeSample runtime;
    NativeThroughputCounters counters;
    runtime.available_memory = 50;
    controller.observe(runtime, counters, 10, 2, 512, 0.1);
    if (!controller.snapshot(2, 512).memory_admission_paused ||
        controller.can_admit(2, 512, 128)) {
        return false;
    }
    runtime.available_memory = 300;
    controller.observe(runtime, counters, 10, 2, 512, 0.1);
    return !controller.snapshot(2, 512).memory_admission_paused &&
        controller.can_admit(2, 512, 128);
}

bool check_runtime_control_interrupts_probe_when_backlog_disappears() {
    using namespace sunpack::sevenzip;
    NativeRuntimeControl controller(8, 0, deterministic_runtime_config(4));
    NativeRuntimeSample runtime;
    NativeThroughputCounters counters;
    controller.observe(runtime, counters, 100, 4, 0, 0.1);
    counters.written_bytes = counters.accepted_bytes = 1'000;
    controller.observe(runtime, counters, 100, 4, 0, 0.1);
    if (controller.snapshot(4, 0).active_limit != 5) {
        return false;
    }
    controller.observe(runtime, counters, 0, 5, 0, 0.1);
    auto snapshot = controller.snapshot(5, 0);
    if (snapshot.active_limit != 4 ||
        snapshot.load_state != NativeLoadState::Unsaturated ||
        snapshot.decision != NativeControllerDecision::SegmentInterrupted) {
        return false;
    }
    counters.written_bytes = counters.accepted_bytes = 2'000;
    controller.observe(runtime, counters, 100, 4, 0, 0.1);
    snapshot = controller.snapshot(4, 0);
    return snapshot.active_limit == 4 &&
        snapshot.load_state == NativeLoadState::Saturated &&
        snapshot.phase == NativeControllerPhase::Baseline &&
        snapshot.decision == NativeControllerDecision::SegmentStarted;
}

bool check_runtime_control_parks_and_rebases_activity() {
    using namespace sunpack::sevenzip;
    auto config = deterministic_runtime_config(4);
    config.warm_start_confirmations = 2;
    NativeRuntimeControl controller(8, 0, config);
    NativeRuntimeSample runtime;
    NativeThroughputCounters counters;
    controller.observe(runtime, counters, 100, 4, 0, 0.1);
    counters.written_bytes = counters.accepted_bytes = 1'000;
    controller.observe(runtime, counters, 100, 4, 0, 0.1);
    controller.end_activity(counters);
    auto snapshot = controller.snapshot(0, 0);
    if (snapshot.active_limit != 4 ||
        snapshot.load_state != NativeLoadState::Idle ||
        snapshot.decision != NativeControllerDecision::ActivityEnded) {
        return false;
    }
    controller.begin_activity(counters, 1.0);
    counters.written_bytes = counters.accepted_bytes = 2'000;
    controller.observe(runtime, counters, 0, 1, 0, 0.1);
    controller.observe(runtime, counters, 100, 4, 0, 0.1);
    snapshot = controller.snapshot(4, 0);
    return snapshot.active_limit == 4 &&
        snapshot.activity_session == 2 &&
        snapshot.saturated_segment == 2 &&
        snapshot.throughput_mode == NativeThroughputMode::None;
}

bool check_runtime_control_warm_start_decays_without_reusing_measurements() {
    using namespace sunpack::sevenzip;
    auto config = deterministic_runtime_config(4);
    config.warm_start_decay_seconds = 30.0;
    config.warm_start_confirmations = 2;
    NativeRuntimeControl controller(8, 0, config);
    NativeRuntimeSample runtime;
    NativeThroughputCounters counters;
    controller.observe(runtime, counters, 100, 4, 0, 0.1);
    counters.written_bytes = counters.accepted_bytes = 1'000;
    controller.observe(runtime, counters, 100, 4, 0, 0.1);
    counters.written_bytes = counters.accepted_bytes = 2'200;
    controller.observe(runtime, counters, 100, 5, 0, 0.1);
    counters.written_bytes = counters.accepted_bytes = 3'600;
    controller.observe(runtime, counters, 100, 6, 0, 0.1);
    counters.written_bytes = counters.accepted_bytes = 4'600;
    controller.observe(runtime, counters, 100, 7, 0, 0.1);
    if (controller.snapshot(7, 0).active_limit != 6) {
        return false;
    }
    controller.end_activity(counters);
    controller.begin_activity(counters, 0.0);
    auto snapshot = controller.snapshot(0, 0);
    if (snapshot.active_limit != 6 || !snapshot.warm_start_used ||
        snapshot.throughput_mode != NativeThroughputMode::None) {
        return false;
    }
    controller.end_activity(counters);
    controller.begin_activity(counters, 15.0);
    snapshot = controller.snapshot(0, 0);
    if (snapshot.active_limit != 5 || !snapshot.warm_start_used) {
        return false;
    }
    controller.end_activity(counters);
    controller.begin_activity(counters, 30.0);
    snapshot = controller.snapshot(0, 0);
    return snapshot.active_limit == 4 && !snapshot.warm_start_used;
}

bool check_native_sizing_scales_linearly_with_cpu() {
    using namespace sunpack::sevenzip;
    NativeSizingOverrides defaults;
    constexpr std::uint64_t abundant_memory = 64ULL << 30;
    struct Expected {
        std::size_t logical_processors;
        std::size_t foreground_jobs;
    };
    const Expected cases[] = {
        {2, 1},
        {4, 2},
        {8, 4},
        {16, 8},
        {32, 16},
        {64, 32},
        {128, 64},
    };
    for (const auto& expected : cases) {
        const NativeMachineResources resources{
            expected.logical_processors,
            abundant_memory,
            abundant_memory,
        };
        const auto plan = derive_native_sizing_plan(resources, defaults);
        if (plan.initial_active_jobs != expected.foreground_jobs) {
            return false;
        }
    }
    return true;
}

bool check_native_sizing_respects_memory_and_overrides() {
    using namespace sunpack::sevenzip;
    const NativeMachineResources resources{32, 8ULL << 30, 4ULL << 30};
    const auto automatic = derive_native_sizing_plan(resources, {});
    // Memory is a hard admission budget, not a thread-capacity slot count.
    if (automatic.thread_capacity != 32 || automatic.initial_active_jobs != 16 ||
        automatic.memory_budget_bytes != (4ULL << 30) * 7 / 10) {
        return false;
    }

    NativeSizingOverrides overrides;
    overrides.thread_capacity = 12;
    overrides.initial_active_jobs = 10;
    overrides.memory_budget_bytes = 2ULL << 30;
    const auto configured = derive_native_sizing_plan(resources, overrides);
    return configured.thread_capacity == 12 && configured.initial_active_jobs == 10 &&
        configured.memory_budget_bytes == (2ULL << 30) &&
        configured.thread_capacity_overridden &&
        configured.initial_active_jobs_overridden &&
        configured.memory_budget_overridden;
}

}  // namespace
#endif

int wmain(int argc, wchar_t** argv) {
#ifdef _WIN32
    if (!check_numbered_volume_paths()) {
        std::cerr << "numbered volume path check failed\n";
        return 2;
    }
    if (!check_wrong_password_evidence()) {
        std::cerr << "wrong password evidence check failed\n";
        return 3;
    }
    if (!check_rar_hint_prefers_signature_handler()) {
        std::cerr << "RAR signature handler selection check failed\n";
        return 16;
    }
    if (!check_password_probe_status_names()) {
        std::cerr << "password probe status name check failed\n";
        return 4;
    }
    if (!check_empty_bounded_password_probe_requires_positive_evidence()) {
        std::cerr << "empty bounded password probe evidence check failed\n";
        return 15;
    }
    if (!check_runtime_control_uses_only_limit_and_hard_memory_for_admission()) {
        std::cerr << "runtime control admission check failed\n";
        return 5;
    }
    if (!check_runtime_control_rolls_back_large_window_regression()) {
        std::cerr << "runtime control large-window rollback check failed\n";
        return 6;
    }
    if (!check_runtime_control_accepts_large_window_improvement()) {
        std::cerr << "runtime control large-window improvement check failed\n";
        return 7;
    }
    if (!check_runtime_control_uses_small_job_window()) {
        std::cerr << "runtime control small-job window check failed\n";
        return 8;
    }
    if (!check_runtime_control_pauses_only_on_memory_emergency()) {
        std::cerr << "runtime control memory emergency check failed\n";
        return 9;
    }
    if (!check_runtime_control_interrupts_probe_when_backlog_disappears()) {
        std::cerr << "runtime control saturated-segment interruption check failed\n";
        return 10;
    }
    if (!check_runtime_control_parks_and_rebases_activity()) {
        std::cerr << "runtime control activity rebase check failed\n";
        return 11;
    }
    if (!check_runtime_control_warm_start_decays_without_reusing_measurements()) {
        std::cerr << "runtime control warm-start decay check failed\n";
        return 12;
    }
    if (!check_native_sizing_scales_linearly_with_cpu()) {
        std::cerr << "native sizing CPU extrapolation check failed\n";
        return 13;
    }
    if (!check_native_sizing_respects_memory_and_overrides()) {
        std::cerr << "native sizing hard-memory/override check failed\n";
        return 14;
    }
#endif

    // The 7-Zip backend is compiled into this binary, so there is no backend
    // location to select any more. An optional argument names the archive to
    // probe; an empty path exercises the "no archive" path.
    std::wstring archive_path;
    if (argc > 1) {
        archive_path = argv[1];
    }

    const bool available = sunpack::sevenzip::is_backend_available();
    const auto result = sunpack::sevenzip::test_password(archive_path, L"");

    std::cout << "backend_available=" << (available ? "true" : "false") << "\n";
    std::cout << "status=" << sunpack::sevenzip::status_name(result.status) << "\n";
    std::cout << "message=" << result.message << "\n";

    return available == result.backend_available ? 0 : 1;
}