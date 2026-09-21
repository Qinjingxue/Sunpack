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

bool check_extraction_handler_selection_is_read_free() {
    using sunpack::sevenzip::extraction_formats_for_hint;

    const auto root = std::filesystem::temp_directory_path() /
        (L"sunpack-extraction-selector-" + std::to_wstring(GetCurrentProcessId()));
    std::error_code error;
    std::filesystem::remove_all(root, error);
    error.clear();
    std::filesystem::create_directories(root, error);
    if (error) {
        return false;
    }

    // Put an RAR4 signature on disk. Extraction must not inspect it: the
    // already-analyzed generic RAR hint maps directly to the fixed handler
    // order (RAR5, then RAR4).
    const auto path = root / L"payload.rar";
    {
        std::ofstream stream(path, std::ios::binary | std::ios::trunc);
        const std::vector<unsigned char> rar4 = {'R', 'a', 'r', '!', 0x1A, 0x07, 0x00};
        stream.write(
            reinterpret_cast<const char*>(rar4.data()),
            static_cast<std::streamsize>(rar4.size()));
    }

    const auto formats = extraction_formats_for_hint(L"rar", path.wstring());
    std::filesystem::remove_all(root, error);
    return formats.size() == 2 &&
        formats[0].Data4[5] == 0xCC &&
        formats[1].Data4[5] == 0x03;
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

void observe_control_observation(
    sunpack::sevenzip::NativeRuntimeControl& controller,
    const sunpack::sevenzip::NativeRuntimeSample& runtime,
    sunpack::sevenzip::NativeThroughputCounters& counters,
    std::size_t active_jobs,
    std::uint64_t bytes_per_window,
    std::uint64_t jobs_per_window = 2,
    std::uint64_t files_per_window = 2
) {
    for (int window = 0; window < 3; ++window) {
        counters.accepted_bytes += bytes_per_window;
        counters.written_bytes += bytes_per_window;
        counters.completed_jobs += jobs_per_window;
        counters.completed_files += files_per_window;
        controller.observe(runtime, counters, 100, active_jobs, 0.1);
    }
}

bool check_runtime_control_waits_for_three_window_observation() {
    using namespace sunpack::sevenzip;
    NativeRuntimeControl controller(8, deterministic_runtime_config(4));
    NativeRuntimeSample runtime;
    NativeThroughputCounters counters;
    controller.observe(runtime, counters, 100, 4, 0.1);

    for (int window = 0; window < 2; ++window) {
        counters.accepted_bytes += 1'000;
        counters.written_bytes += 1'000;
        counters.completed_jobs += 2;
        counters.completed_files += 2;
        controller.observe(runtime, counters, 100, 4, 0.1);
        const auto partial = controller.snapshot(4);
        if (partial.active_limit != 4 ||
            partial.phase != NativeControllerPhase::Baseline ||
            partial.measurement_sequence != static_cast<std::uint64_t>(window + 1) ||
            partial.throughput_mode != NativeThroughputMode::None) {
            return false;
        }
    }

    counters.accepted_bytes += 1'000;
    counters.written_bytes += 1'000;
    counters.completed_jobs += 2;
    counters.completed_files += 2;
    controller.observe(runtime, counters, 100, 4, 0.1);
    const auto snapshot = controller.snapshot(4);
    return snapshot.active_limit == 5 &&
        snapshot.phase == NativeControllerPhase::Probe &&
        snapshot.measurement_sequence == 3 &&
        snapshot.throughput_mode == NativeThroughputMode::Bytes;
}

bool check_runtime_control_rolls_back_large_window_regression() {
    using namespace sunpack::sevenzip;
    NativeRuntimeControl controller(8, deterministic_runtime_config(4));
    NativeRuntimeSample runtime;
    NativeThroughputCounters counters;
    controller.observe(runtime, counters, 100, 4, 0.1);

    observe_control_observation(controller, runtime, counters, 4, 1'000);
    if (controller.snapshot(4).active_limit != 5) {
        return false;
    }

    observe_control_observation(controller, runtime, counters, 5, 800);
    auto snapshot = controller.snapshot(5);
    if (snapshot.active_limit != 4 ||
        snapshot.phase != NativeControllerPhase::Verify ||
        snapshot.decision != NativeControllerDecision::VerifyStarted) {
        return false;
    }

    observe_control_observation(controller, runtime, counters, 4, 1'000);
    snapshot = controller.snapshot(4);
    return snapshot.active_limit == 4 &&
        snapshot.decision == NativeControllerDecision::RolledBack &&
        snapshot.throughput_mode == NativeThroughputMode::Bytes;
}

bool check_runtime_control_emits_fixed_measurement_windows() {
    using namespace sunpack::sevenzip;
    auto config = deterministic_runtime_config(4);
    config.adaptive_enabled = false;
    config.measurement_diagnostics_enabled = true;
    NativeRuntimeControl controller(8, config);
    NativeRuntimeSample runtime;
    NativeThroughputCounters counters;

    controller.observe(runtime, counters, 100, 4, 0.1);
    counters.accepted_bytes = 1'000;
    counters.written_bytes = 700;
    counters.completed_jobs = 2;
    counters.completed_files = 2;
    controller.observe(runtime, counters, 100, 4, 0.1);
    auto snapshot = controller.snapshot(4);
    if (snapshot.active_limit != 4 ||
        snapshot.measurement_sequence != 1 ||
        snapshot.measurement_mode != NativeThroughputMode::Bytes ||
        snapshot.measurement_accepted_bytes != 1'000 ||
        snapshot.measurement_written_bytes != 700 ||
        snapshot.measurement_completed_jobs != 2 ||
        snapshot.measurement_completed_files != 2) {
        return false;
    }

    counters.accepted_bytes = 1'500;
    counters.written_bytes = 1'200;
    counters.completed_jobs = 3;
    counters.completed_files = 3;
    controller.observe(runtime, counters, 100, 4, 0.1);
    snapshot = controller.snapshot(4);
    return snapshot.active_limit == 4 &&
        snapshot.measurement_sequence == 2 &&
        snapshot.measurement_accepted_bytes == 500 &&
        snapshot.measurement_written_bytes == 500 &&
        snapshot.measurement_completed_jobs == 1 &&
        snapshot.measurement_completed_files == 1;
}

bool check_runtime_control_accepts_large_window_improvement() {
    using namespace sunpack::sevenzip;
    NativeRuntimeControl controller(8, deterministic_runtime_config(4));
    NativeRuntimeSample runtime;
    NativeThroughputCounters counters;
    controller.observe(runtime, counters, 100, 4, 0.1);

    observe_control_observation(controller, runtime, counters, 4, 1'000);
    observe_control_observation(controller, runtime, counters, 5, 1'200);
    if (controller.snapshot(5).phase != NativeControllerPhase::Verify ||
        controller.snapshot(5).active_limit != 4) {
        return false;
    }

    observe_control_observation(controller, runtime, counters, 4, 1'000);
    const auto snapshot = controller.snapshot(4);
    return snapshot.active_limit == 6 && snapshot.accepted_probe;
}

bool check_runtime_control_uses_small_job_window() {
    using namespace sunpack::sevenzip;
    auto config = deterministic_runtime_config(4);
    config.large_window_bytes = 1ULL << 30;
    NativeRuntimeControl controller(8, config);
    NativeRuntimeSample runtime;
    NativeThroughputCounters counters;
    controller.observe(runtime, counters, 100, 4, 0.1);

    observe_control_observation(controller, runtime, counters, 4, 0, 2, 2);
    observe_control_observation(controller, runtime, counters, 5, 0, 3, 3);
    if (controller.snapshot(5).phase != NativeControllerPhase::Verify) {
        return false;
    }

    observe_control_observation(controller, runtime, counters, 4, 0, 2, 2);
    const auto snapshot = controller.snapshot(4);
    return snapshot.active_limit == 6 &&
        snapshot.throughput_mode == NativeThroughputMode::Jobs &&
        snapshot.accepted_probe;
}

bool check_runtime_control_rebases_external_discontinuity_at_stable_limit() {
    using namespace sunpack::sevenzip;
    NativeRuntimeControl controller(8, deterministic_runtime_config(4));
    NativeRuntimeSample runtime;
    NativeThroughputCounters counters;
    controller.observe(runtime, counters, 100, 4, 0.1);
    observe_control_observation(controller, runtime, counters, 4, 1'000);
    if (controller.snapshot(4).active_limit != 5 ||
        controller.snapshot(4).phase != NativeControllerPhase::Probe) {
        return false;
    }
    if (!controller.rebase_after_external_discontinuity(counters)) {
        return false;
    }
    const auto snapshot = controller.snapshot(4);
    return snapshot.active_limit == 4 &&
        snapshot.phase == NativeControllerPhase::Baseline &&
        snapshot.decision == NativeControllerDecision::SegmentInterrupted;
}

bool check_runtime_control_waits_for_realized_experimental_concurrency() {
    using namespace sunpack::sevenzip;
    NativeRuntimeControl controller(8, deterministic_runtime_config(4));
    NativeRuntimeSample runtime;
    NativeThroughputCounters counters;
    controller.observe(runtime, counters, 100, 4, 0.1);

    observe_control_observation(controller, runtime, counters, 4, 1'000);
    if (controller.snapshot(4).active_limit != 5) {
        return false;
    }

    counters.accepted_bytes += 1'200;
    counters.written_bytes += 1'200;
    controller.observe(runtime, counters, 100, 4, 0.1);
    auto snapshot = controller.snapshot(4);
    if (snapshot.phase != NativeControllerPhase::Probe || snapshot.active_limit != 5) {
        return false;
    }

    observe_control_observation(controller, runtime, counters, 5, 1'200);
    snapshot = controller.snapshot(5);
    if (snapshot.phase != NativeControllerPhase::Verify || snapshot.active_limit != 4) {
        return false;
    }

    counters.accepted_bytes += 1'000;
    counters.written_bytes += 1'000;
    controller.observe(runtime, counters, 100, 5, 0.1);
    snapshot = controller.snapshot(5);
    if (snapshot.phase != NativeControllerPhase::Verify || snapshot.active_limit != 4) {
        return false;
    }

    observe_control_observation(controller, runtime, counters, 4, 1'000);
    snapshot = controller.snapshot(4);
    return snapshot.active_limit == 6 && snapshot.accepted_probe;
}

bool check_runtime_control_marks_probe_contaminated_on_environment_shift() {
    using namespace sunpack::sevenzip;
    NativeRuntimeControl controller(8, deterministic_runtime_config(4));
    NativeRuntimeSample runtime;
    NativeThroughputCounters counters;
    controller.observe(runtime, counters, 100, 4, 0.1);

    observe_control_observation(controller, runtime, counters, 4, 1'000);
    observe_control_observation(controller, runtime, counters, 5, 1'200);
    observe_control_observation(controller, runtime, counters, 4, 600);
    const auto snapshot = controller.snapshot(4);
    return snapshot.active_limit == 4 &&
        snapshot.phase == NativeControllerPhase::Baseline &&
        snapshot.decision == NativeControllerDecision::Contaminated &&
        !snapshot.accepted_probe;
}

bool check_runtime_control_detects_passive_environment_change() {
    using namespace sunpack::sevenzip;
    auto config = deterministic_runtime_config(4);
    config.hold_windows = 9;
    NativeRuntimeControl controller(8, config);
    NativeRuntimeSample runtime;
    NativeThroughputCounters counters;
    controller.observe(runtime, counters, 100, 4, 0.1);

    // Reject an up probe, then a down probe, so the controller reaches Hold.
    observe_control_observation(controller, runtime, counters, 4, 1'000);
    observe_control_observation(controller, runtime, counters, 5, 800);
    observe_control_observation(controller, runtime, counters, 4, 1'000);
    if (controller.snapshot(4).phase != NativeControllerPhase::Cooldown) {
        return false;
    }

    // Cooldown is deliberately not part of the passive trend detector.
    observe_control_observation(controller, runtime, counters, 4, 1'000);
    if (controller.snapshot(4).phase != NativeControllerPhase::Probe ||
        controller.snapshot(4).active_limit != 3) {
        return false;
    }

    observe_control_observation(controller, runtime, counters, 3, 500);
    observe_control_observation(controller, runtime, counters, 4, 1'000);
    if (controller.snapshot(4).phase != NativeControllerPhase::Cooldown) {
        return false;
    }
    observe_control_observation(controller, runtime, counters, 4, 1'000);
    if (controller.snapshot(4).phase != NativeControllerPhase::Hold) {
        return false;
    }

    // The first Hold observation primes the detector. A large persistent shift in
    // the second one must then be classified as an environment change.
    observe_control_observation(controller, runtime, counters, 4, 1'000);
    if (controller.snapshot(4).decision == NativeControllerDecision::EnvironmentChanged) {
        return false;
    }
    observe_control_observation(controller, runtime, counters, 4, 200);
    const auto snapshot = controller.snapshot(4);
    return snapshot.active_limit == 4 &&
        snapshot.phase == NativeControllerPhase::Baseline &&
        snapshot.decision == NativeControllerDecision::EnvironmentChanged;
}

bool check_runtime_control_interrupts_probe_when_backlog_disappears() {
    using namespace sunpack::sevenzip;
    NativeRuntimeControl controller(8, deterministic_runtime_config(4));
    NativeRuntimeSample runtime;
    NativeThroughputCounters counters;
    controller.observe(runtime, counters, 100, 4, 0.1);
    observe_control_observation(controller, runtime, counters, 4, 1'000);
    if (controller.snapshot(4).active_limit != 5) {
        return false;
    }
    controller.observe(runtime, counters, 0, 5, 0.1);
    auto snapshot = controller.snapshot(5);
    if (snapshot.active_limit != 4 ||
        snapshot.load_state != NativeLoadState::Unsaturated ||
        snapshot.decision != NativeControllerDecision::SegmentInterrupted) {
        return false;
    }
    counters.written_bytes += 1'000;
    counters.accepted_bytes += 1'000;
    controller.observe(runtime, counters, 100, 4, 0.1);
    snapshot = controller.snapshot(4);
    return snapshot.active_limit == 4 &&
        snapshot.load_state == NativeLoadState::Saturated &&
        snapshot.phase == NativeControllerPhase::Baseline &&
        snapshot.decision == NativeControllerDecision::SegmentStarted;
}

bool check_runtime_control_parks_and_rebases_activity() {
    using namespace sunpack::sevenzip;
    auto config = deterministic_runtime_config(4);
    config.warm_start_confirmations = 2;
    NativeRuntimeControl controller(8, config);
    NativeRuntimeSample runtime;
    NativeThroughputCounters counters;
    controller.observe(runtime, counters, 100, 4, 0.1);
    observe_control_observation(controller, runtime, counters, 4, 1'000);
    controller.end_activity(counters);
    auto snapshot = controller.snapshot(0);
    if (snapshot.active_limit != 4 ||
        snapshot.load_state != NativeLoadState::Idle ||
        snapshot.decision != NativeControllerDecision::ActivityEnded) {
        return false;
    }
    controller.begin_activity(counters, 1.0);
    counters.written_bytes += 1'000;
    counters.accepted_bytes += 1'000;
    controller.observe(runtime, counters, 0, 1, 0.1);
    controller.observe(runtime, counters, 100, 4, 0.1);
    snapshot = controller.snapshot(4);
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
    NativeRuntimeControl controller(8, config);
    NativeRuntimeSample runtime;
    NativeThroughputCounters counters;
    controller.observe(runtime, counters, 100, 4, 0.1);

    observe_control_observation(controller, runtime, counters, 4, 1'000);
    observe_control_observation(controller, runtime, counters, 5, 1'200);
    observe_control_observation(controller, runtime, counters, 4, 1'000);
    if (controller.snapshot(4).active_limit != 6) {
        return false;
    }

    observe_control_observation(controller, runtime, counters, 6, 1'400);
    observe_control_observation(controller, runtime, counters, 5, 1'200);
    if (controller.snapshot(5).active_limit != 7) {
        return false;
    }

    observe_control_observation(controller, runtime, counters, 7, 1'000);
    observe_control_observation(controller, runtime, counters, 6, 1'400);
    if (controller.snapshot(6).active_limit != 6) {
        return false;
    }

    controller.end_activity(counters);
    controller.begin_activity(counters, 0.0);
    auto snapshot = controller.snapshot(0);
    if (snapshot.active_limit != 6 || !snapshot.warm_start_used ||
        snapshot.throughput_mode != NativeThroughputMode::None) {
        return false;
    }
    controller.end_activity(counters);
    controller.begin_activity(counters, 15.0);
    snapshot = controller.snapshot(0);
    if (snapshot.active_limit != 5 || !snapshot.warm_start_used) {
        return false;
    }
    controller.end_activity(counters);
    controller.begin_activity(counters, 30.0);
    snapshot = controller.snapshot(0);
    return snapshot.active_limit == 4 && !snapshot.warm_start_used;
}

bool check_native_sizing_scales_linearly_with_cpu() {
    using namespace sunpack::sevenzip;
    NativeSizingOverrides defaults;
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
        const NativeMachineResources resources{expected.logical_processors};
        const auto plan = derive_native_sizing_plan(resources, defaults);
        if (plan.initial_active_jobs != expected.foreground_jobs) {
            return false;
        }
    }
    return true;
}

bool check_native_sizing_respects_overrides() {
    using namespace sunpack::sevenzip;
    const NativeMachineResources resources{32};
    const auto automatic = derive_native_sizing_plan(resources, {});
    if (automatic.thread_capacity != 32 || automatic.initial_active_jobs != 16) {
        return false;
    }

    NativeSizingOverrides overrides;
    overrides.thread_capacity = 12;
    overrides.initial_active_jobs = 10;
    const auto configured = derive_native_sizing_plan(resources, overrides);
    return configured.thread_capacity == 12 && configured.initial_active_jobs == 10 &&
        configured.thread_capacity_overridden &&
        configured.initial_active_jobs_overridden;
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
    if (!check_extraction_handler_selection_is_read_free()) {
        std::cerr << "extraction handler selection performed content probing\n";
        return 17;
    }
    if (!check_password_probe_status_names()) {
        std::cerr << "password probe status name check failed\n";
        return 4;
    }
    if (!check_empty_bounded_password_probe_requires_positive_evidence()) {
        std::cerr << "empty bounded password probe evidence check failed\n";
        return 15;
    }
    if (!check_runtime_control_waits_for_three_window_observation()) {
        std::cerr << "runtime control observation aggregation check failed\n";
        return 23;
    }
    if (!check_runtime_control_rolls_back_large_window_regression()) {
        std::cerr << "runtime control large-window rollback check failed\n";
        return 6;
    }
    if (!check_runtime_control_emits_fixed_measurement_windows()) {
        std::cerr << "runtime control fixed measurement window check failed\n";
        return 22;
    }
    if (!check_runtime_control_accepts_large_window_improvement()) {
        std::cerr << "runtime control large-window improvement check failed\n";
        return 7;
    }
    if (!check_runtime_control_uses_small_job_window()) {
        std::cerr << "runtime control small-job window check failed\n";
        return 8;
    }
    if (!check_runtime_control_rebases_external_discontinuity_at_stable_limit()) {
        std::cerr << "runtime control external-discontinuity rebase check failed\n";
        return 21;
    }
    if (!check_runtime_control_waits_for_realized_experimental_concurrency()) {
        std::cerr << "runtime control realized-concurrency check failed\n";
        return 20;
    }
    if (!check_runtime_control_marks_probe_contaminated_on_environment_shift()) {
        std::cerr << "runtime control contaminated-probe check failed\n";
        return 18;
    }
    if (!check_runtime_control_detects_passive_environment_change()) {
        std::cerr << "runtime control passive environment-change check failed\n";
        return 19;
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
    if (!check_native_sizing_respects_overrides()) {
        std::cerr << "native sizing override check failed\n";
        return 14;
    }
#endif

    (void)argc;
    (void)argv;
    const bool available = sunpack::sevenzip::is_backend_available();
    std::cout << "backend_available=" << (available ? "true" : "false") << "\n";
    return available ? 0 : 1;
}
