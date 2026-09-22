#include "sevenzip_bridge/bridge.hpp"
#include "internal/sevenzip_paths.hpp"
#include "internal/sevenzip_formats.hpp"
#include "internal/password_probe_policy.hpp"
#include "internal/sevenzip_status.hpp"
#include "internal/native_runtime_control.hpp"
#include "internal/native_cpu_budget.hpp"
#include "internal/decoder_cpu_budget.h"
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

sunpack::sevenzip::NativeRuntimeConfig deterministic_runtime_config() {
    sunpack::sevenzip::NativeRuntimeConfig config;
    config.observation_window_seconds = 1.0;
    config.throughput_change_ratio = 0.40;
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

void observe_runtime(
    sunpack::sevenzip::NativeRuntimeControl& controller,
    const sunpack::sevenzip::NativeRuntimeSample& runtime,
    sunpack::sevenzip::NativeThroughputCounters& counters,
    std::uint64_t written_bytes,
    double seconds,
    std::size_t reserved_cpu_credits
) {
    counters.accepted_bytes += written_bytes;
    counters.written_bytes += written_bytes;
    controller.observe(
        runtime,
        counters,
        reserved_cpu_credits,
        seconds);
}

bool check_cpu_budget_accounts_base_and_decoder_credits() {
    using namespace sunpack::sevenzip;
    NativeCpuBudget budget(8);
    if (!budget.try_acquire_base() || budget.reserved_credits() != 1) {
        return false;
    }
    {
        NativeCpuJobContext job(budget);
        NativeCpuContextScope scope(&job);
        if (job.acquire_extra(4, 4) != 4 ||
            budget.reserved_credits() != 5) {
            return false;
        }
        auto snapshot = job.snapshot();
        if (snapshot.current_extra_credits != 4 ||
            snapshot.peak_extra_credits != 4 ||
            snapshot.total_extra_credits_granted != 4) {
            return false;
        }
        job.release_extra(2);
        if (budget.reserved_credits() != 3 ||
            job.snapshot().current_extra_credits != 2) {
            return false;
        }
    }
    if (budget.reserved_credits() != 1) {
        return false;
    }
    budget.release(1);
    return budget.reserved_credits() == 0;
}

bool check_cpu_budget_honors_effective_capacity() {
    using namespace sunpack::sevenzip;
    NativeCpuBudget budget(8);
    for (int i = 0; i < 4; ++i) {
        if (!budget.try_acquire_base()) {
            return false;
        }
    }
    budget.set_effective_capacity(2);
    if (budget.effective_capacity() != 2 ||
        budget.can_acquire_base() ||
        budget.acquire_up_to(1, 1) != 0) {
        return false;
    }
    budget.release(3);
    if (budget.reserved_credits() != 1 ||
        !budget.can_acquire_base() ||
        !budget.try_acquire_base()) {
        return false;
    }
    budget.release(2);
    budget.set_effective_capacity(8);
    return budget.reserved_credits() == 0 &&
        budget.effective_capacity() == 8;
}

bool check_cpu_budget_tracks_decoder_thread_lifetimes() {
    using namespace sunpack::sevenzip;
    NativeCpuBudget budget(8);
    budget.set_effective_capacity(4);
    if (!budget.try_acquire_base() || budget.reserved_credits() != 1) {
        return false;
    }

    {
        NativeCpuJobContext job(budget);
        NativeCpuContextScope scope(&job);
        if (sunpack_cpu_current_job_context() != &job) {
            return false;
        }

        // Each successful internal decoder-thread admission consumes one
        // credit. Exercise both C ABI entry points used by the decoders.
        if (sunpack_cpu_acquire_extra_for_context(&job, 1, 1) != 1 ||
            sunpack_cpu_acquire_extra(1, 1) != 1 ||
            sunpack_cpu_acquire_extra_for_context(&job, 1, 1) != 1 ||
            budget.reserved_credits() != 4 ||
            job.snapshot().current_extra_credits != 3 ||
            job.snapshot().peak_extra_credits != 3 ||
            job.snapshot().total_extra_credits_granted != 3) {
            return false;
        }

        // A fourth decoder thread cannot start without an uncharged credit.
        if (sunpack_cpu_acquire_extra(1, 1) != 0 ||
            budget.reserved_credits() != 4 ||
            job.snapshot().current_extra_credits != 3) {
            return false;
        }

        // Ending each decoder thread returns exactly its credit.
        sunpack_cpu_release_extra(1);
        if (budget.reserved_credits() != 3 ||
            job.snapshot().current_extra_credits != 2) {
            return false;
        }
        sunpack_cpu_release_extra_for_context(&job, 1);
        if (budget.reserved_credits() != 2 ||
            job.snapshot().current_extra_credits != 1) {
            return false;
        }
        sunpack_cpu_release_extra_for_context(&job, 1);
        if (budget.reserved_credits() != 1 ||
            job.snapshot().current_extra_credits != 0) {
            return false;
        }

        // Cleanup is idempotent with respect to the job-owned balance and
        // must not release the base job credit.
        sunpack_cpu_release_extra_for_context(&job, 99);
        if (budget.reserved_credits() != 1 ||
            job.snapshot().current_extra_credits != 0) {
            return false;
        }
    }

    budget.release(1);
    return budget.reserved_credits() == 0;
}

bool check_runtime_control_establishes_one_second_baseline() {
    using namespace sunpack::sevenzip;
    NativeRuntimeControl controller(16, deterministic_runtime_config());
    NativeRuntimeSample runtime;
    NativeThroughputCounters counters;
    controller.begin_activity(counters);

    observe_runtime(controller, runtime, counters, 500, 0.5, 16);
    auto snapshot = controller.snapshot(16);
    if (snapshot.measurement_sequence != 0 ||
        snapshot.effective_cpu_budget != 16) {
        return false;
    }

    observe_runtime(controller, runtime, counters, 500, 0.5, 16);
    snapshot = controller.snapshot(16);
    if (snapshot.measurement_sequence != 0) {
        return false;
    }

    observe_runtime(controller, runtime, counters, 500, 0.5, 16);
    snapshot = controller.snapshot(16);
    return snapshot.measurement_sequence == 1 &&
        snapshot.decision == NativeControllerDecision::BaselineEstablished &&
        snapshot.nominal_cpu_budget == 16 &&
        snapshot.effective_cpu_budget == 16 &&
        snapshot.budget_step == 2 &&
        snapshot.written_bytes_per_second == 1000.0 &&
        snapshot.reference_bytes_per_second == 1000.0;
}

bool check_runtime_control_ignores_unsaturated_windows() {
    using namespace sunpack::sevenzip;
    NativeRuntimeControl controller(16, deterministic_runtime_config());
    NativeRuntimeSample runtime;
    NativeThroughputCounters counters;
    controller.begin_activity(counters);

    observe_runtime(controller, runtime, counters, 500, 0.5, 15);
    observe_runtime(controller, runtime, counters, 500, 0.5, 16);
    auto snapshot = controller.snapshot(16);
    if (snapshot.measurement_sequence != 0) {
        return false;
    }

    observe_runtime(controller, runtime, counters, 500, 0.5, 17);
    observe_runtime(controller, runtime, counters, 500, 0.5, 16);
    snapshot = controller.snapshot(16);
    if (snapshot.measurement_sequence != 0) {
        return false;
    }

    observe_runtime(controller, runtime, counters, 500, 0.5, 16);
    observe_runtime(controller, runtime, counters, 500, 0.5, 16);
    snapshot = controller.snapshot(16);
    return snapshot.measurement_sequence == 1 &&
        snapshot.decision == NativeControllerDecision::BaselineEstablished &&
        snapshot.reference_bytes_per_second == 1000.0;
}

bool check_runtime_control_requires_forty_percent_change() {
    using namespace sunpack::sevenzip;
    NativeRuntimeControl controller(16, deterministic_runtime_config());
    NativeRuntimeSample runtime;
    NativeThroughputCounters counters;
    controller.begin_activity(counters);
    observe_runtime(controller, runtime, counters, 0, 0.1, 16);

    observe_runtime(controller, runtime, counters, 1000, 1.0, 16);
    observe_runtime(controller, runtime, counters, 650, 1.0, 16);
    auto snapshot = controller.snapshot(16);
    if (snapshot.decision != NativeControllerDecision::None ||
        snapshot.effective_cpu_budget != 16) {
        return false;
    }

    observe_runtime(controller, runtime, counters, 590, 1.0, 16);
    snapshot = controller.snapshot(16);
    return snapshot.decision == NativeControllerDecision::BudgetReduced &&
        snapshot.effective_cpu_budget == 14 &&
        snapshot.reference_bytes_per_second == 0.0;
}

bool check_runtime_control_stays_stable_inside_change_band() {
    using namespace sunpack::sevenzip;
    NativeRuntimeControl controller(16, deterministic_runtime_config());
    NativeRuntimeSample runtime;
    NativeThroughputCounters counters;
    controller.begin_activity(counters);
    observe_runtime(controller, runtime, counters, 0, 0.1, 16);
    observe_runtime(controller, runtime, counters, 1000, 1.0, 16);

    // Repeated saturated windows on either side of the reference, but still
    // inside the configured +/-40% band, must not churn the budget.
    for (const std::uint64_t bytes : {650ULL, 700ULL, 1399ULL, 800ULL}) {
        observe_runtime(controller, runtime, counters, bytes, 1.0, 16);
        const auto snapshot = controller.snapshot(16);
        if (snapshot.effective_cpu_budget != 16 ||
            snapshot.decision != NativeControllerDecision::None) {
            return false;
        }
    }
    return true;
}

bool check_runtime_control_reobserves_after_budget_change() {
    using namespace sunpack::sevenzip;
    NativeRuntimeControl controller(16, deterministic_runtime_config());
    NativeRuntimeSample runtime;
    NativeThroughputCounters counters;
    controller.begin_activity(counters);
    observe_runtime(controller, runtime, counters, 0, 0.1, 16);

    observe_runtime(controller, runtime, counters, 1000, 1.0, 16);
    observe_runtime(controller, runtime, counters, 500, 1.0, 16);
    auto snapshot = controller.snapshot(16);
    if (snapshot.decision != NativeControllerDecision::BudgetReduced ||
        snapshot.effective_cpu_budget != 14) {
        return false;
    }

    // Non-preemptive excess use must not establish the new-tier baseline.
    observe_runtime(controller, runtime, counters, 500, 1.0, 16);
    snapshot = controller.snapshot(16);
    if (snapshot.measurement_sequence != 2 ||
        snapshot.reference_bytes_per_second != 0.0) {
        return false;
    }

    observe_runtime(controller, runtime, counters, 0, 0.1, 14);
    snapshot = controller.snapshot(14);
    if (snapshot.measurement_sequence != 2) {
        return false;
    }

    observe_runtime(controller, runtime, counters, 500, 1.0, 14);
    snapshot = controller.snapshot(14);
    return snapshot.measurement_sequence == 3 &&
        snapshot.decision == NativeControllerDecision::BaselineEstablished &&
        snapshot.effective_cpu_budget == 14 &&
        snapshot.reference_bytes_per_second == 500.0;
}

bool check_runtime_control_restores_after_recovery() {
    using namespace sunpack::sevenzip;
    NativeRuntimeControl controller(16, deterministic_runtime_config());
    NativeRuntimeSample runtime;
    NativeThroughputCounters counters;
    controller.begin_activity(counters);
    observe_runtime(controller, runtime, counters, 0, 0.1, 16);

    observe_runtime(controller, runtime, counters, 1000, 1.0, 16);
    observe_runtime(controller, runtime, counters, 500, 1.0, 16);
    observe_runtime(controller, runtime, counters, 0, 0.1, 14);
    observe_runtime(controller, runtime, counters, 500, 1.0, 14);
    observe_runtime(controller, runtime, counters, 710, 1.0, 14);
    auto snapshot = controller.snapshot(14);
    if (snapshot.decision != NativeControllerDecision::BudgetRestored ||
        snapshot.effective_cpu_budget != 16 ||
        snapshot.reference_bytes_per_second != 0.0) {
        return false;
    }

    observe_runtime(controller, runtime, counters, 0, 0.1, 16);
    observe_runtime(controller, runtime, counters, 710, 1.0, 16);
    snapshot = controller.snapshot(16);
    return snapshot.decision == NativeControllerDecision::BaselineEstablished &&
        snapshot.effective_cpu_budget == 16 &&
        snapshot.reference_bytes_per_second == 710.0;
}

bool check_runtime_control_restoration_requires_saturation() {
    using namespace sunpack::sevenzip;
    NativeRuntimeControl controller(16, deterministic_runtime_config());
    NativeRuntimeSample runtime;
    NativeThroughputCounters counters;
    controller.begin_activity(counters);
    observe_runtime(controller, runtime, counters, 0, 0.1, 16);
    observe_runtime(controller, runtime, counters, 1000, 1.0, 16);
    observe_runtime(controller, runtime, counters, 500, 1.0, 16);
    if (controller.snapshot(16).effective_cpu_budget != 14) {
        return false;
    }

    // Recovery evidence while the budget is under-filled is discarded and
    // cannot restore the nominal concurrency.
    observe_runtime(controller, runtime, counters, 701, 1.0, 13);
    if (controller.snapshot(13).effective_cpu_budget != 14) {
        return false;
    }

    // Re-prime, establish the reduced-tier baseline, then recover only on a
    // later exact-saturation window.
    observe_runtime(controller, runtime, counters, 0, 0.1, 14);
    observe_runtime(controller, runtime, counters, 500, 1.0, 14);
    if (controller.snapshot(14).effective_cpu_budget != 14) {
        return false;
    }
    observe_runtime(controller, runtime, counters, 701, 1.0, 14);
    const auto snapshot = controller.snapshot(14);
    return snapshot.decision == NativeControllerDecision::BudgetRestored &&
        snapshot.effective_cpu_budget == 16;
}

bool check_runtime_control_uses_core_eighth_step() {
    using namespace sunpack::sevenzip;
    NativeRuntimeControl controller(32, deterministic_runtime_config());
    NativeRuntimeSample runtime;
    NativeThroughputCounters counters;
    controller.begin_activity(counters);
    observe_runtime(controller, runtime, counters, 0, 0.1, 32);

    observe_runtime(controller, runtime, counters, 1000, 1.0, 32);
    observe_runtime(controller, runtime, counters, 500, 1.0, 32);
    auto snapshot = controller.snapshot(32);
    if (snapshot.effective_cpu_budget != 28 ||
        snapshot.budget_step != 4 ||
        snapshot.decision != NativeControllerDecision::BudgetReduced) {
        return false;
    }

    observe_runtime(controller, runtime, counters, 0, 0.1, 28);
    observe_runtime(controller, runtime, counters, 500, 1.0, 28);
    snapshot = controller.snapshot(28);
    if (snapshot.decision != NativeControllerDecision::BaselineEstablished ||
        snapshot.reference_bytes_per_second != 500.0) {
        return false;
    }

    observe_runtime(controller, runtime, counters, 250, 1.0, 28);
    snapshot = controller.snapshot(28);
    return snapshot.effective_cpu_budget == 24 &&
        snapshot.budget_step == 4 &&
        snapshot.decision == NativeControllerDecision::BudgetReduced;
}

bool check_runtime_control_fixed_mode_only_observes_when_saturated() {
    using namespace sunpack::sevenzip;
    auto config = deterministic_runtime_config();
    config.adaptive_enabled = false;
    config.measurement_diagnostics_enabled = true;
    NativeRuntimeControl controller(8, config);
    NativeRuntimeSample runtime;
    NativeThroughputCounters counters;
    controller.begin_activity(counters);
    observe_runtime(controller, runtime, counters, 0, 0.1, 8);

    observe_runtime(controller, runtime, counters, 1000, 1.0, 8);
    observe_runtime(controller, runtime, counters, 300, 1.0, 7);
    auto snapshot = controller.snapshot(7);
    if (snapshot.measurement_sequence != 1 ||
        snapshot.effective_cpu_budget != 8 ||
        snapshot.reference_bytes_per_second != 1000.0) {
        return false;
    }

    observe_runtime(controller, runtime, counters, 300, 1.0, 8);
    observe_runtime(controller, runtime, counters, 300, 1.0, 8);
    snapshot = controller.snapshot(8);
    return snapshot.measurement_sequence == 2 &&
        snapshot.effective_cpu_budget == 8 &&
        snapshot.reference_bytes_per_second == 1000.0 &&
        snapshot.written_bytes_per_second == 300.0;
}

bool check_runtime_control_activity_reset_restores_nominal_budget() {
    using namespace sunpack::sevenzip;
    NativeRuntimeControl controller(16, deterministic_runtime_config());
    NativeRuntimeSample runtime;
    NativeThroughputCounters counters;
    controller.begin_activity(counters);
    observe_runtime(controller, runtime, counters, 0, 0.1, 16);
    observe_runtime(controller, runtime, counters, 1000, 1.0, 16);
    observe_runtime(controller, runtime, counters, 500, 1.0, 16);
    if (controller.snapshot(16).effective_cpu_budget != 14) {
        return false;
    }

    controller.end_activity(counters);
    controller.begin_activity(counters);
    const auto snapshot = controller.snapshot(0);
    return snapshot.effective_cpu_budget == 16 &&
        snapshot.reference_bytes_per_second == 0.0 &&
        snapshot.measurement_sequence == 2 &&
        snapshot.decision == NativeControllerDecision::ActivityStarted;
}

bool check_native_sizing_tracks_logical_processors() {
    using namespace sunpack::sevenzip;
    const std::size_t cases[] = {1, 2, 4, 8, 16, 32, 64, 128};
    for (const std::size_t logical_processors : cases) {
        const NativeMachineResources resources{logical_processors};
        const auto plan = derive_native_sizing_plan(resources, {});
        if (plan.thread_capacity != logical_processors ||
            plan.thread_capacity_overridden) {
            return false;
        }
    }
    return true;
}

bool check_native_sizing_respects_thread_override() {
    using namespace sunpack::sevenzip;
    const NativeMachineResources resources{32};
    const auto automatic = derive_native_sizing_plan(resources, {});
    if (automatic.thread_capacity != 32 ||
        automatic.thread_capacity_overridden) {
        return false;
    }

    NativeSizingOverrides overrides;
    overrides.thread_capacity = 12;
    const auto configured = derive_native_sizing_plan(resources, overrides);
    return configured.thread_capacity == 12 &&
        configured.thread_capacity_overridden;
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
    if (!check_cpu_budget_accounts_base_and_decoder_credits()) {
        std::cerr << "CPU credit accounting check failed\n";
        return 23;
    }
    if (!check_cpu_budget_honors_effective_capacity()) {
        std::cerr << "CPU credit effective-capacity check failed\n";
        return 22;
    }
    if (!check_cpu_budget_tracks_decoder_thread_lifetimes()) {
        std::cerr << "CPU decoder-thread lifetime credit check failed\n";
        return 28;
    }
    if (!check_runtime_control_establishes_one_second_baseline()) {
        std::cerr << "runtime one-second baseline check failed\n";
        return 7;
    }
    if (!check_runtime_control_ignores_unsaturated_windows()) {
        std::cerr << "runtime saturation-gating check failed\n";
        return 26;
    }
    if (!check_runtime_control_reobserves_after_budget_change()) {
        std::cerr << "runtime budget re-observation check failed\n";
        return 27;
    }
    if (!check_runtime_control_requires_forty_percent_change()) {
        std::cerr << "runtime passive derating check failed\n";
        return 24;
    }
    if (!check_runtime_control_stays_stable_inside_change_band()) {
        std::cerr << "runtime stable-band check failed\n";
        return 29;
    }
    if (!check_runtime_control_restores_after_recovery()) {
        std::cerr << "runtime budget restoration check failed\n";
        return 6;
    }
    if (!check_runtime_control_restoration_requires_saturation()) {
        std::cerr << "runtime saturated-restoration check failed\n";
        return 30;
    }
    if (!check_runtime_control_uses_core_eighth_step()) {
        std::cerr << "runtime CPU eighth-step check failed\n";
        return 18;
    }
    if (!check_runtime_control_fixed_mode_only_observes_when_saturated()) {
        std::cerr << "runtime fixed observation check failed\n";
        return 19;
    }
    if (!check_runtime_control_activity_reset_restores_nominal_budget()) {
        std::cerr << "runtime activity reset check failed\n";
        return 25;
    }
    if (!check_native_sizing_tracks_logical_processors()) {
        std::cerr << "native sizing logical-processor check failed\n";
        return 13;
    }
    if (!check_native_sizing_respects_thread_override()) {
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
