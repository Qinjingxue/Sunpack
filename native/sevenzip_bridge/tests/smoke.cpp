#include "sevenzip_bridge/bridge.hpp"
#include "internal/sevenzip_paths.hpp"
#include "internal/sevenzip_formats.hpp"
#include "internal/password_probe_policy.hpp"
#include "internal/sevenzip_status.hpp"
#include "internal/native_memory_guard.hpp"
#include "internal/native_cpu_budget.hpp"
#include "internal/decoder_cpu_budget.h"
#include "internal/decoder_input_access.h"
#include "internal/sevenzip_streams.hpp"
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
            snapshot.peak_extra_credits != 4) {
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

struct CpuBudgetCallbackProbe {
    std::size_t calls = 0;

    static void on_available(void* context) noexcept {
        auto* probe = static_cast<CpuBudgetCallbackProbe*>(context);
        if (probe) {
            ++probe->calls;
        }
    }
};

bool check_cpu_budget_notifies_only_availability_edges() {
    using namespace sunpack::sevenzip;

    CpuBudgetCallbackProbe probe;
    NativeCpuBudget budget(
        4,
        &CpuBudgetCallbackProbe::on_available,
        &probe);

    if (budget.acquire_up_to(4, 4) != 4 || probe.calls != 0) {
        return false;
    }

    // Saturated -> available wakes exactly once.
    budget.release(1);
    if (probe.calls != 1 || budget.reserved_credits() != 3) {
        return false;
    }

    // Already-available releases do not create redundant wakeups.
    budget.release(1);
    if (probe.calls != 1 || budget.reserved_credits() != 2) {
        return false;
    }

    // Re-saturate, shrink capacity, and release while still saturated.
    if (budget.acquire_up_to(2, 2) != 2) {
        return false;
    }
    budget.set_effective_capacity(2);
    budget.release(2);
    if (probe.calls != 1 || budget.reserved_credits() != 2) {
        return false;
    }

    // Raising the cap from saturated to available is also one edge.
    budget.set_effective_capacity(4);
    if (probe.calls != 2) {
        return false;
    }

    budget.release(2);
    return probe.calls == 2 && budget.reserved_credits() == 0;
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
            job.snapshot().peak_extra_credits != 3) {
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

bool check_cpu_context_exchange_propagates_and_restores() {
    using namespace sunpack::sevenzip;

    NativeCpuBudget budget(4);
    NativeCpuJobContext first(budget);
    NativeCpuJobContext second(budget);

    if (sunpack_cpu_current_job_context() != nullptr) {
        return false;
    }

    {
        NativeCpuContextScope scope(&first);
        if (sunpack_cpu_current_job_context() != &first) {
            return false;
        }

        void* previous =
            sunpack_cpu_exchange_current_job_context(&second);
        if (previous != &first ||
            sunpack_cpu_current_job_context() != &second) {
            return false;
        }

        void* replaced =
            sunpack_cpu_exchange_current_job_context(previous);
        if (replaced != &second ||
            sunpack_cpu_current_job_context() != &first) {
            return false;
        }
    }

    return sunpack_cpu_current_job_context() == nullptr;
}

bool check_cpu_budget_acquire_all_available() {
    using namespace sunpack::sevenzip;
    NativeCpuBudget budget(8);
    if (!budget.try_acquire_base() || !budget.try_acquire_base()) {
        return false;
    }

    NativeCpuJobContext first(budget);
    NativeCpuJobContext second(budget);

    if (sunpack_cpu_acquire_all_available_for_context(&first) != 6 ||
        budget.reserved_credits() != 8 ||
        first.snapshot().current_extra_credits != 6) {
        return false;
    }

    first.release_extra(2);
    if (budget.reserved_credits() != 6 ||
        sunpack_cpu_acquire_all_available_for_context(&second) != 2 ||
        budget.reserved_credits() != 8 ||
        second.snapshot().current_extra_credits != 2) {
        return false;
    }

    first.release_extra(4);
    second.release_extra(2);
    budget.release(2);
    return budget.reserved_credits() == 0;
}

bool check_decoder_random_access_preserves_sequential_cursor() {
    using namespace sunpack::sevenzip;

    const auto root = std::filesystem::temp_directory_path() /
        (L"sunpack-decoder-random-access-" + std::to_wstring(GetCurrentProcessId()));
    std::error_code error;
    std::filesystem::remove_all(root, error);
    error.clear();
    std::filesystem::create_directories(root, error);
    if (error) {
        return false;
    }

    const auto path = root / L"input.bin";
    {
        std::ofstream stream(path, std::ios::binary | std::ios::trunc);
        for (unsigned value = 0; value < 256; ++value) {
            const unsigned char byte = static_cast<unsigned char>(value);
            stream.write(reinterpret_cast<const char*>(&byte), 1);
        }
    }

    auto* raw = new FileInStream(
        path.wstring(),
        nullptr,
        L"file",
        InputPrefetchConfig{false, 512 * 1024, 2});
    CMyComPtr<IInStream> owner(raw);
    if (!raw->is_open()) {
        std::filesystem::remove_all(root, error);
        return false;
    }

    Byte sequential_first[4] = {};
    UInt32 sequential_first_read = 0;
    if (raw->Read(
            sequential_first,
            sizeof(sequential_first),
            &sequential_first_read) != S_OK ||
        sequential_first_read != sizeof(sequential_first) ||
        sequential_first[0] != 0 ||
        sequential_first[3] != 3) {
        std::filesystem::remove_all(root, error);
        return false;
    }

    unsigned long long size = 0;
    if (!sunpack_input_random_access_size(
            static_cast<ISequentialInStream*>(raw),
            &size) ||
        size != 256) {
        std::filesystem::remove_all(root, error);
        return false;
    }

    Byte random_bytes[8] = {};
    unsigned long random_read = 0;
    if (sunpack_input_read_at(
            static_cast<ISequentialInStream*>(raw),
            100,
            random_bytes,
            sizeof(random_bytes),
            &random_read) != S_OK ||
        random_read != sizeof(random_bytes) ||
        random_bytes[0] != 100 ||
        random_bytes[7] != 107) {
        std::filesystem::remove_all(root, error);
        return false;
    }

    Byte sequential_second[4] = {};
    UInt32 sequential_second_read = 0;
    const bool ok =
        raw->Read(
            sequential_second,
            sizeof(sequential_second),
            &sequential_second_read) == S_OK &&
        sequential_second_read == sizeof(sequential_second) &&
        sequential_second[0] == 4 &&
        sequential_second[3] == 7;

    owner.Release();
    std::filesystem::remove_all(root, error);
    return ok;
}

bool check_memory_guard_reduces_below_ten_percent() {
    using namespace sunpack::sevenzip;
    NativeMemoryGuard guard(16);
    if (!guard.observe(1000, 99)) {
        return false;
    }
    const auto snapshot = guard.snapshot();
    return snapshot.nominal_cpu_budget == 16 &&
        snapshot.effective_cpu_budget == 14 &&
        snapshot.budget_step == 2 &&
        snapshot.total_physical_bytes == 1000 &&
        snapshot.available_physical_bytes == 99 &&
        snapshot.available_ratio == 0.099 &&
        snapshot.minimum_available_ratio == 0.10 &&
        snapshot.under_pressure;
}

bool check_memory_guard_keeps_budget_at_threshold() {
    using namespace sunpack::sevenzip;
    NativeMemoryGuard guard(16);
    if (guard.observe(1000, 100)) {
        return false;
    }
    const auto snapshot = guard.snapshot();
    return snapshot.effective_cpu_budget == 16 &&
        !snapshot.under_pressure;
}

bool check_memory_guard_reduces_and_restores_by_core_eighth() {
    using namespace sunpack::sevenzip;
    NativeMemoryGuard guard(32);

    if (!guard.observe(1000, 50) ||
        guard.snapshot().effective_cpu_budget != 28) {
        return false;
    }
    if (!guard.observe(1000, 50) ||
        guard.snapshot().effective_cpu_budget != 24) {
        return false;
    }
    if (!guard.observe(1000, 200) ||
        guard.snapshot().effective_cpu_budget != 28) {
        return false;
    }
    if (!guard.observe(1000, 200) ||
        guard.snapshot().effective_cpu_budget != 32) {
        return false;
    }
    return !guard.observe(1000, 200) &&
        guard.snapshot().effective_cpu_budget == 32;
}

bool check_memory_guard_never_drops_below_one() {
    using namespace sunpack::sevenzip;
    NativeMemoryGuard guard(4);
    for (int i = 0; i < 16; ++i) {
        guard.observe(1000, 1);
    }
    return guard.snapshot().effective_cpu_budget == 1;
}

bool check_memory_guard_custom_ratio() {
    using namespace sunpack::sevenzip;
    NativeMemoryGuardConfig config;
    config.minimum_available_ratio = 0.20;
    NativeMemoryGuard guard(8, config);

    if (guard.observe(1000, 200)) {
        return false;
    }
    if (!guard.observe(1000, 199)) {
        return false;
    }
    const auto snapshot = guard.snapshot();
    return snapshot.effective_cpu_budget == 7 &&
        snapshot.minimum_available_ratio == 0.20 &&
        snapshot.under_pressure;
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
    if (!check_cpu_budget_notifies_only_availability_edges()) {
        std::cerr << "CPU credit availability-edge callback check failed\n";
        return 33;
    }
    if (!check_cpu_budget_tracks_decoder_thread_lifetimes()) {
        std::cerr << "CPU decoder-thread lifetime credit check failed\n";
        return 28;
    }
    if (!check_cpu_budget_acquire_all_available()) {
        std::cerr << "CPU acquire-all credit check failed\n";
        return 31;
    }
    if (!check_cpu_context_exchange_propagates_and_restores()) {
        std::cerr << "CPU context exchange check failed\n";
        return 32;
    }
    if (!check_decoder_random_access_preserves_sequential_cursor()) {
        std::cerr << "decoder random-access cursor isolation check failed\n";
        return 34;
    }
    if (!check_memory_guard_reduces_below_ten_percent()) {
        std::cerr << "memory guard pressure threshold check failed\n";
        return 7;
    }
    if (!check_memory_guard_keeps_budget_at_threshold()) {
        std::cerr << "memory guard threshold boundary check failed\n";
        return 26;
    }
    if (!check_memory_guard_reduces_and_restores_by_core_eighth()) {
        std::cerr << "memory guard CPU eighth-step check failed\n";
        return 18;
    }
    if (!check_memory_guard_never_drops_below_one()) {
        std::cerr << "memory guard minimum budget check failed\n";
        return 24;
    }
    if (!check_memory_guard_custom_ratio()) {
        std::cerr << "memory guard custom ratio check failed\n";
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
