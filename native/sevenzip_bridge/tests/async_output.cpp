#include "internal/sevenzip_async_output.hpp"
#include "internal/sevenzip_volume_registry.hpp"
#include "internal/sevenzip_volume_state.hpp"

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
namespace {

using sunpack::sevenzip::AsyncFileWriter;
using sunpack::sevenzip::AsyncWriterConfig;
using sunpack::sevenzip::make_volume_state;
using sunpack::sevenzip::snapshot_counters;
using sunpack::sevenzip::VolumeWriterRegistry;
using sunpack::sevenzip::WriterMeters;

std::filesystem::path make_test_directory() {
    const auto directory = std::filesystem::temp_directory_path() /
        (L"sunpack-async-output-" + std::to_wstring(GetCurrentProcessId()) +
         L"-" + std::to_wstring(GetTickCount64()));
    std::filesystem::create_directories(directory);
    return directory;
}

bool write_same_file_concurrently(const std::filesystem::path& directory) {
    constexpr std::size_t payload_size = 8U << 20;
    std::vector<unsigned char> expected(payload_size);
    for (std::size_t index = 0; index < expected.size(); ++index) {
        expected[index] = static_cast<unsigned char>((index * 37U + index / 257U) & 0xFFU);
    }

    AsyncFileWriter writer;
    const auto job = writer.make_job();
    const auto file = writer.make_file(
        job, (directory / L"parallel.bin").wstring(), L"parallel.bin", 0, 0);
    std::uint32_t processed = 0;
    if (writer.write(file, expected.data(), static_cast<std::uint32_t>(expected.size()), &processed) != S_OK ||
        processed != expected.size()) {
        return false;
    }
    writer.record_operation_result(file, 0);
    writer.close_file(file, 0, false, {});
    if (writer.finish_job(job) != S_OK) {
        return false;
    }

    const auto snapshot = writer.snapshot_file(file);
    const auto metrics = writer.snapshot_metrics();
    if (snapshot.failed || !snapshot.closed || snapshot.accepted_bytes != expected.size() ||
        snapshot.written_bytes != expected.size() || snapshot.peak_active_data_writes < 2 ||
        metrics.accepted_bytes != expected.size() || metrics.written_bytes != expected.size() ||
        metrics.completed_files != 1 || metrics.completed_jobs != 1) {
        std::cerr << "parallel output state: accepted=" << snapshot.accepted_bytes
                  << " written=" << snapshot.written_bytes
                  << " peak=" << snapshot.peak_active_data_writes << "\n";
        return false;
    }

    std::ifstream input(directory / L"parallel.bin", std::ios::binary);
    std::vector<unsigned char> actual(
        (std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    return actual == expected;
}

bool write_zero_length_file(const std::filesystem::path& directory) {
    AsyncFileWriter writer;
    const auto job = writer.make_job();
    const auto file = writer.make_file(
        job, (directory / L"empty.bin").wstring(), L"empty.bin", 1, 1);
    writer.record_operation_result(file, 0);
    writer.close_file(file, 0, false, {});
    if (writer.finish_job(job) != S_OK) {
        return false;
    }
    const auto snapshot = writer.snapshot_file(file);
    std::error_code error;
    return !snapshot.failed && snapshot.closed && snapshot.written_bytes == 0 &&
        std::filesystem::file_size(directory / L"empty.bin", error) == 0 && !error;
}

bool closes_after_delayed_open_failure(const std::filesystem::path& directory) {
    const auto path = directory / L"existing.bin";
    {
        std::ofstream output(path, std::ios::binary);
        output << "existing";
    }

    AsyncFileWriter writer;
    const auto job = writer.make_job();
    const auto file = writer.make_file(job, path.wstring(), L"existing.bin", 2, 2);
    const unsigned char byte = 0xA5;
    std::uint32_t processed = 0;
    if (writer.write(file, &byte, 1, &processed) != S_OK || processed != 1) {
        return false;
    }
    writer.record_operation_result(file, 0);
    writer.close_file(file, 0, false, {});
    if (writer.finish_job(job) == S_OK) {
        return false;
    }
    const auto snapshot = writer.snapshot_file(file);
    const auto metrics = writer.snapshot_metrics();
    // A permanently failed buffer is accounted as discarded, not left as a
    // permanent accepted/written gap.
    if (metrics.pending_bytes != 0 || metrics.discarded_bytes != 1 ||
        metrics.accepted_bytes != metrics.written_bytes + metrics.discarded_bytes) {
        std::cerr << "failed-open accounting: accepted=" << metrics.accepted_bytes
                  << " written=" << metrics.written_bytes
                  << " discarded=" << metrics.discarded_bytes
                  << " pending=" << metrics.pending_bytes << "\n";
        return false;
    }
    std::ifstream input(path, std::ios::binary);
    std::string existing((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    return snapshot.failed && snapshot.closed && snapshot.written_bytes == 0 &&
        existing == "existing";
}

bool cancelled_job_returns_pending_to_zero(const std::filesystem::path& directory) {
    AsyncFileWriter writer;
    // A job budget below the payload gives real pipeline depth, so the exact accepted
    // count varies and the assertions pin only the accounting identity.
    constexpr std::size_t job_budget = 4U << 20;
    constexpr std::size_t payload_size = 16U << 20;
    std::vector<unsigned char> payload(payload_size, 0x5A);
    const auto job = writer.make_job(job_budget);
    const auto file = writer.make_file(
        job, (directory / L"cancelled.bin").wstring(), L"cancelled.bin", 3, 3);

    std::uint32_t processed = 0;
    std::thread producer([&] {
        writer.write(file, payload.data(), static_cast<std::uint32_t>(payload.size()), &processed);
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    writer.cancel_job(job);
    producer.join();

    const auto mid = writer.snapshot_metrics();
    if (mid.accepted_bytes == 0 || mid.accepted_bytes > payload_size ||
        mid.accepted_bytes != mid.written_bytes + mid.discarded_bytes + mid.pending_bytes) {
        std::cerr << "cancelled mid accounting: accepted=" << mid.accepted_bytes
                  << " written=" << mid.written_bytes
                  << " discarded=" << mid.discarded_bytes
                  << " pending=" << mid.pending_bytes << "\n";
        return false;
    }
    if (!writer.has_active_jobs()) {
        std::cerr << "cancelled job was unregistered before finish_job\n";
        return false;
    }
    const HRESULT result = writer.finish_job(job);
    const auto metrics = writer.snapshot_metrics();
    if (result == S_OK) {
        return false;
    }
    // Whatever the writer flushed is written; the rest is discarded.  Nothing may
    // stay pending once the job has drained, and no job may stay registered.
    if (metrics.pending_bytes != 0 ||
        metrics.accepted_bytes != metrics.written_bytes + metrics.discarded_bytes ||
        writer.has_active_jobs()) {
        std::cerr << "cancelled job accounting: accepted=" << metrics.accepted_bytes
                  << " written=" << metrics.written_bytes
                  << " discarded=" << metrics.discarded_bytes
                  << " pending=" << metrics.pending_bytes
                  << " active_jobs=" << writer.has_active_jobs() << "\n";
        return false;
    }
    return true;
}

bool successful_job_leaves_pending_at_zero(const std::filesystem::path& directory) {
    constexpr std::size_t payload_size = 6U << 20;
    std::vector<unsigned char> payload(payload_size, 0x33);
    AsyncFileWriter writer;
    const auto job = writer.make_job();
    const auto file = writer.make_file(
        job, (directory / L"accounted.bin").wstring(), L"accounted.bin", 4, 4);
    std::uint32_t processed = 0;
    if (writer.write(file, payload.data(), static_cast<std::uint32_t>(payload.size()), &processed) != S_OK) {
        return false;
    }
    writer.record_operation_result(file, 0);
    writer.close_file(file, 0, false, {});
    if (writer.finish_job(job) != S_OK) {
        return false;
    }
    const auto metrics = writer.snapshot_metrics();
    if (metrics.pending_bytes != 0 || metrics.discarded_bytes != 0 ||
        metrics.written_bytes != payload_size ||
        metrics.accepted_bytes != metrics.written_bytes + metrics.discarded_bytes + metrics.pending_bytes) {
        std::cerr << "successful job accounting: accepted=" << metrics.accepted_bytes
                  << " written=" << metrics.written_bytes
                  << " discarded=" << metrics.discarded_bytes
                  << " pending=" << metrics.pending_bytes << "\n";
        return false;
    }
    // Volume and process-wide meters must agree for a single volume.
    const auto volume = writer.snapshot_volume_meters();
    const auto global = writer.snapshot_global_meters();
    if (!(volume == global) || volume.written_bytes != payload_size) {
        std::cerr << "meter sinks disagree: volume=" << volume.written_bytes
                  << " global=" << global.written_bytes << "\n";
        return false;
    }
    return true;
}

bool meters_separate_volumes_but_share_the_global_sink(const std::filesystem::path& directory) {
    constexpr std::size_t first_size = 3U << 20;
    constexpr std::size_t second_size = 5U << 20;
    const std::vector<unsigned char> first(first_size, 0x11);
    const std::vector<unsigned char> second(second_size, 0x22);

    // Both writers contribute to one process-wide sink while keeping independent
    // volume meters.
    auto meters = std::make_shared<WriterMeters>();
    AsyncFileWriter volume_a(meters, make_volume_state("a:", true), AsyncWriterConfig{});
    AsyncFileWriter volume_b(meters, make_volume_state("b:", true), AsyncWriterConfig{});

    for (int index = 0; index < 2; ++index) {
        AsyncFileWriter& writer = index == 0 ? volume_a : volume_b;
        const std::vector<unsigned char>& payload = index == 0 ? first : second;
        const std::wstring name = index == 0 ? L"volume-a.bin" : L"volume-b.bin";
        const auto job = writer.make_job();
        const auto file = writer.make_file(job, (directory / name).wstring(), name, 5, 5);
        std::uint32_t processed = 0;
        if (writer.write(file, payload.data(), static_cast<std::uint32_t>(payload.size()), &processed) != S_OK) {
            return false;
        }
        writer.record_operation_result(file, 0);
        writer.close_file(file, 0, false, {});
        if (writer.finish_job(job) != S_OK) {
            return false;
        }
    }

    const auto global = volume_a.snapshot_global_meters();
    const auto a = volume_a.snapshot_volume_meters();
    const auto b = volume_b.snapshot_volume_meters();
    if (global.written_bytes != first_size + second_size ||
        a.written_bytes != first_size || b.written_bytes != second_size ||
        global.completed_jobs != 2) {
        std::cerr << "multi-volume meters: global=" << global.written_bytes
                  << " a=" << a.written_bytes << " b=" << b.written_bytes
                  << " jobs=" << global.completed_jobs << "\n";
        return false;
    }
    // Both writers see the same process-wide snapshot.
    if (volume_b.snapshot_global_meters().written_bytes != global.written_bytes) {
        std::cerr << "global meter sink is not shared\n";
        return false;
    }
    return true;
}

bool quiescence_tracks_jobs_and_files(const std::filesystem::path& directory) {
    constexpr std::size_t payload_size = 2U << 20;
    const std::vector<unsigned char> payload(payload_size, 0x44);
    AsyncFileWriter writer;
    if (!writer.is_quiescent()) {
        std::cerr << "fresh writer is not quiescent\n";
        return false;
    }
    const auto job = writer.make_job();
    if (writer.is_quiescent()) {
        std::cerr << "writer with a registered job reported quiescent\n";
        return false;
    }
    const auto file = writer.make_file(
        job, (directory / L"quiescent.bin").wstring(), L"quiescent.bin", 6, 6);
    if (writer.is_quiescent()) {
        std::cerr << "writer with a live file reported quiescent\n";
        return false;
    }
    std::uint32_t processed = 0;
    if (writer.write(file, payload.data(), static_cast<std::uint32_t>(payload.size()), &processed) != S_OK) {
        return false;
    }
    writer.record_operation_result(file, 0);
    writer.close_file(file, 0, false, {});
    if (writer.finish_job(job) != S_OK) {
        return false;
    }
    // Once the job drained and no file is live, the facility is reclaimable.
    if (!writer.is_quiescent() || writer.has_active_jobs()) {
        std::cerr << "drained writer is not quiescent\n";
        return false;
    }
    return true;
}

bool configuration_is_snapshotted_not_reread(const std::filesystem::path& directory) {
    AsyncWriterConfig config;
    config.threads_per_volume = 2;
    config.buffer_count = 8;
    config.queue_limit = 16;
    const auto meters = std::make_shared<WriterMeters>();
    AsyncFileWriter writer(meters, make_volume_state("cfg:", true), config);
    if (writer.config().threads_per_volume != 2 || writer.config().buffer_count != 8 ||
        writer.config().queue_limit != 16) {
        std::cerr << "writer did not keep the supplied config\n";
        return false;
    }
    // A facility built from the shared snapshot still writes correctly.
    const std::vector<unsigned char> payload(1U << 20, 0x55);
    const auto job = writer.make_job();
    const auto file = writer.make_file(
        job, (directory / L"configured.bin").wstring(), L"configured.bin", 7, 7);
    std::uint32_t processed = 0;
    if (writer.write(file, payload.data(), static_cast<std::uint32_t>(payload.size()), &processed) != S_OK) {
        return false;
    }
    writer.record_operation_result(file, 0);
    writer.close_file(file, 0, false, {});
    return writer.finish_job(job) == S_OK && writer.is_quiescent();
}

bool registry_routes_by_volume_and_releases_leases(const std::filesystem::path& directory) {
    auto meters = std::make_shared<WriterMeters>();
    AsyncWriterConfig config;
    config.threads_per_volume = 2;
    config.buffer_count = 8;
    VolumeWriterRegistry registry(meters, config);
    if (!registry.empty()) {
        std::cerr << "fresh registry is not empty\n";
        return false;
    }
    // An empty key is still routed, and must not be treated as a volume identity.
    {
        auto lease = registry.acquire("");
        if (!lease.valid() || !lease.writer().volume_key().empty() ||
            lease.writer().volume_state()->persistent) {
            std::cerr << "empty key routing is wrong\n";
            return false;
        }
    }
    registry.shutdown();

    // Same key -> same facility; different key -> different facility.
    AsyncFileWriter* first = nullptr;
    {
        auto lease = registry.acquire("volume-a");
        if (!lease.valid() || lease.writer().volume_key() != "volume-a") {
            std::cerr << "registry did not route volume-a\n";
            return false;
        }
        first = &lease.writer();
        if (lease.writer().config().threads_per_volume != 2 ||
            lease.writer().config().buffer_count != 8 ||
            lease.writer().config().queue_limit != 4096) {
            std::cerr << "facility did not receive the registry config\n";
            return false;
        }
    }
    {
        auto lease = registry.acquire("volume-a");
        if (&lease.writer() != first) {
            std::cerr << "same key produced a different facility\n";
            return false;
        }
    }
    {
        auto other = registry.acquire("volume-b");
        if (&other.writer() == first || other.writer().volume_key() != "volume-b") {
            std::cerr << "distinct keys shared a facility\n";
            return false;
        }
    }
    if (registry.volume_keys().size() != 2) {
        std::cerr << "registry tracked " << registry.volume_keys().size() << " volumes\n";
        return false;
    }

    // One job's data must reach the process-wide meters and, from the per-volume
    // view, vanish with the lease.
    {
        auto lease = registry.acquire("volume-a");
        const std::vector<unsigned char> payload(1U << 20, 0x77);
        const auto job = lease.writer().make_job();
        const auto file = lease.writer().make_file(
            job, (directory / L"registry.bin").wstring(), L"registry.bin", 8, 8);
        std::uint32_t processed = 0;
        if (lease.writer().write(
                file, payload.data(), static_cast<std::uint32_t>(payload.size()), &processed) != S_OK) {
            return false;
        }
        lease.writer().record_operation_result(file, 0);
        lease.writer().close_file(file, 0, false, {});
        if (lease.writer().finish_job(job) != S_OK) {
            return false;
        }
        if (!lease.writer().is_quiescent()) {
            std::cerr << "facility not quiescent after its job drained\n";
            return false;
        }
        const auto aggregate = registry.snapshot();
        if (aggregate.meters.written_bytes != payload.size() ||
            aggregate.live_facilities != 2 || aggregate.any_active_jobs) {
            std::cerr << "registry aggregate: written=" << aggregate.meters.written_bytes
                      << " facilities=" << aggregate.live_facilities
                      << " active=" << aggregate.any_active_jobs << "\n";
            return false;
        }
    }

    registry.shutdown();
    if (!registry.empty()) {
        std::cerr << "registry still holds entries after shutdown\n";
        return false;
    }
    // Counters survive reclamation because they belong to the meters, not the facility.
    const auto after = snapshot_counters(meters->counters);
    if (after.written_bytes != (1U << 20)) {
        std::cerr << "process-wide meters did not survive shutdown: "
                  << after.written_bytes << "\n";
        return false;
    }
    // A facility can be recreated after shutdown without corrupting the meters.
    {
        auto lease = registry.acquire("volume-a");
        if (!lease.valid() || !lease.writer().is_quiescent()) {
            std::cerr << "registry did not recreate a usable facility\n";
            return false;
        }
    }
    registry.shutdown();
    return true;
}

bool registry_reclaims_idle_facilities(const std::filesystem::path& directory) {
    auto meters = std::make_shared<WriterMeters>();
    AsyncWriterConfig config;
    config.threads_per_volume = 2;
    config.buffer_count = 8;
    // The idle timeout only applies to persistent physical volumes; a synthetic
    // per-job key is reclaimable as soon as its lease is gone.
    config.idle_timeout = std::chrono::milliseconds(50);
    VolumeWriterRegistry registry(meters, config);

    // A synthetic key is reclaimed immediately after its lease drops.
    {
        auto lease = registry.acquire("job:probe-1");
        if (!lease.valid() || lease.writer().volume_state()->persistent) {
            std::cerr << "synthetic key was not marked non-persistent\n";
            return false;
        }
        if (lease.writer().config().threads_per_volume != 2 ||
            lease.writer().config().buffer_count != 8 ||
            lease.writer().config().queue_limit != 4096) {
            std::cerr << "synthetic key did not keep the registry config\n";
            return false;
        }
        if (registry.acquire("job:probe-1").created_facility()) {
            std::cerr << "second acquire of the same key created a second facility\n";
            return false;
        }
    }
    // The deadline is already in the past for a synthetic volume.
    if (!registry.next_reap_deadline()) {
        std::cerr << "synthetic volume armed no reclaim deadline\n";
        return false;
    }
    if (registry.reap_idle().size() != 1 || registry.reclaimed_count() != 1) {
        std::cerr << "synthetic facility was not reclaimed: " << registry.reclaimed_count() << "\n";
        return false;
    }
    if (!registry.empty()) {
        std::cerr << "synthetic entry survived reclamation\n";
        return false;
    }

    // A persistent volume keeps its state across reclamation and is only reclaimed
    // once its idle timeout has elapsed.
    {
        auto lease = registry.acquire("volume-p");
        if (!lease.writer().volume_state()->persistent) {
            std::cerr << "physical key was not marked persistent\n";
            return false;
        }
    }
    if (!registry.reap_idle().empty()) {
        std::cerr << "persistent facility was reclaimed before its idle timeout\n";
        return false;
    }
    if (registry.empty()) {
        std::cerr << "persistent entry disappeared before reclamation\n";
        return false;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(80));
    if (registry.reap_idle().size() != 1) {
        std::cerr << "persistent facility was not reclaimed after its idle timeout\n";
        return false;
    }
    // Reclaimed, but the volume state and its counters survive.
    if (registry.volume_keys().size() != 1) {
        std::cerr << "persistent volume state did not survive reclamation\n";
        return false;
    }
    const auto aggregate = registry.snapshot();
    if (aggregate.live_facilities != 0) {
        std::cerr << "reclaimed facility is still counted as live\n";
        return false;
    }
    // The facility can be rebuilt for the same volume afterwards.
    {
        auto lease = registry.acquire("volume-p");
        if (!lease.valid() || !lease.writer().is_quiescent()) {
            std::cerr << "persistent volume could not be rebuilt\n";
            return false;
        }
    }
    registry.shutdown();
    return true;
}

}  // namespace
#endif

int main() {
#ifdef _WIN32
    const auto directory = make_test_directory();
    const bool passed = write_same_file_concurrently(directory) &&
        write_zero_length_file(directory) &&
        closes_after_delayed_open_failure(directory) &&
        cancelled_job_returns_pending_to_zero(directory) &&
        successful_job_leaves_pending_at_zero(directory) &&
        meters_separate_volumes_but_share_the_global_sink(directory) &&
        quiescence_tracks_jobs_and_files(directory) &&
        configuration_is_snapshotted_not_reread(directory) &&
        registry_routes_by_volume_and_releases_leases(directory) &&
        registry_reclaims_idle_facilities(directory);
    std::error_code error;
    std::filesystem::remove_all(directory, error);
    if (!passed) {
        std::cerr << "async output check failed\n";
        return 1;
    }
#endif
    return 0;
}
