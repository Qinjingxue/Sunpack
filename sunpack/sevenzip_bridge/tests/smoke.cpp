#include "sevenzip_bridge/bridge.hpp"
#include "internal/sevenzip_paths.hpp"
#include "internal/sevenzip_formats.hpp"
#include "internal/sevenzip_status.hpp"
#include "internal/native_cpu_budget.hpp"
#include "internal/decoder_cpu_budget.h"
#include "internal/sevenzip_callbacks.hpp"
#include "internal/sevenzip_streams.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

#ifdef _WIN32
namespace {

bool check_probe_cancellation_lifetime() {
    // Transport/KDF tests never cancel these SDK callbacks on a decoder
    // thread. One lifecycle verifies token capture, interruption and isolation.
    using namespace sunpack::sevenzip;
    NativeMemoryManager manager(0);
    NativeMemoryJob job(manager);
    CMyComPtr<IArchiveExtractCallback> extract;
    CMyComPtr<IArchiveOpenCallback> open;
    {
        NativeMemoryScope scope(&job);
        extract = new ExtractCallback(L"secret");
        open = new OpenCallback(L"secret");
    }
    if (extract->SetCompleted(nullptr) != S_OK || open->SetCompleted(nullptr, nullptr) != S_OK) return false;
    job.cancel->store(true);
    bool stopped = false;
    std::thread decoder([&] {
        stopped = extract->SetCompleted(nullptr) == E_ABORT &&
            open->SetCompleted(nullptr, nullptr) == E_ABORT;
    });
    decoder.join();
    CMyComPtr<IArchiveExtractCallback> survivor(new ExtractCallback(L"secret"));
    return stopped && survivor->SetCompleted(nullptr) == S_OK;
}

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

    // The selector accepts only the already-analyzed hint, so no input path
    // can be opened. Generic RAR maps to the fixed order (RAR5, then RAR4).
    const auto formats = extraction_formats_for_hint(L"rar");
    return formats.encrypted_headers && formats.handlers.size() == 2 &&
        formats.handlers[0].Data4[5] == 0xCC &&
        formats.handlers[1].Data4[5] == 0x03;
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

bool check_encrypted_header_open_is_not_a_member_proof() {
    using namespace sunpack::sevenzip;
    // Empty 7z with an AES-encrypted directory and no data members.
    constexpr char archive[] =
        "\x37\x7a\xbc\xaf\x27\x1c\x00\x04\xc7\x28\x03\x8d\x10\x00\x00\x00\x00\x00\x00\x00\x1d\x00\x00\x00\x00"
        "\x00\x00\x00\x4f\x01\xf1\xa6\x6e\x7e\x20\x01\x39\x36\x14\x82\xa7\x41\xc3\x2d\xe1\xd1\xde\x86\x17\x06"
        "\x00\x01\x09\x10\x00\x07\x0b\x01\x00\x01\x24\x06\xf1\x07\x01\x01\x3f\x0c\x02\x0a\x01\xbe\x23\xc2\x58"
        "\x00\x00";
    const auto path = std::filesystem::temp_directory_path() /
        (L"sunpack-encrypted-directory-" + std::to_wstring(GetCurrentProcessId()) + L".7z");
    { std::ofstream file(path, std::ios::binary); file.write(archive, sizeof(archive) - 1); }
    const std::wstring wrong = L"incorrect";
    const auto bounded = test_password_batch(path.wstring(), {}, {}, L"7z", &wrong, 1, {}, true);
    const auto final = test_password_batch(path.wstring(), {}, {}, L"7z", &wrong, 1, {}, false, true);
    std::filesystem::remove(path);
    return bounded.status == PasswordTestStatus::Unsupported && bounded.encrypted &&
        !bounded.password_independent_failure && final.status == PasswordTestStatus::WrongPassword;
}

bool check_rar5_password_probe_with_unknown_unpacked_size() {
    using namespace sunpack::sevenzip;
    // A RAR5 Store member of 16 bytes with CRC32, no password-check bytes,
    // and the unknown-unpacked-size flag. The AES password is "evidence-key".
    constexpr char archive[] =
        "\x52\x61\x72\x21\x1a\x07\x01\x00\xc5\x1a\x33\x32\x03\x01\x00\x00"
        "\x36\x86\xaa\x4e\x34\x02\x03\x25\x10\x0c\x00\x00\x9f\xe6\xf6\xe0"
        "\x00\x00\x01\x78\x24\x01\x00\x00\x08\x00\x01\x02\x03\x04\x05\x06"
        "\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16"
        "\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x79\x2a\x0e\x2c\x6a\xf2\x37"
        "\xa7\x1f\x84\xce\xfa\x88\xae\x90\x32\x19\xb2\x3a\x35\x03\x05\x00\x00";
    const auto path = std::filesystem::temp_directory_path() /
        (L"sunpack-rar-proof-" + std::to_wstring(GetCurrentProcessId()) + L".rar");
    {
        std::ofstream file(path, std::ios::binary);
        file.write(archive, sizeof(archive) - 1);
    }
    const std::wstring candidates[]{L"wrong-before", L"out-of-domain", L"evidence-key"};
    const std::size_t domain[]{0, 2};
#ifdef SUP7Z_DEBUG
    observed_logical_read_bytes = 0;
#endif
    const auto rejected = test_password_batch(path.wstring(), {}, {}, L"rar", candidates, 1, {}, true);
#ifdef SUP7Z_DEBUG
    const auto rejected_bytes = observed_logical_read_bytes;
    observed_logical_read_bytes = 0;
#endif
    const auto deferred = test_password_batch(path.wstring(), {}, {}, L"rar", candidates, 2, {},
        false, false, domain, nullptr, true);
#ifdef SUP7Z_DEBUG
    const bool read_only_rejected_candidate = rejected_bytes > 0 && observed_logical_read_bytes == rejected_bytes;
#else
    const bool read_only_rejected_candidate = true;
#endif
    const auto accepted = test_password_batch(path.wstring(), {}, {}, L"rar", candidates, 2, {}, true, false, domain);

    // The extraction receipt is used on failure. Append a second, damaged
    // member with a different name and a matching header CRC.
    constexpr std::size_t member_start = 16, end_header = sizeof(archive) - 1 - 8;
    std::string damaged(archive + member_start, archive + end_header);
    damaged.replace(0, 4, "\xd4\x7b\x22\xc3", 4);
    damaged[19] = 'y';
    damaged.back() ^= 1;
    {
        std::ofstream file(path, std::ios::binary);
        file.write(archive, end_header);
        file.write(damaged.data(), damaged.size());
        file.write(archive + end_header, sizeof(archive) - 1 - end_header);
    }
    auto output = path;
    output.replace_extension(L".out");
    const auto extracted = extract_archive(path.wstring(), {}, {}, L"rar", candidates[2], output.wstring(), L"");
    std::error_code error;
    std::filesystem::remove(path, error);
    std::filesystem::remove(output / L"x", error);
    std::filesystem::remove(output / L"y", error);
    std::filesystem::remove(output, error);
    return rejected.status == PasswordTestStatus::WrongPassword &&
        deferred.status == PasswordTestStatus::Unsupported && deferred.matched_index == -1 &&
        deferred.possible_candidates == std::vector<std::size_t>{2} && read_only_rejected_candidate &&
        accepted.status == PasswordTestStatus::Ok && accepted.matched_index == 2 && !accepted.weak_match &&
        extracted.status == PasswordTestStatus::Damaged && extracted.password_crc_proven_items == 1;
}

bool check_rar5_short_keyed_member_password_proof() {
    using namespace sunpack::sevenzip;
    // An encrypted single-byte Store member with no password-check field.
    // The same ciphertext can have either a keyed or an ordinary checksum.
    constexpr char archive[] =
        "\x52\x61\x72\x21\x1a\x07\x01\x00\xc5\x1a\x33\x32\x03\x01\x00\x00"
        "\xa2\xc3\xc1\xff\x34\x02\x03\x25\x10\x04\x01\x00\x56\x7a\xbf\x41"
        "\x00\x00\x01\x78\x24\x01\x00\x02\x08\x00\x01\x02\x03\x04\x05\x06"
        "\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16"
        "\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\xd3\x25\x82\x6a\x92\xa2\xe5"
        "\x9f\x1e\xe6\xa5\x75\x15\xfa\x0d\x00\x19\xb2\x3a\x35\x03\x05\x00\x00";
    const auto path = std::filesystem::temp_directory_path() /
        (L"sunpack-rar-keyed-proof-" + std::to_wstring(GetCurrentProcessId()) + L".rar");
    std::string fixture(archive, sizeof(archive) - 1);
    const std::wstring candidates[]{L"wrong-password", L"evidence-key"};
    const auto probe = [&](const std::wstring* keys, std::size_t count) {
        {
            std::ofstream file(path, std::ios::binary);
            file.write(fixture.data(), fixture.size());
        }
        return test_password_batch(path.wstring(), {}, {}, L"rar5", keys, count, {}, true);
    };
    const auto keyed = probe(candidates, 2);

    // The same member remains independently verifiable with optional RAR5
    // metadata. Opening for extraction still exposes both service payloads.
    constexpr char cmt_header[] = "\x47\x80\x92\xc9\x12\x03\x02\x80\x08\x04\x80\x08\x00\x7c\xed\x58\x9d\x00\x00\x03" "CMT";
    constexpr char acl_header[] = "\xf8\x7a\xdc\x26\x12\x03\x02\x80\x08\x04\x80\x08\x00\x1a\xfb\x37\xb7\x00\x00\x03" "ACL";
    const std::string comment(1024, 'C'), acl(1024, 'A');
    fixture.insert(fixture.size() - 8, std::string(acl_header, sizeof(acl_header) - 1) + acl);
    fixture.insert(16, std::string(cmt_header, sizeof(cmt_header) - 1) + comment);
#ifdef SUP7Z_DEBUG
    observed_logical_read_bytes = 0;
#endif
    const auto with_metadata = probe(candidates + 1, 1);
#ifdef SUP7Z_DEBUG
    const bool skipped_payloads = observed_logical_read_bytes > 0 && observed_logical_read_bytes < acl.size();
#else
    const bool skipped_payloads = true;
#endif
    const bool metadata_preserved = [&] {
        auto input = open_archive_stream(path.wstring(), {});
        CMyComPtr<IInArchive> handler;
        CMyComPtr<IArchiveOpenCallback> callback(new OpenCallback(candidates[1]));
        const auto formats = extraction_formats_for_hint(L"rar5");
        if (!input.opened || create_in_archive(formats.handlers.front(), &handler) != S_OK ||
            handler->Open(input.stream, nullptr, callback) != S_OK)
            return false;
        CMyComPtr<IArchiveGetRawProps> raw;
        const void* acl_data = nullptr;
        UInt32 acl_size = 0, acl_type = 0;
        if (handler.QueryInterface(IID_IArchiveGetRawProps, &raw) != S_OK ||
            raw->GetRawProp(0, kpidNtSecure, &acl_data, &acl_size, &acl_type) != S_OK ||
            !acl_data || std::string_view(static_cast<const char*>(acl_data), acl_size) != acl)
            return false;
        PROPVARIANT property{};
        const bool has_comment = handler->GetArchiveProperty(kpidComment, &property) == S_OK &&
                                 prop_text(property) == std::wstring(comment.size(), L'C');
        clear_prop(property);
        return has_comment;
    }();
    fixture.assign(archive, sizeof(archive) - 1);

    fixture.replace(16, 4, "\xb7\x98\x2e\xc7", 4);
    fixture.replace(28, 4, "\x83\x16\xdc\x8c", 4);
    fixture[39] = 0;
    const auto plain = probe(candidates + 1, 1);
    fixture.replace(16, 4, "\x07\x65\x78\xfc", 4);
    fixture.replace(28, 4, "\x9e\x6d\x9f\x53", 4);
    fixture[24] = fixture[26] = 0;
    fixture[39] = 2;
    fixture.erase(73, 16);
    const auto empty = probe(candidates + 1, 1);
    std::error_code error;
    std::filesystem::remove(path, error);
    return keyed.status == PasswordTestStatus::Ok && keyed.matched_index == 1 &&
        with_metadata.status == PasswordTestStatus::Ok && with_metadata.matched_index == 0 &&
        skipped_payloads && metadata_preserved &&
        plain.status == PasswordTestStatus::Unsupported && plain.weak_match &&
        empty.status == PasswordTestStatus::Unsupported && empty.password_independent_failure;
}

bool check_rar5_encrypted_comment_password_fallback() {
    using namespace sunpack::sevenzip;
    constexpr char signature[] = "\x52\x61\x72\x21\x1a\x07\x01\x00\xc5\x1a\x33\x32\x03\x01\x00\x00";
    constexpr char end_header[] = "\x19\xb2\x3a\x35\x03\x05\x00\x00";
    constexpr char crypto_extra[] =
        "\x24\x01\x00\x00\x08\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
        "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f";
    constexpr char good_comment[] =
        "\xa0\x4f\xfd\x37\x36\x03\x03\x25\x10\x04\x10\x00\x9f\xe6\xf6\xe0\x00\x00\x03" "CMT";
    constexpr char padded_comment[] =
        "\xb6\xac\x90\xf1\x36\x03\x03\x25\x10\x04\x0f\x00\x4d\xf1\x65\x2c\x00\x00\x03" "CMT";
    constexpr char corrupt_comment[] =
        "\x5d\x4b\x71\x77\x38\x03\x03\x25\x80\x08\x04\x80\x08\x00\x00\x00\x00\x00\x00\x00\x03" "CMT";
    constexpr char ciphertext[] = "\x79\x2a\x0e\x2c\x6a\xf2\x37\xa7\x1f\x84\xce\xfa\x88\xae\x90\x32";
    constexpr char file_header[] =
        "\x82\x4f\x71\x59\x34\x02\x03\x25\x10\x04\x10\x00\x9f\xe6\xf6\xe0\x00\x00\x01x";
    const auto path = std::filesystem::temp_directory_path() /
        (L"sunpack-rar-encrypted-comment-" + std::to_wstring(GetCurrentProcessId()) + L".rar");
    const std::wstring keys[]{L"wrong-password", L"evidence-key"};
    const auto write_fixture = [&](std::string_view comment_header, std::string_view comment_data, bool add_file, bool add_end) {
        std::ofstream file(path, std::ios::binary);
        file.write(signature, sizeof(signature) - 1);
        file.write(comment_header.data(), comment_header.size());
        file.write(crypto_extra, sizeof(crypto_extra) - 1);
        file.write(comment_data.data(), comment_data.size());
        if (add_file) {
            file.write(file_header, sizeof(file_header) - 1);
            file.write(crypto_extra, sizeof(crypto_extra) - 1);
            file.write(ciphertext, sizeof(ciphertext) - 1);
        }
        if (add_end) file.write(end_header, sizeof(end_header) - 1);
    };
    const std::string damaged(1024, '\0');
    write_fixture({corrupt_comment, sizeof(corrupt_comment) - 1}, damaged, true, true);
#ifdef SUP7Z_DEBUG
    observed_logical_read_bytes = 0;
#endif
    const auto regular = test_password_batch(path.wstring(), {}, {}, L"rar5", keys + 1, 1, {}, true);
#ifdef SUP7Z_DEBUG
    const bool skipped_comment = observed_logical_read_bytes > 0 && observed_logical_read_bytes < damaged.size();
#else
    const bool skipped_comment = true;
#endif
    const std::string_view comment_header{good_comment, sizeof(good_comment) - 1};
    write_fixture({padded_comment, sizeof(padded_comment) - 1}, {ciphertext, sizeof(ciphertext) - 1}, false, true);
    const auto comment = test_password_batch(path.wstring(), {}, {}, L"rar5", keys, 2, {}, true);
    write_fixture(comment_header, {ciphertext, sizeof(ciphertext) - 1}, false, true);
    const bool comment_metadata_preserved = [&] {
        auto input = open_archive_stream(path.wstring(), {});
        CMyComPtr<IInArchive> handler;
        CMyComPtr<IArchiveOpenCallback> callback(new OpenCallback(keys[1]));
        const auto formats = extraction_formats_for_hint(L"rar5");
        UInt32 items = 0;
        if (!input.opened || create_in_archive(formats.handlers.front(), &handler) != S_OK ||
            handler->Open(input.stream, nullptr, callback) != S_OK ||
            handler->GetNumberOfItems(&items) != S_OK || items != 0)
            return false;
        PROPVARIANT property{};
        const bool success = handler->GetArchiveProperty(kpidComment, &property) == S_OK &&
            prop_text(property) == L"16 bytes of data";
        clear_prop(property);
        return success;
    }();
    write_fixture(comment_header, {ciphertext, 8}, false, false);
    const auto truncated = test_password_batch(path.wstring(), {}, {}, L"rar5", keys + 1, 1, {}, true);
    std::error_code error;
    std::filesystem::remove(path, error);
    return regular.status == PasswordTestStatus::Ok && regular.matched_index == 0 && skipped_comment &&
        comment.status == PasswordTestStatus::Ok && comment.matched_index == 1 && comment_metadata_preserved &&
        truncated.status == PasswordTestStatus::Unsupported && truncated.encrypted;
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

    // Re-saturating and releasing produces the next availability edge.
    if (budget.acquire_up_to(2, 2) != 2) {
        return false;
    }
    budget.release(2);
    if (probe.calls != 2 || budget.reserved_credits() != 2) {
        return false;
    }

    budget.release(2);
    return probe.calls == 2 && budget.reserved_credits() == 0;
}

bool check_cpu_budget_tracks_decoder_thread_lifetimes() {
    using namespace sunpack::sevenzip;
    NativeCpuBudget budget(4);
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

}  // namespace
#endif

int wmain(int argc, wchar_t** argv) {
#ifdef _WIN32
    if (!check_probe_cancellation_lifetime()) {
        std::cerr << "password probe cancellation lifetime check failed\n";
        return 34;
    }
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
    if (!check_encrypted_header_open_is_not_a_member_proof()) {
        std::cerr << "bounded probe classified encrypted directory Open as member evidence\n";
        return 38;
    }
    if (!check_rar5_password_probe_with_unknown_unpacked_size()) {
        std::cerr << "RAR5 unknown unpacked size password proof check failed\n";
        return 35;
    }
    if (!check_rar5_short_keyed_member_password_proof()) {
        std::cerr << "RAR5 short keyed member password proof check failed\n";
        return 36;
    }
    if (!check_rar5_encrypted_comment_password_fallback()) {
        std::cerr << "RAR5 encrypted comment fallback check failed\n";
        return 37;
    }

    if (!check_cpu_budget_accounts_base_and_decoder_credits()) {
        std::cerr << "CPU credit accounting check failed\n";
        return 23;
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

#endif

    (void)argc;
    (void)argv;
    return 0;
}
