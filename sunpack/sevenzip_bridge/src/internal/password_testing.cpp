#include "sevenzip_bridge/bridge.hpp"

#include <algorithm>
#include <optional>

#include "password_parallel.hpp"

#include "sevenzip_callbacks.hpp"

#include "sevenzip_formats.hpp"

#include "sevenzip_paths.hpp"

#include "sevenzip_properties.hpp"

#include "sevenzip_status.hpp"

#include "sevenzip_streams.hpp"
#ifdef _WIN32
#include "password_proof_property.hpp"
#endif

namespace sunpack::sevenzip
{

#ifdef _WIN32

    namespace
    {

        PasswordTestResult needs_volume_or_tail_damaged_result(
            const char *evidence,
            const std::wstring &requested_name,
            bool password_requested)
        {
            PasswordTestResult result;
            result.status = PasswordTestStatus::NeedsVolumeOrTailDamaged;
            result.missing_volume = true;
            result.password_independent_failure = !password_requested;
            result.message = "password probe could not read required tail data; missing volume or damaged tail offset/structure";
            if (evidence && *evidence)
            {
                result.message += " [evidence=";
                result.message += evidence;
                result.message += "]";
            }
            if (!requested_name.empty())
            {
                result.message += " [requested_volume=";
                for (wchar_t ch : requested_name)
                {
                    result.message.push_back(ch >= 0x20 && ch <= 0x7e ? static_cast<char>(ch) : '?');
                }
                result.message += "]";
            }
            return result;
        }

        struct BoundedPasswordProbeSelection
        {
            std::optional<UInt32> index;
            bool member_mode = false;
            bool weak = false;
            bool item_count_known = false;
            UInt32 item_count = 0;
            bool encrypted = false;
        };

        struct MemberProof {
            UInt32 index;
            UInt64 cost;
            UInt64 coverage;
            bool weak;
            bool variable;
            bool operator<(const MemberProof& other) const {
                if (weak != other.weak) return !weak;
                if (variable != other.variable) return variable;
                if (weak && coverage != other.coverage) return coverage > other.coverage;
                if (cost != other.cost) return cost < other.cost;
                return index < other.index;
            }
        };

        struct ProbeVolumeRanges {
            std::vector<UInt64> starts;
            std::vector<UInt32> variable;
            mutable std::optional<VolumeReadUncertainty> reads;

            ProbeVolumeRanges(const VolumeAttemptPlan* plan, const std::vector<ExtractInputRange>& ranges,
                              const std::wstring& format) {
                if (!plan || std::none_of(plan->variation.begin(), plan->variation.end(),
                    [](const auto& slot) { return slot.variable; })) return;
                if ((format == L"7z" || format == L"zip") && !ranges.empty() &&
                    std::none_of(plan->variation.begin(), plan->variation.end(), [](const auto& slot) { return slot.variable_length; }))
                    reads.emplace();
                starts.reserve(ranges.size() + 1);
                variable.reserve(ranges.size() + 1);
                starts.push_back(0);
                variable.push_back(0);
                for (std::size_t i = 0; i < ranges.size(); ++i) {
                    const auto& r = ranges[i];
                    starts.push_back(r.has_end && r.end - r.start <= UINT64_MAX - starts.back()
                        ? starts.back() + r.end - r.start : UINT64_MAX);
                    variable.push_back(variable.back() + plan->variation[i].variable);
                    if (reads && plan->variation[i].variable)
                        reads->uncertain_ranges.emplace_back(starts[i], starts[i + 1]);
                }
            }
            VolumeReadUncertainty* observer() const { return reads ? &*reads : nullptr; }
            bool independent() const { return reads && !reads->uncertain_read.load(std::memory_order_relaxed); }
            bool contains(IInArchive* archive, UInt32 index, const std::wstring& format) const {
                if (starts.empty()) return false;
                PROPVARIANT prop{};
                if (format == L"rar4" || format == L"rar5") {
                    if (!get_item_property(archive, index, kpidSunpackProofDisks, prop)) return false;
                    const auto disks = prop_u64(prop);
                    const auto first = static_cast<UInt32>(disks), last = static_cast<UInt32>(disks >> 32);
                    return first <= last && last < variable.size() - 1 && variable[last + 1] != variable[first];
                }
                if (!get_item_property(archive, index, kpidSunpackProofOffset, prop)) return false;
                auto begin = prop_u64(prop);
                if (format == L"zip" && get_item_property(archive, index, kpidVolumeIndex, prop)) {
                    const auto disk = prop_u32(prop);
                    if (disk >= starts.size() - 1 || begin > UINT64_MAX - starts[disk]) return false;
                    begin += starts[disk];
                }
                if (!get_item_property(archive, index, kpidSunpackProofPackedSize, prop)) return false;
                const auto size = prop_u64(prop);
                return intersects(begin, size);
            }
            bool intersects(UInt64 begin, UInt64 size) const {
                if (starts.empty() || !size || begin >= starts.back()) return false;
                const auto end = begin + (std::min)(size, starts.back() - begin);
                const auto first = std::upper_bound(starts.begin(), starts.end(), begin) - starts.begin() - 1;
                const auto after = std::lower_bound(starts.begin(), starts.end(), end) - starts.begin();
                return variable[after] != variable[first];
            }
        };

        BoundedPasswordProbeSelection bounded_password_probe_selection(IInArchive *archive, const std::wstring &format,
            bool header_password, const ProbeVolumeRanges& volumes, std::vector<MemberProof>* alternatives = nullptr)
        {
            BoundedPasswordProbeSelection selection;
            if (!archive)
            {
                return selection;
            }
            if (archive->GetNumberOfItems(&selection.item_count) != S_OK)
            {
                return selection;
            }
            selection.item_count_known = true;
            selection.encrypted = header_password;
            if (format == L"enc") {
                // The ENC handler reports the quick-block result in Extract's
                // test callback, even when its Open succeeded with a wrong key.
                selection.index = 0;
                return selection;
            }
            const bool zip = format == L"zip";
            selection.member_mode = zip || format == L"7z";
            PROPVARIANT archive_value;
            PropVariantInit(&archive_value);
            const bool solid = archive->GetArchiveProperty(kpidSolid, &archive_value) == S_OK && prop_bool(archive_value);
            clear_prop(archive_value);

            const bool seven_zip = format == L"7z";
            std::optional<MemberProof> regular, best;
            UInt64 solid_prefix = 0;
            UInt32 last_block = UINT32_MAX;
            std::optional<UInt64> copy_start;
            for (UInt32 index = 0; index < selection.item_count; ++index)
            {
                PROPVARIANT value{};
                const bool is_encrypted = get_item_property(archive, index, kpidEncrypted, value) && prop_bool(value);
                clear_prop(value);
                selection.encrypted |= is_encrypted;
                const bool is_dir = get_item_property(archive, index, kpidIsDir, value) && prop_bool(value);
                clear_prop(value);
                if (is_dir) continue;
                get_item_property(archive, index, kpidSize, value);
                const UInt64 size = prop_u64(value);
                clear_prop(value);
                UInt64 cost = size;
                if (solid) {
                    if (seven_zip) {
                        if (get_item_property(archive, index, kpidBlock, value)) {
                            const auto block = prop_u32(value);
                            if (last_block != block) {
                                solid_prefix = 0;
                                copy_start.reset();
                                clear_prop(value);
                                if (get_item_property(archive, index, kpidSunpackAesCopyStart, value))
                                    copy_start = prop_u64(value);
                            }
                            last_block = block;
                        }
                    } else if (!get_item_property(archive, index, kpidSolid, value) || !prop_bool(value)) {
                        solid_prefix = 0;
                    }
                    clear_prop(value);
                    solid_prefix += size;
                    cost = solid_prefix;
                }
                if (!regular || cost < regular->cost) regular = MemberProof{index, cost, 0, false, false};
                if (!is_encrypted) continue;
                const bool authenticated = zip &&
                    get_item_property(archive, index, kpidSunpackMacPackedSize, value);
                if (authenticated) cost = prop_u64(value);
                clear_prop(value);
                UInt64 coverage = 0;
                if (!authenticated && get_item_property(archive, index, kpidSunpackProofSize, value))
                    coverage = prop_u64(value);
                clear_prop(value);
                // A single tiny CRC contains only 8 * size evidence bits.
                // Do not add evidence across members: different folders may
                // repeat the same encrypted bytes, IV and contents.
                if (!authenticated && !coverage) continue;
                bool variable = false;
                if (copy_start && coverage == size && solid_prefix - size >= 16) {
                    const auto offset = solid_prefix - size;
                    const auto start = (offset & ~UInt64{15}) - 16;
                    cost = size + (offset - start);
                    variable = volumes.intersects(*copy_start + start, (cost + 15) & ~UInt64{15});
                } else variable = volumes.contains(archive, index, format);
                MemberProof member{index, cost, coverage, !authenticated && !strong_member_crc(coverage), variable};
                if (!best || member < *best) best = member;
                if (alternatives) alternatives->push_back(member);
            }
            if (!selection.encrypted) {
                if (regular) selection.index = regular->index;
            } else if (best) {
                selection.index = best->index;
                selection.weak = best->weak;
            }
            return selection;
        }

        // One batch owns at most one reusable handler. Encrypted headers still
        // open per candidate; neither archive objects nor callbacks enter a
        // process cache or survive the batch's last confirmation.
        struct PasswordProbeCache
        {
            CMyComPtr<IInArchive> archive;
            CMyComPtr<IArchiveOpenCallback> callback;
            OpenCallback *callback_state = nullptr;
            BoundedPasswordProbeSelection selection;
            PasswordTestResult evidence;

            void reset()
            {
                if (archive) archive->Close();
                archive.Release();
                callback.Release();
                callback_state = nullptr;
            }
            ~PasswordProbeCache() { reset(); }
        };

        void probe_opened_archive(
            IInArchive *archive, const BoundedPasswordProbeSelection &selection,
            const std::wstring &password, bool &encryption_evidence, bool final_read_only,
            HRESULT &hr, Int32 &operation)
        {
            auto *raw_callback = new ExtractCallback(password);
            CMyComPtr<IArchiveExtractCallback> callback(raw_callback);
            hr = S_OK;
            if (final_read_only) {
                // The final read-only pass covers every member. A preceding
                // bounded proof has already removed its rejected passwords.
                hr = archive->Extract(nullptr, kAllItems, kTestMode, callback);
            } else if (selection.index) {
                const auto mode = selection.member_mode ? kSunpackVerifyMember : kTestMode;
                hr = archive->Extract(&*selection.index, 1, mode, callback);
            }
            if (!final_read_only && selection.weak && selection.member_mode && selection.index &&
                hr == S_OK && raw_callback->operation_result() == kOpOk) {
                // A seekable AES/Copy substream can verify another CRC with
                // the same key without decoding the solid prefix again.
                PROPVARIANT block{};
                if (get_item_property(archive, *selection.index, kpidBlock, block) && block.vt == VT_UI4) {
                    const auto folder = prop_u32(block);
                    clear_prop(block);
                    const auto next = *selection.index + 1;
                    PROPVARIANT proof{};
                    PROPVARIANT copy{};
                    if (next < selection.item_count &&
                        get_item_property(archive, next, kpidBlock, block) &&
                        block.vt == VT_UI4 && prop_u32(block) == folder &&
                        get_item_property(archive, next, kpidSunpackAesCopyStart, copy) &&
                        copy.vt == VT_UI8 &&
                        get_item_property(archive, next, kpidSunpackProofSize, proof) &&
                        prop_u64(proof) != 0 &&
                        prop_u64(proof) <= sizeof(UInt32)) {
                        auto *second = new ExtractCallback(password);
                        CMyComPtr<IArchiveExtractCallback> second_callback(second);
                        const auto second_hr = archive->Extract(&next, 1, kSunpackVerifyMember, second_callback);
                        if (second_hr == S_OK && (second->operation_result() == kOpWrongPassword ||
                                                  second->operation_result() == kOpCrcError)) {
                            hr = second_hr;
                            operation = second->operation_result();
                            encryption_evidence = true;
                            clear_prop(proof);
                            clear_prop(copy);
                            clear_prop(block);
                            return;
                        }
                    }
                    clear_prop(proof);
                    clear_prop(copy);
                }
                clear_prop(block);
            }
            operation = raw_callback->operation_result();
            encryption_evidence = encryption_evidence || raw_callback->password_requested();
        }

    } // namespace

    PasswordTestResult test_one_password(


        const std::wstring &archive_path,

        const std::wstring &password,

        const std::vector<std::wstring> &part_paths,

        const ExtractionFormats &selection_formats,

        const std::vector<ExtractInputRange> &input_ranges,

        const std::vector<std::wstring> &canonical_names,
        const std::wstring &format_hint,
        PasswordProbeCache &cache,
        bool scan_only, bool final_read_only, const ProbeVolumeRanges& volumes

    )
    {
        if (native_job_cancelled()) {
            PasswordTestResult result;
            result.status = PasswordTestStatus::Error;
            result.message = "password probe cancelled";
            return result;
        }
        if (cache.archive)
        {
            PasswordTestResult result = cache.evidence;
            bool encrypted = result.encrypted;
            HRESULT hr = S_OK;
            Int32 operation = kOpOk;
            probe_opened_archive(cache.archive, cache.selection, password,
                encrypted, final_read_only, hr, operation);
            result.operation_result = operation;
            if (cache.callback_state->missing_volume_requested() && (hr != S_OK || operation != kOpOk) &&
                !((result.archive_type == L"rar4" || result.archive_type == L"rar5") &&
                  cache.selection.index && looks_wrong_password(hr, operation, encrypted)))
                return needs_volume_or_tail_damaged_result("probe_volume_callback_not_found", cache.callback_state->missing_volume_name(),
                    cache.callback_state->password_requested());
            if (cache.callback_state->volume_open_failed() || FAILED(hr)) {
                result.status = PasswordTestStatus::Error;
                result.message = "password probe could not read or decode the selected member";
                cache.reset();
                return result;
            }
            if (!cache.callback_state->password_requested())
            {
                if (hr == S_OK && operation == kOpOk)
                {
                    result.status = PasswordTestStatus::Ok;
                    result.message = "password accepted";
                    result.weak_match = cache.selection.weak && !final_read_only;
                    return result;
                }
                if (looks_wrong_password(hr, operation, encrypted))
                {
                    result.status = PasswordTestStatus::WrongPassword;
                    result.encrypted = true;
                    result.message = "wrong password";
                    return result;
                }
            }
            // An inconclusive handler result keeps the original fallback path.
            cache.reset();
        }

        PasswordTestResult result;
        result.archive_type = format_hint;

        bool any_format_created = false;

        bool any_opened = false;

        HRESULT last_hr = E_FAIL;

        Int32 last_op_res = kOpOk;
        bool last_encryption_evidence = false;

        const auto &formats = selection_formats.handlers;
        const UInt64 start_only = 0;
        for (std::size_t attempt_index = 0; attempt_index < formats.size() * 2; ++attempt_index)
        {
            if (native_job_cancelled()) {
                result.status = PasswordTestStatus::Error;
                result.message = "password probe cancelled";
                return result;
            }
            const GUID &format = formats[attempt_index % formats.size()];
            const UInt64 *search_limit = attempt_index < formats.size() ? &start_only : nullptr;

            CMyComPtr<IInArchive> archive;

            HRESULT hr = create_in_archive(format, &archive);

            if (hr != S_OK || !archive)
            {

                last_hr = hr;

                continue;
            }

            any_format_created = true;

            auto input = open_archive_stream(archive_path, part_paths,
                nullptr, canonical_names, InputPrefetchConfig{false}, input_ranges, volumes.observer());

            if (!input.opened)
            {

                const auto numbered = [](const std::wstring& path) { return parse_volume_number(path).has_value(); };
                if (is_sfx_path(archive_path) &&
                    (std::any_of(part_paths.begin(), part_paths.end(), numbered) ||
                     (part_paths.empty() && !canonical_names.empty() &&
                      std::any_of(input_ranges.begin(), input_ranges.end(), [&](const ExtractInputRange& range) {
                          return numbered(range.path);
                      }))))
                {
                    result.status = PasswordTestStatus::NeedsVolumeOrTailDamaged;
                    result.message = "split self-extracting archive stub is missing";
                    return result;
                }

                result.status = PasswordTestStatus::Error;

                result.message = "archive file could not be opened";

                return result;
            }

            auto *raw_open_callback = new OpenCallback(password, std::move(input.callback_path), part_paths, canonical_names,
                InputPrefetchConfig{false}, native_job_cancel_token(), input_ranges, volumes.observer());
            CMyComPtr<IArchiveOpenCallback> open_callback(raw_open_callback);

            hr = archive->Open(input.stream.Interface(), search_limit, open_callback.Interface());
            // A later handler/search attempt cannot erase an earlier
            // encrypted-header callback from this candidate's Open.
            last_encryption_evidence = last_encryption_evidence || raw_open_callback->password_requested();

            if (hr != S_OK && raw_open_callback->missing_volume_requested())
            {
                auto missing = needs_volume_or_tail_damaged_result(
                    "open_volume_callback_not_found",
                    raw_open_callback->missing_volume_name(), raw_open_callback->password_requested());
                if (!format_hint.empty()) missing.archive_type = format_hint;
                return missing;
            }

            if (raw_open_callback->volume_open_failed())
            {
                result.status = PasswordTestStatus::Error;
                result.message = "archive split volume could not be opened";
                return result;
            }

            if (hr != S_OK)
            {

                last_hr = hr;

                continue;
            }

            any_opened = true;
            result.archive_type = canonical_archive_type_for_guid(format);
            auto selection = bounded_password_probe_selection(archive, result.archive_type, raw_open_callback->password_requested(), volumes);
            if (final_read_only && !raw_open_callback->missing_volume_requested() && selection.item_count_known && rar4_rejected_empty_encrypted_headers(
                    archive.Interface(), format, selection.item_count, raw_open_callback->password_requested()))
            {
                result.status = PasswordTestStatus::WrongPassword;
                result.encrypted = true;
                result.operation_result = kOpWrongPassword;
                result.message = "RAR4 encrypted headers could not be decoded";
                archive->Close();
                return result;
            }
            last_encryption_evidence = last_encryption_evidence || selection.encrypted;
            result.encrypted = result.encrypted || last_encryption_evidence;
            result.missing_volume = raw_open_callback->missing_volume_requested();
            if (scan_only && !raw_open_callback->missing_volume_requested() && !selection.encrypted &&
                !last_encryption_evidence && selection.item_count_known)
            {
                archive->Close();
                result.status = PasswordTestStatus::Ok;
                return result;
            }
            if (!selection.index && !(final_read_only && raw_open_callback->password_requested() && selection.item_count != 0))
            {
                archive->Close();
                if (raw_open_callback->missing_volume_requested())
                    return needs_volume_or_tail_damaged_result("open_volume_callback_not_found", raw_open_callback->missing_volume_name(),
                        raw_open_callback->password_requested());
                result.status = PasswordTestStatus::Unsupported;
                result.message = "no independently authenticated member can confirm the password";
                result.password_independent_failure = !raw_open_callback->password_requested();
                return result;
            }
            probe_opened_archive(archive, selection, password,
                last_encryption_evidence, final_read_only, hr, last_op_res);
            const auto method_unavailable = [&] {
                return hr == E_NOTIMPL || (hr == S_OK &&
                    (last_op_res == kOpUnsupportedMethod || last_op_res == kOpUnavailable));
            };
            if (!final_read_only && method_unavailable() && selection.index && selection.item_count > 1) {
                // Build the ordered inventory only when the cheapest member's
                // codec or data was unavailable. Normal probes retain one index.
                std::vector<MemberProof> alternatives;
                bounded_password_probe_selection(archive, result.archive_type,
                    raw_open_callback->password_requested(), volumes, &alternatives);
                std::sort(alternatives.begin(), alternatives.end());
                for (const auto& member : alternatives) {
                    if (member.index == *selection.index) continue;
                    selection.index = member.index;
                    selection.weak = member.weak;
                    probe_opened_archive(archive, selection, password, last_encryption_evidence,
                        final_read_only, hr, last_op_res);
                    if (!method_unavailable()) break;
                }
            }
            result.operation_result = last_op_res;
            last_hr = hr;
            // RAR's handler may request the next volume during Open, having
            // already indexed whole earlier members. A password failure for
            // one of those complete members still belongs to this candidate.
            const bool checked_rar_member = (result.archive_type == L"rar4" || result.archive_type == L"rar5") &&
                selection.index && looks_wrong_password(hr, last_op_res, last_encryption_evidence);
            if (raw_open_callback->missing_volume_requested() && (hr != S_OK || last_op_res != kOpOk) && !checked_rar_member) {
                auto missing = needs_volume_or_tail_damaged_result("probe_volume_callback_not_found", raw_open_callback->missing_volume_name(),
                    raw_open_callback->password_requested());
                archive->Close();
                return missing;
            }
            if (raw_open_callback->volume_open_failed() || (FAILED(hr) && hr != E_NOTIMPL)) {
                archive->Close();
                result.status = PasswordTestStatus::Error;
                result.message = "password probe could not read or decode the selected member";
                return result;
            }
            if (hr == E_NOTIMPL || last_op_res == kOpUnsupportedMethod) {
                archive->Close();
                result.status = PasswordTestStatus::Unsupported;
                result.message = "no supported decoder could confirm the password";
                result.password_independent_failure = !raw_open_callback->password_requested();
                return result;
            }
            const bool weak_match = selection.weak && !final_read_only;
            if (!raw_open_callback->password_requested() &&
                looks_wrong_password(hr, last_op_res, last_encryption_evidence))
            {
                cache.reset();
                cache.archive = archive;
                cache.callback = open_callback;
                cache.callback_state = raw_open_callback;
                cache.selection = std::move(selection);
                cache.evidence = result;
            }
            else archive->Close();

            if (hr == S_OK && last_op_res == kOpOk)
            {

                result.status = PasswordTestStatus::Ok;

                result.message = "password accepted";
                result.weak_match = weak_match;

                return result;
            }

            if (looks_wrong_password(hr, last_op_res, last_encryption_evidence))
            {

                result.status = PasswordTestStatus::WrongPassword;
                result.encrypted = true;

                result.message = "wrong password";

                break;
            }

            if (looks_damaged(last_op_res))
            {

                result.status = PasswordTestStatus::Damaged;

                result.message = std::string("archive appears damaged [operation_result=") +
                                 operation_result_name(last_op_res) + "]";

                break;
            }
        }

        if (!any_format_created)
        {

            result.status = PasswordTestStatus::Unsupported;
            result.password_independent_failure = true;

            result.message = "the embedded 7-Zip backend did not create a supported archive handler";
        }
        else if (!any_opened &&
                 looks_wrong_password(last_hr, last_op_res, last_encryption_evidence))
        {

            result.status = PasswordTestStatus::WrongPassword;
            result.encrypted = true;

            result.message = "wrong password";
        }
        else if (!any_opened)
        {

            result.status = PasswordTestStatus::Unsupported;

            result.message = "archive could not be opened by supported handlers";
            result.password_independent_failure = !last_encryption_evidence;
        }
        else if (looks_damaged(last_op_res))
        {

            result.status = PasswordTestStatus::Damaged;

            result.message = std::string("archive appears damaged [operation_result=") +
                             operation_result_name(last_op_res) + "]";
        }
        else if (looks_wrong_password(last_hr, last_op_res, last_encryption_evidence))
        {

            result.status = PasswordTestStatus::WrongPassword;
            result.encrypted = true;

            result.message = "wrong password";
        }
        else
        {

            result.status = PasswordTestStatus::Error;

            result.message = "archive test failed";
        }

        return result;
    }

#endif

    PasswordTestResult test_password_batch(
        const std::wstring &archive_path,
        const std::vector<std::wstring> &part_paths,
        const std::vector<ExtractInputRange> &input_ranges,
        const std::wstring &format_hint,
        const std::wstring *candidates,
        std::size_t candidate_count,
        const std::vector<std::wstring> &canonical_names,
        bool scan_only, bool final_read_only, const std::size_t* candidate_indices, const VolumeAttemptPlan* volume_plan)
    {
#ifdef _WIN32
        const auto formats = extraction_formats_for_hint(format_hint);
        const ProbeVolumeRanges volumes(volume_plan, input_ranges, format_hint);
        const std::wstring empty;
        const auto count = (std::max)(candidate_count, std::size_t{1});
        const auto global_index = [candidate_indices](std::size_t index) {
            return candidate_indices ? candidate_indices[index] : index;
        };
        if (count == 1) {
            ExtractionReplayScope replay(nullptr);
            PasswordProbeCache cache;
            const auto index = global_index(0);
            auto result = test_one_password(archive_path, candidate_count ? candidates[index] : empty,
                part_paths, formats, input_ranges, canonical_names, format_hint, cache, scan_only, final_read_only, volumes);
            if (result.status == PasswordTestStatus::Ok) {
                if (!result.weak_match || final_read_only) result.matched_index = static_cast<int>(index);
                else {
                    result.status = PasswordTestStatus::Unsupported;
                    result.possible_candidates.push_back(index);
                }
            }
            result.rejects_fixed_geometry = result.status == PasswordTestStatus::WrongPassword && volumes.independent();
            return result;
        }
        PasswordParallelism parallel(count);
        std::atomic<std::size_t> next{0}, earliest{count};
        std::vector<std::optional<PasswordTestResult>> outcomes(parallel.size());
        std::vector<std::optional<PasswordTestResult>> unresolved(parallel.size());
        enum class CandidateProof : unsigned char { Untested, Rejected, Unresolved, Weak };
        std::vector<CandidateProof> proofs(count, CandidateProof::Untested);
        parallel.run(parallel.size(), [&](std::size_t lane, std::size_t) {
          PasswordProbeCache cache;
          for (;;) {
            const auto index = next.fetch_add(1, std::memory_order_relaxed);
            if (index >= earliest.load(std::memory_order_relaxed)) break;
            if (native_job_cancelled()) {
                break;
            }
            auto current = test_one_password(archive_path, candidate_count == 0 ? empty : candidates[global_index(index)],
                part_paths, formats, input_ranges, canonical_names, format_hint, cache, scan_only, final_read_only, volumes);
            if (native_job_cancelled()) break;
            if (current.weak_match && !final_read_only) {
                proofs[index] = CandidateProof::Weak;
                continue;
            }
            if (!current.password_independent_failure &&
                (current.status == PasswordTestStatus::Unsupported || current.status == PasswordTestStatus::NeedsVolumeOrTailDamaged ||
                 current.status == PasswordTestStatus::Damaged)) {
                // Decrypting another header can expose a different usable
                // member. Preserve this candidate and continue the method.
                proofs[index] = CandidateProof::Unresolved;
                if (!unresolved[lane]) {
                    current.matched_index = static_cast<int>(index);
                    unresolved[lane] = std::move(current);
                }
                continue;
            }
            if (current.status != PasswordTestStatus::WrongPassword)
            {
                current.matched_index = static_cast<int>(index);
                auto old = earliest.load(std::memory_order_relaxed);
                while (index < old && !earliest.compare_exchange_weak(old, index, std::memory_order_relaxed)) {}
                outcomes[lane] = std::move(current);
                break;
            }
            proofs[index] = CandidateProof::Rejected;
          }
        });
        PasswordTestResult last;
        if (native_job_cancelled()) {
            last.status = PasswordTestStatus::Error;
            last.message = "password probe cancelled";
            return last;
        }
        for (auto& outcome : outcomes) {
            if (!outcome || static_cast<std::size_t>(outcome->matched_index) != earliest.load()) continue;
            if (outcome->status == PasswordTestStatus::Ok) {
                outcome->matched_index = static_cast<int>(global_index(outcome->matched_index));
                return std::move(*outcome);
            }
            last = std::move(*outcome);
            break;
        }
        const auto stop = earliest.load();
        if (last.matched_index == -1) {
            for (auto& outcome : unresolved)
                if (outcome && (last.matched_index == -1 || outcome->matched_index < last.matched_index))
                    last = std::move(*outcome);
        }
        bool weak_match = false;
        for (std::size_t i = 0; i < count; ++i) {
            if (proofs[i] == CandidateProof::Rejected) continue;
            if (i < stop && proofs[i] == CandidateProof::Untested) continue;
            weak_match |= proofs[i] == CandidateProof::Weak;
            last.possible_candidates.push_back(global_index(i));
        }
        if (stop == 0 && last.possible_candidates.size() == count && !weak_match)
            last.possible_candidates.clear();
        if (!last.possible_candidates.empty()) {
            last.encrypted |= weak_match;
            last.weak_match = weak_match;
            if (last.matched_index < 0) last.status = PasswordTestStatus::Unsupported;
            last.matched_index = -1;
            return last;
        }
        if (last.matched_index >= 0) {
            last.matched_index = -1;
            return last;
        }
        last.status = PasswordTestStatus::WrongPassword;
        last.rejects_fixed_geometry = volumes.independent();
        last.encrypted = true;
        last.matched_index = -1;
        last.message = "wrong password";
        return last;
#else
        PasswordTestResult result;
        result.status = PasswordTestStatus::BackendUnavailable;
        result.message = "native password testing is only implemented on Windows";
        return result;
#endif
    }

} // namespace sunpack::sevenzip
