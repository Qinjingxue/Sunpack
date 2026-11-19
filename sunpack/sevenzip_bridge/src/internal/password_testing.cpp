#include "sevenzip_bridge/bridge.hpp"
#include "sevenzip_bridge/enc.h"

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

        PasswordTestResult unsupported_decoder_result(PasswordTestResult result, const OpenCallback& open)
        {
            result.status = PasswordTestStatus::Unsupported;
            result.message = "no supported decoder could confirm the password";
            result.password_independent_failure = !open.password_requested();
            return result;
        }

        PasswordTestResult damaged_member_result(PasswordTestResult result, Int32 operation)
        {
            result.status = PasswordTestStatus::Damaged;
            result.message = std::string("archive appears damaged [operation_result=") +
                             operation_result_name(operation) + "]";
            return result;
        }

        enum class MemberMode : unsigned char { Normal, Zip, SevenZip };

        struct BoundedPasswordProbeSelection
        {
            std::optional<UInt32> index;
            MemberMode member_mode = MemberMode::Normal;
            bool weak = false;
            bool measure_coverage = false;
            bool can_strengthen = false;
            bool item_count_known = false;
            UInt32 item_count = 0;
            bool encrypted = false;
        };

        constexpr std::size_t large_zip_directory_entries = 2048;

        bool may_have_large_zip_directory(const std::wstring& path) {
            // A central-directory record has at least 46 bytes. A short
            // archive can use the existing parallel path immediately.
            std::error_code error;
            const auto size = std::filesystem::file_size(win32_extended_path(path), error);
            return !error && size >= 46 * large_zip_directory_entries;
        }

        enum class MemberVolumeMatch : unsigned char { Fixed, Possible, Covered };

        struct MemberProof {
            UInt32 index;
            UInt64 cost;
            UInt64 coverage;
            bool weak;
            MemberVolumeMatch volume;
            bool auxiliary = false;
            bool operator<(const MemberProof& other) const {
                // Try optional metadata after ordinary members. A member spanning
                // an uncertain volume can answer two questions with one decode.
                if (auxiliary != other.auxiliary) return !auxiliary;
                const auto effort = volume == MemberVolumeMatch::Covered ? cost / 2 : cost;
                const auto other_effort = other.volume == MemberVolumeMatch::Covered ? other.cost / 2 : other.cost;
                if (effort != other_effort) return effort < other_effort;
                if (weak != other.weak) return !weak;
                if (weak && coverage != other.coverage) return coverage > other.coverage;
                if (volume != other.volume) return volume > other.volume;
                if (cost != other.cost) return cost < other.cost;
                return index < other.index;
            }
        };

        struct ProbeVolumeRanges {
            std::vector<UInt64> starts;
            std::vector<UInt32> variable;
            mutable std::optional<VolumeReadUncertainty> reads;
            mutable std::atomic<bool> incomplete_read{false};

            ProbeVolumeRanges(const VolumeAttemptPlan* plan, const std::vector<ExtractInputRange>& ranges,
                              const std::wstring& format) {
                if (!plan || std::none_of(plan->variation.begin(), plan->variation.end(),
                    [](const auto& slot) { return slot.variable; })) return;
                if ((format == L"7z" || format == L"zip" || format == L"rar" ||
                     format == L"rar4" || format == L"rar5") && !ranges.empty() &&
                    std::all_of(ranges.begin(), ranges.end(), [](const auto& range) { return range.has_end; }))
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
                    if (reads && plan->variation[i].variable) {
                        reads->uncertain_ranges.emplace_back(starts[i], starts[i + 1]);
                        reads->variable_slots.push_back(i);
                    }
                }
                if (reads && !reads->uncertain_ranges.empty())
                    reads->observed = std::make_unique<std::atomic<bool>[]>(reads->uncertain_ranges.size());
            }
            VolumeReadUncertainty* observer() const { return reads ? &*reads : nullptr; }
            void attach(PasswordTestResult& result, bool open_incomplete = false) const {
                // An unavailable method can be reused for the same bytes
                // and candidate domain. It never rejects a composition.
                const bool unavailable = result.status == PasswordTestStatus::Unsupported &&
                    result.password_independent_failure && result.possible_candidates.empty();
                const bool accepted = result.status == PasswordTestStatus::Ok && result.encrypted;
                // A successful member proof survives an earlier failed data
                // read. A batch-wide rejection requires every trial to be
                // complete. Incomplete directory reads affect member selection.
                if (!reads || reads->untracked_named_volume.load(std::memory_order_relaxed) ||
                    result.missing_volume || open_incomplete || native_job_cancelled() ||
                    (!accepted && (incomplete_read.load(std::memory_order_relaxed) ||
                        (!unavailable && result.status != PasswordTestStatus::WrongPassword)))) return;
                result.rejects_fixed_geometry = result.status == PasswordTestStatus::WrongPassword &&
                    !reads->uncertain_read.load(std::memory_order_relaxed);
                if (!reads->observed) return;
                auto& used = result.observed_volume_slots.emplace();
                for (std::size_t range = 0; range < reads->variable_slots.size(); ++range) {
                    if (reads->observed[range].load(std::memory_order_relaxed)) used.push_back(reads->variable_slots[range]);
                }
            }
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
            bool header_password, const ProbeVolumeRanges& volumes, bool final_read_only,
            std::vector<MemberProof>* alternatives = nullptr)
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
            // The final test will process every item. An encrypted Open already
            // establishes encryption without a separate walk of item properties.
            if (final_read_only && header_password) return selection;
            const bool zip = format == L"zip";
            const bool rar5 = format == L"rar5";
            const bool seven_zip = format == L"7z";
            if (zip) selection.member_mode = MemberMode::Zip;
            else if (seven_zip) selection.member_mode = MemberMode::SevenZip;
            PROPVARIANT archive_value;
            PropVariantInit(&archive_value);
            const bool solid = archive->GetArchiveProperty(kpidSolid, &archive_value) == S_OK && prop_bool(archive_value);
            clear_prop(archive_value);

            std::optional<MemberProof> regular, best;
            UInt32 confirmation_members = 0;
            UInt64 solid_prefix = 0;
            UInt32 last_block = UINT32_MAX;
            std::optional<UInt64> copy_start;
            std::optional<bool> folder_overlap;
            for (UInt32 index = 0; index < selection.item_count; ++index)
            {
                PROPVARIANT value{};
                const bool is_encrypted = get_item_property(archive, index, kpidEncrypted, value) && prop_bool(value);
                clear_prop(value);
                selection.encrypted |= is_encrypted;
                if (!solid && selection.encrypted && !is_encrypted) continue;
                const bool is_dir = get_item_property(archive, index, kpidIsDir, value) && prop_bool(value);
                clear_prop(value);
                if (is_dir) continue;
                // ZIP's proof properties already return the packed MAC span
                // or the unpacked CRC span. Only solid cost accumulation and
                // the ordinary fallback need a separate size in that format.
                UInt64 size = 0;
                if (solid || !zip || !is_encrypted) {
                    get_item_property(archive, index, kpidSize, value);
                    size = prop_u64(value);
                    clear_prop(value);
                }
                UInt64 cost = size;
                if (solid) {
                    if (seven_zip) {
                        if (get_item_property(archive, index, kpidBlock, value)) {
                            const auto block = prop_u32(value);
                            if (last_block != block) {
                                solid_prefix = 0;
                                copy_start.reset();
                                folder_overlap.reset();
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
                    solid_prefix += (std::min)(size, UINT64_MAX - solid_prefix);
                    cost = solid_prefix;
                }
                if (!selection.encrypted && (!regular || cost < regular->cost))
                    regular = MemberProof{index, cost, 0, false, MemberVolumeMatch::Fixed};
                if (!is_encrypted) continue;
                const bool has_mac = (zip || rar5) &&
                    get_item_property(archive, index, kpidSunpackMacPackedSize, value);
                const auto packed = has_mac ? prop_u64(value) : 0;
                // An empty RAR5 MAC with no packed member authenticates header
                // metadata alone. Rust already checks that structural proof.
                const bool authenticated = has_mac && (zip || packed != 0);
                if (authenticated) {
                    cost = zip ? packed : (std::max)(cost, packed);
                }
                clear_prop(value);
                UInt64 coverage = 0;
                if (!authenticated && get_item_property(archive, index, kpidSunpackProofSize, value))
                    coverage = prop_u64(value);
                clear_prop(value);
                if (zip && !solid && !authenticated) cost = coverage;
                // A single tiny CRC contains only 8 * size evidence bits.
                // Do not add evidence across members: different folders may
                // repeat the same encrypted bytes, IV and contents.
                if (!authenticated && !coverage) continue;
                auto volume = MemberVolumeMatch::Fixed;
                if (copy_start && coverage == size) {
                    const auto offset = solid_prefix - size;
                    const auto start = SunpackAesCopyReadStart(offset);
                    cost = size + (offset - start);
                    if (cost <= UINT64_MAX - 15) {
                        cost = (cost + 15) & ~UInt64{15};
                        if (start <= UINT64_MAX - *copy_start && volumes.intersects(*copy_start + start, cost))
                            volume = MemberVolumeMatch::Covered;
                    }
                } else if (seven_zip && solid) {
                    // The compressed solid decoder can finish at any point within this
                    // folder. Use the bound only to order probes, and observe actual reads.
                    if (!folder_overlap) folder_overlap = volumes.contains(archive, index, format);
                    if (*folder_overlap) volume = MemberVolumeMatch::Possible;
                } else if (volumes.contains(archive, index, format)) {
                    volume = MemberVolumeMatch::Covered;
                }
                const bool measured = coverage == kSunpackUnknownProofSize;
                if (measured) {
                    if (get_item_property(archive, index, kpidPackSize, value))
                        cost += (std::min)(prop_u64(value), UINT64_MAX - cost);
                    clear_prop(value);
                }
                const bool auxiliary = !final_read_only && rar5 && index + 1 == selection.item_count &&
                    get_item_property(archive, index, kpidIsAux, value) && prop_bool(value);
                clear_prop(value);
                MemberProof member{index, cost, coverage,
                    !authenticated && (measured || !strong_member_crc(coverage)), volume, auxiliary};
                confirmation_members += !member.weak || measured;
                if (!best || member < *best) best = member;
                if (alternatives) alternatives->push_back(member);
            }
            if (!selection.encrypted) {
                if (regular) selection.index = regular->index;
            } else if (best) {
                selection.index = best->index;
                selection.weak = best->weak;
                selection.measure_coverage = best->coverage == kSunpackUnknownProofSize;
                selection.can_strengthen = confirmation_members > static_cast<UInt32>(
                    !best->weak || selection.measure_coverage);
            }
            return selection;
        }

        // Each lane owns at most one reusable handler. Encrypted headers still
        // open per candidate; neither archive objects nor callbacks enter a
        // process cache or survive the batch's last confirmation.
        struct PasswordProbeCache
        {
            ExtractInputTrace input_trace;
            OpenedArchiveStream input{};
            CMyComPtr<IInArchive> archive;
            CMyComPtr<IArchiveOpenCallback> callback;
            OpenCallback *callback_state = nullptr;
            bool open_incomplete = false;
            BoundedPasswordProbeSelection selection;
            PasswordTestResult evidence;
            std::vector<MemberProof> alternatives;
            std::optional<std::size_t> alternatives_heap;

            static constexpr auto cheaper_last = [](const MemberProof& a, const MemberProof& b) { return b < a; };

            void clear_alternatives()
            {
                alternatives.clear();
                alternatives_heap.reset();
            }

            void order_alternatives()
            {
                std::make_heap(alternatives.begin(), alternatives.end(), cheaper_last);
                alternatives_heap = alternatives.size();
            }

            const MemberProof& alternative_at(std::size_t order)
            {
                // Keep the already tried order at the end of the heap for
                // other candidates. Only sort as far as the proof needs.
                const auto index = alternatives.size() - order - 1;
                if (index < *alternatives_heap) {
                    std::pop_heap(alternatives.begin(), alternatives.begin() + *alternatives_heap, cheaper_last);
                    --*alternatives_heap;
                }
                return alternatives[index];
            }

            void remember(IInArchive* input, IArchiveOpenCallback* open, OpenCallback* state,
                          BoundedPasswordProbeSelection selected, const PasswordTestResult& result)
            {
                archive = input;
                callback = open;
                callback_state = state;
                selection = selected;
                evidence = result;
            }

            void reset()
            {
                if (archive) archive->Close();
                archive.Release();
                callback.Release();
                callback_state = nullptr;
                open_incomplete = false;
                clear_alternatives();
            }
            ~PasswordProbeCache() { reset(); }
        };

        HRESULT probe_read_error(const OpenCallback& open, const ExtractInputTrace& trace, HRESULT operation) {
            auto error = open.input_error();
            if (!FAILED(error)) error = static_cast<HRESULT>(trace.read_hresult);
            if (!FAILED(error) && open.volume_open_failed()) return FAILED(operation) ? operation : E_FAIL;
            return error;
        }

        std::optional<std::pair<UInt32, UInt64>> next_copy_crc(IInArchive* archive, UInt32 index, UInt32 count)
        {
            PROPVARIANT value{};
            if (index + 1 >= count || !get_item_property(archive, index, kpidBlock, value)) return {};
            const auto folder = prop_u32(value);
            clear_prop(value);
            if (!get_item_property(archive, index, kpidSunpackAesCopyStart, value) || value.vt != VT_UI8) {
                clear_prop(value);
                return {};
            }
            clear_prop(value);
            // Streamless items within this folder share its block index but
            // cannot contribute any plaintext checksum evidence.
            for (++index; index < count; ++index) {
                const bool same_folder = get_item_property(archive, index, kpidBlock, value) &&
                    value.vt == VT_UI4 && prop_u32(value) == folder;
                clear_prop(value);
                if (!same_folder) break;
                const auto coverage = get_item_property(archive, index, kpidSunpackProofSize, value) ? prop_u64(value) : 0;
                clear_prop(value);
                if (coverage && coverage <= sizeof(UInt32)) return std::pair{index, coverage};
            }
            return {};
        }

        void probe_opened_archive(
            IInArchive *archive, BoundedPasswordProbeSelection &selection,
            const std::wstring &password, bool &encryption_evidence, bool final_read_only,
            HRESULT &hr, Int32 &operation)
        {
            const auto measure_item = !final_read_only && selection.measure_coverage ? selection.index : std::nullopt;
            auto *raw_callback = new ExtractCallback(password, measure_item);
            CMyComPtr<IArchiveExtractCallback> callback(raw_callback);
            hr = S_OK;
            if (final_read_only) {
                // The final read-only pass covers every member. A preceding
                // bounded proof has already removed its rejected passwords.
                hr = archive->Extract(nullptr, kAllItems, kTestMode, callback);
            } else if (selection.index) {
                const auto mode = selection.member_mode == MemberMode::Normal ? kTestMode : kSunpackVerifyMember;
                hr = archive->Extract(&*selection.index, 1, mode, callback);
            }
            operation = raw_callback->operation_result();
            if (measure_item && hr == S_OK && operation == kOpOk) {
                const auto coverage = raw_callback->measured_size();
                if (!coverage) operation = kOpUnavailable;
                selection.weak = !strong_member_crc(coverage);
            }
            encryption_evidence = encryption_evidence || raw_callback->password_requested();
        }

        void probe_available_member(
            IInArchive* archive, BoundedPasswordProbeSelection& selection, OpenCallback& open,
            PasswordProbeCache& cache, const std::wstring& format, const ProbeVolumeRanges& volumes,
            const std::wstring& password, bool& encrypted, bool final_read_only,
            HRESULT& hr, Int32& operation)
        {
            HRESULT read_error = S_OK;
            const auto probe = [&] {
                cache.input_trace.read_hresult = 0;
                open.clear_input_error();
                probe_opened_archive(archive, selection, password, encrypted, final_read_only, hr, operation);
                read_error = probe_read_error(open, cache.input_trace, hr);
                if (FAILED(read_error)) {
                    volumes.incomplete_read.store(true, std::memory_order_relaxed);
                    hr = read_error;
                }
            };
            const auto interrupted = [&] {
                return native_job_cancelled() || hr == E_ABORT || hr == E_OUTOFMEMORY;
            };
            const auto accepted = [&] { return hr == S_OK && operation == kOpOk; };
            const auto can_try_another = [&] {
                // ZIP can report a damaged local header for just this member.
                return FAILED(read_error) || hr == E_NOTIMPL ||
                    (hr == S_OK && (operation == kOpUnsupportedMethod ||
                        operation == kOpUnavailable || operation == kOpUnexpectedEnd ||
                        (operation == kOpHeadersError && format == L"zip")));
            };
            probe();
            if (final_read_only || !selection.index || selection.item_count <= 1 || interrupted()) return;

            const auto first = selection;
            std::optional<BoundedPasswordProbeSelection> weak_match;
            std::optional<UInt32> copy_checked;
            const auto retain_weak = [&](std::size_t tried) {
                if (weak_match || !accepted() || !selection.weak) return;
                weak_match = selection;
                if (selection.member_mode != MemberMode::SevenZip) return;
                // The companion shares this AES/Copy folder's key and can
                // contribute a rejection without decoding its solid prefix.
                const auto companion = next_copy_crc(archive, *selection.index, selection.item_count);
                if (!companion || companion->first == *first.index ||
                    std::any_of(cache.alternatives.end() - tried, cache.alternatives.end(),
                        [&](const auto& member) { return member.index == companion->first; })) return;
                copy_checked = companion->first;
                selection.index = *copy_checked;
                selection.weak = !strong_member_crc(companion->second);
                probe();
                if (interrupted() || (accepted() && !selection.weak) ||
                    (hr == S_OK && (operation == kOpWrongPassword || operation == kOpCrcError))) {
                    weak_match.reset();
                    return;
                }
                selection = *weak_match;
                hr = S_OK;
                operation = kOpOk;
                read_error = S_OK;
            };
            retain_weak(0);
            if (interrupted() || (weak_match ? !first.can_strengthen : !can_try_another())) return;
            if (!cache.alternatives_heap) {
                bounded_password_probe_selection(archive, format, open.password_requested(), volumes, false, &cache.alternatives);
                cache.order_alternatives();
            }
            auto failure = selection;
            auto failure_hr = hr;
            auto failure_op = operation;
            for (std::size_t order = 0; order < cache.alternatives.size(); ++order) {
                const auto& member = cache.alternative_at(order);
                if (member.index == *first.index || member.index == copy_checked ||
                    (weak_match && member.weak && member.coverage != kSunpackUnknownProofSize)) continue;
                selection.index = member.index;
                selection.weak = member.weak;
                selection.measure_coverage = member.coverage == kSunpackUnknownProofSize;
                probe();
                if (interrupted() || (accepted() && !selection.weak)) return;
                retain_weak(order + 1);
                if (interrupted() || (!weak_match && !can_try_another())) return;
                // Other members may use a different password. Keep an
                // observed weak match when no stronger proof succeeds.
                if (weak_match) continue;
                if ((FAILED(read_error) && (failure_hr == E_NOTIMPL || !FAILED(failure_hr))) ||
                    (hr == S_OK && operation == kOpUnexpectedEnd && (failure_hr == E_NOTIMPL ||
                        (failure_hr == S_OK && failure_op == kOpUnsupportedMethod)))) {
                    failure = selection;
                    failure_hr = hr;
                    failure_op = operation;
                }
            }
            selection = weak_match.value_or(failure);
            hr = weak_match ? S_OK : failure_hr;
            operation = weak_match ? kOpOk : failure_op;
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
        bool scan_only, bool final_read_only, const ProbeVolumeRanges& volumes,
        bool* defer_small_zip = nullptr

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
            auto selection = cache.selection;
            probe_available_member(cache.archive, selection, *cache.callback_state, cache, result.archive_type, volumes,
                password, encrypted, final_read_only, hr, operation);
            result.operation_result = operation;
            result.missing_volume = cache.callback_state->missing_volume_requested();
            if (cache.callback_state->missing_volume_requested() && (hr != S_OK || operation != kOpOk) &&
                !((result.archive_type == L"rar4" || result.archive_type == L"rar5") &&
                  selection.index && looks_wrong_password(hr, operation, encrypted)))
                return needs_volume_or_tail_damaged_result("probe_volume_callback_not_found", cache.callback_state->missing_volume_name(),
                    cache.callback_state->password_requested());
            if (FAILED(hr) && hr != E_NOTIMPL) {
                result.status = PasswordTestStatus::Error;
                result.message = "password probe could not read or decode the selected member";
                result.password_independent_failure = hr == E_ABORT || hr == E_OUTOFMEMORY;
                cache.reset();
                cache.input.stream.Release();
                return result;
            }
            if (hr == E_NOTIMPL || operation == kOpUnsupportedMethod) {
                return unsupported_decoder_result(std::move(result), *cache.callback_state);
            }
            if (!cache.callback_state->password_requested())
            {
                if (hr == S_OK && operation == kOpOk)
                {
                    result.status = PasswordTestStatus::Ok;
                    result.message = "password accepted";
                    result.weak_match = selection.weak && !final_read_only;
                    return result;
                }
                if (looks_wrong_password(hr, operation, encrypted))
                {
                    result.status = PasswordTestStatus::WrongPassword;
                    result.encrypted = true;
                    result.message = "wrong password";
                    return result;
                }
                if (looks_damaged(operation))
                    return damaged_member_result(std::move(result), operation);
            }
            // An inconclusive handler result keeps the original fallback path.
            cache.reset();
        }

        PasswordTestResult result;
        result.archive_type = format_hint;

        bool any_format_created = false;

        bool any_opened = false;

        HRESULT last_open_hr = E_FAIL;
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
                continue;
            }

            any_format_created = true;

            cache.input_trace.read_hresult = 0;
            auto& input = cache.input;
            // A lane always probes the same logical input. Only its handler
            // and password change as it tries keys or alternate formats.
            if (!input.stream || input.stream->Seek(0, STREAM_SEEK_SET, nullptr) != S_OK) {
                input = open_archive_stream(archive_path, part_paths, &cache.input_trace,
                    canonical_names, InputPrefetchConfig{false}, input_ranges, volumes.observer());
            }

            if (!input.opened)
            {
                input.stream.Release();

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
                result.password_independent_failure = true;

                result.message = "archive file could not be opened";

                return result;
            }

            auto *raw_open_callback = new OpenCallback(password, input.callback_path, part_paths, canonical_names,
                InputPrefetchConfig{false}, native_job_cancel_token(), input_ranges, volumes.observer(), !final_read_only);
            CMyComPtr<IArchiveOpenCallback> open_callback(raw_open_callback);

            hr = archive->Open(input.stream.Interface(), search_limit, open_callback.Interface());
            cache.open_incomplete = FAILED(probe_read_error(*raw_open_callback, cache.input_trace, hr));
            if (cache.open_incomplete) volumes.incomplete_read.store(true, std::memory_order_relaxed);
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

            if (hr != S_OK && cache.open_incomplete)
            {
                input.stream.Release();
                result.status = PasswordTestStatus::Error;
                result.message = "archive split volume could not be opened";
                result.password_independent_failure = !raw_open_callback->password_requested();
                return result;
            }

            if (hr != S_OK)
            {

                last_open_hr = hr;

                continue;
            }

            any_opened = true;
            cache.clear_alternatives();
            result.archive_type = canonical_archive_type_for_guid(format);
            auto selection = bounded_password_probe_selection(archive, result.archive_type,
                raw_open_callback->password_requested(), volumes, final_read_only);
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
            if (defer_small_zip && selection.item_count < large_zip_directory_entries && !raw_open_callback->password_requested() &&
                !result.missing_volume) {
                cache.remember(archive.Interface(), open_callback.Interface(), raw_open_callback, selection, result);
                *defer_small_zip = true;
                return result;
            }
            Int32 last_op_res = kOpOk;
            const auto initial_selection = selection;
            probe_available_member(archive, selection, *raw_open_callback, cache, result.archive_type, volumes,
                password, last_encryption_evidence, final_read_only, hr, last_op_res);
            result.operation_result = last_op_res;
            result.missing_volume = raw_open_callback->missing_volume_requested();
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
            if (FAILED(hr) && hr != E_NOTIMPL) {
                archive->Close();
                input.stream.Release();
                result.status = PasswordTestStatus::Error;
                result.message = "password probe could not read or decode the selected member";
                result.password_independent_failure = hr == E_ABORT || hr == E_OUTOFMEMORY;
                return result;
            }
            if (hr == E_NOTIMPL || last_op_res == kOpUnsupportedMethod) {
                archive->Close();
                return unsupported_decoder_result(std::move(result), *raw_open_callback);
            }
            const bool weak_match = selection.weak && !final_read_only;
            if (!raw_open_callback->password_requested() &&
                (looks_wrong_password(hr, last_op_res, last_encryption_evidence) ||
                 (weak_match && hr == S_OK && last_op_res == kOpOk)))
            {
                cache.remember(archive.Interface(), open_callback.Interface(), raw_open_callback, initial_selection, result);
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

                return result;
            }

            if (looks_damaged(last_op_res))
                return damaged_member_result(std::move(result), last_op_res);
        }

        if (!any_format_created)
        {

            result.status = PasswordTestStatus::Unsupported;
            result.password_independent_failure = true;

            result.message = "the embedded 7-Zip backend did not create a supported archive handler";
        }
        else if (!any_opened)
        {
            // A bounded probe needs member evidence. Open's failure can
            // also reflect unavailable or damaged directory data.
            const bool wrong = final_read_only && looks_wrong_password(last_open_hr, kOpOk, last_encryption_evidence);
            result.status = wrong ? PasswordTestStatus::WrongPassword : PasswordTestStatus::Unsupported;
            result.encrypted = last_encryption_evidence;
            result.message = wrong ? "wrong password" : "archive could not be opened by supported handlers";
            result.password_independent_failure = !last_encryption_evidence;
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
        bool scan_only, bool final_read_only, const std::size_t* candidate_indices,
        const VolumeAttemptPlan* volume_plan, bool leave_last_candidate)
    {
#ifdef _WIN32
        const auto formats = extraction_formats_for_hint(format_hint);
        const bool enc = formats.handlers.size() == 1 && formats.handlers.front().Data4[5] == kEncFormatId;
        if (enc && !final_read_only) {
            // Open would run the same quick-block proof as Rust. The ENC
            // handler has no additional bounded member proof.
            PasswordTestResult result;
            result.status = PasswordTestStatus::Unsupported;
            result.archive_type = L"enc";
            result.encrypted = true;
            result.password_independent_failure = true;
            result.message = "ENC has no independent bounded member proof";
            return result;
        }
        const auto count = (std::max)(candidate_count, std::size_t{1});
        const auto global_index = [candidate_indices](std::size_t index) {
            return candidate_indices ? candidate_indices[index] : index;
        };
        const auto probe_end = leave_last_candidate && candidate_count && !scan_only && !final_read_only
            ? count - 1 : count;
        if (!probe_end) {
            PasswordTestResult result;
            result.status = PasswordTestStatus::Unsupported;
            result.possible_candidates.push_back(global_index(0));
            return result;
        }
        const ProbeVolumeRanges volumes(volume_plan, input_ranges, format_hint);
        const std::wstring empty;
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
            volumes.attach(result, cache.open_incomplete);
            return result;
        }
        // A prioritized ZIP password often already has a structural match.
        // Give it the first decode before other lanes duplicate the archive's
        // directory. Keep the same lane and handler when more keys are needed.
        const bool prioritized = !volume_plan && !final_read_only && format_hint == L"zip" && count >= 8 &&
            part_paths.empty() && input_ranges.empty() && may_have_large_zip_directory(archive_path);
        PasswordProbeCache primary_cache;
        std::optional<PasswordTestResult> first;
        bool deferred = false;
        if (prioritized) {
            ExtractionReplayScope replay(nullptr);
            first = test_one_password(archive_path, candidates[global_index(0)],
                part_paths, formats, input_ranges, canonical_names, format_hint, primary_cache,
                scan_only, final_read_only, volumes, &deferred);
            if (deferred) first.reset();
            if (first && first->status == PasswordTestStatus::Ok && !first->weak_match && !native_job_cancelled()) {
                first->matched_index = static_cast<int>(global_index(0));
                volumes.attach(*first, primary_cache.open_incomplete);
                return std::move(*first);
            }
        }
        auto lanes = probe_end - std::size_t{!deferred && prioritized};
        const auto& selected = primary_cache.selection;
        if (primary_cache.archive && !selected.measure_coverage &&
            selected.item_count >= large_zip_directory_entries && selected.index) {
            // Every lane parses the whole directory. Amortize that cost for
            // tiny proofs while allowing expensive KDF batches to scale.
            PROPVARIANT packed{};
            if (get_item_property(primary_cache.archive, *selected.index, kpidPackSize, packed) &&
                prop_u64(packed) <= 256) {
                PROPVARIANT coverage{};
                const bool mac = get_item_property(primary_cache.archive, *selected.index, kpidSunpackMacPackedSize, coverage);
                const bool tiny_crc = !mac && get_item_property(primary_cache.archive, *selected.index, kpidSunpackProofSize, coverage) &&
                    prop_u64(coverage) <= 256;
                clear_prop(coverage);
                if (mac || tiny_crc) {
                    const auto needed = mac ? lanes / (selected.item_count / 64) : 0;
                    lanes = (std::min)(lanes, (std::max)(std::size_t{4}, needed));
                }
            }
            clear_prop(packed);
        }
        PasswordParallelism parallel(lanes);
        std::atomic<std::size_t> next{std::size_t{prioritized}}, earliest{count};
        struct BatchOutcome {
            std::optional<PasswordTestResult> result;
            bool open_incomplete = false;
        };
        std::vector<BatchOutcome> outcomes(parallel.size());
        std::vector<std::optional<PasswordTestResult>> unresolved(parallel.size());
        enum class CandidateProof : unsigned char { Untested, Rejected, Unresolved, Weak };
        std::vector<CandidateProof> proofs(count, CandidateProof::Untested);
        const auto record = [&](std::size_t lane, std::size_t index, PasswordTestResult current, bool open_incomplete) {
            if (current.weak_match && !final_read_only) {
                proofs[index] = CandidateProof::Weak;
                return false;
            }
            if (!current.password_independent_failure &&
                (current.status == PasswordTestStatus::Unsupported || current.status == PasswordTestStatus::NeedsVolumeOrTailDamaged ||
                 current.status == PasswordTestStatus::Damaged || current.status == PasswordTestStatus::Error)) {
                // Decrypting another header can expose a different usable
                // member. Preserve this candidate and continue the method.
                proofs[index] = CandidateProof::Unresolved;
                if (!unresolved[lane]) {
                    current.matched_index = static_cast<int>(index);
                    unresolved[lane] = std::move(current);
                }
                return false;
            }
            if (current.status != PasswordTestStatus::WrongPassword)
            {
                current.matched_index = static_cast<int>(index);
                auto old = earliest.load(std::memory_order_relaxed);
                while (index < old && !earliest.compare_exchange_weak(old, index, std::memory_order_relaxed)) {}
                outcomes[lane] = {std::move(current), open_incomplete};
                return true;
            }
            proofs[index] = CandidateProof::Rejected;
            return false;
        };
        if (first && !native_job_cancelled()) record(0, 0, std::move(*first), primary_cache.open_incomplete);
        if (earliest.load(std::memory_order_relaxed) != 0) parallel.run(parallel.size(), [&](std::size_t lane, std::size_t) {
          PasswordProbeCache extra_cache;
          auto& cache = lane == 0 ? primary_cache : extra_cache;
          bool use_deferred = lane == 0 && deferred;
          for (;;) {
            const auto index = std::exchange(use_deferred, false) ? 0 : next.fetch_add(1, std::memory_order_relaxed);
            if (index >= probe_end || index >= earliest.load(std::memory_order_relaxed) || native_job_cancelled()) break;
            auto current = test_one_password(archive_path, candidates[global_index(index)],
                part_paths, formats, input_ranges, canonical_names, format_hint, cache, scan_only, final_read_only, volumes);
            if (native_job_cancelled() || record(lane, index, std::move(current), cache.open_incomplete)) break;
          }
        });
        if (probe_end < count && earliest.load(std::memory_order_relaxed) == count && !native_job_cancelled()) {
            // The caller already has the only viable volume composition.
            // If every earlier key was disproved, extraction can confirm
            // the final candidate without decoding a member twice.
            if (std::all_of(proofs.begin(), proofs.begin() + probe_end,
                    [](auto proof) { return proof == CandidateProof::Rejected; })) {
                proofs.back() = CandidateProof::Unresolved;
            } else {
                parallel.limit(1);
                ExtractionReplayScope replay(nullptr);
                auto current = test_one_password(archive_path, candidates[global_index(probe_end)],
                    part_paths, formats, input_ranges, canonical_names, format_hint, primary_cache,
                    scan_only, final_read_only, volumes);
                record(0, probe_end, std::move(current), primary_cache.open_incomplete);
            }
        }
        PasswordTestResult last;
        if (native_job_cancelled()) {
            last.status = PasswordTestStatus::Error;
            last.message = "password probe cancelled";
            return last;
        }
        for (auto& [outcome, open_incomplete] : outcomes) {
            if (!outcome || static_cast<std::size_t>(outcome->matched_index) != earliest.load()) continue;
            if (outcome->status == PasswordTestStatus::Ok) {
                outcome->matched_index = static_cast<int>(global_index(outcome->matched_index));
                volumes.attach(*outcome, open_incomplete);
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
            volumes.attach(last);
            return last;
        }
        last.status = PasswordTestStatus::WrongPassword;
        volumes.attach(last);
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
