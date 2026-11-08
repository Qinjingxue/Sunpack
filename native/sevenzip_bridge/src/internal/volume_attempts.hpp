#pragma once
#include <algorithm>
#include <atomic>
#include <cstddef>
#include <string>
#include <vector>
#include "sevenzip_bridge/bridge.hpp"

namespace sunpack::sevenzip {
struct VolumeAttemptSlot {
    unsigned int number = 0;
    std::wstring name;
    std::size_t domain = 0;
};
struct VolumeSlotVariation {
    std::size_t source = 0;
    unsigned int number = 0;
    unsigned long long length = 0;
    bool variable = false, variable_length = false;
};
struct VolumeAttemptPlan {
    unsigned long long head_size_from_total = 0;
    unsigned long long minimum_size = 0;
    std::vector<ExtractInputRange> sources;
    std::vector<unsigned long long> tail_totals;
    std::vector<std::vector<std::size_t>> domains;
    std::vector<std::vector<VolumeAttemptSlot>> layouts;
    std::vector<VolumeSlotVariation> variation;

    // The plan is immutable after parsing. Summarize domains once, then merge
    // by ordinal AND slot number across layouts (paths alone lose slice identity).
    void prepare() {
        std::vector<VolumeSlotVariation> summaries;
        for (const auto& choices : domains) {
            VolumeSlotVariation info;
            info.source = choices.front();
            const auto& first = sources[info.source];
            info.length = first.has_end ? first.end - first.start : 0;
            info.variable = choices.size() != 1;
            for (auto choice : choices) {
                const auto& range = sources[choice];
                info.variable_length |= !range.has_end || range.end - range.start != info.length;
            }
            summaries.push_back(info);
        }
        std::size_t maximum = 0;
        for (const auto& slots : layouts) maximum = (std::max)(maximum, slots.size());
        variation.assign(maximum, {});
        std::vector<std::size_t> counts(maximum);
        for (const auto& slots : layouts) for (std::size_t i = 0; i < slots.size(); ++i) {
            const auto& info = summaries[slots[i].domain];
            auto& merged = variation[i];
            if (!counts[i]++) { merged = info; merged.number = slots[i].number; }
            else {
                merged.variable |= info.variable || merged.source != info.source || merged.number != slots[i].number;
                merged.variable_length |= info.variable_length || merged.length != info.length || merged.number != slots[i].number;
            }
        }
        for (std::size_t i = 0; i < maximum; ++i) {
            if (counts[i] != layouts.size() || (i == 0 && (head_size_from_total || !tail_totals.empty())))
                variation[i].variable = variation[i].variable_length = true;
        }
    }
};

// Iterative DFS keeps only one injective composition. No product, attempt
// limit, recursion stack or archive/decoder object survives a retry.
struct VolumeAttemptCursor {
    std::size_t layout = 0, attempts = 0;
    std::vector<std::size_t> digits, selected;
    std::vector<unsigned char> used;
    bool started = false, discard_pending = false, output_owned = false;
    void reserve(const VolumeAttemptPlan& plan) {
        std::size_t maximum = 0;
        for (const auto& slots : plan.layouts) maximum = (std::max)(maximum, slots.size());
        digits.reserve(maximum); selected.reserve(maximum);
        used.assign(plan.sources.size(), 0);
    }
    bool next(const VolumeAttemptPlan& plan, const std::atomic<bool>* cancel = nullptr) {
        while (layout < plan.layouts.size()) {
            const auto& slots = plan.layouts[layout];
            std::size_t depth = 0;
            if (digits.empty()) {
                digits.assign(slots.size(), 0);
                selected.assign(slots.size(), plan.sources.size());
            } else {
                depth = slots.size() - 1;
                used[selected[depth]] = 0;
                ++digits[depth];
            }
            for (;;) {
                if (cancel && cancel->load(std::memory_order_relaxed)) return false;
                const auto& choices = plan.domains[slots[depth].domain];
                if (digits[depth] == choices.size()) {
                    digits[depth] = 0;
                    if (depth == 0) break;
                    --depth;
                    used[selected[depth]] = 0;
                    ++digits[depth];
                    continue;
                }
                const auto source = choices[digits[depth]];
                if (used[source]) {
                    ++digits[depth]; continue;
                }
                selected[depth] = source;
                used[source] = 1;
                if (++depth != slots.size()) { digits[depth] = 0; continue; }
                // Overlapping evidence tiers can denote the same composition.
                // Membership in an earlier layout avoids an ever-growing seen set.
                bool duplicate = false;
                for (std::size_t old = 0; old < layout && !duplicate; ++old) {
                    const auto& previous = plan.layouts[old];
                    if (previous.size() != slots.size()) continue;
                    duplicate = true;
                    for (std::size_t i = 0; i < slots.size(); ++i)
                        if (previous[i].number != slots[i].number || previous[i].name != slots[i].name ||
                            std::find(plan.domains[previous[i].domain].begin(), plan.domains[previous[i].domain].end(), selected[i]) == plan.domains[previous[i].domain].end()) {
                            duplicate = false; break;
                        }
                }
                if (!duplicate) { ++attempts; return true; }
                --depth; used[selected[depth]] = 0; ++digits[depth];
            }
            ++layout; digits.clear(); selected.clear();
        }
        return false;
    }
};
}
