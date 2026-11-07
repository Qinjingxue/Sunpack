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
    std::vector<std::size_t> choices;
};
struct VolumeAttemptPlan {
    unsigned long long head_size_from_total = 0;
    unsigned long long minimum_size = 0;
    std::vector<ExtractInputRange> sources;
    std::vector<std::vector<VolumeAttemptSlot>> layouts;
};

// Iterative DFS keeps only one injective composition. No product, attempt
// limit, recursion stack or archive/decoder object survives a retry.
struct VolumeAttemptCursor {
    std::size_t layout = 0, attempts = 0;
    std::vector<std::size_t> digits, selected;
    bool started = false, discard_pending = false, output_owned = false;
    void reserve(const VolumeAttemptPlan& plan) {
        std::size_t maximum = 0;
        for (const auto& slots : plan.layouts) maximum = (std::max)(maximum, slots.size());
        digits.reserve(maximum); selected.reserve(maximum);
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
                ++digits[depth];
            }
            for (;;) {
                if (cancel && cancel->load(std::memory_order_relaxed)) return false;
                if (digits[depth] == slots[depth].choices.size()) {
                    digits[depth] = 0;
                    if (depth == 0) break;
                    ++digits[--depth];
                    continue;
                }
                const auto source = slots[depth].choices[digits[depth]];
                if (std::find(selected.begin(), selected.begin() + depth, source) != selected.begin() + depth) {
                    ++digits[depth]; continue;
                }
                selected[depth] = source;
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
                            std::find(previous[i].choices.begin(), previous[i].choices.end(), selected[i]) == previous[i].choices.end()) {
                            duplicate = false; break;
                        }
                }
                if (!duplicate) { ++attempts; return true; }
                --depth; ++digits[depth];
            }
            ++layout; digits.clear(); selected.clear();
        }
        return false;
    }
};
}
