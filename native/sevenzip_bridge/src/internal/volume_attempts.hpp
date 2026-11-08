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
    std::vector<unsigned long long> domain_capacity;
    bool insufficient_sources = false;

    // The plan is immutable after parsing. Summarize domains once, then merge
    // by ordinal AND slot number across layouts (paths alone lose slice identity).
    void prepare() {
        // Injectivity forbids using a source twice. Even counting unused or
        // overlapping ranges is a safe upper bound; unknown ends suffice.
        auto needed = minimum_size;
        for (const auto& source : sources) {
            if (!needed) break;
            needed = source.has_end ? needed - (std::min)(needed, source.end - source.start) : 0;
        }
        insufficient_sources = needed != 0;
        std::vector<VolumeSlotVariation> summaries;
        summaries.reserve(domains.size());
        domain_capacity.clear();
        if (minimum_size) domain_capacity.reserve(domains.size());
        for (const auto& choices : domains) {
            VolumeSlotVariation info;
            const auto& first = sources[choices.front()];
            info.length = first.has_end ? first.end - first.start : 0;
            info.variable = choices.size() != 1;
            unsigned long long capacity = 0;
            for (auto choice : choices) {
                const auto& range = sources[choice];
                info.variable_length |= !range.has_end || range.end - range.start != info.length;
                capacity = (std::max)(capacity, range.has_end
                    ? (std::min)(minimum_size, range.end - range.start) : minimum_size);
            }
            if (minimum_size) domain_capacity.push_back(capacity);
            summaries.push_back(info);
        }
        const auto [shortest, longest] = std::minmax_element(layouts.begin(), layouts.end(),
            [](const auto& a, const auto& b) { return a.size() < b.size(); });
        variation.clear();
        if (longest == layouts.end()) return;
        variation.reserve(longest->size());
        for (const auto& slot : *longest) variation.push_back(summaries[slot.domain]);
        for (const auto& slots : layouts) for (std::size_t i = 0; i < slots.size(); ++i) {
            const auto& reference = (*longest)[i];
            const auto& info = summaries[slots[i].domain];
            auto& merged = variation[i];
            const bool different_slot = reference.number != slots[i].number;
            merged.variable |= info.variable || different_slot ||
                domains[reference.domain].front() != domains[slots[i].domain].front();
            merged.variable_length |= info.variable_length || different_slot || merged.length != info.length;
        }
        for (std::size_t i = shortest->size(); i < variation.size(); ++i) {
            variation[i].variable = variation[i].variable_length = true;
        }
        if (!variation.empty() && (head_size_from_total || !tail_totals.empty()))
            variation.front().variable = variation.front().variable_length = true;
    }
};

// Iterative DFS keeps only one injective composition. No product, attempt
// limit, recursion stack or archive/decoder object survives a retry.
struct VolumeAttemptCursor {
    std::size_t layout = 0, attempts = 0;
    std::vector<std::size_t> digits, selected;
    std::vector<unsigned char> used;
    std::vector<unsigned long long> remaining, suffix_capacity;
    std::vector<std::size_t> domain_remaining, shared_domains;
    bool started = false, discard_pending = false;
    void reserve(const VolumeAttemptPlan& plan) {
        const auto maximum = plan.variation.size();
        digits.reserve(maximum); selected.reserve(maximum);
        if (plan.minimum_size) { remaining.reserve(maximum + 1); suffix_capacity.reserve(maximum + 1); }
        used.assign(plan.sources.size(), 0);
        domain_remaining.resize(plan.domains.size());
    }
    // Necessary injectivity condition for each repeated domain, not a general
    // matching solver. Count only until enough unused choices are found.
    bool shared_domains_fit(const VolumeAttemptPlan& plan, std::size_t depth, std::size_t selected_domain) const {
        for (auto domain : shared_domains) {
            // Consuming a source in the slot's own domain also satisfies one
            // of its demands; only the other domains can lose capacity.
            if (domain == selected_domain) continue;
            auto needed = domain_remaining[domain];
            const auto& choices = plan.domains[domain];
            if (!needed) continue;
            if (needed > choices.size()) return false;
            // At most depth choices can have been consumed by the prefix.
            if (depth <= choices.size() - needed) continue;
            for (auto source : choices)
                if (!used[source] && --needed == 0) break;
            if (needed) return false;
        }
        return true;
    }
    void unselect(const std::vector<VolumeAttemptSlot>& slots, std::size_t depth) {
        used[selected[depth]] = 0;
        ++domain_remaining[slots[depth].domain];
    }
    void skip_layout() {
        for (auto source : selected) used[source] = 0;
        ++layout;
        digits.clear();
        selected.clear();
    }
    bool next(const VolumeAttemptPlan& plan, const std::atomic<bool>* cancel = nullptr) {
        if (plan.insufficient_sources) return false;
        while (layout < plan.layouts.size()) {
            const auto& slots = plan.layouts[layout];
            std::size_t depth = 0;
            if (digits.empty()) {
                // Only domains referenced by this layout can be read below.
                for (const auto& slot : slots) domain_remaining[slot.domain] = 0;
                shared_domains.clear();
                for (const auto& slot : slots)
                    if (++domain_remaining[slot.domain] == 2) shared_domains.push_back(slot.domain);
                if (!shared_domains_fit(plan, 0, plan.domains.size())) { ++layout; continue; }
                if (plan.minimum_size) {
                    suffix_capacity.assign(slots.size() + 1, 0);
                    for (std::size_t i = slots.size(); i-- > 0;)
                        suffix_capacity[i] = suffix_capacity[i + 1] + (std::min)(
                            plan.minimum_size - suffix_capacity[i + 1], plan.domain_capacity[slots[i].domain]);
                    // Even the largest independent choices cannot supply the
                    // declared bytes. Discard the whole subtree without I/O.
                    if (suffix_capacity[0] < plan.minimum_size) { ++layout; continue; }
                    remaining.assign(slots.size() + 1, 0);
                    remaining[0] = plan.minimum_size;
                }
                digits.assign(slots.size(), 0);
                selected.assign(slots.size(), plan.sources.size());
            } else {
                depth = slots.size() - 1;
                unselect(slots, depth);
                ++digits[depth];
            }
            for (;;) {
                if (cancel && cancel->load(std::memory_order_relaxed)) return false;
                const auto& choices = plan.domains[slots[depth].domain];
                if (digits[depth] == choices.size()) {
                    digits[depth] = 0;
                    if (depth == 0) break;
                    --depth;
                    unselect(slots, depth);
                    ++digits[depth];
                    continue;
                }
                const auto source = choices[digits[depth]];
                if (used[source]) {
                    ++digits[depth]; continue;
                }
                if (plan.minimum_size) {
                    const auto& range = plan.sources[source];
                    remaining[depth + 1] = range.has_end
                        ? remaining[depth] - (std::min)(remaining[depth], range.end - range.start) : 0;
                    if (remaining[depth + 1] > suffix_capacity[depth + 1]) {
                        ++digits[depth]; continue;
                    }
                }
                selected[depth] = source;
                used[source] = 1;
                --domain_remaining[slots[depth].domain];
                if (!shared_domains_fit(plan, depth + 1, slots[depth].domain)) {
                    unselect(slots, depth); ++digits[depth]; continue;
                }
                if (++depth != slots.size()) { digits[depth] = 0; continue; }
                // Overlapping evidence tiers can denote the same composition.
                // Membership in an earlier layout avoids an ever-growing seen set.
                bool duplicate = false;
                for (std::size_t old = 0; old < layout && !duplicate; ++old) {
                    const auto& previous = plan.layouts[old];
                    if (previous.size() != slots.size()) continue;
                    duplicate = true;
                    for (std::size_t i = 0; i < slots.size(); ++i)
                        if (previous[i].number != slots[i].number || previous[i].name != slots[i].name) {
                            duplicate = false; break;
                        }
                        else if (previous[i].domain != slots[i].domain) {
                            const auto& domain = plan.domains[previous[i].domain];
                            if (std::find(domain.begin(), domain.end(), selected[i]) == domain.end()) {
                                duplicate = false; break;
                            }
                        }
                }
                if (!duplicate) { ++attempts; return true; }
                --depth; unselect(slots, depth); ++digits[depth];
            }
            ++layout; digits.clear(); selected.clear();
        }
        return false;
    }
};
}
