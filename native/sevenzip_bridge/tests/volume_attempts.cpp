// Exhaustive small-plan oracle catches lost/reordered compositions after
// pruning, backtracking and layout deduplication. Real extraction tests cannot
// enumerate these interactions; one bounded native test covers them together.
#include "internal/volume_attempts.hpp"
#include <iostream>
#include <limits>
#include <random>
#include <set>
#include <tuple>

using namespace sunpack::sevenzip;
using Composition = std::pair<std::size_t, std::vector<std::size_t>>;
using Key = std::vector<std::tuple<unsigned int, std::wstring, std::size_t>>;

static std::vector<Composition> reference(const VolumeAttemptPlan& plan) {
    std::vector<Composition> result;
    std::set<Key> seen;
    for (std::size_t layout = 0; layout < plan.layouts.size(); ++layout) {
        const auto& maximum = plan.layouts[layout];
        const auto minimum = plan.minimum_slots.empty() || !plan.minimum_slots[layout]
            ? maximum.size() : plan.minimum_slots[layout];
        // Expand tiny reference families explicitly, independently of the
        // production cursor's prefix/domain projection.
        for (auto count = maximum.size(); count >= minimum; --count) {
        auto slots = maximum;
        slots.resize(count);
        slots.back().domain = maximum.back().domain;
        std::vector<std::size_t> selected;
        auto visit = [&](auto&& self, unsigned long long needed) -> void {
            if (selected.size() == slots.size()) {
                if (needed) return;
                Key key;
                for (std::size_t i = 0; i < slots.size(); ++i)
                    key.emplace_back(slots[i].number, slots[i].name, selected[i]);
                if (seen.insert(key).second) result.emplace_back(layout, selected);
                return;
            }
            for (auto source : plan.domains[slots[selected.size()].domain]) {
                if (std::find(selected.begin(), selected.end(), source) != selected.end()) continue;
                selected.push_back(source);
                const auto& range = plan.sources[source];
                self(self, range.has_end ? needed - (std::min)(needed, range.end - range.start) : 0);
                selected.pop_back();
            }
        };
        visit(visit, plan.minimum_size);
        }
    }
    return result;
}

static bool compare(VolumeAttemptPlan plan) {
    const auto expected = reference(plan);
    plan.prepare();
    VolumeAttemptCursor cursor;
    cursor.reserve(plan);
    std::size_t index = 0;
    while (cursor.next(plan)) {
        if (index == expected.size() || expected[index++] != Composition(cursor.layout, cursor.selected)) return false;
    }
    return index == expected.size() && cursor.attempts == index;
}

static VolumeAttemptSlot slot(std::size_t ordinal, std::size_t domain) {
    return {static_cast<unsigned int>(ordinal + 1), L"part" + std::to_wstring(ordinal), domain};
}

int main() {
    // A prefix from a different domain consumes a scarce source. The failing
    // branch must be skipped, then all permutations under the next prefix kept.
    VolumeAttemptPlan plan;
    plan.sources.resize(4);
    plan.domains = {{0, 3}, {0, 1, 2}, {3}};
    plan.layouts = {{slot(0, 0), slot(1, 1), slot(2, 1), slot(3, 1)},
                    {slot(0, 2), slot(1, 1), slot(2, 1), slot(3, 1)}};
    if (!compare(plan)) return 1;

    // Each slot sees the same large source, but injectivity permits its bytes
    // only once. This is length infeasibility despite enough distinct choices.
    plan.sources.resize(12);
    for (auto& range : plan.sources) { range.has_end = true; range.end = 1; }
    plan.sources[0].end = 100;
    plan.minimum_size = 112;
    plan.domains = {{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}};
    plan.layouts = {{}};
    for (std::size_t i = 0; i < 12; ++i) plan.layouts[0].push_back(slot(i, 0));
    plan.prepare();
    VolumeAttemptCursor insufficient;
    insufficient.reserve(plan);
    if (insufficient.next(plan) || insufficient.attempts) return 4;

    // Global capacity passes only because a large source belongs to a later
    // layout. The first layout must be skipped without factorial backtracking.
    plan.sources.push_back(plan.sources[0]);
    plan.sources.back().end = plan.minimum_size;
    plan.domains.push_back({12});
    plan.layouts.push_back({slot(0, 1)});
    plan.prepare();
    VolumeAttemptCursor reachable;
    reachable.reserve(plan);
    if (!reachable.next(plan) || reachable.layout != 1 || reachable.next(plan)) return 5;

    // The large unsatisfiable layout must not obstruct a later valid layout.
    plan = {};
    plan.sources.resize(11);
    plan.domains = {{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, {0}};
    plan.layouts = {{}, {slot(0, 1)}};
    for (std::size_t i = 0; i < 12; ++i) plan.layouts[0].push_back(slot(i, 0));
    plan.prepare();
    VolumeAttemptCursor cursor;
    cursor.reserve(plan);
    if (!cursor.next(plan) || cursor.layout != 1 || cursor.selected != std::vector<std::size_t>{0}
        || cursor.next(plan) || cursor.attempts != 1) return 2;

    std::mt19937 random(0x51A2);
    const auto maximum = (std::numeric_limits<unsigned long long>::max)();
    const unsigned long long lengths[] = {0, 1, 7, maximum / 2, maximum - 1, maximum};
    for (unsigned int trial = 0; trial < 30000; ++trial) {
        plan = {};
        plan.minimum_size = lengths[random() % 6];
        plan.sources.resize(1 + random() % 6);
        for (auto& range : plan.sources) {
            range.has_end = random() % 4 != 0;
            range.end = lengths[random() % 6];
        }
        plan.domains.resize(1 + random() % 5);
        for (auto& domain : plan.domains) {
            for (std::size_t i = 0; i < plan.sources.size(); ++i)
                if (random() % 2) domain.push_back(i);
            if (domain.empty()) domain.push_back(random() % plan.sources.size());
            std::shuffle(domain.begin(), domain.end(), random);
        }
        plan.layouts.resize(1 + random() % 3);
        for (auto& layout : plan.layouts) {
            const auto size = 1 + random() % 6;
            for (std::size_t i = 0; i < size; ++i) {
                auto value = slot(i, random() % plan.domains.size());
                if (random() % 7 == 0) value.name += L"other";
                layout.push_back(std::move(value));
            }
            plan.minimum_slots.push_back(size > 1 && random() % 2 ? 2 + random() % (size - 1) : 0);
        }
        if (!compare(plan)) { std::cerr << "plan mismatch: " << trial << '\n'; return 3; }
    }
    std::cout << "30000 plans match exhaustive candidate order\n";
}
