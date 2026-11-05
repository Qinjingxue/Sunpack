from __future__ import annotations

from collections import deque

import pytest

from sunpack.runtime.watch.quiet_policy import AdaptiveQuietPolicy, AdaptiveQuietTracker
from tests.helpers.watch_write_simulator import WriteScenario, representative_write_scenarios, simulate_writes


def test_policy_starts_immediately_then_learns_without_a_minimum_wait():
    tracker = AdaptiveQuietTracker(AdaptiveQuietPolicy())

    tracker.observe(0.0, size=1, mtime=0.0)
    assert tracker.quiet_seconds == 0.0

    tracker.observe(0.1, size=2, mtime=0.1)

    assert 0.1 < tracker.quiet_seconds < 0.15


def test_policy_extends_immediately_after_one_long_observed_interval():
    tracker = AdaptiveQuietTracker(AdaptiveQuietPolicy())
    tracker.observe(0.0, size=1, mtime=0.0)

    tracker.observe(300.0, size=2, mtime=300.0)

    assert tracker.quiet_seconds > 300.0


def test_weighted_p90_uses_real_sample_age_and_excludes_underflowed_history():
    """Same interval values/counts, different timestamps: event rank is insufficient."""
    policy = AdaptiveQuietPolicy()

    samples = [(20.0, 20.0), (0.1, 20.1), (0.1, 20.2), (0.1, 20.3)]
    assert policy.effective_interval(deque(samples)) == 20.0
    samples.append((0.1, 20.4))
    assert policy.effective_interval(deque(samples)) == 0.1
    samples = [(20.0, 0.0), (0.1, 1000.1), (0.1, 1000.2), (0.1, 1000.3)]
    assert policy.effective_interval(deque(samples)) == 0.1
    # Underflowed weights must not become the P0/minimum or P100/maximum.
    for percentile in (0.0, 1.0):
        edge_policy = AdaptiveQuietPolicy(interval_percentile=percentile)
        assert edge_policy.effective_interval(deque([(0.01, 0.0), *samples])) == 0.1


def test_same_metadata_event_does_not_distort_write_interval_history():
    tracker = AdaptiveQuietTracker(AdaptiveQuietPolicy())
    tracker.observe(0.0, size=1, mtime=0.0)
    tracker.observe(0.1, size=2, mtime=0.1)

    tracker.observe(5.0, size=2, mtime=0.1)

    assert tracker.intervals == (0.1,)


def test_boundary_observation_updates_baseline_without_learning_wait_interval():
    tracker = AdaptiveQuietTracker(AdaptiveQuietPolicy())
    tracker.observe(0.0, size=1, mtime=0.0)
    tracker.observe(0.1, size=2, mtime=0.1)
    quiet_seconds = tracker.quiet_seconds

    tracker.observe(
        5.0,
        size=3,
        mtime=5.0,
        content_changed=True,
        learn_interval=False,
    )

    assert tracker.intervals == (0.1,)
    assert tracker.quiet_seconds == quiet_seconds
    assert tracker.last_content_event_at == 5.0


def test_explicit_metadata_only_change_updates_snapshot_without_resetting_quiet_window():
    tracker = AdaptiveQuietTracker(AdaptiveQuietPolicy())
    tracker.observe(0.0, size=1024, mtime=100.0, change_usn=10)

    quiet_seconds = tracker.observe(
        5.0,
        size=1024,
        mtime=50.0,
        change_usn=11,
        content_changed=False,
    )

    assert quiet_seconds == 0.0
    assert tracker.intervals == ()
    assert tracker.last_mtime == 50.0
    assert tracker.last_change_usn == 11


@pytest.mark.parametrize("observations", [10, 100])
def test_fast_copy_learns_without_requiring_high_callback_throughput(observations):
    tracker = AdaptiveQuietTracker(AdaptiveQuietPolicy())
    tracker.observe(0.0, size=1, mtime=0.0)
    for index in range(1, observations + 1):
        now = 0.1 * index / observations
        tracker.observe(now, size=index + 1, mtime=now)
    assert tracker.quiet_seconds < 0.02
    assert len(tracker.intervals) == min(observations, tracker.policy.window_size)


def test_rate_changes_grow_immediately_and_forget_long_pause_after_four_fast_writes():
    """Exercise both directions without the removed shrink gate or smoothing."""
    tracker = AdaptiveQuietTracker(AdaptiveQuietPolicy())
    tracker.observe(0.0, size=1, mtime=0.0)
    tracker.observe(20.0, size=2, mtime=20.0)
    learned = tracker.quiet_seconds
    assert learned > 20.0
    for index in range(1, 5):
        now = 20.0 + 0.1 * index
        tracker.observe(now, size=index + 2, mtime=now)
        if index < 4:
            assert tracker.quiet_seconds == learned
        else:
            assert 0.1 < tracker.quiet_seconds < 0.15
    tracker.observe(320.4, size=7, mtime=320.4)
    assert tracker.quiet_seconds > 300.0


@pytest.mark.parametrize("scenario", representative_write_scenarios())
def test_representative_cadences_are_invariant_to_time_units(scenario: WriteScenario):
    """The interval estimator is scale-free; the retained mapping is tested above."""
    policy = AdaptiveQuietPolicy(logarithmic_scale=0.0)
    result = simulate_writes(scenario, policy)

    for factor in (1e-6, 1e6):
        scaled = WriteScenario(scenario.name, tuple(value * factor for value in scenario.intervals))
        scaled_result = simulate_writes(scaled, policy)
        assert scaled_result.final_quiet_seconds == pytest.approx(result.final_quiet_seconds * factor)
