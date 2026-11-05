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
    assert tracker.quiet_seconds == 0.0
    tracker.observe(0.2, size=3, mtime=0.2)

    assert 0.1 < tracker.quiet_seconds < 0.15


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
    tracker.observe(0.2, size=3, mtime=0.2)

    tracker.observe(5.0, size=3, mtime=0.2)

    assert tracker.intervals == (0.1, 0.1)


def test_boundary_observation_updates_baseline_without_learning_wait_interval():
    tracker = AdaptiveQuietTracker(AdaptiveQuietPolicy())
    tracker.observe(0.0, size=1, mtime=0.0)
    tracker.observe(0.1, size=2, mtime=0.1)
    tracker.observe(0.2, size=3, mtime=0.2)
    quiet_seconds = tracker.quiet_seconds

    tracker.observe(
        5.0,
        size=4,
        mtime=5.0,
        content_changed=True,
        learn_interval=False,
    )

    assert tracker.intervals == (0.1, 0.1)
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


def test_pause_is_excluded_but_repeated_slow_cadence_is_learned_then_fast_writes_shrink():
    """An isolated pause and a sustained slow writer require different predictions."""
    tracker = AdaptiveQuietTracker(AdaptiveQuietPolicy())
    tracker.observe(0.0, size=1, mtime=0.0)
    tracker.observe(0.1, size=2, mtime=0.1)
    tracker.observe(0.2, size=3, mtime=0.2)
    fast = tracker.quiet_seconds
    tracker.observe(300.2, size=4, mtime=300.2)
    assert tracker.quiet_seconds == fast
    tracker.observe(300.3, size=5, mtime=300.3)
    assert tracker.quiet_seconds < 0.15
    tracker.observe(600.3, size=6, mtime=600.3)
    assert tracker.quiet_seconds < 0.15
    tracker.observe(900.3, size=7, mtime=900.3)
    learned = tracker.quiet_seconds
    assert learned > 300.0
    for index in range(1, 5):
        now = 900.3 + 0.1 * index
        tracker.observe(now, size=index + 7, mtime=now)
        if index < 4:
            assert tracker.quiet_seconds == learned
        else:
            assert 0.1 < tracker.quiet_seconds < 0.15


def test_truncation_starts_a_new_phase_and_boundary_probe_breaks_confirmation():
    tracker = AdaptiveQuietTracker(AdaptiveQuietPolicy())
    for now, size in ((0.0, 10), (0.1, 11), (0.2, 12)):
        tracker.observe(now, size=size, mtime=now)
    tracker.observe(300.2, size=13, mtime=300.2)
    tracker.observe(400.2, size=14, mtime=400.2, learn_interval=False)
    tracker.observe(700.2, size=15, mtime=700.2)
    assert tracker.quiet_seconds < 0.15
    tracker.observe(700.3, size=1, mtime=700.3)
    assert tracker.quiet_seconds == tracker.cadence_seconds == tracker.pending_interval_seconds == 0.0
    assert tracker.intervals == ()


def test_close_summary_ends_frequency_sampling_without_claiming_file_completion():
    tracker = AdaptiveQuietTracker(AdaptiveQuietPolicy())
    for now, size in ((0.0, 1), (0.1, 2), (0.2, 3)):
        tracker.observe(now, size=size, mtime=now)
    learned = tracker.quiet_seconds
    tracker.observe(0.3, size=3, mtime=0.2, change_usn=4, content_changed=False, phase_boundary=True)
    assert tracker.last_content_event_at is None
    tracker.observe(300.3, size=4, mtime=300.3)
    assert tracker.quiet_seconds == learned and tracker.pending_interval_seconds == 0.0
    tracker.observe(300.4, size=5, mtime=300.4)
    assert tracker.quiet_seconds < 0.15


@pytest.mark.parametrize("scenario", representative_write_scenarios())
def test_representative_cadences_are_invariant_to_time_units(scenario: WriteScenario):
    """The interval estimator is scale-free; the retained mapping is tested above."""
    policy = AdaptiveQuietPolicy(logarithmic_scale=0.0)
    result = simulate_writes(scenario, policy)

    for factor in (1e-6, 1e6):
        scaled = WriteScenario(scenario.name, tuple(value * factor for value in scenario.intervals))
        scaled_result = simulate_writes(scaled, policy)
        assert scaled_result.final_quiet_seconds == pytest.approx(result.final_quiet_seconds * factor)
