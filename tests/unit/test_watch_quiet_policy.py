from __future__ import annotations

import math

import pytest

from sunpack.config.fields.watch import normalize_watch_config
from sunpack.filesystem.watcher.quiet_policy import AdaptiveQuietPolicy, AdaptiveQuietTracker
from tests.helpers.watch_write_simulator import WriteScenario, representative_write_scenarios, simulate_writes


def test_watch_quiet_config_migrates_legacy_cold_start_without_clamping_dynamic_floor():
    config = normalize_watch_config(
        {"quiet_seconds": 5, "quiet_min_seconds": 8, "quiet_max_seconds": 3}
    )

    assert config["cold_start_seconds"] == 5
    assert config["quiet_min_seconds"] == 8
    assert config["quiet_max_seconds"] == 8
    assert "quiet_seconds" not in config


def test_explicit_cold_start_takes_precedence_over_legacy_alias():
    config = normalize_watch_config({"quiet_seconds": 5, "cold_start_seconds": 1})

    assert config["cold_start_seconds"] == 1
    assert config["boundary_confirmation_seconds"] == 0.5


def test_policy_starts_below_dynamic_floor_then_corrects_after_first_interval():
    tracker = AdaptiveQuietTracker(AdaptiveQuietPolicy())

    tracker.observe(0.0, size=1, mtime=0.0)
    assert tracker.quiet_seconds == 1.0

    tracker.observe(0.1, size=2, mtime=0.1)

    assert 1.25 < tracker.quiet_seconds < 1.5


def test_policy_extends_immediately_after_one_long_observed_interval():
    tracker = AdaptiveQuietTracker(AdaptiveQuietPolicy())
    tracker.observe(0.0, size=1, mtime=0.0)

    tracker.observe(20.0, size=2, mtime=20.0)

    assert tracker.quiet_seconds > 20.0


def test_policy_uses_lower_initial_growth_curve():
    policy = AdaptiveQuietPolicy()

    expected = 1.25 + 1.0 + 0.75 * math.log1p(1.0 / 2.0)

    assert policy.target_seconds([1.0]) == pytest.approx(expected)
    assert policy.target_seconds([1.0]) < 4.0


def test_policy_uses_p90_instead_of_a_single_maximum_interval():
    policy = AdaptiveQuietPolicy()

    assert policy.effective_interval([1.0] * 9 + [20.0]) == pytest.approx(2.9)


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

    assert quiet_seconds == 1.0
    assert tracker.intervals == ()
    assert tracker.last_mtime == 50.0
    assert tracker.last_change_usn == 11


@pytest.mark.parametrize(
    ("scenario_name", "maximum_latency"),
    (("very_fast", 4.0), ("fast", 6.0), ("moderate", 10.0)),
)
def test_fast_and_moderate_writes_complete_quickly(scenario_name: str, maximum_latency: float):
    scenarios = {item.name: item for item in representative_write_scenarios()}
    result = simulate_writes(scenarios[scenario_name], AdaptiveQuietPolicy())

    assert result.premature_attempts <= (1 if scenario_name == "moderate" else 0)
    assert result.completion_latency <= maximum_latency


@pytest.mark.parametrize("scenario", representative_write_scenarios())
def test_representative_writes_avoid_repeated_premature_attempts(scenario: WriteScenario):
    result = simulate_writes(scenario, AdaptiveQuietPolicy())

    expected_maximum = 2 if scenario.name in {"slowing", "temporary_pauses"} else 1
    assert result.premature_attempts <= expected_maximum
