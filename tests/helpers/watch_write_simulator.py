from __future__ import annotations

from dataclasses import dataclass

from sunpack.watch.quiet_policy import AdaptiveQuietPolicy, AdaptiveQuietTracker


@dataclass(frozen=True)
class WriteScenario:
    name: str
    intervals: tuple[float, ...]


@dataclass(frozen=True)
class SimulationResult:
    name: str
    premature_attempts: int
    completion_latency: float
    final_quiet_seconds: float


def simulate_writes(scenario: WriteScenario, policy: AdaptiveQuietPolicy) -> SimulationResult:
    """Simulate content-changing watchdog events and pauses between them."""

    tracker = AdaptiveQuietTracker(policy)
    now = 0.0
    size = 0
    premature_attempts = 0
    tracker.observe(now, size=size, mtime=now)
    for interval in scenario.intervals:
        if interval > tracker.quiet_seconds:
            premature_attempts += 1
        now += interval
        size += 1
        tracker.observe(now, size=size, mtime=now)
    return SimulationResult(
        name=scenario.name,
        premature_attempts=premature_attempts,
        completion_latency=tracker.quiet_seconds,
        final_quiet_seconds=tracker.quiet_seconds,
    )


def representative_write_scenarios() -> tuple[WriteScenario, ...]:
    return (
        WriteScenario("very_fast", (0.1,) * 80),
        WriteScenario("fast", (0.5,) * 60),
        WriteScenario("moderate", (2.0,) * 40),
        WriteScenario("slow", (8.0,) * 24),
        WriteScenario("very_slow", (20.0,) * 12),
        WriteScenario("bursty", ((0.2,) * 8 + (3.0,)) * 8),
        WriteScenario("slowing", (0.2,) * 20 + (1.0,) * 10 + (5.0,) * 8 + (12.0,) * 5),
        WriteScenario("temporary_pauses", (0.5,) * 20 + (4.0,) + (0.5,) * 12 + (8.0,) + (0.5,) * 12),
    )
