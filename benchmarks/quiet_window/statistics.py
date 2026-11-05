from __future__ import annotations

import math
import random
import statistics


EVALUATION_CONTRACT = "sunpack.quiet-window/6"

# Fixed-duration, arbitrarily positioned half-open windows [start, start+span).
# Integer nanoseconds share the latency SLO's timestamp resolution. Every
# admission counts, including simultaneous admissions of different volumes.
BURST_WINDOWS = (("100ms", 100_000_000), ("1s", 1_000_000_000), ("10s", 10_000_000_000))
BURST_METRICS = tuple(f"invalid_burst_{label}_{suffix}" for label, _ in BURST_WINDOWS
                      for suffix in ("per_input", "p95_per_trace", "input_max_per_trace", "all_inputs"))

METRICS = ("false_ready_file_rate", "premature_proposals_per_file", "censored_complete_rate",
           "invalid_proposals_per_file",
           "censored_usable_rate",
           "mean_ready_to_valid_proposal_seconds", "censored_valid_proposal_rate",
           "mean_detection_latency_seconds", "busy_proposals_per_file", "early_group_proposals_per_file",
           "premature_exposure_seconds_per_file", "within_50ms", "within_500ms", "within_2s", "within_10s", "within_60s")
METRICS += ("valid_within_50ms", "valid_within_500ms", "valid_within_2s", "valid_within_10s", "valid_within_60s")
METRICS += BURST_METRICS


def sliding_peak(timestamps_ns, span_ns):
    """Linear scan of sorted timestamps; no bins and no time-step sampling."""
    left = peak = 0
    for right, at in enumerate(timestamps_ns):
        while at - timestamps_ns[left] >= span_ns:
            left += 1
        peak = max(peak, right - left + 1)
    return peak


def invalid_bursts(inputs):
    """Writer-truth scoring only; never supplied to the admission policy."""
    histories = []
    for item in inputs:
        ready = item["processing_ready_at"]
        histories.append(sorted(round(at * 1_000_000_000) for at in item["proposal_times"]
                                if ready is None or at < ready))
    concurrent = sorted(at for history in histories for at in history)
    metrics = {}
    for label, span in BURST_WINDOWS:
        peaks = [sliding_peak(history, span) for history in histories]
        prefix = f"invalid_burst_{label}_"
        metrics.update({prefix + "per_input": statistics.mean(peaks) if peaks else None,
                        prefix + "p95_per_trace": quantile(peaks, 0.95),
                        prefix + "input_max_per_trace": max(peaks, default=0),
                        prefix + "all_inputs": sliding_peak(concurrent, span)})
    return metrics


def quantile(values, probability):
    if not values:
        return None
    values = sorted(values)
    position = (len(values) - 1) * probability
    lower = math.floor(position)
    upper = math.ceil(position)
    return values[lower] + (values[upper] - values[lower]) * (position - lower)


def summarize_files(files: list[dict]) -> dict:
    total = len(files)
    completed = [file for file in files if file["completed"]]
    latencies = [file["first_detection_latency"] for file in completed if file["first_detection_latency"] is not None]
    arrived = [file for file in files if file["processing_ready_at"] is not None]
    valid_latencies = [file["ready_to_valid_proposal_seconds"] for file in arrived
                       if file["ready_to_valid_proposal_seconds"] is not None]
    result = {
        "files": total, "completed_files": len(completed), "detected_complete_files": len(latencies),
        "complete_arrival_files": len(arrived), "valid_proposal_files": len(valid_latencies),
        "ineligible_valid_proposal_files": total - len(arrived),
        "mean_ready_to_valid_proposal_seconds": statistics.mean(valid_latencies) if valid_latencies else None,
        "censored_valid_proposal_rate": 1 - len(valid_latencies) / len(arrived) if arrived else None,
        "false_ready_file_rate": sum(file["premature"] > 0 for file in files) / total,
        "premature_proposals_per_file": sum(file["premature"] for file in files) / total,
        "invalid_proposals_per_file": sum(file["invalid_proposals"] for file in files) / total,
        "censored_complete_rate": 1 - len(latencies) / len(completed) if completed else None,
        "censored_usable_rate": sum(file["first_usable_latency"] is None for file in completed) / len(completed) if completed else None,
        "mean_detection_latency_seconds": statistics.mean(latencies) if latencies else None,
        "busy_proposals_per_file": sum(file["busy_proposals"] for file in files) / total,
        "early_group_proposals_per_file": sum(file["early_group_proposals"] for file in files) / total,
        "premature_exposure_seconds_per_file": sum(file["premature_exposure_seconds"] for file in files) / total,
        "conditional_latency_p50_seconds": quantile(latencies, 0.5),
        "conditional_latency_p95_seconds": quantile(latencies, 0.95),
        "conditional_latency_p99_seconds": quantile(latencies, 0.99),
    }
    result.update(invalid_bursts(files))
    for name, budget in (("within_50ms", 0.05), ("within_500ms", 0.5), ("within_2s", 2), ("within_10s", 10), ("within_60s", 60)):
        # Express the inclusive SLO in integer nanoseconds. Subtracting two
        # large binary timestamps can otherwise turn exactly 0.5s into
        # 0.50000000000001s and spuriously fail half of a fixed-0.5s control.
        result[name] = sum(round(value * 1_000_000_000) <= round(budget * 1_000_000_000)
                           for value in latencies) / len(completed) if completed else None
        result["valid_" + name] = sum(round(value * 1_000_000_000) <= round(budget * 1_000_000_000)
                                     for value in valid_latencies) / len(arrived) if arrived else None
    return result


def macro(rows: list[dict]) -> dict:
    """Equal trace weight; callers first stratify family/channel/width/tie order."""
    return {metric: statistics.mean(values) if (values := [row[metric] for row in rows if row.get(metric) is not None]) else None
            for metric in METRICS}


def interval(values: list[float], *, seed: int = 948173, repetitions: int = 2000) -> dict:
    if not values:
        return {"mean": None, "ci95": None, "independent_seed_blocks": 0}
    mean = statistics.mean(values)
    if len(values) < 2:
        return {"mean": mean, "ci95": None, "independent_seed_blocks": len(values)}
    rng = random.Random(seed)
    estimates = [statistics.mean(rng.choices(values, k=len(values))) for _ in range(repetitions)]
    return {"mean": mean, "ci95": [quantile(estimates, 0.025), quantile(estimates, 0.975)],
            "independent_seed_blocks": len(values)}


def paired_comparison(samples: list[dict], baseline: dict) -> dict:
    previous = {(row["split"], row["seed"]): row for row in baseline["samples"] if row["algorithm"] == "adaptive"}
    result = {}
    for split in sorted({row["split"] for row in samples}):
        current = [row for row in samples if row["split"] == split and row["algorithm"] == "adaptive"]
        if {(row["split"], row["seed"]) for row in current} != {key for key in previous if key[0] == split}:
            raise ValueError("baseline has a different seed cohort")
        result[split] = {metric: interval([
            row[metric] - previous[(split, row["seed"])][metric] for row in current
            if row[metric] is not None and previous[(split, row["seed"])][metric] is not None
        ]) for metric in METRICS}
    return result
