from __future__ import annotations

import math
import random
import statistics


METRICS = ("false_ready_file_rate", "premature_proposals_per_file", "censored_complete_rate",
           "censored_usable_rate",
           "mean_detection_latency_seconds", "busy_proposals_per_file", "early_group_proposals_per_file",
           "premature_exposure_seconds_per_file", "within_50ms", "within_500ms", "within_2s", "within_10s", "within_60s")


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
    result = {
        "files": total, "completed_files": len(completed), "detected_complete_files": len(latencies),
        "false_ready_file_rate": sum(file["premature"] > 0 for file in files) / total,
        "premature_proposals_per_file": sum(file["premature"] for file in files) / total,
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
    for name, budget in (("within_50ms", 0.05), ("within_500ms", 0.5), ("within_2s", 2), ("within_10s", 10), ("within_60s", 60)):
        # Express the inclusive SLO in integer nanoseconds. Subtracting two
        # large binary timestamps can otherwise turn exactly 0.5s into
        # 0.50000000000001s and spuriously fail half of a fixed-0.5s control.
        result[name] = sum(round(value * 1_000_000_000) <= round(budget * 1_000_000_000)
                           for value in latencies) / len(completed) if completed else None
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
