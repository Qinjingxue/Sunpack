from __future__ import annotations

import math
import random
import statistics
from collections import defaultdict
from bisect import bisect_left

from .cases import PROTOCOL


def _median_sampler(values: list[float], rng: random.Random):
    """Sample the inner median bootstrap, using its exact CDF for odd N.

    The default process counts are 3 and 7. This avoids regenerating and sorting
    those tiny inner samples millions of times without changing their law.
    """
    n = len(values)
    if min(values) == max(values):
        constant = math.log(values[0])
        return lambda: constant
    if n % 2:
        ordered = sorted(values)
        cdf = [sum(math.comb(n, j) * (i / n) ** j * (1 - i / n) ** (n - j)
                   for j in range(n // 2 + 1, n + 1)) for i in range(1, n + 1)]
        logs = [math.log(value) for value in ordered]
        return lambda: logs[bisect_left(cdf, rng.random())]
    return lambda: math.log(statistics.median(rng.choices(values, k=n)))


def summarize(rows: list[dict], *, reference: str = "sunpack") -> dict:
    """Collapse inner samples before any comparison or uncertainty estimate."""
    cells = defaultdict(list)
    failures = []
    for row in rows:
        if row.get("status") != "ok":
            failures.append({key: row.get(key) for key in ("case", "configuration", "block", "status", "error", "exit_code")})
            continue
        values = {name: row[name] for name in ("bytes", "build_ns", "drop_ns") if name in row}
        ops = defaultdict(list)
        for sample in row.get("samples", []):
            ops[sample["op"]].append(sample["wall_ns"])
        values.update({name: statistics.median(samples) for name, samples in ops.items()})
        for metric, value in values.items():
            cells[(row["case"], row["family"], row["configuration"], metric)].append((row["block"], value))
    absolute = []
    lookup = {}
    for key, values in cells.items():
        name, family, config, metric = key
        result = {"case": name, "family": family, "configuration": config, "metric": metric,
                  "process_blocks": len(values), "median": statistics.median(v for _, v in values),
                  "min": min(v for _, v in values), "max": max(v for _, v in values)}
        absolute.append(result)
        lookup[key] = dict(values)
    ratios = defaultdict(list)
    for (name, family, config, metric), values in lookup.items():
        if config == reference:
            continue
        baseline = lookup.get((name, family, reference, metric), {})
        paired = [value / baseline[block] for block, value in values.items()
                  if block in baseline and value > 0 and baseline[block] > 0]
        if paired:
            ratios[(family, config, metric)].append((name, paired))
    relative = []
    rng = random.Random(PROTOCOL["seeds"]["statistics"])
    for (family, config, metric), cases in sorted(ratios.items()):
        estimates = [statistics.median(pairs) for _, pairs in cases]
        center = math.exp(statistics.mean(math.log(v) for v in estimates))
        samplers = [_median_sampler(pairs, rng) for _, pairs in cases]
        bootstrap = []
        for _ in range(1000):
            bootstrap.append(math.exp(sum(rng.choice(samplers)() for _ in cases) / len(cases)))
        bootstrap.sort()
        relative.append({"family": family, "configuration": config, "reference": reference,
                         "metric": metric, "cases": len(cases), "ratio_geomean": center,
                         "bootstrap_95_low": bootstrap[24], "bootstrap_95_high": bootstrap[974],
                         "worst_case_ratio": max(estimates), "best_case_ratio": min(estimates),
                         "scope": "observed cases/process blocks only; public seeds are not blind samples"})
    pareto = []
    by_case = defaultdict(dict)
    for row in absolute:
        by_case[row["case"]].setdefault(row["configuration"], {})[row["metric"]] = row["median"]
    for name, configurations in sorted(by_case.items()):
        for axes in [("bytes", "build_ns", "sequential_all"), ("bytes", "lower_mixed"), ("bytes", "seek_forward")]:
            eligible = {config: tuple(values[metric] for metric in axes)
                        for config, values in configurations.items() if all(metric in values for metric in axes)}
            front = [config for config, point in eligible.items() if not any(
                all(a <= b for a, b in zip(other, point)) and any(a < b for a, b in zip(other, point))
                for candidate, other in eligible.items() if candidate != config)]
            if front:
                pareto.append({"case": name, "axes": axes, "front": sorted(front),
                               "valid_configurations": len(eligible), "scope": "descriptive median frontier; uncertainty not resolved here"})
    characteristics = {}
    for row in rows:
        if row.get("status") == "ok" and "n" in row:
            characteristics.setdefault(row["case"], {key: row[key] for key in
                ["n", "span", "type_counts", "duplicate_offsets", "duplicate_tuples", "origin"] if key in row})
    parallelism = sorted({row.get("parallel_jobs", 1) for row in rows})
    return {"absolute": absolute, "paired_ratios": relative, "pareto": pareto,
            "execution": {"parallel_jobs": parallelism,
                          "timing_context": "shared-host" if any(n > 1 for n in parallelism) else "isolated",
                          "scope": "Concurrent timings include host contention; isolated latency claims need --parallel-jobs 1."},
            "case_characteristics": characteristics, "failures": failures,
            "coverage": {"scheduled_rows": len(rows), "valid_rows": sum(r.get("status") == "ok" for r in rows),
                         "unsupported_rows": sum(r.get("status") == "unsupported" for r in rows),
                         "invalid_rows": sum(r.get("status") == "invalid" for r in rows)},
            "aggregation": "inner medians -> paired process blocks -> per-family hierarchical bootstrap; no pooled inner-loop N"}


def markdown(summary: dict) -> str:
    lines = ["# Hit-index benchmark results", "", "Raw samples, failed/unsupported cases and the frozen corpus manifest accompany this report.", "",
             f"Valid: {summary['coverage']['valid_rows']}/{summary['coverage']['scheduled_rows']}; "
             f"unsupported: {summary['coverage']['unsupported_rows']}; invalid: {summary['coverage']['invalid_rows']}.", "",
             "Ratios below 1 use less space/time than the reference. These are family-specific estimates, not an overall winner.", "",
             "| Family | Configuration | Metric | Cases | Ratio | Bootstrap interval | Worst case |",
             "|---|---|---|---:|---:|---|---:|"]
    execution = summary.get("execution")
    if execution:
        lines[4:4] = [f"Execution: {execution['parallel_jobs']} parallel jobs; {execution['timing_context']}. "
                      "Concurrent timings include host contention; they are separate from isolated latency results.", ""]
    for row in summary["paired_ratios"]:
        if row["metric"] not in {"bytes", "build_ns", "sequential_all", "lower_mixed", "seek_forward"}:
            continue
        lines.append(f"| {row['family']} | {row['configuration']} | {row['metric']} | {row['cases']} | "
                     f"{row['ratio_geomean']:.3f} | {row['bootstrap_95_low']:.3f}–{row['bootstrap_95_high']:.3f} | {row['worst_case_ratio']:.3f} |")
    if summary["failures"]:
        lines += ["", "## Invalid and unsupported rows", "", "These remain in the coverage denominator and carry no invented performance score.", ""]
        for row in summary["failures"]:
            lines.append(f"- {row['configuration']} / {row['case']} / block {row['block']}: {row['status']}: {row['error']}")
    return "\n".join(lines) + "\n"


def main():
    """Merge compatible shards without silently pooling different execution modes."""
    import argparse
    import json
    from pathlib import Path
    from .cases import configurations, synthetic

    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument("reports", nargs="+", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    reports = [json.loads(path.read_text(encoding="utf-8")) for path in args.reports]
    first = reports[0]
    parameters = {k: v for k, v in first["parameters"].items() if k != "shard_index"}
    shards = set()
    rows = []
    cells = set()
    common = {}
    corpora = []
    for path, report in zip(args.reports, reports):
        if {k: v for k, v in report["parameters"].items() if k != "shard_index"} != parameters:
            raise ValueError("Cannot merge different protocols or measurement parameters")
        shard = report["parameters"]["shard_index"]
        if shard in shards:
            raise ValueError("Duplicate shard")
        shards.add(shard)
        for name in ["protocol.json", "sources.lock.json", "source-identities.json", "tooling-identities.json", "configurations.json"]:
            data = json.loads((path.parent / name).read_text(encoding="utf-8"))
            if name == "sources.lock.json":
                data = {k: {a: b for a, b in v.items() if a != "path"} for k, v in data.items()}
            if name in common and data != common[name]:
                raise ValueError(f"Cannot merge different frozen inputs: {name}")
            common[name] = data
        for field in ["rustc", "clang", "platform", "machine", "cpu", "rustflags", "capabilities", "power_plan", "bridge_xxh128", "candidate_bridge_xxh128"]:
            if report["environment"].get(field) != first["environment"].get(field):
                raise ValueError(f"Environment or probe changed: {field}")
        corpus = json.loads((path.parent / "corpus.json").read_text(encoding="utf-8"))
        if corpora and corpus["cases"] != corpora[0]["cases"]:
            raise ValueError("Corpus changed between shards; reuse the same manifest")
        corpora.append(corpus)
        for row in report["samples"]:
            key = (row["case"], row["configuration"], row["block"])
            if key in cells:
                raise ValueError(f"Duplicate measured cell: {key}")
            cells.add(key)
            rows.append(row)
    expected_cases = {case["name"] for case in corpora[0]["cases"]}
    names = {config["name"] for config in common["configurations.json"]}
    expected = {(case, config, block) for case in expected_cases for config in names for block in range(parameters["process_blocks"])}
    if cells - expected:
        raise ValueError("Unexpected cells")
    summary = summarize(rows)
    gates = [report["summary"]["gates"] for report in reports]
    required = PROTOCOL["measurement"]["evaluation"]
    missing = []
    if parameters["suite"] != "evaluation":
        missing.append("evaluation suite")
    if shards != set(range(parameters["shard_count"])) or cells != expected:
        missing.append("all shards and scheduled cells")
    if not {case.name for case in synthetic("evaluation")} <= expected_cases:
        missing.append("complete evaluation synthetic matrix")
    if not {config["name"] for config in configurations("evaluation")} <= names:
        missing.append("complete baseline configurations")
    if any(parameters.get(key, 0) < value for key, value in required.items()):
        missing.append("required process/sample/warmup/query dimensions")
    if any(gate["source_changed"] or gate["candidate_errors"] for gate in gates):
        missing.append("candidate correctness and stable source")
    for layer in ["mandatory_public_data", "real_traces", "builder", "lifetime", "full_scan"]:
        if not all(gate.get(layer) for gate in gates):
            missing.append(layer)
    candidate_hash = first["environment"].get("candidate_bridge_xxh128")
    for gate in gates:
        conformance = gate.get("conformance")
        if not (conformance and conformance["same_source"] and conformance["parameters"]["suite"] == "conformance"
                and conformance["candidate_bridge_xxh128"] == candidate_hash
                and conformance.get("reference_bridge_xxh128") == first["environment"].get("bridge_xxh128")
                and conformance.get("native_executable_xxh128") == first["environment"].get("native_executable_xxh128")
                and conformance["gates"].get("complete_synthetic_selection")
                and conformance["gates"].get("complete_baseline_selection")
                and conformance["gates"].get("scheduled_cells_complete")
                and not conformance["gates"]["candidate_errors"] and not conformance["gates"]["source_changed"]):
            missing.append("matching complete conformance evidence")
            break
    summary["qualification"] = {"mechanically_complete": not missing, "missing": missing,
                                 "scope": "Does not certify effect size, external-data representativeness or paper claims."}
    args.output.mkdir(parents=True, exist_ok=True)
    result = {"parameters": parameters, "environment": first["environment"], "samples": rows, "summary": summary,
              "source_reports": [str(p.resolve()) for p in args.reports]}
    (args.output / "report.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    (args.output / "report.md").write_text(markdown(summary), encoding="utf-8")
    print(json.dumps(summary["qualification"], ensure_ascii=False))


if __name__ == "__main__":
    main()
