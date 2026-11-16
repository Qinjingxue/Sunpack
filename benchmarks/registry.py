from __future__ import annotations
from dataclasses import dataclass

@dataclass(frozen=True)
class Scenario:
    group: str
    name: str
    description: str
    arguments: tuple[str, ...]
    module: str = "benchmarks.scenarios.native_boundary"

_ROWS = [
    ("scan", "directory", "Mixed directory and embedded/carrier discovery through the native CLI.", ("--mode", "scan")),
    ("extraction", "format-matrix", "Generated multi-format and split-volume CLI workloads.", ("--mode", "extract")),
    ("extraction", "real-archive", "Supplied real archive CLI latency and native memory.", ("--mode", "extract")),
    ("extraction", "cli-vs-7z", "Native CLI versus raw 7-Zip on identical generated archives.", ("--mode", "extract", "--compare-7z")),
    ("memory", "residual-rss", "Resident runtime and worker memory across repeated directory requests.", ("--mode", "memory", "--formats", "zip,7z")),
    ("memory", "many-tasks", "Concurrent native directory workload, sampled peak and retained resources.", ("--mode", "memory", "--formats", "zip,7z", "--copies", "8", "--large-file-mib", "4")),
    ("memory", "password-store", "Scoped password-store request latency and resident memory.", ("--mode", "passwords")),
    ("watch", "state-persistence", "Native Watch bootstrap and completed-state restart cost.", ("--mode", "watch", "--formats", "zip", "--copies", "50", "--small-files", "64", "--large-files", "0")),
    ("watch", "live-arrival", "Continuous Watch arrival latency and runtime plus Broker memory.", ("--mode", "watch", "--live-arrival", "--formats", "zip", "--small-files", "64", "--large-files", "0")),
]
SCENARIOS = {(group, name): Scenario(group, name, description, arguments) for group, name, description, arguments in _ROWS}
for scenario in (
    Scenario("watch", "dedup-index", "Watch logical-input dedup admission, WAL and memory scaling.", (), "benchmarks.scenarios.watch_dedup_index"),
    Scenario("password", "probe-matrix", "Cold password candidate probing by encrypted format.", (), "benchmarks.scenarios.password_probe"),
    Scenario("worker", "format-matrix", "Direct worker 300 MiB reproducible format matrix.", (), "benchmarks.scenarios.worker_300m"),
    Scenario("scan", "embedded", "Large carrier embedded archive scanning.", (), "benchmarks.scenarios.embedded_scan"),
    Scenario("scan", "hit-index", "Production hit-index build, traversal and memory.", (), "benchmarks.scenarios.hit_index_native"),
    Scenario("extraction", "e2e-300m", "CLI 300 MiB format matrix.", ("--mode", "cli"), "benchmarks.scenarios.e2e_300m"),
    Scenario("watch", "e2e-300m", "Watch 300 MiB format matrix.", ("--mode", "watch"), "benchmarks.scenarios.e2e_300m"),
    Scenario("scan", "game-tree", "Direct recursive directory scan and authorization.", (), "benchmarks.scenarios.game_tree"),
    Scenario("watch", "quiet-corpus", "Replay the full writer corpus through native Watch admission.", (), "benchmarks.scenarios.quiet_corpus"),
):
    SCENARIOS[(scenario.group, scenario.name)] = scenario
