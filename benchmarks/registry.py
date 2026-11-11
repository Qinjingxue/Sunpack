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
]
SCENARIOS = {(group, name): Scenario(group, name, description, arguments) for group, name, description, arguments in _ROWS}
