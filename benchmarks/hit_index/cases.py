from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
from pathlib import Path
import random

HERE = Path(__file__).resolve().parent
PROTOCOL = json.loads((HERE / "protocol.json").read_text(encoding="utf-8"))


@dataclass(frozen=True)
class Case:
    name: str
    family: str
    arguments: dict = field(default_factory=dict)
    provenance: dict = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)

    def argv(self):
        return [item for key, value in self.arguments.items() for item in ("--" + key, str(value))]


def synthetic(suite: str) -> list[Case]:
    seed_group = "evaluation" if suite == "evaluation" else "development"
    seeds = PROTOCOL["seeds"][seed_group]
    if suite == "quick":
        seeds = seeds[:1]
    recipes = [
        ("empty", "uniform", 0, 2097152, "one", {}),
        ("few", "uniform", 127, 2097152, "uniform", {}),
        ("uniform-sparse", "uniform", 32768, 1 << 27, "one", {}),
        ("clustered-sparse", "clustered", 32768, 1 << 27, "one", {}),
        ("uniform-dense", "uniform", 65536, 2097152, "uniform", {}),
        ("arithmetic", "arithmetic", 65536, 2097152, "one", {}),
        ("outliers-end", "outliers", 65536, 2097152, "one", {"phase": 127}),
        ("outliers-start", "outliers", 65536, 2097152, "palette3", {"phase": 0}),
        ("runs", "runs", 65536, 1 << 24, "uniform", {}),
        ("piecewise", "piecewise", 65536, 1 << 27, "skew", {}),
        ("coincident", "duplicates", 65536, 2097152, "coincident", {}),
        ("multiplicity", "constant", 4096, 2097152, "uniform", {}),
        ("high-base", "uniform", 4096, 2097152, "palette3", {"base": 1 << 40}),
        ("bit-boundaries", "bit-boundaries", 257, 1 << 28, "periodic", {}),
    ]
    if suite == "evaluation":
        recipes = []
        for n in PROTOCOL["evaluation_lengths"]:
            for profile in ["uniform", "clustered", "gaps", "geometric", "outliers", "runs", "piecewise", "arithmetic", "duplicates"]:
                universe = min(1 << 31, max(2097152, n * (4096 if profile == "piecewise" else 256 if profile == "runs" else 32)))
                for types in ["one", "uniform", "palette3", "skew", "runs", "periodic"]:
                    recipes.append((f"{profile}-{n}-{types}", profile, n, universe, types, {}))
        # Controlled one-variable diagnostic sweeps, including unaligned jumps.
        for every in [16, 128, 1024]:
            for gap in [256, 4096, 65536]:
                for phase in [0, 1, 63, 127]:
                    recipes.append((f"outlier-{every}-{gap}-{phase}", "outliers", 65536, 1 << 29, "one", {"exception-every": every, "exception-gap": gap, "phase": phase}))
    if suite == "conformance":
        recipes = []
        for n in PROTOCOL["boundary_lengths"]:
            for profile, types in [("uniform", "uniform"), ("arithmetic", "palette3"), ("outliers", "one"), ("constant", "uniform"), ("duplicates", "coincident")]:
                recipes.append((f"{profile}-{n}", profile, n, max(2097152, n * 32), types, {}))
        seeds = seeds[:2]
        recipes += [recipe for recipe in [
            ("high-base", "uniform", 4097, 2097152, "palette3", {"base": 1 << 40}),
            ("wide-span", "arithmetic", 4097, 1 << 31, "periodic", {}),
            ("bit-boundaries", "bit-boundaries", 257, 1 << 28, "periodic", {}),
            ("contiguous-tail", "contiguous", 129, 2097152, "runs", {}),
        ]]
    return [Case(f"{name}-s{seed}", "synthetic-" + profile,
                 {"profile": profile, "n": n, "universe": universe, "types": types, "seed": seed, **extras},
                 {"seed_group": seed_group, "generator": "upstream FastPFOR Uniform/ClusterData" if profile in {"uniform", "clustered"} else "project diagnostic recipe", "fit": "none; infeasible recipes fail"})
            for name, profile, n, universe, types, extras in recipes for seed in seeds]


def configurations(suite: str, selected: list[str] | None = None) -> list[dict]:
    algorithms = selected or PROTOCOL["algorithms"]
    result = [{"name": name, "algorithm": name, "block": 128} for name in algorithms]
    if suite != "conformance":
        for name in ["svb", "bp128", "fastpfor128"]:
            if name in algorithms:
                for block in ([4096, 65536] if name == "fastpfor128" else [4096]):
                    result.append({"name": f"{name}-b{block}", "algorithm": name, "block": block})
    return result


def schedule(cases: list[Case], configurations: list[dict], blocks: int):
    # Common permutation, independent of results. Cyclic ordering ensures each
    # algorithm occupies each ordinal over a complete cycle of blocks.
    rng = random.Random(PROTOCOL["seeds"]["selection"])
    shuffled = list(cases)
    rng.shuffle(shuffled)
    configs = list(configurations)
    rng.shuffle(configs)
    for block in range(blocks):
        ordered = shuffled[block % max(1, len(shuffled)):] + shuffled[:block % max(1, len(shuffled))]
        for ci, case in enumerate(ordered):
            offset = (block + ci) % len(configs)
            for order, config in enumerate(configs[offset:] + configs[:offset]):
                yield block, order, case, config
