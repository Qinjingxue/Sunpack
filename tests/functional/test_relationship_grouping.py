from pathlib import Path
import struct
import zlib

import pytest

from sunpack.config.schema import normalize_config
from sunpack.coordinator.scanner import ScanOrchestrator
from sunpack.coordinator.task_provider import ArchiveTaskProvider
from sunpack.coordinator.target_scan import build_fact_bags_for_targets
from sunpack.detection.scheduler import DetectionScheduler
from tests.helpers.detection_config import with_detection_pipeline


SCAN_CONFIG = normalize_config(with_detection_pipeline({
}, precheck=[
    {"name": "size_range", "enabled": True, "gte": 0},
    {"name": "embedded_payload_identity", "enabled": True},
]))


def _minimal_7z_header() -> bytes:
    next_header = b"\x17\x06"
    start_header = struct.pack("<QQI", 0, len(next_header), zlib.crc32(next_header) & 0xFFFFFFFF)
    start_crc = zlib.crc32(start_header) & 0xFFFFFFFF
    return b"7z\xbc\xaf\x27\x1c" + b"\x00\x04" + struct.pack("<I", start_crc) + start_header + next_header


def _write_files(root: Path, names: list[str]):
    root.mkdir(parents=True, exist_ok=True)
    for name in names:
        lower = name.lower()
        if lower.endswith(".7z") or (".7z." in lower and lower.rsplit(".", 1)[-1].isdigit()):
            payload = b"7z\xbc\xaf\x27\x1c" + b"fixture"
        elif ".zip." in lower:
            payload = b"PK\x03\x04" + b"fixture"
        elif ".part" in lower and lower.endswith(".rar"):
            payload = b"Rar!\x1a\x07\x00" + b"fixture"
        else:
            payload = f"fixture::{name}".encode("utf-8")
        (root / name).write_bytes(payload)


def _scan_parts(root: Path) -> dict[str, list[str]]:
    results = ScanOrchestrator(SCAN_CONFIG).scan(str(root))
    actual = {}
    for result in results:
        key = Path(result.main_path).name
        if key.endswith(".7z.001"):
            key = key.removesuffix(".7z.001")
        elif key.endswith(".zip.001"):
            key = key.removesuffix(".zip.001")
        elif ".part1.rar" in key:
            key = key.split(".part1.rar", 1)[0]
        elif key.endswith(".exe") and len(result.all_parts) > 1:
            key = key.removesuffix(".exe")
        actual[key] = sorted(Path(path).name for path in result.all_parts)
    return actual


@pytest.mark.parametrize(
    ("name", "files", "expected"),
    [
        (
            "similar unrelated files are not grouped",
            ["alpha.7z.001", "alpha.7z.002", "alpha.7z.003", "alpha.004", "alpha.7z.notes.txt"],
                {},
        ),
        (
            "similar group names do not cross",
            [
                "story.7z.001",
                "story.7z.002",
                "story.7z.003",
                "story_alt.7z.001",
                "story_alt.7z.002",
                "story_alt.7z.003",
            ],
                {},
        ),
        (
            "interleaved formats form separate groups",
            [
                "mix_a.7z.001",
                "mix_b.zip.001",
                "mix_c.part1.rar",
                "mix_a.7z.002",
                "mix_b.zip.002",
                "mix_c.part2.rar",
                "mix_a.7z.003",
                "mix_b.zip.003",
                "mix_c.part3.rar",
            ],
                {},
        ),
        (
            "missing first volume remains grouped for backend validation",
            ["losthead.7z.002", "losthead.7z.003"],
                {},
        ),
        (
            "fake disguised part files are ignored without real head",
            ["trap.part1.rar.mask", "trap.part2.rar.mask", "trap.part3.rar.mask"],
            {},
        ),
    ],
    ids=lambda value: value if isinstance(value, str) else None,
)
def test_relationship_grouping_scenarios(tmp_path, name, files, expected):
    _write_files(tmp_path / name, files)

    assert _scan_parts(tmp_path / name) == expected


def test_naked_executable_does_not_attach_disguised_parts(tmp_path):
    root = tmp_path / "disguised_exe_companion_with_regular_exe"
    _write_files(
        root,
        [
            "bundle.exe",
            "bundle.7z.001.camouflage",
            "bundle.7z.002.camouflage",
            "bundle.7z.003.camouflage",
            "helper.exe",
            "helper.part1.rar",
        ],
    )
    (root / "bundle.exe").write_bytes(_minimal_7z_header())
    (root / "helper.exe").write_bytes(b"MZ")

    actual = _scan_parts(root)

    assert actual == {
        "bundle.exe": ["bundle.exe"],
    }


def test_missing_middle_split_volume_is_not_emitted_as_a_relation_group(tmp_path):
    root = tmp_path / "missing_middle"
    _write_files(root, ["gap.7z.001", "gap.7z.002", "gap.7z.004"])

    bags = build_fact_bags_for_targets([str(root)], config=SCAN_CONFIG)
    gap = [
        bag for bag in bags
        if Path(bag.get("candidate.entry_path") or "").name.startswith("gap.7z.")
    ]

    assert len(gap) == 3
    assert all(not bag.get("relation.is_split_related") for bag in gap)
    assert all(len(bag.get("candidate.member_paths") or []) == 1 for bag in gap)


def test_missing_head_split_volume_is_not_emitted_as_a_relation_group(tmp_path):
    root = tmp_path / "missing_head"
    _write_files(root, ["lost.7z.002", "lost.7z.003"])

    bags = build_fact_bags_for_targets([str(root)], config=SCAN_CONFIG)
    lost = [
        bag for bag in bags
        if Path(bag.get("candidate.entry_path") or "").name.startswith("lost.7z.")
    ]

    assert len(lost) == 2
    assert all(not bag.get("relation.is_split_related") for bag in lost)
    assert all(len(bag.get("candidate.member_paths") or []) == 1 for bag in lost)


def test_missing_head_split_volume_is_not_recovered_by_filename_only_candidate(tmp_path):
    root = tmp_path / "recovered_head"
    _write_files(root, ["lost.7z", "lost.7z.002", "lost.7z.003"])
    for path in root.iterdir():
        path.write_bytes(b"x" * (1024 * 1024))

    bags = build_fact_bags_for_targets([str(root)], config=SCAN_CONFIG)
    recovered = [
        bag for bag in bags
        if str(root / "lost.7z.002") in (bag.get("candidate.member_paths") or [])
    ]

    assert len(recovered) == 1
    assert [Path(path).name for path in recovered[0].get("candidate.member_paths")] == [
        "lost.7z.002",
    ]
    assert not recovered[0].get("relation.is_split_related")
