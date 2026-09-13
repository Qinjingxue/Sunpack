from __future__ import annotations

import re
import asyncio
import subprocess
from pathlib import Path

import pytest

from sunpack.config.loader import load_config
from sunpack.config.schema import normalize_config
from sunpack.contracts.tasks import ArchiveTask
from sunpack.coordinator.engine import PipelineEngine
from sunpack.coordinator.task_provider import ArchiveTaskProvider
from sunpack.coordinator.target_groups import relation_group_to_fact_bag
from sunpack.coordinator.watch_group_coordinator import WatchGroupCoordinator
from sunpack.detection.input_planning import ArchiveInputPlanningStage
from sunpack.extraction.scheduler import ExtractionScheduler
from sunpack.filesystem.directory_scanner import DirectoryScanner
from sunpack.passwords.directory_context import DirectoryPasswordContextStore
from sunpack.relations import RelationsScheduler
from tests.helpers.detection_config import with_detection_pipeline
from tests.helpers.real_archives import ArchiveFixtureFactory
from tests.helpers.tool_config import get_optional_winrar, get_test_tools


MIB = 1024 * 1024


@pytest.fixture(scope="module")
def mixed_real_volumes(tmp_path_factory):
    root = tmp_path_factory.mktemp("structure-volume-resolution")
    return root, *_mixed_real_volume_directory(root)


def test_mixed_camouflaged_real_volumes_are_structure_resolved_and_extractable(mixed_real_volumes):
    tmp_path, common, cases, paths_by_format = mixed_real_volumes
    scheduler = RelationsScheduler()
    all_paths = [str(path) for path in common.iterdir() if path.is_file()]

    for archive_format in ("7z", "zip", "rar"):
        current = [str(paths_by_format[archive_format][0])]
        group = scheduler.resolve_volume_once(current, all_paths, format_hint=archive_format)

        assert group is not None
        assert {Path(path).name for path in group.input_paths} == {
            path.name for path in paths_by_format[archive_format]
        }
        assert [volume.number for volume in group.split_volumes] == list(
            range(1, len(paths_by_format[archive_format]) + 1)
        )
        assert all(path.stat().st_size > MIB for path in paths_by_format[archive_format])
        if archive_format == "rar":
            assert all(volume.source == "structure" for volume in group.split_volumes)
        else:
            assert group.split_volumes[0].source == "structure"

        task = ArchiveTask.from_fact_bag(relation_group_to_fact_bag(group))
        planned = ArchiveInputPlanningStage(load_config()).plan_task_to_tasks(task)
        assert len(planned) == 1
        extractor = ExtractionScheduler(max_retries=1)
        out_dir = tmp_path / "direct_outputs" / archive_format
        try:
            result = extractor.extract(planned[0], str(out_dir))
        finally:
            extractor.close()

        assert result.success is True
        marker = next(out_dir.rglob(cases[archive_format].marker_name))
        assert marker.read_text(encoding="utf-8") == cases[archive_format].marker_text


def test_mixed_directory_schedules_only_one_structural_head_per_format(mixed_real_volumes):
    _tmp_path, common, _cases, paths_by_format = mixed_real_volumes
    config = normalize_config(
        with_detection_pipeline(
            {},
            precheck=[
                {"name": "size_range", "enabled": True, "gte": 0},
                {"name": "seven_zip_structure_accept", "enabled": True},
                {"name": "zip_structure_accept", "enabled": True},
                {"name": "rar_structure_accept", "enabled": True},
            ],
        )
    )

    tasks = ArchiveTaskProvider(config).scan_targets([str(common)])

    assert {Path(task.main_path).name for task in tasks} == {
        paths_by_format[archive_format][0].name
        for archive_format in ("7z", "zip", "rar")
    }


def test_pipeline_uses_initial_structure_group_without_missing_volume_retry(
    mixed_real_volumes, monkeypatch
):
    tmp_path, common, cases, paths_by_format = mixed_real_volumes
    first = paths_by_format["7z"][0]
    output_root = tmp_path / "pipeline_output"
    config = normalize_config(
        with_detection_pipeline(
            {
                "recursive_extract": "1",
                "verification": {"enabled": False, "methods": []},
                "post_extract": {
                    "archive_cleanup_mode": "k",
                    "flatten_single_directory": False,
                },
                "output": {
                    "root": str(output_root),
                    "common_root": str(common),
                },
            },
            precheck=[
                {"name": "size_range", "enabled": True, "gte": 0},
                {"name": "seven_zip_structure_accept", "enabled": True},
            ],
        )
    )

    engine = PipelineEngine(config)
    original_resolver = RelationsScheduler.resolve_volume_once_in_directory
    resolution_attempts = 0

    def counting_resolver(scheduler, current_paths, *, format_hint=""):
        nonlocal resolution_attempts
        resolution_attempts += 1
        return original_resolver(
            scheduler,
            current_paths,
            format_hint=format_hint,
        )

    monkeypatch.setattr(
        RelationsScheduler,
        "resolve_volume_once_in_directory",
        counting_resolver,
    )
    async def run():
        async with engine:
            return await asyncio.wait_for(engine.run([str(first)]), 60)
    response = asyncio.run(run())

    assert response.summary.success_count == 1
    assert response.summary.failed_tasks == []
    assert resolution_attempts == 0
    marker = next(output_root.rglob(cases["7z"].marker_name))
    assert marker.read_text(encoding="utf-8") == cases["7z"].marker_text


def test_real_strict_middle_gap_survives_structure_precheck_and_holds_watch(tmp_path):
    case = ArchiveFixtureFactory().create(
        tmp_path,
        "strict_middle_gap",
        "7z",
        split=True,
        payload_size=420 * 1024,
        split_volume_size=100 * 1024,
    )
    parts = sorted(path for path in case.archive_dir.iterdir() if path.is_file())
    assert len(parts) >= 3
    parts[1].unlink()

    groups = RelationsScheduler().build_candidate_groups(
        DirectoryScanner(str(case.archive_dir)).scan()
    )
    group = next(group for group in groups if group.logical_name == "strict_middle_gap")

    assert group.split_group_complete is False
    assert group.split_missing_reason == "missing_middle"
    assert group.split_missing_indices == [2]
    assert group.split_completeness_status == "middle_gap"
    assert group.split_completeness_confidence == "strong"

    snapshot = WatchGroupCoordinator({}).resolve_head(str(parts[0]))
    assert snapshot is not None
    assert snapshot.missing_indices == (2,)
    assert snapshot.should_wait_for_relation_gap is True


def test_structure_resolution_recomputes_a_residual_middle_gap(tmp_path):
    case = ArchiveFixtureFactory().create(
        tmp_path,
        "residual_gap_source",
        "7z",
        split=True,
        payload_size=9 * MIB + MIB // 2,
        split_volume_size=2 * MIB,
    )
    original_parts = sorted(path for path in case.archive_dir.iterdir() if path.is_file())
    assert len(original_parts) >= 5
    common = tmp_path / "residual_gap"
    common.mkdir()
    renamed = []
    for number, source in enumerate(original_parts, start=1):
        if number == 4:
            continue
        target = common / f"residual.alpha.7z.{number:03d}.noise.bin"
        source.replace(target)
        renamed.append(target)

    group = RelationsScheduler().resolve_volume_once(
        [str(renamed[0])],
        [str(path) for path in common.iterdir() if path.is_file()],
        format_hint="7z",
    )

    assert group is not None
    assert [volume.number for volume in group.split_volumes] == [1, 2, 3, 5]
    assert group.split_group_complete is False
    assert group.split_missing_reason == "missing_middle"
    assert group.split_missing_indices == [4]
    assert group.split_observed_missing_ranges == [(4, 4)]
    assert group.split_completeness_status == "middle_gap"
    assert group.split_completeness_confidence == "strong"


@pytest.mark.skipif(get_optional_winrar() is None, reason="WinRAR is required to generate modern split ZIP")
def test_modern_split_zip_with_camouflaged_names_runs_full_pipeline(tmp_path):
    winrar = get_optional_winrar()
    assert winrar is not None
    source = tmp_path / "source"
    source.mkdir()
    payload = source / "payload.bin"
    payload.write_bytes(bytes((index * 131 + 17) & 0xFF for index in range(3 * MIB)))
    generated = tmp_path / "generated"
    generated.mkdir()
    archive = generated / "modern.zip"
    result = subprocess.run(
        [
            str(winrar),
            "a",
            "-afzip",
            "-m0",
            "-v1m",
            "-inul",
            str(archive),
            str(payload),
        ],
        cwd=str(source),
        capture_output=True,
        timeout=60,
    )
    assert result.returncode == 0

    parts = sorted(generated.iterdir())
    assert [path.suffix.lower() for path in parts] == [".z01", ".z02", ".z03", ".zip"]
    mixed = tmp_path / "mixed"
    mixed.mkdir()
    renamed = []
    for source_part in parts:
        suffix = source_part.suffix.lower()
        marker = suffix.removeprefix(".")
        target = mixed / f"shared.alpha.{marker}.useless.{len(renamed)}.fake"
        source_part.replace(target)
        renamed.append(target)

    config = normalize_config(
        with_detection_pipeline(
            {
                "verification": {"enabled": False, "methods": []},
            },
            precheck=[
                {"name": "size_range", "enabled": True, "gte": 0},
                {"name": "zip_structure_accept", "enabled": True},
            ],
        )
    )
    tasks = ArchiveTaskProvider(config).scan_targets([str(mixed)])

    assert len(tasks) == 1
    assert tasks[0].matched_rules == ["zip_structure_accept"]
    descriptor = tasks[0].archive_input()
    assert descriptor.volume_style == "zip_spanned"
    assert [part.volume_number for part in descriptor.parts] == [1, 2, 3, 4]
    assert [part.role for part in descriptor.parts] == ["first", "member", "member", "terminal"]
    assert [part.canonical_name for part in descriptor.parts] == [
        "shared.z01",
        "shared.z02",
        "shared.z03",
        "shared.zip",
    ]

    extractor = ExtractionScheduler(max_retries=0)
    output = tmp_path / "output"
    try:
        extraction = extractor.extract(tasks[0], str(output))
    finally:
        extractor.close()

    assert extraction.success is True
    extracted = next(output.rglob("payload.bin"))
    assert extracted.read_bytes() == payload.read_bytes()


def test_embedded_7z_sfx_with_opaque_camouflaged_members_runs_full_pipeline(tmp_path):
    case = ArchiveFixtureFactory().create(
        tmp_path,
        "embedded_sfx_source",
        "7z",
        payload_size=3 * MIB,
    )
    sfx_module = get_test_tools()["seven_zip_sfx"]
    assert sfx_module is not None and sfx_module.is_file()
    logical = sfx_module.read_bytes() + case.entry_path.read_bytes()
    split_size = MIB
    mixed = tmp_path / "sfx_mixed"
    mixed.mkdir()
    parts = []
    for number, offset in enumerate(range(0, len(logical), split_size), start=1):
        marker = "exe" if number == 1 else "7z"
        target = mixed / f"shared.bundle.{marker}.part{number}.useless.fake"
        target.write_bytes(logical[offset : offset + split_size])
        parts.append(target)
    assert len(parts) >= 3

    config = normalize_config(
        with_detection_pipeline(
            {
                "verification": {"enabled": False, "methods": []},
            },
            precheck=[
                {"name": "size_range", "enabled": True, "gte": 0},
                {"name": "seven_zip_structure_accept", "enabled": True},
                {"name": "embedded_payload_identity", "enabled": True},
            ],
        )
    )
    tasks = ArchiveTaskProvider(config).scan_targets([str(mixed)])

    assert len(tasks) == 1
    descriptor = tasks[0].archive_input()
    assert descriptor.format_hint == "7z"
    assert descriptor.part_paths() == [str(path) for path in parts]
    assert [part.volume_number for part in descriptor.parts] == list(range(1, len(parts) + 1))

    extractor = ExtractionScheduler(max_retries=0)
    output = tmp_path / "sfx_output"
    try:
        extraction = extractor.extract(tasks[0], str(output))
    finally:
        extractor.close()

    assert extraction.success is True
    marker = next(output.rglob(case.marker_name))
    assert marker.read_text(encoding="utf-8") == case.marker_text


@pytest.mark.skipif(get_optional_winrar() is None, reason="WinRAR is required to generate RAR SFX")
def test_raw_split_rar_sfx_with_opaque_camouflaged_members_runs_full_pipeline(tmp_path):
    winrar = get_optional_winrar()
    assert winrar is not None
    source = tmp_path / "rar_sfx_source"
    source.mkdir()
    payload = source / "rar-sfx-payload.bin"
    payload.write_bytes(bytes((index * 73 + 29) & 0xFF for index in range(3 * MIB)))
    logical_sfx = tmp_path / "raw-split-rar.exe"
    result = subprocess.run(
        [
            str(winrar),
            "a",
            "-sfx",
            "-m0",
            "-inul",
            str(logical_sfx),
            str(payload),
        ],
        cwd=str(source),
        capture_output=True,
        timeout=60,
    )
    assert result.returncode == 0

    split_size = MIB
    mixed = tmp_path / "rar_sfx_mixed"
    mixed.mkdir()
    logical = logical_sfx.read_bytes()
    parts = []
    for number, offset in enumerate(range(0, len(logical), split_size), start=1):
        marker = "exe" if number == 1 else "rar"
        target = mixed / f"shared.bundle.{marker}.part{number}.useless.fake"
        target.write_bytes(logical[offset : offset + split_size])
        parts.append(target)
    assert len(parts) >= 3

    config = normalize_config(
        with_detection_pipeline(
            {
                "verification": {"enabled": False, "methods": []},
            },
            precheck=[
                {"name": "size_range", "enabled": True, "gte": 0},
                {"name": "rar_structure_accept", "enabled": True},
                {"name": "embedded_payload_identity", "enabled": True},
            ],
        )
    )
    tasks = ArchiveTaskProvider(config).scan_targets([str(mixed)])

    assert len(tasks) == 1
    descriptor = tasks[0].archive_input()
    assert descriptor.format_hint == "rar"
    assert descriptor.part_paths() == [str(path) for path in parts]
    assert [part.volume_number for part in descriptor.parts] == list(range(1, len(parts) + 1))

    extractor = ExtractionScheduler(max_retries=0)
    output = tmp_path / "rar_sfx_output"
    try:
        extraction = extractor.extract(tasks[0], str(output))
    finally:
        extractor.close()

    assert extraction.success is True
    extracted = next(output.rglob(payload.name))
    assert extracted.read_bytes() == payload.read_bytes()


def test_encrypted_plain_and_sfx_volume_matrix_with_shared_stem_and_noisy_suffixes(tmp_path):
    """Real tools, one directory, one primary stem, mixed wrong/right passwords."""

    fixture_root = tmp_path / "fixtures"
    mixed = tmp_path / "mixed"
    mixed.mkdir()
    factory = ArchiveFixtureFactory()
    variants = [
        ("plain7z", "7z", False),
        ("sfx7z", "7z", True),
        ("plainzip", "zip", False),
        ("sfxzip", "zip", True),
        ("plainrar", "rar", False),
        ("sfxrar", "rar", True),
    ]
    passwords = {variant: f"correct-{variant}-password" for variant, _format, _sfx in variants}
    cases = {}
    expected_parts: dict[str, list[Path]] = {}

    for variant, archive_format, sfx in variants:
        try:
            case = factory.create(
                fixture_root,
                f"encrypted_{variant}",
                archive_format,
                password=passwords[variant],
                split=True,
                sfx=sfx,
                payload_size=5 * MIB + MIB // 2,
                split_volume_size=2 * MIB,
            )
        except (FileNotFoundError, RuntimeError) as exc:
            pytest.skip(str(exc))
        cases[variant] = case
        renamed_parts = []
        for fallback, source_part in enumerate(sorted(case.archive_dir.iterdir()), start=1):
            number = _source_volume_number(source_part.name, 0)
            if number <= 0:
                # Current 7-Zip SFX distributions contain a small launcher in
                # addition to the actual encrypted volume set. Keep it in the
                # mixed directory, but it is not an archive data volume.
                launcher = mixed / f"shared.{variant}.launcher.exe.unused.fake"
                source_part.replace(launcher)
                continue
            target = mixed / (
                f"shared.{variant}.{archive_format}.part{number}."
                f"unused-{fallback}.download.fake"
            )
            source_part.replace(target)
            renamed_parts.append(target)
        renamed_parts.sort(key=lambda path: _source_volume_number(path.name, 0))
        assert len(renamed_parts) >= 3
        assert all(path.stat().st_size > MIB for path in renamed_parts)
        expected_parts[variant] = renamed_parts

    wrong_passwords = [f"wrong-password-{index:02d}" for index in range(12)]
    password_candidates = [
        wrong_passwords[0],
        passwords["plainrar"],
        *wrong_passwords[1:6],
        passwords["sfx7z"],
        passwords["plainzip"],
        *wrong_passwords[6:],
        passwords["plain7z"],
        passwords["sfxrar"],
        passwords["sfxzip"],
    ]
    (mixed / ".sunpack-passwords.txt").write_text(
        "\n".join(password_candidates) + "\n",
        encoding="utf-8",
    )

    config = normalize_config(
        with_detection_pipeline(
            {
                "verification": {"enabled": False, "methods": []},
                "process": {},
            },
            precheck=[
                {"name": "size_range", "enabled": True, "gte": 0},
                {"name": "seven_zip_structure_accept", "enabled": True},
                {"name": "zip_structure_accept", "enabled": True},
                {"name": "rar_structure_accept", "enabled": True},
                {"name": "embedded_payload_identity", "enabled": True},
            ],
        )
    )
    tasks = ArchiveTaskProvider(config).scan_targets([str(mixed)])
    split_tasks = [task for task in tasks if len(task.archive_input().parts) >= 3]

    assert len(split_tasks) == len(variants)
    task_by_variant = {}
    for variant, paths in expected_parts.items():
        expected = {str(path) for path in paths}
        matches = [
            task
            for task in split_tasks
            if set(task.archive_input().part_paths()) == expected
        ]
        assert len(matches) == 1, (variant, [task.archive_input().part_paths() for task in split_tasks])
        task_by_variant[variant] = matches[0]

    planner = ArchiveInputPlanningStage(config)
    for variant in list(task_by_variant):
        planned = planner.plan_task_to_tasks(task_by_variant[variant])
        assert len(planned) == 1
        task_by_variant[variant] = planned[0]

    planned_tasks = list(task_by_variant.values())
    DirectoryPasswordContextStore(config).annotate(planned_tasks)
    extractor = ExtractionScheduler(
        max_retries=1,
        process_config={},
        extraction_config=config.get("extraction"),
    )
    try:
        for variant, _archive_format, _sfx in variants:
            output = tmp_path / "outputs" / variant
            result = extractor.extract(task_by_variant[variant], str(output))
            assert result.success is True, (variant, result.error, result.diagnostics)
            assert result.password_used == passwords[variant]
            marker = next(output.rglob(cases[variant].marker_name))
            assert marker.read_text(encoding="utf-8") == cases[variant].marker_text
    finally:
        extractor.close()


def _mixed_real_volume_directory(tmp_path: Path):
    factory = ArchiveFixtureFactory()
    common = tmp_path / "mixed"
    common.mkdir()
    cases = {}
    paths_by_format = {}
    payload_size = 9 * MIB + MIB // 2
    split_size = 2 * MIB

    for archive_format in ("7z", "zip", "rar"):
        case = factory.create(
            tmp_path,
            f"source_{archive_format}",
            archive_format,
            split=True,
            payload_size=payload_size,
            split_volume_size=split_size,
        )
        original_parts = sorted(path for path in case.archive_dir.iterdir() if path.is_file())
        renamed = []
        for fallback_number, source in enumerate(original_parts, start=1):
            number = _source_volume_number(source.name, fallback_number)
            if archive_format == "rar":
                target_name = f"shared.gamma.part{number}.rar.trash.pkg"
            else:
                noise = "alpha" if archive_format == "7z" else "beta"
                suffix = "noise.bin" if archive_format == "7z" else "junk.dat"
                target_name = f"shared.{noise}.{archive_format}.{number:03d}.{suffix}"
            target = common / target_name
            source.replace(target)
            renamed.append(target)
        cases[archive_format] = case
        paths_by_format[archive_format] = sorted(renamed, key=lambda path: _source_volume_number(path.name, 0))

    for name in (
        "shared.alpha.7z.999.noise.bin",
        "shared.beta.zip.999.junk.dat",
    ):
        with (common / name).open("wb") as stream:
            stream.truncate(MIB + 1)

    return common, cases, paths_by_format


def _source_volume_number(name: str, fallback: int) -> int:
    for pattern in (r"\.part(\d+)", r"\.(\d{3})(?:\.|$)"):
        match = re.search(pattern, name, re.IGNORECASE)
        if match:
            return int(match.group(1))
    return fallback
