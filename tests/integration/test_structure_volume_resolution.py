from __future__ import annotations

import asyncio
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from sunpack.core.config.loader import load_config
from sunpack.core.config.schema import normalize_config
from sunpack.core.contracts.filesystem import DirectorySnapshot, FileEntry
from sunpack.core.passwords.directory_context import DirectoryPasswordContextStore
from sunpack.pipeline.coordinator.engine import PipelineEngine
from sunpack.pipeline.coordinator.target_groups import relation_group_to_candidate
from sunpack.pipeline.coordinator.task_provider import ArchiveTaskProvider
from sunpack.pipeline.coordinator.task_scan import direct_file_task
from sunpack.pipeline.discovery.detection.input_planning import (
    ArchiveInputPlanningStage,
)
from sunpack.pipeline.discovery.filesystem.directory_scanner import DirectoryScanner
from sunpack.pipeline.discovery.relations import RelationsScheduler
from sunpack.pipeline.discovery.relations.resolver import RelationResolver
from sunpack.pipeline.extraction.scheduler import ExtractionScheduler
from tests.helpers.config_factory import make_config
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

        candidate = relation_group_to_candidate(group)
        resolved = RelationResolver().resolve([candidate]).resolved_tasks
        assert len(resolved) == 1
        task = resolved[0]
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


@pytest.mark.parametrize("archive_format", ("7z", "zip", "rar"))
@pytest.mark.parametrize("name_style", (
    "format_number", "number_only", "extensionless_head", "invalid_number_noise",
    "bare_format_head",
    "context_free_numbers", "monotonic_filename_tiers",
))
def test_first_dot_stem_and_loose_format_markers_resolve_real_volume_sets(
    tmp_path, archive_format, name_style
):
    """Probe the requested filename tolerance against real split archives."""
    factory = ArchiveFixtureFactory()
    scheduler = RelationsScheduler()

    try:
        case = factory.create(
            tmp_path,
            f"first_dot_{archive_format}",
            archive_format,
            split=True,
            payload_size=1024 * 1024,
            split_volume_size=256 * 1024,
        )
    except (FileNotFoundError, RuntimeError) as exc:
        pytest.skip(str(exc))

    renamed = []
    originals = sorted(path for path in case.archive_dir.iterdir() if path.is_file())
    for index, source in enumerate(originals, start=1):
        number = _source_volume_number(source.name, index)
        if name_style in {"context_free_numbers", "monotonic_filename_tiers"}:
            if number == 1:
                target_name = "shared.header1"
            elif name_style == "monotonic_filename_tiers" and number == 2:
                target_name = f"shared.{archive_format}.002"
            elif name_style == "monotonic_filename_tiers" and number == 3:
                target_name = "shared.header3"
            else:
                target_name = f"shared.zero0.segment{chr(96 + number)}{number:04d}data"
        elif name_style == "bare_format_head" and number == 1:
            target_name = f"shared.{archive_format}"
        elif name_style == "extensionless_head" and number == 1:
            target_name = "shared"
        elif name_style == "invalid_number_noise":
            target_name = f"shared.zero0.build4294967296.chunk{number}.opaque"
        elif name_style != "format_number":
            target_name = f"shared.noise{index}.chunk{number}.opaque"
        elif archive_format == "rar":
            # RAR's requested filename signal is only part + number.
            target_name = f"shared.noise{index}.part{number}.opaque"
        elif archive_format == "7z":
            # The format and a non-zero-padded number appear in the suffix.
            target_name = f"shared.noise{index}.7z.chunk{number}.opaque"
        else:
            # ZIP reverses the format/number order and changes the noise.
            target_name = f"shared.noise{index}.chunk{number}.zip.opaque"
        target = case.archive_dir / target_name
        source.rename(target)
        renamed.append((number, target))

    renamed.sort(key=lambda item: item[0])
    first_path = str(renamed[0][1])
    all_paths = [str(path) for _number, path in renamed]
    group = scheduler.resolve_volume_once(
        [first_path],
        all_paths,
        format_hint=archive_format,
    )

    assert group is not None, (archive_format, [path.name for _number, path in renamed])
    assert set(group.input_paths) == set(all_paths)
    assert group.logical_name == "shared"
    assert [volume.number for volume in group.split_volumes] == [
        number for number, _path in renamed
    ]
    resolved = RelationResolver().resolve([relation_group_to_candidate(group)]).resolved_tasks
    assert len(resolved) == 1
    planned = ArchiveInputPlanningStage(load_config()).plan_task_to_tasks(resolved[0])
    assert len(planned) == 1
    output = tmp_path / "output"
    extractor = ExtractionScheduler(max_retries=0)
    try:
        result = extractor.extract(planned[0], str(output))
    finally:
        extractor.close()
    assert result.success is True, result.error
    assert next(output.rglob(case.marker_name)).read_text(encoding="utf-8") == case.marker_text


@pytest.mark.parametrize("archive_format", ("7z", "zip"))
def test_context_free_numbers_preserve_encrypted_sfx_launcher_ownership(tmp_path, archive_format):
    password = "context-free-encrypted-sfx"
    case = ArchiveFixtureFactory().create(
        tmp_path, f"loose_sfx_{archive_format}", archive_format,
        split=True, sfx=True, password=password,
        payload_size=MIB, split_volume_size=MIB // 4,
    )
    renamed = []
    launcher = None
    for source in sorted(case.archive_dir.iterdir()):
        number = _source_volume_number(source.name, 0)
        if number == 0:
            launcher = source.replace(case.archive_dir / "shared.exe")
            continue
        name = "shared.header1" if number == 1 else f"shared.blob{chr(96 + number)}{number:04d}tail"
        renamed.append((number, source.replace(case.archive_dir / name)))
    renamed.sort()
    assert launcher is not None
    paths = [str(path) for _, path in renamed]
    group = RelationsScheduler().resolve_volume_once(
        [paths[0]], paths + [str(launcher)], format_hint=archive_format,
    )
    assert group is not None
    assert group.input_paths == paths
    assert group.carrier_path == str(launcher)
    assert set(group.owned_paths) == set(paths + [str(launcher)])
    tasks = RelationResolver().resolve([relation_group_to_candidate(group)]).resolved_tasks
    assert len(tasks) == 1
    planned = ArchiveInputPlanningStage(load_config()).plan_task_to_tasks(tasks[0])
    assert len(planned) == 1
    extractor = ExtractionScheduler(cli_passwords=["wrong", password], builtin_passwords=[], max_retries=1)
    output = tmp_path / "output"
    try:
        result = extractor.extract(planned[0], str(output))
    finally:
        extractor.close()
    assert result.success is True, result.error
    assert result.password_used == password
    assert next(output.rglob(case.marker_name)).read_text(encoding="utf-8") == case.marker_text


def test_context_free_numeric_noise_does_not_create_a_missing_7z_volume(tmp_path):
    case = ArchiveFixtureFactory().create(
        tmp_path, "loose_numeric_slot_noise", "7z", split=True,
        payload_size=MIB // 2, split_volume_size=MIB // 4,
    )
    originals = sorted(case.archive_dir.iterdir())
    assert len(originals) == 3
    names = ("shared.header1", "shared.x2.y03", "shared.z3.w0004")
    parts = [source.replace(case.archive_dir / name) for source, name in zip(originals, names)]
    noise = case.archive_dir / "shared.notes"
    noise.write_text("unrelated same-stem notes", encoding="utf-8")
    paths = [str(path) for path in parts]
    group = RelationsScheduler().resolve_volume_once(
        [paths[0]], paths + [str(noise)], format_hint="7z",
    )
    assert group is not None
    assert group.input_paths == paths
    assert [volume.number for volume in group.split_volumes] == [1, 2, 3]
    assert set(group.owned_paths) == set(paths)
    resolved = RelationResolver().resolve([relation_group_to_candidate(group)]).resolved_tasks
    assert len(resolved) == 1
    planned = ArchiveInputPlanningStage(load_config()).plan_task_to_tasks(resolved[0])
    assert len(planned) == 1
    output = tmp_path / "output"
    extractor = ExtractionScheduler(max_retries=0)
    try:
        result = extractor.extract(planned[0], str(output))
    finally:
        extractor.close()
    assert result.success is True, result.error
    assert next(output.rglob(case.marker_name)).read_text(encoding="utf-8") == case.marker_text
    assert next(output.rglob("payload.bin")).stat().st_size == MIB // 2
    assert noise.read_text(encoding="utf-8") == "unrelated same-stem notes"


def test_same_stem_opaque_members_with_competing_formats_are_not_guessed(tmp_path):
    mixed = tmp_path / "mixed"
    mixed.mkdir()
    paths_by_format = {}
    for archive_format in ("7z", "zip"):
        case = ArchiveFixtureFactory().create(
            tmp_path, f"ambiguous_{archive_format}", archive_format,
            split=True, payload_size=MIB, split_volume_size=MIB // 4,
        )
        paths = []
        for index, source in enumerate(sorted(case.archive_dir.iterdir()), start=1):
            number = _source_volume_number(source.name, index)
            # Both formats would own the same numeric slots; opaque suffixes
            # provide no format fact with which to split those slots.
            label = "alpha" if archive_format == "7z" else "beta"
            target = mixed / f"shared.noise{chr(96 + number)}.source-{label}.chunk{number}.opaque"
            source.rename(target)
            paths.append(target)
        paths_by_format[archive_format] = paths

    all_paths = [str(path) for paths in paths_by_format.values() for path in paths]
    for archive_format, paths in paths_by_format.items():
        group = RelationsScheduler().resolve_volume_once(
            [str(paths[0])], all_paths, format_hint=archive_format,
        )
        assert group is not None
        assert group.head_metadata["volume_set_incomplete"] is True
        assert set(group.input_paths) <= {str(paths[0]), str(paths[-1])}


@pytest.mark.parametrize("formats", [("7z", "7z"), ("7z", "zip"), ("7z", "rar")])
@pytest.mark.parametrize("name_style", ["standard", "prefix", "shape", "marker_shape"])
def test_competing_heads_keep_direct_schemes_and_partition_declared_formats(tmp_path, formats, name_style):
    mixed = tmp_path / "mixed"
    mixed.mkdir()
    sets = []
    cases = []
    for label, archive_format in zip(("alpha", "beta"), formats):
        case = ArchiveFixtureFactory().create(
            tmp_path, label, archive_format, split=True,
            payload_size=MIB, split_volume_size=MIB // 4,
        )
        paths = []
        for index, source in enumerate(sorted(case.archive_dir.iterdir()), start=1):
            number = _source_volume_number(source.name, index)
            if name_style == "standard":
                name = f"shared.{label}.{archive_format}.{number:03d}.opaque"
            elif name_style == "prefix":
                name = f"shared.{label}.chunk{number}.opaque"
            elif name_style == "marker_shape":
                name = f"shared.part{number}.{label}.opaque"
            else:
                name = f"shared.chunk{number}.{label}.opaque"
            if formats[0] != formats[1] and name_style != "standard":
                name += f".{archive_format}"
            target = mixed / name
            source.rename(target)
            paths.append(target)
        sets.append(paths)
        cases.append(case)

    all_paths = [str(path) for paths in sets for path in paths]
    logical_names = set()
    for paths, archive_format, case, label in zip(sets, formats, cases, ("alpha", "beta")):
        group = RelationsScheduler().resolve_volume_once(
            [str(paths[0])], all_paths, format_hint=archive_format,
        )
        if formats[0] == formats[1] and name_style != "standard":
            assert group is None
            continue
        assert group is not None
        assert set(group.input_paths) == {str(path) for path in paths}
        if name_style == "standard":
            assert label in group.logical_name
        assert "\0" not in group.logical_name
        logical_names.add(group.logical_name)
        tasks = RelationResolver().resolve([relation_group_to_candidate(group)]).resolved_tasks
        assert len(tasks) == 1
        planned = ArchiveInputPlanningStage(load_config()).plan_task_to_tasks(tasks[0])
        assert len(planned) == 1
        output = tmp_path / "outputs" / case.case_id
        extractor = ExtractionScheduler(max_retries=0)
        try:
            result = extractor.extract(planned[0], str(output))
        finally:
            extractor.close()
        assert result.success is True, result.error
        assert next(output.rglob(case.marker_name)).read_text(encoding="utf-8") == case.marker_text
    if name_style == "standard":
        assert len(logical_names) == 2


@pytest.mark.parametrize("competing", [False, True])
@pytest.mark.parametrize("sfx", [False, True])
@pytest.mark.parametrize("marker", [1, 99])
def test_rar_structure_overrides_false_part_marker(tmp_path, competing, sfx, marker):
    factory = ArchiveFixtureFactory()
    case = factory.create(tmp_path, "alpha", "rar", split=True, sfx=sfx,
        payload_size=MIB, split_volume_size=MIB // 4)
    mixed = tmp_path / "mixed"
    mixed.mkdir()
    paths = []
    for index, source in enumerate(sorted(case.archive_dir.iterdir()), start=1):
        number = _source_volume_number(source.name, index)
        target = mixed / f"shared.alpha.part{marker}.chunk{number}.opaque"
        source.rename(target)
        paths.append((number, target))
    paths.sort()
    all_paths = [str(path) for _, path in paths]
    if competing:
        other = factory.create(tmp_path, "beta", "7z", split=True,
            payload_size=MIB, split_volume_size=MIB // 4)
        for index, source in enumerate(sorted(other.archive_dir.iterdir()), start=1):
            number = _source_volume_number(source.name, index)
            target = mixed / f"shared.beta.7z.chunk{number}.opaque"
            source.rename(target)
            all_paths.append(str(target))
    group = RelationsScheduler().resolve_volume_once(
        [str(paths[0][1])], all_paths, format_hint="rar")
    assert group is not None
    assert set(group.input_paths) == {str(path) for _, path in paths}
    assert [part.number for part in group.split_volumes] == [number for number, _ in paths]
    assert all(part.source == "structure" for part in group.split_volumes)
    tasks = RelationResolver().resolve([relation_group_to_candidate(group)]).resolved_tasks
    assert len(tasks) == 1
    planned = ArchiveInputPlanningStage(load_config()).plan_task_to_tasks(tasks[0])
    assert len(planned) == 1
    output = tmp_path / "output"
    extractor = ExtractionScheduler(max_retries=0)
    try:
        result = extractor.extract(planned[0], str(output))
    finally:
        extractor.close()
    assert result.success is True, result.error
    assert next(output.rglob(case.marker_name)).read_text(encoding="utf-8") == case.marker_text


@pytest.mark.parametrize("archive_format", ["7z", "zip"])
@pytest.mark.parametrize("sfx", [False, True])
@pytest.mark.parametrize("password", [None, "number-position-password"])
def test_structural_head_number_position_orders_real_opaque_members(tmp_path, archive_format, sfx, password):
    case = ArchiveFixtureFactory().create(tmp_path, "position", archive_format,
        split=True, sfx=sfx, password=password, payload_size=MIB, split_volume_size=MIB // 4)
    paths = []
    for index, source in enumerate(sorted(case.archive_dir.iterdir()), start=1):
        number = _source_volume_number(source.name, 0)
        if number == 0:
            source.rename(case.archive_dir / "shared.exe")
            continue
        # All opaque middle volumes have a false part99 marker. Padding can
        # change without changing the number position learned from the head.
        token = str(number).zfill(2 if number % 2 else 3)
        target = case.archive_dir / f"shared.part99.chunk{token}.opaque"
        source.rename(target)
        paths.append((number, target))
    paths.sort()
    inputs = [str(path) for _, path in paths]
    passwords = {path: password for path in inputs} if password else None
    group = RelationsScheduler().resolve_volume_once(
        [inputs[0]], inputs, format_hint=archive_format, path_passwords=passwords)
    assert group is not None
    assert set(group.input_paths) == set(inputs)
    assert [part.number for part in group.split_volumes] == [number for number, _ in paths]
    assert group.head_metadata.get("volume_set_incomplete") is not True
    if password:
        (case.archive_dir / "sunpack-passwords.txt").write_text(
            f"wrong-password\n{password}\n", encoding="utf-8")
    tasks = RelationResolver().resolve([relation_group_to_candidate(group)]).resolved_tasks
    assert len(tasks) == 1
    config = load_config()
    planned = ArchiveInputPlanningStage(config).plan_task_to_tasks(tasks[0])
    assert len(planned) == 1
    DirectoryPasswordContextStore(config).annotate(planned)
    extractor = ExtractionScheduler(max_retries=0)
    output = tmp_path / "output"
    try:
        result = extractor.extract(planned[0], str(output))
    finally:
        extractor.close()
    assert result.success is True, result.error
    assert next(output.rglob(case.marker_name)).read_text(encoding="utf-8") == case.marker_text


@pytest.mark.parametrize("archive_format", ["7z", "zip"])
def test_multiple_matching_seed_numbers_resolve_the_unique_global_channel(tmp_path, archive_format):
    case = ArchiveFixtureFactory().create(tmp_path, "ambiguous_position", archive_format,
        split=True, payload_size=MIB, split_volume_size=MIB // 4)
    paths = []
    for index, source in enumerate(sorted(case.archive_dir.iterdir()), start=1):
        number = _source_volume_number(source.name, index)
        target = case.archive_dir / f"shared.part99.build1.chunk{number}.opaque"
        source.rename(target)
        paths.append(str(target))
    group = RelationsScheduler().resolve_volume_once(
        [paths[0]], paths, format_hint=archive_format)
    assert group is not None
    assert group.input_paths == paths
    assert [volume.number for volume in group.split_volumes] == list(range(1, len(paths) + 1))
    assert group.head_metadata.get("volume_set_incomplete") is not True


def test_distinct_global_mappings_remain_blocked_and_cannot_be_resolved(tmp_path):
    case = ArchiveFixtureFactory().create(
        tmp_path, "two_channels", "7z", split=True,
        payload_size=MIB, split_volume_size=MIB // 4,
    )
    paths = []
    for number, source in enumerate(sorted(case.archive_dir.iterdir()), start=1):
        alternative = {2: 3, 3: 2}.get(number, number)
        target = case.archive_dir / f"shared.build{number}.chunk{alternative}.opaque"
        source.rename(target)
        paths.append(str(target))
    assert len(paths) >= 3
    scheduler = RelationsScheduler()
    groups = scheduler.build_candidate_groups(DirectoryScanner(str(case.archive_dir), config=make_config()).scan())
    group = next(group for group in groups if group.head_path == paths[0])
    assert group.head_metadata["relation_failure_reason"] == "ambiguous_volume_mapping"
    assert group.head_metadata["volume_set_incomplete"] is True
    assert group.head_metadata["relation_confirmed"] is False
    result = RelationResolver().resolve([relation_group_to_candidate(group)])
    assert not result.resolved_tasks
    assert result.blocked_paths
    assert scheduler.resolve_volume_once([paths[0]], paths, format_hint="7z") is None


@pytest.mark.parametrize("archive_format", ["7z", "zip"])
def test_volume_retry_can_start_from_a_verified_launcher_companion(tmp_path, archive_format):
    case = ArchiveFixtureFactory().create(
        tmp_path, "launcher_retry", archive_format, sfx=True, split=True,
        payload_size=256 * 1024, split_volume_size=64 * 1024,
    )
    launcher = str(case.entry_path)
    paths = [str(path) for path in case.archive_dir.iterdir()]
    group = RelationsScheduler().resolve_volume_once([launcher], paths, format_hint=archive_format)
    assert group is not None
    assert group.companion_paths == [launcher]
    assert launcher not in group.input_paths
    assert group.head_metadata["relation_confirmed"] is True
    assert [part.number for part in group.split_volumes] == list(range(1, len(group.split_volumes) + 1))
    task = direct_file_task(launcher, all_parts=paths)
    assert task.carrier_path == launcher
    assert launcher in task.cleanup_parts
    assert launcher not in task.all_parts


def test_extra_numeric_tail_cannot_bypass_seven_zip_size_validation(tmp_path):
    factory = ArchiveFixtureFactory()
    case = factory.create(tmp_path, "valid", "7z", split=True,
        payload_size=MIB, split_volume_size=MIB // 4)
    other = factory.create(tmp_path, "extra", "7z", split=True,
        payload_size=MIB, split_volume_size=MIB // 4)
    paths = []
    for number, source in enumerate(sorted(case.archive_dir.iterdir()), start=1):
        target = case.archive_dir / f"shared.chunk{number}.opaque"
        source.rename(target)
        paths.append(str(target))
    extra = case.archive_dir / "shared.chunk999.opaque"
    sorted(other.archive_dir.iterdir())[-1].rename(extra)
    paths.append(str(extra))
    assert RelationsScheduler().resolve_volume_once([paths[0]], paths, format_hint="7z") is None


@pytest.mark.parametrize("sfx_format", ["7z", "rar"])
@pytest.mark.parametrize("failed_relation", ["incomplete", "rejected"])
def test_failed_split_relation_preserves_standalone_sfx(tmp_path, sfx_format, failed_relation):
    factory = ArchiveFixtureFactory()
    standalone = factory.create(tmp_path, "standalone", sfx_format, sfx=True, payload_size=MIB)
    split = factory.create(tmp_path, "split", "7z", split=True,
        payload_size=MIB, split_volume_size=MIB // 4)
    mixed = tmp_path / "mixed"
    mixed.mkdir()
    launcher = mixed / "shared.exe"
    standalone.entry_path.rename(launcher)
    parts = sorted(split.archive_dir.iterdir())
    parts[0].rename(mixed / "shared.7z.001")
    if failed_relation == "incomplete":
        parts[1].rename(mixed / "shared.7z.002")
    else:
        oversized = factory.create(tmp_path, "oversized", "7z", split=True,
            payload_size=4 * MIB, split_volume_size=2 * MIB)
        sorted(oversized.archive_dir.iterdir())[0].rename(mixed / "shared.7z.002")

    config = make_config({"filesystem": {"scan_filters": []}})
    groups = RelationsScheduler().build_candidate_groups(
        DirectoryScanner(str(mixed), config=config).scan(),
    )
    matches = [group for group in groups if group.head_path == str(launcher)]
    assert len(matches) == 1
    assert matches[0].kind == "file"
    assert matches[0].input_paths == [str(launcher)]
    assert matches[0].head_metadata["relation_confirmed"] is True


def test_opaque_members_cannot_be_guessed_across_password_blocked_formats(tmp_path):
    factory = ArchiveFixtureFactory()
    seven_zip = factory.create(tmp_path, "plain", "7z", split=True,
        payload_size=MIB, split_volume_size=MIB // 4)
    encrypted_rar = factory.create(tmp_path, "encrypted", "rar", split=True,
        password="candidate-password", payload_size=MIB, split_volume_size=MIB // 4)
    mixed = tmp_path / "mixed"
    mixed.mkdir()
    paths = []
    for index, source in enumerate(sorted(seven_zip.archive_dir.iterdir()), start=1):
        number = _source_volume_number(source.name, index)
        name = "shared.7z.part1.opaque" if number == 1 else f"shared.part{number}.opaque"
        target = mixed / name
        source.rename(target)
        paths.append(target)
    rar_head = mixed / "shared.rar.part1.opaque"
    sorted(encrypted_rar.archive_dir.iterdir())[0].rename(rar_head)
    all_paths = [str(path) for path in paths] + [str(rar_head)]
    group = RelationsScheduler().resolve_volume_once([str(paths[0])], all_paths, format_hint="7z")
    assert group is not None
    assert group.input_paths == [str(paths[0])]
    assert group.head_metadata["volume_set_incomplete"] is True


def test_loose_rar_names_reconcile_after_missing_middle_volume_arrives(tmp_path):
    case = ArchiveFixtureFactory().create(
        tmp_path, "gap", "rar", split=True,
        payload_size=MIB, split_volume_size=MIB // 4,
    )
    paths = []
    for index, source in enumerate(sorted(case.archive_dir.iterdir()), start=1):
        number = _source_volume_number(source.name, index)
        target = case.archive_dir / f"shared.noise{number}.chunk{number}.opaque"
        source.rename(target)
        paths.append(target)
    middle = paths[1]
    withheld = tmp_path / "withheld"
    middle.rename(withheld)
    scheduler = RelationsScheduler()
    incomplete = scheduler.resolve_volume_once(
        [str(paths[0])], [str(path) for path in paths if path.exists()], format_hint="rar",
    )
    assert incomplete is not None
    assert incomplete.head_metadata["volume_set_incomplete"] is True

    withheld.rename(middle)
    complete = scheduler.resolve_volume_once(
        [str(paths[0])], [str(path) for path in paths], format_hint="rar",
    )
    assert complete is not None
    assert not complete.head_metadata.get("volume_set_incomplete", False)
    assert set(complete.input_paths) == {str(path) for path in paths}


def test_mixed_directory_schedules_only_one_structural_head_per_format(mixed_real_volumes):
    _tmp_path, common, _cases, paths_by_format = mixed_real_volumes
    config = normalize_config(
        with_detection_pipeline(
            {},
            precheck=[
                {"name": "size_range", "enabled": True, "gte": 0},
                {"name": "relation_archive_accept", "enabled": True},
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
                {"name": "relation_archive_accept", "enabled": True},
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


def test_pipeline_middle_volume_target_exposes_resolved_physical_family(mixed_real_volumes):
    tmp_path, common, _cases, paths_by_format = mixed_real_volumes
    parts = paths_by_format["7z"]
    assert len(parts) >= 2
    selected = parts[1]
    output_root = tmp_path / "pipeline_middle_volume_output"
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
                {"name": "relation_archive_accept", "enabled": True},
            ],
        )
    )

    async def run():
        async with PipelineEngine(config) as engine:
            return await asyncio.wait_for(engine.run([str(selected)]), 60)

    response = asyncio.run(run())

    assert response.summary.success_count == 1
    assert response.discovery.entry_paths == (str(selected),)
    assert set(response.discovery.claimed_paths) == {str(path) for path in parts}
    assert response.discovery.blocked_paths == ()


def test_real_strict_middle_gap_is_emitted_as_an_incomplete_relation_group(tmp_path):
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
        DirectoryScanner(str(case.archive_dir), config=make_config()).scan()
    )
    remaining = {str(path) for path in parts if path.exists()}
    split = [group for group in groups if group.is_split_candidate]
    assert len(split) == 1
    assert set(split[0].input_paths) == remaining
    assert split[0].head_metadata["volume_set_incomplete"] is True
    assert [volume.number for volume in split[0].split_volumes] == [1, 3, 4, 5]


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
    assert group.head_metadata["volume_set_incomplete"] is True
    assert group.input_paths == [str(path) for path in renamed]


def test_structure_resolution_stays_within_the_head_parent_directory(
    mixed_real_volumes, tmp_path
):
    """A same-stem first volume in another directory cannot affect resolution."""
    _fixture_root, _common, _cases, paths_by_format = mixed_real_volumes
    scan_root = tmp_path / "directory_scope"
    first_directory = scan_root / "first"
    second_directory = scan_root / "second"
    first_directory.mkdir(parents=True)
    second_directory.mkdir()

    source_parts = paths_by_format["7z"]
    source_by_number = {
        _source_volume_number(path.name, index): path
        for index, path in enumerate(source_parts, start=1)
    }
    assert 1 in source_by_number and 3 in source_by_number
    first_parts = []
    for number in (1, 3):
        target = first_directory / source_by_number[number].name
        shutil.copy2(source_by_number[number], target)
        first_parts.append(target)
    foreign_first = second_directory / first_parts[0].name
    shutil.copy2(first_parts[0], foreign_first)

    all_paths = [str(path) for path in [*first_parts, foreign_first]]
    scheduler = RelationsScheduler()
    direct_group = scheduler.resolve_volume_once(
        [str(first_parts[0])],
        all_paths,
        format_hint="7z",
    )
    assert direct_group is not None
    assert direct_group.head_metadata["volume_set_incomplete"] is True
    assert str(foreign_first) not in direct_group.input_paths

    entries = [
        FileEntry(path=path, is_dir=False, size=path.stat().st_size, mtime_ns=path.stat().st_mtime_ns)
        for path in [*first_parts, foreign_first]
    ]
    snapshot = DirectorySnapshot.from_entries(scan_root, entries)
    groups = scheduler.build_candidate_groups(snapshot)
    assert {path for group in groups for path in group.input_paths} == set(all_paths)
    assert all(group.head_metadata.get("volume_set_incomplete") is True for group in groups)
    assert not any(
        str(foreign_first) in group.input_paths
        and any(str(path) in group.input_paths for path in first_parts)
        for group in groups
    )


def test_structure_resolution_rejects_current_paths_from_different_directories(
    mixed_real_volumes, tmp_path
):
    _fixture_root, _common, _cases, paths_by_format = mixed_real_volumes
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    source = paths_by_format["7z"][0]
    first_path = first / source.name
    second_path = second / source.name
    shutil.copy2(source, first_path)
    shutil.copy2(source, second_path)

    assert RelationsScheduler().resolve_volume_once(
        [str(first_path), str(second_path)],
        [str(first_path), str(second_path)],
        format_hint="7z",
    ) is None


@pytest.mark.skipif(get_optional_winrar() is None, reason="WinRAR is required to generate modern split ZIP")
@pytest.mark.parametrize("opaque_competition", [False, True])
def test_modern_split_zip_with_camouflaged_names_runs_full_pipeline(tmp_path, opaque_competition):
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
        name = (f"shared.chunk{len(renamed) + 1}.zipdata.bin" if opaque_competition
            else f"shared.alpha.{marker}.useless.{len(renamed)}.fake")
        target = mixed / name
        source_part.replace(target)
        renamed.append(target)

    if opaque_competition:
        other = ArchiveFixtureFactory().create(tmp_path, "other", "7z", split=True,
            payload_size=MIB, split_volume_size=MIB // 4)
        for number, part in enumerate(sorted(other.archive_dir.iterdir()), start=1):
            part.rename(mixed / f"shared.chunk{number}.7zdata.bin")

    config = normalize_config(
        with_detection_pipeline(
            {
                "verification": {"enabled": False, "methods": []},
            },
            precheck=[
                {"name": "size_range", "enabled": True, "gte": 0},
                {"name": "relation_archive_accept", "enabled": True},
            ],
        )
    )
    tasks = ArchiveTaskProvider(config).scan_targets([str(mixed)])

    assert len(tasks) == (2 if opaque_competition else 1)
    zip_tasks = [task for task in tasks if task.archive_input().format_hint == "zip"]
    assert len(zip_tasks) == 1
    task = zip_tasks[0]
    assert task.discovery_source == "relations"
    descriptor = task.archive_input()
    assert descriptor.volume_style == "zip_spanned"
    assert [part.volume_number for part in descriptor.parts] == [1, 2, 3, 4]
    assert [part.role for part in descriptor.parts] == ["first", "member", "member", "terminal"]
    logical = "shared" if opaque_competition else "shared.alpha"
    assert task.logical_name == logical
    assert [part.canonical_name for part in descriptor.parts] == [
        f"{logical}.z01", f"{logical}.z02", f"{logical}.z03", f"{logical}.zip",
    ]

    extractor = ExtractionScheduler(max_retries=0)
    output = tmp_path / "output"
    try:
        extraction = extractor.extract(task, str(output))
    finally:
        extractor.close()

    assert extraction.success is True
    extracted = next(output.rglob("payload.bin"))
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
    (mixed / "sunpack-passwords.txt").write_text(
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
                {"name": "relation_archive_accept", "enabled": True},
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

    return common, cases, paths_by_format


def _source_volume_number(name: str, fallback: int) -> int:
    for pattern in (r"\.part(\d+)", r"\.(\d{3})(?:\.|$)"):
        match = re.search(pattern, name, re.IGNORECASE)
        if match:
            return int(match.group(1))
    return fallback
