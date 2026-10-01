from __future__ import annotations

import shutil
import uuid
from dataclasses import dataclass
from pathlib import Path

from tests.helpers.native_fixture import assemble_carrier, assert_exact_tree, file_inventory
from tests.helpers.real_archives import (
    ArchiveCase, ArchiveFixtureFactory, choose_entry_path,
    create_7z_archive, create_rar_archive, create_zip_archive,
)
from tests.real.plan6_confused_volumes.plan6_support import SCENARIOS, apply_volume_confusion


@dataclass(frozen=True)
class NestedCase:
    outer: ArchiveCase
    parts: tuple[Path, ...]
    passwords: tuple[str, str, str]
    ready_marker: str
    ready_files: dict
    blocked: ArchiveCase
    blocked_name: str
    layout: dict


def build_nested_case(root: Path, tag: str, outer_format: str) -> NestedCase:
    """Disguised encrypted split -> carrier -> encrypted 7z -> two ZIP branches.

    Every encryption level has a distinct secret. The healthy ZIP branch must
    survive a failure/retry in its sibling. Only external tools build archives;
    Rust writes the carrier and calculates expected payload hashes.
    """
    secrets = tuple(f"{tag}-{level}-{uuid.uuid4().hex}" for level in ("outer", "middle", "leaf"))
    fixtures = root / f"sources-{tag}"
    ready_source = fixtures / f"ready-{tag}"
    ready_source.mkdir(parents=True)
    ready_marker = f"ready-{tag}.txt"
    (ready_source / ready_marker).write_text(f"healthy sibling::{tag}\n", encoding="utf-8")
    (ready_source / "empty.bin").write_text("", encoding="utf-8")
    ready_files = file_inventory(ready_source)
    branches = fixtures / f"branches-{tag}"
    branches.mkdir()
    create_zip_archive(ready_source, branches / "ready.zip")
    blocked = ArchiveFixtureFactory().create(
        fixtures, f"blocked-{tag}", "zip", password=secrets[2],
        payload_size=192 * 1024, payload_profile="structured",
    )
    blocked_name = f"blocked-{tag}.unrelated"
    shutil.copyfile(blocked.entry_path, branches / blocked_name)
    middle = fixtures / "middle.7z"
    create_7z_archive(branches, middle, password=secrets[1])
    outer_source = fixtures / f"wrapper-{tag}"
    outer_source.mkdir()
    layout = assemble_carrier(outer_source / "nested-picture.jpg", [middle], seed=0x1A2B3C, decoys=True)
    (outer_source / "outer-note.txt").write_text(f"outer::{tag}\n", encoding="utf-8")
    archive_dir = root / f"input-{tag}"
    archive_dir.mkdir()
    writer = {"7z": create_7z_archive, "zip": create_zip_archive, "rar": create_rar_archive}[outer_format]
    writer(
        outer_source, archive_dir / f"{tag}.{outer_format}", password=secrets[0],
        split=True, split_volume_size=40 * 1024,
    )
    outer = ArchiveCase(
        case_id=tag, archive_dir=archive_dir,
        entry_path=choose_entry_path(archive_dir, tag, outer_format),
        marker_name=ready_marker, marker_text=f"healthy sibling::{tag}\n",
        archive_format=outer_format, password=secrets[0], split=True,
    )
    parts = apply_volume_confusion(outer, SCENARIOS[2], add_distractors=False)
    assert len(parts) >= 3, "the lifecycle fixture must really span several volumes"
    return NestedCase(outer, tuple(parts), secrets, ready_marker, ready_files, blocked, blocked_name, layout)


def assert_nested_outputs(root: Path, case: NestedCase, *, leaf_success: bool) -> None:
    ready = list(root.rglob(case.ready_marker))
    assert len(ready) == 1, f"healthy branch missing or extracted more than once: {ready}"
    assert_exact_tree(ready[0].parent, case.ready_files)
    blocked = list(root.rglob(case.blocked.marker_name))
    if leaf_success:
        assert len(blocked) == 1, f"blocked branch missing or extracted more than once: {blocked}"
        assert_exact_tree(blocked[0].parent, case.blocked.metadata["expected_files"])
    else:
        assert blocked == [], "unknown leaf password must not publish successful leaf output"
