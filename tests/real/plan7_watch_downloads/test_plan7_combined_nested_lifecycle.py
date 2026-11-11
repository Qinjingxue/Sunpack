from pathlib import Path

import pytest

from tests.helpers.marker_utils import marker_present
from tests.helpers.native_fixture import assemble_carrier, assert_exact_tree
from tests.helpers.real_archives import ArchiveCase, choose_entry_path, create_7z_archive
from tests.real.archive_boundary import require_generator
from tests.real.nested_cases import assert_nested_outputs, build_nested_case
from tests.real.plan6_confused_volumes.plan6_support import SCENARIOS, apply_volume_confusion
from tests.real.plan7_watch_downloads.plan7_support import download, wait_for, watch_setup


pytestmark = pytest.mark.requires_watch_broker


@pytest.mark.parametrize("outer_format,cleanup,restart", [
    ("7z", "d", True), ("zip", "d", True), ("rar", "d", True), ("zip", "k", False),
])
def test_plan7_disguised_encrypted_split_nested_carrier(package, tmp_path, outer_format, cleanup, restart):
    require_generator(outer_format)
    case = build_nested_case(tmp_path / "fixtures", f"watch-{outer_format}", outer_format)
    watch = watch_setup(package, tmp_path, passwords=case.passwords[:2], cleanup=cleanup, flatten=True)
    for part in reversed(case.parts[:-1]):
        download(watch, part)
    watch.await_event("suspended_missing_volume")
    assert not marker_present(watch.output, case.ready_marker)
    assert not marker_present(watch.output, case.lz4_marker)
    assert not marker_present(watch.output, case.blocked.marker_name)
    if restart:
        watch.restart()

    download(watch, case.parts[-1])
    blocker = watch.await_event("failed_password", path=case.blocked_name)
    retry = Path(blocker["path"])
    assert retry.parent == watch.root and retry.is_file()
    assert_nested_outputs(watch.output, case, leaf_success=False)
    if restart:
        watch.restart()
        assert retry.is_file()
        assert not marker_present(watch.output, case.blocked.marker_name)

    watch.passwords(["wrong-again", *case.passwords])
    watch.await_archive(case.blocked)
    watch.stop()
    assert not retry.exists()
    assert all((watch.root / part.name).is_file() == (cleanup == "k") for part in case.parts)
    assert_nested_outputs(watch.output, case, leaf_success=True)
    watch.assert_no_terminal_failures()


def test_plan7_cp437_names_inside_encrypted_disguised_split_carrier(package, tmp_path):
    from scripts.generate_real_structure_corpus import STRUCTURE_CASES, generate

    corpus = tmp_path / "corpus"
    sample, = generate(corpus, cases=tuple(case for case in STRUCTURE_CASES if case[0] == "bsdtar-zip-cp437"))
    wrapper = tmp_path / "wrapper"
    wrapper.mkdir()
    assemble_carrier(wrapper / "picture.jpg", [corpus / sample["file"]], seed=437, decoys=True)
    archive_dir = tmp_path / "volumes"
    archive_dir.mkdir()
    password = "cp437-watch-regression"
    create_7z_archive(wrapper, archive_dir / "legacy.7z", password=password,
                      split=True, split_volume_size=4096)
    outer = ArchiveCase(
        case_id="legacy", archive_dir=archive_dir,
        entry_path=choose_entry_path(archive_dir, "legacy", "7z"),
        marker_name="marker.txt", marker_text="corpus::bsdtar-zip-cp437\n",
        archive_format="7z", password=password, split=True,
    )
    parts = apply_volume_confusion(outer, SCENARIOS[2], add_distractors=False)
    assert len(parts) >= 2
    watch = watch_setup(package, tmp_path, passwords=["wrong", password], cleanup="d", flatten=True)
    for part in reversed(parts[:-1]):
        download(watch, part)
    watch.await_event("suspended_missing_volume")
    assert not marker_present(watch.output, outer.marker_name)
    watch.restart()

    download(watch, parts[-1])
    wait_for(lambda: marker_present(watch.output, outer.marker_name), "CP437 carrier marker")
    watch.stop()
    marker, = watch.output.rglob(outer.marker_name)
    assert_exact_tree(marker.parent, sample["expected_files"])
    watch.assert_no_terminal_failures()
