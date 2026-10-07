import json
import subprocess

import pytest
from sunpack_native import AnalysisBinaryView, relations_size_filter_split_family_keys

from sunpack.pipeline.coordinator.task_provider import ArchiveTaskProvider
from sunpack.pipeline.discovery.relations import RelationsScheduler
from sunpack.pipeline.extraction.scheduler import ExtractionScheduler
from sunpack.core.support.resources import get_sevenzip_bridge_worker_path
from tests.helpers.config_factory import make_config
from tests.helpers.native_fixture import assert_exact_tree, native_fixture
from tests.helpers.real_archives import create_zip_multidisk_archive


def test_zipx_split_alias_preserves_size_anchors_and_extracts_physical_parts(tmp_path):
    case = create_zip_multidisk_archive(tmp_path, "payload", payload_size=4096)
    first = (case.archive_dir / "payload.z01").rename(case.archive_dir / "payload.zx01")
    terminal = (case.archive_dir / "payload.zip").rename(case.archive_dir / "payload.zipx")
    assert terminal.stat().st_size < first.stat().st_size

    keys = relations_size_filter_split_family_keys(str(terminal))
    assert keys == relations_size_filter_split_family_keys(str(first))
    assert len(keys) == 1
    assert keys[0].startswith("zip:spanned\x1f")

    config = make_config({
        "filesystem": {"scan_filters": [
            {"name": "size_range", "enabled": True, "gte": first.stat().st_size},
        ]},
        "verification": {"enabled": False},
    })
    tasks = ArchiveTaskProvider(config).scan_targets([str(case.archive_dir)])
    assert len(tasks) == 1
    task = tasks[0]
    descriptor = task.archive_input()
    assert descriptor.format_hint == "zip"
    assert descriptor.volume_style == "zip_spanned"
    assert descriptor.logical_name == "payload"
    assert descriptor.part_paths() == [str(first), str(terminal)]
    assert [part.canonical_name for part in descriptor.parts] == ["payload.z01", "payload.zip"]
    assert [part.role for part in descriptor.parts] == ["first", "terminal"]

    # A direct retry hint is also normalized at the Rust boundary.
    group = RelationsScheduler().resolve_volume_once(
        [str(first)], [str(first), str(terminal)], format_hint=".ZIPX",
    )
    assert group is not None
    assert group.input_paths == [str(first), str(terminal)]

    extractor = ExtractionScheduler(max_retries=0)
    output = tmp_path / "output"
    try:
        result = extractor.extract(task, str(output))
    finally:
        extractor.close()
    assert result.success is True
    assert_exact_tree(output, case.metadata["expected_files"])


@pytest.mark.parametrize("method,password", [("LZMA", None), ("Deflate", "zipx-secret")])
def test_zipx_methods_and_passwords_reuse_zip_pipeline(tmp_path, method, password):
    from tests.helpers.real_archives import ArchiveFixtureFactory
    from tests.real.plan1_real_archives.plan1_support import assert_plan1_success

    case = ArchiveFixtureFactory().create(
        tmp_path, "advanced", "zip", payload_size=256,
        compression_method=method, password=password,
    )
    case.entry_path = case.entry_path.rename(case.entry_path.with_suffix(".zipx"))
    assert_plan1_success(case, ".zip", passwords=["wrong", password] if password else [])


@pytest.mark.parametrize("method", [93, 96, 97, 94])
def test_zipx_zstd_and_unsupported_methods_keep_zip_identity(tmp_path, method):
    archive = tmp_path / "method.zipx"
    fixture = native_fixture("zip_method", output=str(archive), method=method)
    if method == 93:
        view = AnalysisBinaryView(str(archive))
        try:
            local = dict(view.probe_zip_local_header(0))
        finally:
            view.close()
        assert local["compression_method"] == 93
        assert local["plausible"] is True
        assert local["error"] == ""

    tasks = ArchiveTaskProvider(make_config()).scan_targets([str(archive)])
    assert len(tasks) == 1
    assert tasks[0].archive_input().format_hint == "zip"

    # Exercise the worker's defensive alias directly, including dot/case normalization.
    output = tmp_path / "output"
    process = subprocess.run(
        [get_sevenzip_bridge_worker_path()],
        input=json.dumps({"job_id": "zipx-method", "archive_path": str(archive),
                          "output_dir": str(output), "format_hint": ".ZIPX"}),
        capture_output=True, text=True, encoding="utf-8", timeout=30,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    final = next(json.loads(line) for line in process.stdout.splitlines()
                 if line.startswith("{") and json.loads(line).get("type") == "result")
    if method == 93:
        assert process.returncode == 0, final
        assert final["status"] == "ok", final
        assert_exact_tree(output, fixture["expected_files"])
    else:
        assert process.returncode != 0
        assert final["failure_kind"] == "unsupported_method", final
