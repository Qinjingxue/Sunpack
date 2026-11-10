from sunpack_native import encode_worker_frame
from tests.helpers.worker_events import worker_events
"""Real native fixtures: Python projects metadata; C++ generates binary inputs."""
import asyncio
import concurrent.futures
import subprocess
from pathlib import Path

import pytest
from sunpack_native import NativeWorkerResultAccumulator, inspect_compression_stream_identity
from sunpack.core.analysis.engine import AnalysisEngine
from sunpack.core.analysis.embedded.result import embedded_scan_prepass
from sunpack_native import scan_embedded_archives
from sunpack.core.contracts.archive_input import ArchiveInputDescriptor, ArchiveInputPart, InputExtent
from sunpack.pipeline.discovery.detection.input_planning import ArchiveInputPlanningStage
from tests.helpers.archive_tasks import make_archive_task
from tests.helpers.native_build import sevenzip_artifact
from tests.helpers.native_fixture import file_inventory

ROOT = Path(__file__).resolve().parents[2]


def fingerprints(path):
    return sorted((row["size"], row["crc32"]) for row in file_inventory(path).values())


@pytest.fixture(scope="module")
def fixtures(tmp_path_factory):
    generator = sevenzip_artifact("sunpack_sevenzip_lz4.exe")
    folder = tmp_path_factory.mktemp("lz4_native")
    subprocess.run([str(generator), str(folder)], check=True, capture_output=True, timeout=60)
    return folder


def worker(descriptor, output):
    request = {"job_id": output.name, "archive_input": descriptor.to_dict(),
               "archive_path": descriptor.entry_path, "output_dir": str(output)}
    completed = subprocess.run(
        [str(sevenzip_artifact("sunpack_sevenzip_worker.exe"))], input=encode_worker_frame(request),
        capture_output=True,   timeout=30,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    accumulator = NativeWorkerResultAccumulator(output.name)
    result = None
    for event in worker_events(completed.stdout):
        if event:
            accumulator.accept(event)
            if event.get("type") == "result":
                result = event
    assert result, completed.stderr
    return result


@pytest.mark.parametrize("block", range(4, 8))
@pytest.mark.parametrize("bits", range(16))
def test_frame_options_analysis_is_complete_without_payload_decode(fixtures, block, bits):
    report = AnalysisEngine().analyze_path(str(fixtures / f"frame_{block}_{bits}.lz4"))
    selected = report.best_selected
    assert selected.format == "lz4" and selected.status == "extractable"
    candidate = selected.details["candidates"][0]
    assert candidate["extractable"]
    assert candidate["end_offset"] == (fixtures / f"frame_{block}_{bits}.lz4").stat().st_size


@pytest.mark.parametrize("name", ["concat.bin", "concat_partial.bin", "frame_4_0.lz4",
    "frame_4_5.lz4", "empty.lz4", "payload.tar.lz4", "high_compression.lz4", "uncompressed_blocks.lz4"])
def test_worker_finalizes_lz4_content(fixtures, tmp_path, name):
    result = worker(ArchiveInputDescriptor(entry_path=str(fixtures / name), format_hint="lz4"), tmp_path / "output")
    assert result["status"] == "ok"
    assert result["verified_manifest"]["validated"]
    rows = result["verified_manifest"]["native_rows"].file_page()
    assert not rows[0]["crc_ok"]
    assert sum(p.stat().st_size for p in (tmp_path / "output").rglob("*") if p.is_file()) == result["bytes_written"]


def test_skippable_prefix_disguised_identity_and_exact_carrier(fixtures, tmp_path):
    assert inspect_compression_stream_identity(str(fixtures / "concat.bin"))["identity_strong"]
    path = fixtures / "carrier.dat"
    scan = scan_embedded_archives(str(path))
    assert len(scan["candidates"]) == 1
    item = scan["candidates"][0]
    assert item["offset"] == 1031 and item["end_offset"] == path.stat().st_size - 29
    descriptor = ArchiveInputDescriptor(entry_path=str(path), open_mode="file_range", format_hint="lz4",
        parts=[ArchiveInputPart(InputExtent(str(path), item["offset"], item["end_offset"]))])
    result = worker(descriptor, tmp_path / "carrier")
    assert result["status"] == "ok"


@pytest.mark.parametrize("name,kind", [("bad_content.lz4", "checksum_error"), ("bad_header.lz4", "checksum_error"),
                                        ("bad_block.lz4", "checksum_error"), ("truncated.lz4", "input_truncated")])
def test_lz4_damage_does_not_become_wrong_password(fixtures, tmp_path, name, kind):
    path = fixtures / name
    result = worker(ArchiveInputDescriptor(entry_path=str(path), format_hint="lz4"), tmp_path / name)
    assert result["status"] == "failed" and not result["wrong_password"]
    assert result["checksum_error"] if kind == "checksum_error" else result["operation_result_name"] == "unexpected_end"
    assert path.exists()


def test_parallel_jobs_have_independent_lz4_state(fixtures, tmp_path):
    descriptor = ArchiveInputDescriptor(entry_path=str(fixtures / "concat.bin"), format_hint="lz4")
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda i: worker(descriptor, tmp_path / str(i)), range(16)))
    assert all(r["status"] == "ok" for r in results)


def test_gigabyte_skippable_tar_uses_length_jumps(fixtures, tmp_path):
    from sunpack.core.analysis.request import AnalysisCapability
    path = fixtures / "large_skip.tar.lz4"
    report = AnalysisEngine().analyze_path(str(path), capabilities=frozenset({AnalysisCapability.FORMAT_STRUCTURE}))
    assert report.best_selected.format == "lz4"
    assert report.read_bytes < 5 * 1024 * 1024
    descriptor = ArchiveInputDescriptor(entry_path=str(path), format_hint="lz4")
    result = worker(descriptor, tmp_path / "large_skip")
    assert result["status"] == "ok"


def test_skippable_only_needs_explicit_format_context(fixtures, tmp_path):
    path = fixtures / "skips_only.lz4"
    assert not inspect_compression_stream_identity(str(path))["identity_strong"]
    result = worker(ArchiveInputDescriptor(entry_path=str(path), format_hint="lz4"), tmp_path / "skips")
    assert result["status"] == "ok"


def test_confirmed_lz4_planning_does_not_scan_a_gigabyte_skippable_payload(fixtures):
    from sunpack.pipeline.coordinator.task_provider import ArchiveTaskProvider
    from tests.helpers.config_factory import make_config

    path = fixtures / "large_skip.tar.lz4"
    task, = ArchiveTaskProvider(make_config()).discover_targets([str(path)]).tasks
    assert task.discovery_source == "detection"
    assert task.archive_input().analysis["structure_complete"]
    ArchiveInputPlanningStage({}).plan_task(task)
    assert task.knowledge().get("input_planning.read_bytes", 0) < 5 * 1024 * 1024


def test_shared_skippable_magic_does_not_claim_a_zstandard_stream_as_lz4(fixtures):
    path = fixtures / "skip_zstd.bin"
    identity = inspect_compression_stream_identity(str(path))
    assert identity["format"] != "lz4"
    scan = scan_embedded_archives(str(path))
    assert [c["format"] for c in scan["candidates"]] == ["zstd"]
    report = AnalysisEngine().analyze_path(str(path), initial_prepass=embedded_scan_prepass(scan))
    assert report.best_selected.format == "zstd"
    assert not any(e.format == "lz4" and e.status != "not_found" for e in report.evidences)


@pytest.mark.parametrize("name", ["unsupported_legacy.bin", "unsupported_legacy_carrier.dat"])
def test_legacy_is_not_identified_by_analysis_or_embedded_scan(fixtures, name):
    path = fixtures / name
    assert not inspect_compression_stream_identity(str(path))["identity_strong"]
    assert not any(c["format"] == "lz4" for c in scan_embedded_archives(str(path))["candidates"])
    report = AnalysisEngine().analyze_path(str(path))
    assert not any(e.format in {"lz4", "tar.lz4"} and e.status != "not_found" for e in report.evidences)


@pytest.mark.parametrize("id", [0, 123, 4294967295])
def test_dict_id_returns_generic_unsupported_and_keeps_source(fixtures, tmp_path, id):
    path = fixtures / f"unsupported_id_{id}.lz4"
    task = make_archive_task(path, format_hint="lz4")
    ArchiveInputPlanningStage({}).plan_task(task)
    descriptor = task.archive_input()
    assert descriptor.analysis["structure_complete"]
    result = worker(descriptor, tmp_path / "unsupported")
    assert result["status"] == "failed" and result["native_status"] == "unsupported"
    assert result["failure_kind"] == "unsupported_method"
    assert not result["damaged"] and not result["wrong_password"] and path.exists()


def test_invalid_backreference_is_generic_data_error(fixtures, tmp_path):
    result = worker(ArchiveInputDescriptor(entry_path=str(fixtures / "bad_data.lz4"), format_hint="lz4"), tmp_path / "bad")
    assert result["status"] == "failed" and result["damaged"] and not result["wrong_password"]


def test_shared_worker_interleaves_success_damage_and_unsupported_jobs(fixtures, tmp_path):
    from sunpack.pipeline.extraction.internal.sevenzip.sevenzip_runner import _AsyncNativeWorkerProcess
    events = []

    async def run():
        process = _AsyncNativeWorkerProcess(str(sevenzip_artifact("sunpack_sevenzip_worker.exe")))
        await process.start()
        try:
            finished = []
            for i in range(16):
                name = ("frame_7_15.lz4", "concat.bin", "bad_content.lz4", "unsupported_id_0.lz4")[i % 4]
                descriptor = ArchiveInputDescriptor(entry_path=str(fixtures / name), format_hint="lz4")
                request = encode_worker_frame({"job_id": str(i), "origin": "watch" if i % 2 else "foreground",
                    "archive_input": descriptor.to_dict(), "archive_path": descriptor.entry_path,
                    "output_dir": str(tmp_path / str(i))})
                await process.submit(request, str(i),
                    on_event=lambda event: events.append(event) or event.get("event") == "job_finished",
                    on_error=lambda message: events.append({"error": message}))
                finished.append(process._jobs[str(i)]["finished"])
            await asyncio.wait_for(asyncio.gather(*finished), 30)
        finally:
            await process.close()

    asyncio.run(run())
    assert not any("error" in event for event in events)
    results = {int(e["job_id"]): e for e in events if e.get("type") == "result"}
    assert len(results) == 16
    for i, result in results.items():
        assert result["status"] == ("ok" if i % 4 < 2 else "failed")
        if i % 4 == 3:
            assert result["native_status"] == "unsupported" and result["failure_kind"] == "unsupported_method"


def test_prefix_carrier_is_a_strict_subrange_at_zero(fixtures, tmp_path):
    path = fixtures / "prefix_carrier.dat"
    task = make_archive_task(path, format_hint="lz4")
    ArchiveInputPlanningStage({}).plan_task(task)
    node, = task.inputs
    descriptor = node.descriptor
    assert descriptor.open_mode == "file_range"
    extent = descriptor.primary_extent
    assert extent.start == 0 and extent.end == path.stat().st_size - 29
    result = worker(descriptor, tmp_path / "prefix")
    assert result["status"] == "ok"

    assert fingerprints(fixtures / "expected_standard") == fingerprints(tmp_path / "prefix")
