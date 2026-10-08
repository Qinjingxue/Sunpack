"""Real native fixtures: Python projects metadata; C++ generates binary inputs."""
import asyncio
import concurrent.futures
import json
import subprocess
from pathlib import Path

import pytest
from sunpack_native import (
    NativeWorkerResultAccumulator, compute_directory_crc_manifest,
    inspect_compression_stream_identity, parse_worker_transport_event,
)
from sunpack.core.analysis.engine import AnalysisEngine
from sunpack.core.analysis.embedded.scanner import scan_embedded_archives
from sunpack.core.contracts.archive_input import ArchiveInputDescriptor, ArchiveInputPart, InputExtent
from sunpack.pipeline.discovery.detection.input_planning import ArchiveInputPlanningStage
from sunpack.pipeline.extraction.output_inventory import collect_output_inventory
from sunpack.pipeline.extraction.scheduler import ExtractionScheduler
from sunpack.pipeline.verification.evidence import build_verification_evidence
from sunpack.pipeline.verification.methods.archive_test_crc import ArchiveTestCrcMethod
from tests.helpers.archive_tasks import make_archive_task
from tests.helpers.native_build import sevenzip_artifact

ROOT = Path(__file__).resolve().parents[2]


def fingerprints(path):
    manifest = compute_directory_crc_manifest(str(path), 100)
    assert manifest["status"] == "ok" and not manifest.get("truncated"), manifest
    return {(row["size"], row["crc32"]) for row in manifest["files"]}


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
        [str(sevenzip_artifact("sunpack_sevenzip_worker.exe"))], input=json.dumps(request),
        capture_output=True, text=True, encoding="utf-8", timeout=30,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    accumulator = NativeWorkerResultAccumulator(output.name)
    result = None
    for line in completed.stdout.splitlines():
        event = parse_worker_transport_event(line)
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
    plan = selected.details["stream_plan"]
    assert plan["complete"] and plan["frames"] == 1
    assert plan["content_checked_frames"] == bool(bits & 2)
    assert plan["block_checked_frames"] == bool(bits & 4)
    assert plan["expected_size"] == (5 * 1024 * 1024 if bits & 8 else None)


@pytest.mark.parametrize("name,frames,skips,integrity", [
    ("concat.bin", 2, 3, "verified_complete"), ("concat_partial.bin", 2, 0, "verified_partial"),
    ("frame_4_0.lz4", 1, 0, "unknown"), ("frame_4_5.lz4", 1, 0, "unknown"),
    ("empty.lz4", 1, 0, "verified_complete"), ("payload.tar.lz4", 1, 0, "verified_complete"),
    ("high_compression.lz4", 1, 0, "verified_complete"), ("uncompressed_blocks.lz4", 1, 0, "verified_complete"),
])
def test_worker_receipt_matches_plan_and_finalized_inventory(fixtures, tmp_path, name, frames, skips, integrity):
    path = fixtures / name
    report = AnalysisEngine().analyze_path(str(path))
    selected = report.best_selected
    descriptor = ArchiveInputDescriptor(entry_path=str(path), format_hint=selected.format,
                                        analysis={"stream_plan": selected.details["stream_plan"]})
    result = worker(descriptor, tmp_path / "output")
    assert result["status"] == "ok"
    receipt = result["stream_receipt"]
    assert (receipt["frames"], receipt["skippable_frames"]) == (frames, skips)
    inventory = collect_output_inventory(str(tmp_path / "output"), result)
    verified = inventory.verify_stream_receipt(descriptor.analysis["stream_plan"], receipt)
    assert verified["status"] == "passed", verified
    assert verified["content_integrity"] == integrity
    # The checksum algorithm is source-plan diagnostics, not verifier dispatch.
    neutral_plan = {key: value for key, value in descriptor.analysis["stream_plan"].items()
                    if key != "content_checksum_algorithm"}
    neutral = inventory.verify_stream_receipt(neutral_plan, receipt)
    assert neutral["status"] == "passed" and "checksum_algorithm" not in neutral
    diagnostic = inventory.verify_stream_receipt(dict(neutral_plan, content_checksum_algorithm="other-checksum"), receipt)
    assert diagnostic["status"] == "passed" and diagnostic["checksum_algorithm"] == "other-checksum"
    # The old CRC32 evidence must stay empty for LZ4.
    rows = result["verified_manifest"]["native_rows"].file_page()
    assert not rows[0]["crc_ok"]
    forged = dict(receipt, frames=frames + 1)
    assert inventory.verify_stream_receipt(descriptor.analysis["stream_plan"], forged)["status"] == "failed"
    diagnostics = {"skippable_frames", "block_checked_frames"}
    # Diagnostic changes/omissions must not bind planner and decoder state machines.
    for projected in (
        {key: value for key, value in receipt.items() if key not in diagnostics},
        dict(receipt, **{key: receipt[key] + 1 for key in diagnostics}),
    ):
        projected_plan = {key: value for key, value in descriptor.analysis["stream_plan"].items() if key not in diagnostics}
        assert inventory.verify_stream_receipt(projected_plan, projected)["status"] == "passed"
    for field in ("input_bytes", "output_bytes", "content_checked_frames", "error"):
        assert inventory.verify_stream_receipt(descriptor.analysis["stream_plan"],
            dict(receipt, **{field: receipt[field] + 1}))["status"] == "failed", field
    missing_coverage = {key: value for key, value in receipt.items() if key != "content_checked_frames"}
    assert inventory.verify_stream_receipt(descriptor.analysis["stream_plan"], missing_coverage)["status"] == "failed"


def test_skippable_prefix_disguised_identity_and_exact_carrier(fixtures, tmp_path):
    assert inspect_compression_stream_identity(str(fixtures / "concat.bin"))["identity_strong"]
    path = fixtures / "carrier.dat"
    scan = scan_embedded_archives(str(path))
    assert len(scan.candidates) == 1
    item = scan.candidates[0]
    assert item.offset == 1031 and item.end_offset == path.stat().st_size - 29
    descriptor = ArchiveInputDescriptor(entry_path=str(path), open_mode="file_range", format_hint="lz4",
        parts=[ArchiveInputPart(InputExtent(str(path), item.offset, item.end_offset))], analysis={"stream_plan": item.stream_plan})
    result = worker(descriptor, tmp_path / "carrier")
    assert result["status"] == "ok"
    assert result["stream_receipt"]["input_bytes"] == item.end_offset - item.offset


@pytest.mark.parametrize("name,kind", [("bad_content.lz4", "checksum_error"), ("bad_header.lz4", "checksum_error"),
                                        ("bad_block.lz4", "checksum_error"), ("truncated.lz4", "input_truncated")])
def test_lz4_damage_does_not_become_wrong_password(fixtures, tmp_path, name, kind):
    path = fixtures / name
    result = worker(ArchiveInputDescriptor(entry_path=str(path), format_hint="lz4"), tmp_path / name)
    assert result["status"] == "failed" and not result["wrong_password"]
    assert result["checksum_error"] if kind == "checksum_error" else result["operation_result_name"] == "unexpected_end"
    assert path.exists()


def test_explicit_concat_input_reuses_multivolume_reader_and_worker(fixtures, tmp_path):
    paths = [str(fixtures / f"split.any.00{i}") for i in (1, 2)]
    report = AnalysisEngine().analyze_paths(paths)
    selected = report.best_selected
    assert selected.format == "lz4" and selected.details["stream_plan"]["complete"]
    descriptor = ArchiveInputDescriptor(entry_path=paths[0], open_mode="concat_ranges", format_hint="lz4",
        extents=[InputExtent(path) for path in paths], analysis={"stream_plan": selected.details["stream_plan"]})
    result = worker(descriptor, tmp_path / "split")
    assert result["status"] == "ok" and result["stream_receipt"]["output_bytes"] == 5 * 1024 * 1024


def test_parallel_jobs_have_independent_lz4_state(fixtures, tmp_path):
    descriptor = ArchiveInputDescriptor(entry_path=str(fixtures / "concat.bin"), format_hint="lz4")
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda i: worker(descriptor, tmp_path / str(i)), range(16)))
    assert all(r["status"] == "ok" and r["stream_receipt"]["frames"] == 2 for r in results)


def test_gigabyte_skippable_tar_uses_length_jumps(fixtures, tmp_path):
    from sunpack.core.analysis.request import AnalysisCapability
    path = fixtures / "large_skip.tar.lz4"
    report = AnalysisEngine().analyze_path(str(path), capabilities=frozenset({AnalysisCapability.FORMAT_STRUCTURE}))
    assert report.best_selected.format == "tar.lz4"
    assert report.read_bytes < 5 * 1024 * 1024
    descriptor = ArchiveInputDescriptor(entry_path=str(path), format_hint="lz4")
    result = worker(descriptor, tmp_path / "large_skip")
    assert result["status"] == "ok" and result["stream_receipt"]["skippable_frames"] == 1
    assert result["stream_receipt"]["input_bytes"] == path.stat().st_size


def test_skippable_only_needs_explicit_format_context(fixtures, tmp_path):
    path = fixtures / "skips_only.lz4"
    assert not inspect_compression_stream_identity(str(path))["identity_strong"]
    result = worker(ArchiveInputDescriptor(entry_path=str(path), format_hint="lz4"), tmp_path / "skips")
    assert result["status"] == "ok" and result["stream_receipt"]["frames"] == 0
    assert result["stream_receipt"]["output_bytes"] == 0


def test_confirmed_lz4_planning_does_not_scan_a_gigabyte_skippable_payload(fixtures):
    task = make_archive_task(fixtures / "large_skip.tar.lz4", format_hint="lz4", discovery_source="detection")
    report = ArchiveInputPlanningStage({}).plan_task(task)
    assert report and report.read_bytes < 5 * 1024 * 1024
    assert task.archive_input().analysis["stream_plan"]["input_bytes"] > 1024 * 1024 * 1024


def test_shared_skippable_magic_does_not_claim_a_zstandard_stream_as_lz4(fixtures):
    path = fixtures / "skip_zstd.bin"
    identity = inspect_compression_stream_identity(str(path))
    assert identity["format"] != "lz4"
    scan = scan_embedded_archives(str(path))
    assert [c.format for c in scan.candidates] == ["zstd"]
    report = AnalysisEngine().analyze_path(str(path), initial_prepass=scan.to_prepass())
    assert report.best_selected.format == "zstd"
    assert not any(e.format == "lz4" and e.status != "not_found" for e in report.evidences)


@pytest.mark.parametrize("name", ["unsupported_legacy.bin", "unsupported_legacy_carrier.dat"])
def test_legacy_is_not_identified_by_analysis_or_embedded_scan(fixtures, name):
    path = fixtures / name
    assert not inspect_compression_stream_identity(str(path))["identity_strong"]
    assert not any(c.format == "lz4" for c in scan_embedded_archives(str(path)).candidates)
    report = AnalysisEngine().analyze_path(str(path))
    assert not any(e.format in {"lz4", "tar.lz4"} and e.status != "not_found" for e in report.evidences)


@pytest.mark.parametrize("id", [0, 123, 4294967295])
def test_dict_id_returns_generic_unsupported_and_keeps_source(fixtures, tmp_path, id):
    path = fixtures / f"unsupported_id_{id}.lz4"
    task = make_archive_task(path, format_hint="lz4")
    ArchiveInputPlanningStage({}).plan_task(task)
    descriptor = task.archive_input()
    assert descriptor.analysis["stream_plan"]["complete"]
    result = worker(descriptor, tmp_path / "unsupported")
    assert result["status"] == "failed" and result["native_status"] == "unsupported"
    assert result["failure_kind"] == "unsupported_method"
    assert not result["damaged"] and not result["wrong_password"] and path.exists()
    assert result["stream_receipt"]["error"] == 5


def test_unsupported_tar_sample_does_not_claim_tar(fixtures):
    report = AnalysisEngine().analyze_path(str(fixtures / "unsupported_id.tar.lz4"))
    assert report.best_selected.format == "lz4"
    assert not any(e.format == "tar.lz4" and e.status != "not_found" for e in report.evidences)


def test_invalid_backreference_is_generic_data_error(fixtures, tmp_path):
    result = worker(ArchiveInputDescriptor(entry_path=str(fixtures / "bad_data.lz4"), format_hint="lz4"), tmp_path / "bad")
    assert result["status"] == "failed" and result["damaged"] and not result["wrong_password"]
    assert result["stream_receipt"]["error"] == 3


def test_stream_verification_dispatch_is_format_neutral(fixtures, tmp_path):
    task = make_archive_task(fixtures / "frame_7_15.lz4", format_hint="lz4")
    ArchiveInputPlanningStage({}).plan_task(task)
    runner = ExtractionScheduler(extraction_config={"quiet": True})
    try:
        result = runner.extract(task, str(tmp_path / "output"))
        assert result.success, result
        evidence = build_verification_evidence(task, result)
        from dataclasses import replace
        neutral = replace(evidence, archive_input=replace(evidence.archive_input, format_hint="other-stream"))
        step = ArchiveTestCrcMethod().verify(neutral, {})
        assert step.status == "passed" and step.content_integrity_hint == "verified_complete"
        assert step.verification_strength == "checksum"
    finally:
        runner.close()


def test_shared_worker_interleaves_success_damage_and_unsupported_jobs(fixtures, tmp_path):
    from sunpack.pipeline.extraction.internal.sevenzip.sevenzip_runner import _AsyncNativeWorkerProcess
    events = []

    async def run():
        process = _AsyncNativeWorkerProcess(str(sevenzip_artifact("sunpack_sevenzip_worker.exe")), None)
        await process.start()
        try:
            finished = []
            for i in range(16):
                name = ("frame_7_15.lz4", "concat.bin", "bad_content.lz4", "unsupported_id_0.lz4")[i % 4]
                descriptor = ArchiveInputDescriptor(entry_path=str(fixtures / name), format_hint="lz4")
                request = json.dumps({"job_id": str(i), "origin": "watch" if i % 2 else "foreground",
                    "archive_input": descriptor.to_dict(), "archive_path": descriptor.entry_path,
                    "output_dir": str(tmp_path / str(i))})
                await process.submit(request, str(i), parsed_events=True,
                    on_line=lambda line, event: events.append(event) or event.get("event") == "job_finished",
                    on_timeout=lambda message: events.append({"error": message}))
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
        if i % 4 == 0:
            assert result["stream_receipt"]["content_checked_frames"] == 1


def test_prefix_carrier_is_a_strict_subrange_at_zero(fixtures, tmp_path):
    path = fixtures / "prefix_carrier.dat"
    task = make_archive_task(path, format_hint="lz4")
    report = ArchiveInputPlanningStage({}).plan_task(task)
    assert len(report.extractable_segments) == 1
    evidence, segment = report.extractable_segments[0]
    assert segment.start_offset == 0 and segment.end_offset == path.stat().st_size - 29
    descriptor = ArchiveInputPlanningStage({})._archive_input_for_segment(task, evidence, segment)
    assert descriptor.open_mode == "file_range"
    result = worker(descriptor, tmp_path / "prefix")
    assert result["status"] == "ok"
    assert result["stream_receipt"]["input_bytes"] == segment.end_offset
    assert fingerprints(fixtures / "expected_standard") == fingerprints(tmp_path / "prefix")


def test_incomplete_split_never_has_a_complete_stream_plan(fixtures):
    report = AnalysisEngine().analyze_path(str(fixtures / "split.any.001"))
    assert not report.selected
    evidence = next(e for e in report.evidences if e.format == "lz4")
    assert not evidence.details["stream_plan"]["complete"]
