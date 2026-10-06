"""Real native fixtures: Python projects metadata; C++ generates binary inputs."""
import asyncio
import concurrent.futures
import json
import os
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
from sunpack.core.contracts.discovery import DiscoveryCandidate
from sunpack.pipeline.discovery.detection.input_planning import ArchiveInputPlanningStage
from sunpack.pipeline.discovery.embedded.discovery import EmbeddedDiscovery
from sunpack.pipeline.extraction.output_inventory import collect_output_inventory
from sunpack.pipeline.extraction.scheduler import ExtractionScheduler
from sunpack.pipeline.verification.evidence import build_verification_evidence
from sunpack.pipeline.verification.methods.archive_test_crc import ArchiveTestCrcMethod
from tests.helpers.archive_tasks import make_archive_task

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "native" / "sevenzip_bridge" / "build-x64" / "Release"


def fingerprints(path):
    manifest = compute_directory_crc_manifest(str(path), 100)
    assert manifest["status"] == "ok" and not manifest.get("truncated"), manifest
    return {(row["size"], row["crc32"]) for row in manifest["files"]}


@pytest.fixture(scope="module")
def fixtures(tmp_path_factory):
    generator = BUILD / "sunpack_sevenzip_lz4.exe"
    if not generator.is_file():
        pytest.skip("Build the sunpack_sevenzip_lz4 native fixture/test target")
    folder = tmp_path_factory.mktemp("lz4_native")
    subprocess.run([str(generator), str(folder)], check=True, capture_output=True, timeout=60)
    return folder


def worker(descriptor, output):
    request = {"job_id": output.name, "archive_input": descriptor.to_dict(),
               "archive_path": descriptor.entry_path, "output_dir": str(output)}
    completed = subprocess.run(
        [str(BUILD / "sunpack_sevenzip_worker.exe")], input=json.dumps(request),
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


@pytest.mark.parametrize("name,frames,legacy,skips", [
    ("concat.bin", 2, 0, 3), ("legacy.lz4", 1, 1, 0), ("mixed.lz4", 2, 1, 0),
    ("empty.lz4", 1, 0, 0), ("payload.tar.lz4", 1, 0, 0), ("legacy_zero.lz4", 1, 1, 0),
    ("high_compression.lz4", 1, 0, 0), ("uncompressed_blocks.lz4", 1, 0, 0),
])
def test_worker_receipt_matches_plan_and_finalized_inventory(fixtures, tmp_path, name, frames, legacy, skips):
    path = fixtures / name
    report = AnalysisEngine().analyze_path(str(path))
    selected = report.best_selected
    descriptor = ArchiveInputDescriptor(entry_path=str(path), format_hint=selected.format,
                                        analysis={"stream_plan": selected.details["stream_plan"]})
    result = worker(descriptor, tmp_path / "output")
    assert result["status"] == "ok"
    receipt = result["stream_receipt"]
    assert (receipt["frames"], receipt["legacy_frames"], receipt["skippable_frames"]) == (frames, legacy, skips)
    inventory = collect_output_inventory(str(tmp_path / "output"), result)
    verified = inventory.verify_stream_receipt(descriptor.analysis["stream_plan"], receipt)
    assert verified["status"] == "passed", verified
    assert verified["content_integrity"] == ("unknown" if legacy == frames else "verified_partial" if legacy else "verified_complete")
    # The old CRC32 evidence must stay empty for LZ4.
    rows = result["verified_manifest"]["native_rows"].file_page()
    assert not rows[0]["crc_ok"]
    forged = dict(receipt, frames=frames + 1)
    assert inventory.verify_stream_receipt(descriptor.analysis["stream_plan"], forged)["status"] == "failed"


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


@pytest.mark.parametrize("name", ["legacy_carrier.dat", "legacy_carrier_short_tail.dat"])
def test_legacy_unknown_boundary_reports_blocked_and_preserves_source(fixtures, name):
    path = fixtures / name
    candidate = DiscoveryCandidate(ArchiveInputDescriptor(entry_path=str(path)), "", (), "embedded", size=path.stat().st_size)
    result = EmbeddedDiscovery({}).discover([candidate])
    assert result.findings and result.findings[0].reason == "embedded_information_required"
    assert not result.resolved_tasks and path.exists()


@pytest.mark.parametrize("name,kind", [("bad_content.lz4", "checksum_error"), ("bad_header.lz4", "checksum_error"),
                                        ("bad_block.lz4", "checksum_error"), ("truncated.lz4", "input_truncated")])
def test_lz4_damage_does_not_become_wrong_password(fixtures, tmp_path, name, kind):
    path = fixtures / name
    result = worker(ArchiveInputDescriptor(entry_path=str(path), format_hint="lz4"), tmp_path / name)
    assert result["status"] == "failed" and not result["wrong_password"]
    assert result["checksum_error"] if kind == "checksum_error" else result["operation_result_name"] == "unexpected_end"
    assert path.exists()


@pytest.mark.parametrize("name,default", [("dictionary.lz4", False), ("dictionary_no_id.lz4", True), ("dictionary_zero_id.lz4", False)])
@pytest.mark.parametrize("relative", [False, True])
def test_dictionary_flows_through_planning_extraction_and_verification(fixtures, tmp_path, name, default, relative):
    path = fixtures / name
    dictionary_path = os.path.relpath(fixtures / "dict.raw") if relative else str(fixtures / "dict.raw")
    options = {"default_dictionary": dictionary_path if default else "",
               "dictionaries": {} if default else {"0" if name == "dictionary_zero_id.lz4" else "123": dictionary_path}}
    task = make_archive_task(path, format_hint="lz4")
    stage = ArchiveInputPlanningStage({"analysis": {"lz4": options}})
    stage.plan_task(task)
    assert task.archive_input().analysis["stream_plan"]["complete"]
    runner = ExtractionScheduler(extraction_config={"quiet": True})
    try:
        result = runner.extract(task, str(tmp_path / "output"))
        assert result.success, result
        evidence = build_verification_evidence(task, result)
        step = ArchiveTestCrcMethod().verify(evidence, {})
        assert step.status == "passed" and step.content_integrity_hint == "verified_complete", step
        assert step.verification_strength == "checksum"
    finally:
        runner.close()


def test_missing_dictionary_is_information_required(fixtures, tmp_path):
    path = fixtures / "dictionary.lz4"
    report = AnalysisEngine().analyze_path(str(path))
    lz4 = next(e for e in report.evidences if e.format == "lz4")
    assert lz4.details["information_required"] and lz4.status == "damaged"
    result = worker(ArchiveInputDescriptor(entry_path=str(path), format_hint="lz4"), tmp_path / "missing")
    assert result["failure_kind"] == "dictionary_required" and not result["damaged"]
    assert result["stream_receipt"]["dictionary_id"] == 123 and path.exists()


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


def test_unreadable_dictionary_is_information_required_not_damage(fixtures, tmp_path):
    descriptor = ArchiveInputDescriptor(entry_path=str(fixtures / "dictionary.lz4"), format_hint="lz4",
        analysis={"lz4": {"dictionaries": [{"id": 123, "path": str(tmp_path / "missing.raw")}]}})
    result = worker(descriptor, tmp_path / "unreadable")
    assert result["failure_kind"] == "dictionary_required" and not result["damaged"]
    assert result["stream_receipt"]["error"] == 8


def test_dictionary_without_id_does_not_make_a_false_damage_claim(fixtures, tmp_path):
    descriptor = ArchiveInputDescriptor(entry_path=str(fixtures / "dictionary_no_id.lz4"), format_hint="lz4")
    result = worker(descriptor, tmp_path / "unlabelled")
    assert result["status"] == "failed" and not result["damaged"] and not result["wrong_password"]
    assert result["failure_kind"] == "dictionary_or_data" and result["stream_receipt"]["error"] == 9


@pytest.mark.parametrize("mapping", [{"-1": "dict"}, {"4294967296": "dict"}, {"123": ""},
                                     {"123": "dict", "00123": "other"}])
def test_dictionary_configuration_rejects_invalid_or_ambiguous_ids(mapping):
    with pytest.raises(ValueError):
        AnalysisEngine({"analysis": {"lz4": {"dictionaries": mapping}}})


@pytest.mark.parametrize("large", [False, True])
def test_each_frame_selects_its_dictionary_and_uses_only_the_effective_tail(fixtures, tmp_path, large):
    options = {"default_dictionary": "", "dictionaries": {
        "123": str(fixtures / ("dict_large.raw" if large else "dict.raw")),
        "4294967295": str(fixtures / "dict_second.raw"),
    }}
    task = make_archive_task(fixtures / "dictionary_switch.lz4", format_hint="lz4")
    ArchiveInputPlanningStage({"analysis": {"lz4": options}}).plan_task(task)
    descriptor = task.archive_input()
    assert descriptor.analysis["stream_plan"]["dictionary_ids"] == [123, 4294967295]
    result = worker(descriptor, tmp_path / "switch")
    assert result["status"] == "ok" and result["stream_receipt"]["frames"] == 3
    assert fingerprints(fixtures / "expected_switch") == fingerprints(tmp_path / "switch")


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


def test_shared_worker_interleaves_dictionary_success_damage_and_missing_jobs(fixtures, tmp_path):
    from sunpack.pipeline.extraction.internal.sevenzip.sevenzip_runner import _AsyncNativeWorkerProcess
    events = []

    async def run():
        process = _AsyncNativeWorkerProcess(str(BUILD / "sunpack_sevenzip_worker.exe"), None)
        await process.start()
        try:
            finished = []
            for i in range(16):
                name = ("dictionary.lz4", "concat.bin", "bad_content.lz4", "dictionary.lz4")[i % 4]
                descriptor = ArchiveInputDescriptor(entry_path=str(fixtures / name), format_hint="lz4",
                    analysis={"lz4": {"dictionaries": [{"id": 123, "path": str(fixtures / "dict.raw")}]}} if i % 4 == 0 else {})
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
            assert result["failure_kind"] == "dictionary_required"
        if i % 4 == 0:
            assert result["stream_receipt"]["content_checked_frames"] == 1
