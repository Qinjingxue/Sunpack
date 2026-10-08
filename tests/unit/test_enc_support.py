"""Official ENC vectors through the existing worker, discovery and verification."""
import asyncio
import json
import shutil
from pathlib import Path

import pytest
from sunpack_native import NativeWorkerResultAccumulator, parse_worker_transport_event
from sunpack.core.analysis import ArchiveAnalyzer
from sunpack.core.passwords.resolver import archive_structure_password_state
from sunpack.pipeline.discovery.detection.input_planning import ArchiveInputPlanningStage
from sunpack.pipeline.discovery.filesystem.directory_scanner import DirectoryScanner
from tests.helpers.archive_tasks import make_archive_task
from tests.helpers.config_factory import make_config
from tests.unit.test_lz4_support import BUILD
import subprocess
from sunpack_native import enc_fast_verify_passwords, enc_fast_verify_passwords_from_ranges

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "native" / "sunpack_enc" / "tests" / "data"


def _flip_byte(path: Path, offset: int) -> None:
    with path.open("r+b") as stream:
        stream.seek(offset)
        value = stream.read(1)
        assert len(value) == 1
        stream.seek(offset)
        stream.write(bytes([value[0] ^ 1]))


def worker(path, output, candidates=("sunpack-test",), *, origin="foreground"):
    request = {"job_id": output.name, "origin": origin, "archive_path": str(path),
               "archive_input": {"kind": "file", "entry_path": str(path), "format_hint": "enc"},
               "output_dir": str(output), "password_candidates": list(candidates)}
    completed = subprocess.run([str(BUILD / "sunpack_sevenzip_worker.exe")],
                               input=json.dumps(request, ensure_ascii=False), text=True,
                               capture_output=True, encoding="utf-8", timeout=30,
                               creationflags=subprocess.CREATE_NO_WINDOW)
    accumulator = NativeWorkerResultAccumulator(output.name)
    result = None
    for line in completed.stdout.splitlines():
        event = parse_worker_transport_event(line)
        if event:
            accumulator.accept(event)
            if event.get("type") == "result":
                result = event
    assert result, completed.stderr + completed.stdout
    return result


@pytest.mark.parametrize("code", range(10))
def test_all_official_ciphers_use_one_unnamed_authenticated_item(tmp_path, code):
    path = DATA / f"algorithm_{code}.mov"
    proof = enc_fast_verify_passwords(str(path), ["wrong", "sunpack-test", "later"])
    assert proof["status"] == "match" and proof["matched_index"] == 1
    assert proof["attempts"] == 2 and not proof["final_confirmation_required"]
    result = worker(path, tmp_path / "output")
    assert result["status"] == "ok" and result["archive_type"] == "enc", result
    assert result["matched_index"] == 0 and result["password_attempts"] == 0
    assert result["encrypted"] and result["files_written"] == 1
    assert result["bytes_written"] == (DATA / "expected.zip").stat().st_size
    assert [p.name for p in (tmp_path / "output").iterdir()] == [path.stem]
    assert result["verified_manifest"]["validated"]


@pytest.mark.parametrize("name,password", [
    ("unicode.enc", "contraseña中文😀"), ("params_01.enc", "sunpack-test"),
    ("params_10.enc", "sunpack-test"), ("recovery.enc", "sunpack-test"),
])
def test_unicode_kdf_variants_and_embedded_recovery(tmp_path, name, password):
    proof = enc_fast_verify_passwords(str(DATA / name), ["wrong", password])
    assert proof["status"] == "match" and proof["matched_index"] == 1
    result = worker(DATA / name, tmp_path / "output", (password,))
    assert result["status"] == "ok", result
    expected = "recovery.zip" if name == "recovery.enc" else "expected.zip"
    assert result["bytes_written"] == (DATA / expected).stat().st_size


@pytest.mark.parametrize("candidates", [("wrong",), ("wrong1", "wrong2", "wrong3")])
def test_wrong_candidates_are_rejected_by_rust(candidates):
    result = enc_fast_verify_passwords(str(DATA / "algorithm_0.mov"), list(candidates))
    assert result["status"] == "no_match" and result["matched_index"] == -1
    assert result["attempts"] == len(candidates)


def test_wrong_selected_password_uses_generic_failure_contract(tmp_path):
    result = worker(DATA / "algorithm_0.mov", tmp_path / "output", ("wrong",))
    assert result["status"] == "failed" and result["native_status"] == "wrong_password"
    assert result["password_candidates_all_rejected"] and result["matched_index"] == -1
    assert result["password_attempts"] == 1
    assert result["bytes_written"] == 0 and not result["damaged"]


def test_mac_damage_is_data_damage_after_password_proof(tmp_path):
    result = worker(DATA / "bad_mac.enc", tmp_path / "output")
    assert result["status"] == "failed" and result["damaged"] and result["checksum_error"]
    assert not result["wrong_password"] and not result["password_candidates_all_rejected"]
    assert not result["verified_manifest"]["validated"]


def test_recovery_framing_damage_is_reported_as_damage(tmp_path):
    path = tmp_path / "recovery.bin"
    shutil.copyfile(DATA / "recovery.enc", path)
    _flip_byte(path, path.stat().st_size - 120)
    proof = enc_fast_verify_passwords(str(path), ["sunpack-test"])
    assert proof["status"] == "match"
    result = worker(path, tmp_path / "output")
    assert result["damaged"] and not result["wrong_password"]
    assert not result["verified_manifest"]["validated"]


def test_discovery_is_extension_independent_and_planning_does_not_reanalyse():
    config = make_config()
    snapshot = DirectoryScanner(str(DATA), include_raw_snapshot=True, config=config).scan()
    routes = {Path(path).name: (route, fmt) for path, _size, route, fmt, _mask
              in snapshot.non_relation_file_routing_rows()}
    assert routes["algorithm_0.mov"] == ("detection", "enc")
    assert ArchiveAnalyzer.confirm_format_identity(str(DATA / "algorithm_0.mov"), "enc")
    assert not ArchiveAnalyzer.confirm_format_identity(str(DATA / "expected.zip"), "enc")
    task = make_archive_task(DATA / "algorithm_0.mov", format_hint="enc", discovery_source="detection")
    assert archive_structure_password_state(task) == "required"
    assert ArchiveInputPlanningStage(config).plan_task(task) is None
    assert task.archive_input().open_mode == "file" and not task.archive_input().parts


def test_shared_worker_interleaves_watch_cli_success_wrong_password_and_damage(tmp_path):
    from sunpack.pipeline.extraction.internal.sevenzip.sevenzip_runner import _AsyncNativeWorkerProcess
    events = []

    async def run():
        process = _AsyncNativeWorkerProcess(str(BUILD / "sunpack_sevenzip_worker.exe"), None)
        await process.start()
        try:
            finished = []
            for i in range(16):
                path = DATA / ("bad_mac.enc" if i % 4 == 3 else f"algorithm_{i % 10}.mov")
                candidates = ["wrong1"] if i % 4 == 2 else ["sunpack-test"]
                request = json.dumps({"job_id": str(i), "origin": "watch" if i % 2 else "foreground",
                                      "archive_path": str(path), "format_hint": "enc",
                                      "output_dir": str(tmp_path / str(i)), "password_candidates": candidates})
                await process.submit(request, str(i), parsed_events=True,
                                     on_line=lambda line, event: events.append(event) or event.get("event") == "job_finished",
                                     on_timeout=lambda message: events.append({"error": message}))
                finished.append(process._jobs[str(i)]["finished"])
            await asyncio.wait_for(asyncio.gather(*finished), 30)
        finally:
            await process.close()
    asyncio.run(run())
    results = {int(e["job_id"]): e for e in events if e.get("type") == "result"}
    assert len(results) == 16
    for i, result in results.items():
        expected = "wrong_password" if i % 4 == 2 else "damaged" if i % 4 == 3 else "ok"
        assert result["native_status"] == expected, result


def test_native_batch_preserves_priority_ranges_and_parallel_context_lifecycle():
    from concurrent.futures import ThreadPoolExecutor
    path = DATA / "algorithm_0.mov"
    candidates = [f"wrong-{i}" for i in range(20)] + ["sunpack-test", "sunpack-test"]
    proof = enc_fast_verify_passwords(str(path), candidates)
    assert proof["matched_index"] == 20 and proof["attempts"] == 21
    ranges = [{"path": str(path), "start": 0, "end": 20},
              {"path": str(path), "start": 20, "end": path.stat().st_size}]
    assert enc_fast_verify_passwords_from_ranges(ranges, candidates)["matched_index"] == 20
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda i: enc_fast_verify_passwords(
            str(DATA / f"algorithm_{i % 10}.mov"), ["wrong", "sunpack-test"]), range(16)))
    assert all(r["matched_index"] == 1 and r["attempts"] == 2 for r in results)


def test_prepared_context_is_invalidated_when_input_changes(tmp_path):
    path = tmp_path / "changing.enc"
    shutil.copyfile(DATA / "algorithm_0.mov", path)
    assert enc_fast_verify_passwords(str(path), ["sunpack-test"])["status"] == "match"
    _flip_byte(path, 40)
    assert enc_fast_verify_passwords(str(path), ["sunpack-test"])["status"] == "no_match"
    _flip_byte(path, 40)
    assert enc_fast_verify_passwords(str(path), ["sunpack-test"])["status"] == "match"


def test_concurrent_candidate_batches_keep_priority_after_empty_and_rejected_batches():
    from concurrent.futures import ThreadPoolExecutor
    path = str(DATA / "algorithm_0.mov")
    batches = [[], ["wrong"], ["sunpack-test", "sunpack-test"],
               ["wrong", "sunpack-test", "sunpack-test", "later"],
               ["wrong1", "wrong2", "wrong3", "wrong4"],
               [f"wrong-{i}" for i in range(13)] + ["sunpack-test", "sunpack-test"]] * 2
    with ThreadPoolExecutor(max_workers=8) as pool:
        for _ in range(2):
            results = list(pool.map(lambda candidates: enc_fast_verify_passwords(path, candidates), batches))
            for candidates, result in zip(batches, results):
                expected = candidates.index("sunpack-test") if "sunpack-test" in candidates else -1
                assert result["matched_index"] == expected
                assert result["attempts"] == (expected + 1 if expected >= 0 else len(candidates))
