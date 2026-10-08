"""Independent SSE payloads exercise worker CPU credits and cipher backends."""
import asyncio
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from sunpack_native import parse_worker_transport_event
from tests.helpers.native_fixture import file_inventory, native_fixture
from tests.helpers.native_build import sevenzip_artifact


ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "tests/data/enc_parallel"


@pytest.fixture(scope="module", params=[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], ids=["aes", "rc6", "serpent", "blowfish256", "twofish", "gost", "blowfish448", "threefish", "shacal", "c4"])
def large_enc(tmp_path_factory, request):
    root = tmp_path_factory.mktemp(f"enc-{request.param}")
    shutil.copyfile(DATA / f"algorithm_{request.param}.enc", root / "large.enc")
    shutil.copyfile(DATA / "large.expected", root / "large.expected")
    damaged = root / "damaged.bin"
    native_fixture("copy", source=str(root / "large.enc"), output=str(damaged))
    native_fixture("flip", path=str(damaged), offset=damaged.stat().st_size - 1)
    return root


@pytest.mark.parametrize("capacity,executor_threads", [(1, None), (2, None), (3, None), (5, None), (9, None), (9, 3), (9, 1)])
def test_large_enc_uses_only_granted_credits_and_matches_official_bytes(tmp_path, large_enc, capacity, executor_threads):
    request = {"job_id": "enc", "origin": "foreground", "archive_path": str(large_enc / "large.enc"),
               "format_hint": "enc", "output_dir": str(tmp_path / "out"), "password": "sunpack-test"}
    env = os.environ | {"SUNPACK_NATIVE_WORKER_THREAD_CAPACITY": str(capacity)}
    if executor_threads:
        env["RAYON_NUM_THREADS"] = str(executor_threads)
    completed = subprocess.run([str(sevenzip_artifact("sunpack_sevenzip_worker.exe"))],
                               input=json.dumps(request), capture_output=True, text=True, encoding="utf-8",
                               timeout=30, creationflags=subprocess.CREATE_NO_WINDOW,
                               env=env)
    events = [event for line in completed.stdout.splitlines()
              if (event := parse_worker_transport_event(line))]
    result = next(event for event in events if event.get("type") == "result")
    assert result["status"] == "ok" and result["verified_manifest"]["validated"], result
    expected = file_inventory(large_enc)["large.expected"]
    assert file_inventory(tmp_path / "out")["large"] == expected
    cpu = next(event for event in events if event.get("event") == "decoder_started")
    # Open borrowed up to three extra credits for the final KDF and returned
    # all of them before this first extraction progress callback.
    assert cpu["decoder_cpu_credits"] == 1
    assert cpu["current_decoder_extra_credits"] == 0
    assert cpu["peak_decoder_extra_credits"] == min(3, capacity - 1)
    assert not cpu["decoder_parallel"]


def test_parallel_enc_releases_credits_after_mac_failure_for_watch_and_cli(tmp_path, large_enc, monkeypatch):
    from sunpack.pipeline.extraction.internal.sevenzip.sevenzip_runner import _AsyncNativeWorkerProcess

    monkeypatch.setenv("SUNPACK_NATIVE_WORKER_THREAD_CAPACITY", "4")
    events = []

    async def run():
        process = _AsyncNativeWorkerProcess(str(sevenzip_artifact("sunpack_sevenzip_worker.exe")), None)
        await process.start()
        try:
            for wave in range(3):
                finished = []
                for index in range(1 if wave == 2 else 8):
                    job_id = str(wave * 8 + index)
                    path = large_enc / ("damaged.bin" if index % 4 == 3 else "large.enc")
                    password = "wrong" if index % 4 == 2 else "sunpack-test"
                    request = {"job_id": job_id, "origin": "watch" if index % 2 else "foreground",
                               "archive_path": str(path), "format_hint": "enc", "password": password,
                               "output_dir": str(tmp_path / job_id)}
                    await process.submit(json.dumps(request), job_id, parsed_events=True,
                                         on_line=lambda line, event: events.append(event) or event.get("event") == "job_finished",
                                         on_timeout=lambda message: events.append({"error": message}))
                    finished.append(process._jobs[job_id]["finished"])
                await asyncio.wait_for(asyncio.gather(*finished), 30)
        finally:
            await process.close()

    asyncio.run(run())
    results = {int(e["job_id"]): e for e in events if e.get("type") == "result"}
    assert len(results) == 17
    for index, result in results.items():
        expected = "wrong_password" if index % 4 == 2 else "damaged" if index % 4 == 3 else "ok"
        assert result["native_status"] == expected, result
    cpu = [e for e in events if e.get("event") == "decoder_started"]
    assert cpu and all(e["decoder_cpu_credits"] == 1 and e["current_decoder_extra_credits"] == 0 for e in cpu)
    final_cpu = next(e for e in cpu if e["job_id"] == "16")
    assert final_cpu["peak_decoder_extra_credits"] == 3


@pytest.mark.parametrize("origin", ["foreground", "watch"])
@pytest.mark.parametrize("incomplete", [False, True])
def test_enc_carrier_ranges_keep_ctr_continuity_and_reject_missing_tail(tmp_path, large_enc, origin, incomplete):
    from sunpack_native import enc_fast_verify_passwords_from_ranges
    from tests.helpers.native_fixture import assemble_carrier

    carrier = tmp_path / "disguised.mkv"
    segment = assemble_carrier(carrier, [large_enc / "large.enc"],
                               junk_min=37, junk_max=37)["segments"][0]
    start, length = segment["offset"], segment["length"]
    # Fragment the header, quick proof, and payload at unaligned boundaries.
    cuts = [0, 20, 40, 71, 72, 65543, length - (33 if incomplete else 0)]
    ranges = [{"path": str(carrier), "start": start + a, "end": start + b}
              for a, b in zip(cuts, cuts[1:])]
    proof = enc_fast_verify_passwords_from_ranges(ranges, ["wrong", "sunpack-test", "sunpack-test"])
    assert proof["status"] == "match" and proof["matched_index"] == 1
    request = {"job_id": "ranges", "origin": origin, "archive_path": str(carrier),
               "archive_input": {"kind": "archive_input", "entry_path": str(carrier),
                                 "open_mode": "concat_ranges", "format_hint": "enc", "ranges": ranges},
               "output_dir": str(tmp_path / "out"), "password_candidates": ["sunpack-test"]}
    completed = subprocess.run([str(sevenzip_artifact("sunpack_sevenzip_worker.exe"))],
                               input=json.dumps(request), capture_output=True, text=True, encoding="utf-8",
                               timeout=30, creationflags=subprocess.CREATE_NO_WINDOW,
                               env=os.environ | {"SUNPACK_NATIVE_WORKER_THREAD_CAPACITY": "4"})
    events = [event for line in completed.stdout.splitlines()
              if (event := parse_worker_transport_event(line))]
    result = next(event for event in events if event.get("type") == "result")
    if incomplete:
        assert result["native_status"] == "damaged" and not result["wrong_password"], result
        assert not result["verified_manifest"]["validated"]
    else:
        assert result["status"] == "ok" and result["verified_manifest"]["validated"], result
        assert list(file_inventory(tmp_path / "out").values()) == [file_inventory(large_enc)["large.expected"]]
    cpu = next(event for event in events if event.get("event") == "decoder_started")
    assert cpu["current_decoder_extra_credits"] == 0
