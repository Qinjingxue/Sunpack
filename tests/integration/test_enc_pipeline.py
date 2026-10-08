"""ENC is an ordinary stream extraction; recursive discovery owns its payload."""
import asyncio
import json
import os
import subprocess
import sys

import pytest
from sunpack.core.contracts.results import OutcomeKind
from sunpack.pipeline.coordinator.engine import PipelineEngine
from tests.helpers.config_factory import make_config
from tests.unit.test_enc_support import DATA, ROOT
from sunpack.pipeline.extraction.internal.sevenzip.sevenzip_runner import SevenZipRunner


@pytest.fixture
def worker_jobs(monkeypatch):
    jobs = []
    original = SevenZipRunner._build_job
    def capture(self, **kwargs):
        job = original(self, **kwargs)
        jobs.append(job)
        return job
    monkeypatch.setattr(SevenZipRunner, "_build_job", capture)
    return jobs


def config_for(tmp_path, passwords=("wrong", "sunpack-test")):
    return make_config({"recursive_extract": "6", "cli": {"quiet": True},
                        "user_passwords": list(passwords),
                        "output": {"root": str(tmp_path / "out")},
                        "post_extract": {"archive_cleanup_mode": "k", "flatten_single_directory": False}})


@pytest.mark.parametrize("origin", ["foreground", "watch"])
@pytest.mark.parametrize("name,count", [("algorithm_0.mov", 2), ("nested.enc", 4), ("recovery.enc", 2)])
def test_ordinary_recursion_authentication_and_no_extension_output(tmp_path, origin, name, count, worker_jobs):
    source = tmp_path / "misnamed.photo"
    os.link(DATA / name, source)

    async def run():
        async with PipelineEngine(config_for(tmp_path)) as engine:
            return await engine.run([str(source)], origin=origin)
    response = asyncio.run(run())
    assert not response.summary.failed_tasks, response.summary.failures
    assert response.summary.success_count == count, response.summary.target_results
    assert all(r.outcome_kind == OutcomeKind.COMPLETE_SUCCESS for r in response.summary.target_results)
    assert any(p.name in {"inside.txt", "source.txt"} for p in (tmp_path / "out").rglob("*"))
    assert source.exists()
    enc_jobs = [job for job in worker_jobs if job.get("format_hint") == "enc"]
    assert enc_jobs
    assert all(job["password"] == "sunpack-test" and not job.get("password_candidates") for job in enc_jobs)


@pytest.mark.parametrize("origin", ["foreground", "watch"])
@pytest.mark.parametrize("name,passwords", [("algorithm_0.mov", ("wrong",)), ("bad_mac.enc", ("sunpack-test",))])
def test_failed_enc_never_recurses_or_deletes_source(tmp_path, origin, name, passwords, worker_jobs, monkeypatch):
    from sunpack.core.passwords.verifier.enc_fast import EncFastVerifier

    def unexpected_probe(*args, **kwargs):
        pytest.fail("single candidate ran a redundant host password KDF")

    monkeypatch.setattr(EncFastVerifier, "verify_batch", unexpected_probe)
    source = tmp_path / "failed.movie"; os.link(DATA / name, source)
    config = config_for(tmp_path, passwords)
    config["post_extract"]["archive_cleanup_mode"] = "d"

    async def run():
        async with PipelineEngine(config) as engine:
            return await engine.run([str(source)], origin=origin)
    response = asyncio.run(run())
    assert response.summary.success_count == 0 and response.summary.failed_tasks
    assert len(response.summary.target_results) == 1
    assert source.exists()
    assert not any(p.name == "inside.txt" for p in (tmp_path / "out").rglob("*"))
    assert len(worker_jobs) == 1


@pytest.mark.parametrize("origin", ["foreground", "watch"])
@pytest.mark.parametrize("name,count", [
    (f"algorithm_{code}.mov", 2) for code in range(10)
] + [("nested.enc", 4), ("recovery.enc", 2)])
def test_single_candidate_enc_reuses_worker_confirmation_without_host_kdf(
    tmp_path, origin, name, count, worker_jobs, monkeypatch,
):
    from sunpack.core.passwords.verifier.enc_fast import EncFastVerifier

    def unexpected_probe(*args, **kwargs):
        pytest.fail("single ENC candidate ran a redundant host password KDF")

    monkeypatch.setattr(EncFastVerifier, "verify_batch", unexpected_probe)
    source = tmp_path / "single.photo"
    os.link(DATA / name, source)

    async def run():
        async with PipelineEngine(config_for(tmp_path, ("sunpack-test",))) as engine:
            return await engine.run([str(source)], origin=origin)

    response = asyncio.run(run())
    assert not response.summary.failed_tasks, response.summary.failures
    assert response.summary.success_count == count
    enc_jobs = [job for job in worker_jobs if job.get("format_hint") == "enc"]
    assert enc_jobs
    assert all(job.get("password_candidates") == ["sunpack-test"] for job in enc_jobs)
    assert source.exists()


@pytest.mark.parametrize("direct", [False, True])
def test_cli_disguised_enc_recurses_through_existing_zip_path(tmp_path, direct):
    source = tmp_path / "film.mp4"; os.link(DATA / "algorithm_0.mov", source)
    result = subprocess.run([sys.executable, "-B", str(ROOT / "sunpack.py"), "extract", "--json",
                             *(["--direct-file"] if direct else []), "--out-dir", str(tmp_path / "out"),
                             "--cleanup", "k", "--recur", "2", "-p", "sunpack-test",
                             "--no-builtin-pw", str(source), "--no-pause"],
                            capture_output=True, text=True, encoding="utf-8", timeout=45,
                            creationflags=subprocess.CREATE_NO_WINDOW)
    assert result.returncode == 0, result.stderr + result.stdout
    response = json.loads(result.stdout)
    assert response["summary"]["success_count"] == 2, response
