from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

from benchmarks import cli


def test_cleanup_benchmark_run_workdir_only_removes_matching_run(tmp_path, monkeypatch) -> None:
    work = tmp_path / ".work"
    work.mkdir()
    current = work / "scan-A-child"
    other = work / "scan-B-child"
    current.mkdir()
    other.mkdir()
    monkeypatch.setattr(cli, "BENCHMARK_WORK_ROOT", work)

    cli._cleanup_benchmark_run_workdir("A")

    assert not current.exists()
    assert other.exists()


def test_keep_workdir_skips_parent_cleanup(monkeypatch) -> None:
    cleanup_ids: list[str] = []

    def fake_cleanup(run_id: str) -> None:
        cleanup_ids.append(run_id)

    monkeypatch.setattr(cli, "_cleanup_benchmark_run_workdir", fake_cleanup)
    monkeypatch.setattr(cli.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(returncode=0))

    assert cli._run_scenario_in_subprocess("fake.module", ["--keep-workdir"], 1) == 0
    assert cleanup_ids == []


def test_cleanup_script_restricts_services_to_generated_ids() -> None:
    script = Path(__file__).resolve().parents[2] / "scripts" / "cleanup_test_artifacts.ps1"
    source = script.read_text(encoding="utf-8")

    assert "$testServicePattern = '^SunPackWatchBrokerTest_[0-9a-fA-F]{32}$'" in source
    assert "$service.Name -notmatch $testServicePattern" in source
    assert "$env:SUNPACK_SPACE_TEST_VHD_DIR" in source


def test_clean_removes_only_selected_regenerable_roots(tmp_path, monkeypatch) -> None:
    cache = tmp_path / ".cache"
    work = tmp_path / ".work"
    results = tmp_path / "results"
    cache.mkdir()
    work.mkdir()
    results.mkdir()
    (cache / "cached.bin").write_text("cache", encoding="utf-8")
    (work / "workspace.bin").write_text("work", encoding="utf-8")
    (results / "report.json").write_text("report", encoding="utf-8")
    monkeypatch.setattr(cli, "BENCHMARK_CACHE_ROOT", cache)
    monkeypatch.setattr(cli, "BENCHMARK_WORK_ROOT", work)

    assert cli.main(["clean", "--cache", "--work"]) == 0

    assert not cache.exists()
    assert not work.exists()
    assert (results / "report.json").read_text(encoding="utf-8") == "report"


def test_clean_requires_an_explicit_target() -> None:
    try:
        cli.main(["clean"])
    except SystemExit as exc:
        assert exc.code == 2
    else:
        raise AssertionError("clean without a target must fail")


def test_watch_scenario_runs_in_a_subprocess(monkeypatch) -> None:
    observed: dict[str, object] = {}

    @contextmanager
    def fake_broker_service():
        observed["broker_entered"] = True
        yield
        observed["broker_exited"] = True

    def fake_run(module: str, arguments: list[str], timeout: float) -> int:
        observed["module"] = module
        observed["arguments"] = arguments
        observed["timeout"] = timeout
        return 17

    monkeypatch.setattr(cli, "_run_scenario_in_subprocess", fake_run)
    monkeypatch.setattr(
        "benchmarks.watch_broker.temporary_watch_broker_service",
        fake_broker_service,
    )

    assert cli.main(["--timeout", "12", "watch", "real-file", "--runs", "2"]) == 17
    assert observed == {
        "module": "benchmarks.scenarios.watch_real_file",
        "arguments": ["--runs", "2"],
        "timeout": 12.0,
        "broker_entered": True,
        "broker_exited": True,
    }
