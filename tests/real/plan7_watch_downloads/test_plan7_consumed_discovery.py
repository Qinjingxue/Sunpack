"""A discovery proof must tolerate sources consumed by a successful peer.

The ordinary Plan7 case cannot force discovery to resume after family cleanup;
the coalesced-handoff regression starts after discovery has already succeeded.
Removing this case loses that earlier lifetime boundary. Reuse one complete
real Plan7 run rather than repeat the format matrix or race the scheduler.
"""
import asyncio
import json
from pathlib import Path
import threading

from sunpack.core.passwords.relation_prober import RelationsPasswordProber
from sunpack.pipeline.coordinator.async_work import AsyncWorkBroker
from sunpack.pipeline.coordinator.engine import PipelineEngine
from sunpack.runtime.watch.scheduler import WatchScheduler
from tests.real.plan7_watch_downloads.plan7_support import WatchHarness
from tests.real.plan7_watch_downloads.test_plan7_lz4_wrapped_rar_volumes import (
    test_plan7_four_lz4_wrapped_encrypted_rar_volumes_extract_automatically as run_case,
)


def test_plan7_discovery_resumes_after_successful_family_consumes_its_inputs(
    tmp_path, monkeypatch, plan7_error,
):
    wrappers_finished = asyncio.Event()
    family_finished = asyncio.Event()
    snapshot_captured = asyncio.Event()
    release_probe = threading.Event()
    probe_held = threading.Event()
    owner_loop = None
    original_run = AsyncWorkBroker.run
    original_engine_run = PipelineEngine.run
    original_finish = WatchScheduler._finish_active_request
    original_close = WatchHarness.close
    original_records = run_case.__globals__["display_records"]
    original_probe = RelationsPasswordProber.resolve_file
    wrappers = set()
    resumed = []
    failures = []
    trace = []

    async def track_wrappers(self, targets, **kwargs):
        targets = tuple(targets)
        response = await original_engine_run(self, targets, **kwargs)
        if response.summary.failures and any(str(getattr(target, "path", target)).endswith(".rar")
                                             for target in targets):
            trace.append({"response_failures": [failure.to_dict() for failure in response.summary.failures]})
        wrappers.update(str(getattr(target, "path", target)) for target in targets
                        if str(getattr(target, "path", target)).endswith(".rar.lz4"))
        if len(wrappers) == 4:
            wrappers_finished.set()
        return response

    async def order_discovery(self, stage, key, function, *args, **kwargs):
        nonlocal owner_loop
        owner_loop = asyncio.get_running_loop()
        roots = args[0] if stage == "discover_detect" and args else ()
        members = [str(path) for path in roots
                   if str(path).endswith(".rar") and "watch" in Path(path).parts]
        if members:
            trace.append({"held": members})
            if any(path.endswith(".part1.rar") for path in members):
                await snapshot_captured.wait()
                await wrappers_finished.wait()
            elif not any(path.endswith(".part4.rar") for path in members):
                await family_finished.wait()
                assert all(not Path(path).exists() for path in members), members
                resumed.extend(members)
                trace.append({"resume_after_cleanup": members})
        return await original_run(self, stage, key, function, *args, **kwargs)

    def order_probe(self, path, **kwargs):
        result = original_probe(self, path, **kwargs)
        if str(path).endswith(".part4.rar") and "watch" in Path(path).parts and not probe_held.is_set():
            # The real password probe has succeeded. Pause before its result
            # upgrades the original table; retain every real native decision.
            assert result is not None and result.password
            probe_held.set()
            trace.append({"snapshot_captured_before_cleanup": str(path)})
            owner_loop.call_soon_threadsafe(snapshot_captured.set)
            assert release_probe.wait(20), "successful family never released the password probe"
            assert not Path(path).exists(), path
            resumed.append(str(path))
        return result

    async def finish_request(self, request):
        result = await original_finish(self, request)
        if request.candidate.path.endswith(".part1.rar") and result.succeeded:
            assert not Path(request.candidate.path).exists()
            trace.append({"successful_family_projected": request.candidate.path})
            family_finished.set()
            release_probe.set()
        # The original assertion must observe every actual native log write.
        self.log.flush()
        return result

    def capture_records(path):
        rows = original_records(path)
        failures.extend(row for row in rows if row["event"] in {"error", "failed_terminal"})
        return rows

    def close(self):
        wrappers_finished.set()
        family_finished.set()
        snapshot_captured.set()
        release_probe.set()
        return original_close(self)

    monkeypatch.setattr(AsyncWorkBroker, "run", order_discovery)
    monkeypatch.setattr(PipelineEngine, "run", track_wrappers)
    monkeypatch.setattr(RelationsPasswordProber, "resolve_file", order_probe)
    monkeypatch.setattr(WatchScheduler, "_finish_active_request", finish_request)
    monkeypatch.setattr(WatchHarness, "close", close)
    monkeypatch.setitem(run_case.__globals__, "display_records", capture_records)
    try:
        run_case(tmp_path, "rename_commit", "keep", plan7_error)
        assert probe_held.is_set() and any(path.endswith(".part4.rar") for path in resumed), trace
        assert not failures, failures
    finally:
        evidence = {"trace": trace, "failures": failures}
        plan7_error["consumed_discovery"] = evidence
        (tmp_path / "consumed-discovery.json").write_text(
            json.dumps(evidence, indent=2), encoding="utf-8",
        )
