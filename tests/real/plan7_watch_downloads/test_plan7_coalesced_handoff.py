"""Deterministic regression for the original Plan7 CI failure.

Reuse the complete original Plan7 case, including the real observer, broker,
archives, passwords, cleanup and assertions. Only order existing await boundaries;
never fabricate a discovery result, exception, response or failure event.

Independent coverage: ordinary Plan7 and lease-registry cases cannot force an
owner to disappear during a coalesced follower's runtime finalization. Removing
this schedule leaves that handoff untested. One real case covers the entire
failure at about two seconds, including successful output and empty Watch state.
"""
import asyncio
import json
from pathlib import Path

from sunpack.pipeline.coordinator.async_work import AsyncWorkBroker
from sunpack.pipeline.coordinator.engine import PipelineEngine, _PathLeaseRegistry
from sunpack.pipeline.coordinator.reporting import RunReporter
from sunpack.runtime.watch.scheduler import WatchScheduler
from sunpack.runtime.watch.log import WatchLogStore
from tests.display_history import records
from tests.real.plan7_watch_downloads.plan7_support import WatchHarness
from tests.real.plan7_watch_downloads.test_plan7_lz4_wrapped_rar_volumes import (
    test_plan7_lz4_wrapped_rar_volumes_arriving_in_separate_directories_extract_automatically as run_case,
)


def test_plan7_coalesced_owner_finishes_before_follower_lookup(tmp_path, monkeypatch, plan7_error):
    wrappers_finished = asyncio.Event()
    head_submitted = asyncio.Event()
    follower_coalesced = asyncio.Event()
    successful_family_projected = asyncio.Event()
    original_run = AsyncWorkBroker.run
    original_engine_run = PipelineEngine.run
    original_replace = _PathLeaseRegistry.replace
    original_drain = RunReporter.drain_progress
    original_finish = WatchScheduler._finish_active_request
    original_submit = WatchScheduler._submit_candidate
    original_write = WatchLogStore.write
    original_display_records = run_case.__globals__['display_records']
    original_close = WatchHarness.close
    assertion_failures = []
    submitted_tasks = set()
    released_tasks = set()
    family_succeeded = False
    wrappers = set()
    owner_task = None
    owner_id = ''
    follower_task = None
    engine = None
    owner_removed_before_handoff = False
    trace = []

    def record(event, **details):
        trace.append({'event': event, **details})

    def released_all_others():
        if family_succeeded and not (submitted_tasks - released_tasks - {follower_task}):
            successful_family_projected.set()

    async def track_submission(self, candidate):
        result = await original_submit(self, candidate)
        if result is not None:
            submitted_tasks.add(result.task)
            successful_family_projected.clear()
            if candidate.path.endswith('.part1.rar'):
                record('promoted head admitted by the real Watch scheduler', path=candidate.path)
                head_submitted.set()
        return result

    def capture_actual_write(self, event, **payload):
        if event in {'pipeline_sources_claimed', 'pipeline_sources_released', 'done', 'failed_terminal', 'error'}:
            record('actual WatchLogStore.write', name=event, payload=payload)
        return original_write(self, event, **payload)

    async def finish_wrappers(self, targets, **kwargs):
        nonlocal engine
        engine = self
        targets = tuple(targets)
        result = await original_engine_run(self, targets, **kwargs)
        for target in targets:
            path = str(getattr(target, 'path', target))
            if path.endswith('.rar.lz4'):
                wrappers.add(path)
                record('outer wrapper completed', path=path, count=len(wrappers))
        if len(wrappers) == 4:
            wrappers_finished.set()
        return result

    async def gate_discovery(self, stage, key, function, *args, **kwargs):
        roots = args[0] if stage == 'discover_detect' and args else ()
        if (isinstance(roots, (list, tuple))
                and any(str(path).endswith('.rar') and 'watch' in Path(path).parts for path in roots)):
            record('hold promoted member discovery until all four wrappers finish', roots=list(roots))
            await wrappers_finished.wait()
            await head_submitted.wait()
        return await original_run(self, stage, key, function, *args, **kwargs)

    async def gate_replace(self, owner, paths, **kwargs):
        nonlocal owner_task, owner_id, follower_task
        paths = tuple(paths)
        result = await original_replace(self, owner, paths, **kwargs)
        if paths and all(str(path).endswith('.rar') for path in paths):
            record('real lease result', request=owner, paths=list(paths),
                   coalesced_owner=owner_id if result is not None else None)
            if result is None and owner_task is None:
                owner_id = owner
                owner_task = asyncio.current_task()
                record('hold admitted owner until a follower coalesces', owner=owner)
                await follower_coalesced.wait()
            elif result is not None and follower_task is None:
                follower_task = asyncio.current_task()
                record('follower coalesced', owner=owner_id, follower=owner)
                follower_coalesced.set()
        return result

    async def gate_drain(self):
        nonlocal owner_removed_before_handoff
        await original_drain(self)
        if asyncio.current_task() is follower_task:
            record('hold follower finalization until owner task finishes')
            await asyncio.shield(owner_task)
            await successful_family_projected.wait()
            owner_removed_before_handoff = owner_id not in engine._active_requests
            record('owner finished; resume original follower owner-task lookup')

    async def finish_owner(self, request):
        nonlocal family_succeeded
        result = await original_finish(self, request)
        if request.task is follower_task:
            # Drain the actual native writer before the original case reads
            # history. No sleep and no synthetic failed_terminal row.
            self.log.flush()
        released_tasks.add(request.task)
        if request.candidate.path.endswith('.rar') and result.succeeded:
            family_succeeded = True
            record('successful family completion projected and source claims released', path=request.candidate.path)
        released_all_others()
        return result

    def capture_assertion_records(path):
        rows = original_display_records(path)
        assertion_failures.extend(
            row for row in rows if row.get('event') in {'failed_terminal', 'error'}
        )
        record('original Plan7 assertion reads durable history', failures=assertion_failures)
        return rows

    def release_gates_and_close(self):
        # Preserve the original failure if a gate becomes unreachable, while
        # allowing the real harness to join and release every admitted request.
        for gate in (wrappers_finished, head_submitted, follower_coalesced, successful_family_projected):
            gate.set()
        return original_close(self)

    monkeypatch.setattr(AsyncWorkBroker, 'run', gate_discovery)
    monkeypatch.setattr(PipelineEngine, 'run', finish_wrappers)
    monkeypatch.setattr(_PathLeaseRegistry, 'replace', gate_replace)
    monkeypatch.setattr(RunReporter, 'drain_progress', gate_drain)
    monkeypatch.setattr(WatchScheduler, '_finish_active_request', finish_owner)
    monkeypatch.setattr(WatchScheduler, '_submit_candidate', track_submission)
    monkeypatch.setattr(WatchLogStore, 'write', capture_actual_write)
    monkeypatch.setitem(run_case.__globals__, 'display_records', capture_assertion_records)
    monkeypatch.setattr(WatchHarness, 'close', release_gates_and_close)
    try:
        run_case(tmp_path, plan7_error)
        assert follower_coalesced.is_set() and owner_removed_before_handoff, trace
        assert not assertion_failures
    finally:
        event_file = tmp_path / 'wrapped-rar-split-dirs' / 'events.json'
        failures = [row for row in records(event_file) if row.get('event') in {'failed_terminal', 'error'}] if event_file.is_file() else []
        evidence = {'owner': owner_id, 'trace': trace,
                    'owner_removed_before_handoff': owner_removed_before_handoff,
                    'failures_at_original_assertion': assertion_failures, 'failures': failures}
        plan7_error['coalesced_handoff'] = evidence
        (tmp_path / 'injected-handoff.json').write_text(json.dumps(evidence, indent=2), encoding='utf-8')
        print('Deterministic Plan7 evidence:', tmp_path / 'injected-handoff.json')
        print(json.dumps(assertion_failures, indent=2))
