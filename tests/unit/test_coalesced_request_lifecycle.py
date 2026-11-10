"""Result handoff, independent cancellation and release after owner retirement.

Real Plan7 covers successful extraction, but cannot force owner exceptions and
both cancellation channels while another follower is tearing down. Removing
these cases loses that shared-result contract and retained-Task coverage. A
small control-plane runtime avoids repeating native archive work for each exit.
"""
import asyncio
import gc
import weakref

import pytest

from sunpack.core.contracts.pipeline import PipelineResponse
from sunpack.core.contracts.results import OutcomeKind, RunSummary, TargetRunResult
from sunpack.pipeline.coordinator.async_work import CancellationToken
from sunpack.pipeline.coordinator.engine import PipelineEngine
from tests.helpers.config_factory import make_config


@pytest.mark.parametrize('owner_exit', ['success', 'error', 'cancel'])
def test_coalesced_followers_keep_the_owner_result_without_owning_its_lifetime(
    tmp_path, monkeypatch, owner_exit,
):
    source = tmp_path / 'shared-input'
    source.write_text('same physical generation')

    async def scenario():
        owner_admitted, finish_owner = asyncio.Event(), asyncio.Event()
        late_captured, finish_late = asyncio.Event(), asyncio.Event()
        token_waiting, task_waiting = asyncio.Event(), asyncio.Event()
        token, task_token = CancellationToken(), CancellationToken()
        owner_request_id = ''
        for cancellation, waiting in ((token, token_waiting), (task_token, task_waiting)):
            subscribe = cancellation.subscribe

            def observe(callback, subscribe=subscribe, waiting=waiting):
                remove = subscribe(callback)
                waiting.set()
                return remove

            monkeypatch.setattr(cancellation, 'subscribe', observe)

        class Runtime:
            def __init__(self, services, submission, leases):
                self.submission, self.leases = submission, leases
                self.reporter = None

            async def execute_async(self, broker, cancellation):
                nonlocal owner_request_id
                handoff = await self.leases.replace(
                    self.submission.request_id, [str(source)], coalesce_exact=True,
                    cancellation=cancellation,
                )
                if handoff is not None:
                    if cancellation is token or cancellation is task_token:
                        raise handoff
                    # Model arbitrary runtime-finalization work before the
                    # engine consumes its already confirmed result handoff.
                    try:
                        raise handoff
                    finally:
                        late_captured.set()
                        await finish_late.wait()
                owner_request_id = self.submission.request_id
                owner_admitted.set()
                await finish_owner.wait()
                if owner_exit == 'error':
                    raise OSError('owner operation failed')
                return PipelineResponse(owner_request_id, RunSummary(target_results=(
                    TargetRunResult(str(source), OutcomeKind.COMPLETE_SUCCESS),
                )))

        async with PipelineEngine(make_config()) as engine:
            engine._request_runtime_factory = Runtime
            owner = asyncio.create_task(engine.run([str(source)], origin='watch'))
            requests = [owner]
            try:
                await owner_admitted.wait()
                cancelled = asyncio.create_task(engine.run([str(source)], origin='watch', cancellation=token))
                requests.append(cancelled)
                await token_waiting.wait()
                token.cancel()
                response = await cancelled
                assert response.interrupted and not owner.done()
                assert not token._callbacks

                cancelled_task = asyncio.create_task(engine.run(
                    [str(source)], origin='watch', cancellation=task_token,
                ))
                requests.append(cancelled_task)
                await task_waiting.wait()
                cancelled_task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await cancelled_task
                assert not owner.done() and not task_token._callbacks

                late = asyncio.create_task(engine.run([str(source)], origin='watch'))
                requests.append(late)
                await late_captured.wait()
                if owner_exit == 'cancel':
                    owner.cancel()
                else:
                    finish_owner.set()
                [owner_result] = await asyncio.gather(owner, return_exceptions=True)
                assert owner_request_id not in engine._active_requests
                assert not late.done()
                finish_late.set()
                [late_result] = await asyncio.gather(late, return_exceptions=True)
                if owner_exit == 'success':
                    assert late_result.summary is owner_result.summary
                    assert late_result.summary.success_count == 1
                    assert late_result.request_id != owner_request_id
                    assert late_result.discovery.coalesced_from_request_id == owner_request_id
                elif owner_exit == 'error':
                    assert isinstance(owner_result, OSError) and late_result is owner_result
                else:
                    assert isinstance(owner_result, asyncio.CancelledError)
                    assert isinstance(late_result, asyncio.CancelledError)
                assert engine.is_idle()
                assert not engine._path_leases._generation_owners
                assert not engine._path_leases._pins
            finally:
                finish_owner.set()
                finish_late.set()
                for request in requests:
                    if not request.done():
                        request.cancel()
                await asyncio.gather(*requests, return_exceptions=True)
        return engine, [weakref.ref(request) for request in requests]

    # A deadline diagnoses a broken handoff deadlock; Events alone set order.
    engine, references = asyncio.run(asyncio.wait_for(scenario(), 10))
    gc.collect()
    assert all(reference() is None for reference in references)
    assert not engine._active_requests
