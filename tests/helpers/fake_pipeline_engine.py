from __future__ import annotations

import uuid
from types import SimpleNamespace

from sunpack.contracts.pipeline import PipelineArtifacts, PipelineResponse


class FakePipelineEngine:
    """Async engine test double backed by a lightweight runner factory."""

    def __init__(self, runner_factory):
        self.runner_factory = runner_factory
        self.user_passwords = []
        self.builtin_passwords = []
        self._recent_passwords = []
        self.work_broker = _InlineBroker()

    async def __aenter__(self):
        return self

    async def aclose(self, *, graceful=True):
        return None

    async def __aexit__(self, exc_type, exc, traceback):
        await self.aclose()

    @property
    def recent_passwords(self):
        return list(self._recent_passwords)

    def update_password_sources(self, *, user_passwords, builtin_passwords):
        self.user_passwords = list(user_passwords)
        self.builtin_passwords = list(builtin_passwords)

    def is_idle(self):
        return True

    def reconfigure_request(self, config):
        self.config = dict(config)

    async def set_process_mode(self, *, background):
        self.background = bool(background)

    async def clear_runtime_caches(self):
        return {"fake": True}

    async def run(
        self,
        targets,
        *,
        direct=False,
        request_config=None,
        stdout=None,
        stderr=None,
        output_committer=None,
        progress_callback=None,
        origin="foreground",
        detection_options=None,
    ):
        paths = [target.path if hasattr(target, "path") else str(target) for target in targets]
        output = dict(targets[0].output) if targets and hasattr(targets[0], "output") else {}
        config = dict(request_config or {})
        config["output"] = {**(config.get("output") or {}), **output}
        config.setdefault("user_passwords", list(self.user_passwords))
        config.setdefault("builtin_passwords", list(self.builtin_passwords))
        runner = self.runner_factory(config)
        summary = runner.run_targets(paths)
        summary.cleanup_results = []
        self._recent_passwords = list(getattr(runner, "recent_passwords", ()) or ())
        context = getattr(runner, "context", SimpleNamespace(flatten_candidates=()))
        recovered_outputs = getattr(context, "recovered_outputs", ()) or ()
        generated_outputs = [
            str(item.get("out_dir") or "")
            for item in recovered_outputs
            if isinstance(item, dict) and item.get("out_dir")
        ]
        response = PipelineResponse(
            request_id=uuid.uuid4().hex,
            summary=summary,
            artifacts=PipelineArtifacts(
                flatten_targets=tuple([*(getattr(context, "flatten_candidates", ()) or ()), *generated_outputs]),
            ),
            recent_passwords=tuple(self._recent_passwords),
        )
        if output_committer is not None:
            response = await output_committer.commit(config, response)
        return response


class _InlineBroker:
    async def run(self, _stage, _file_id, operation, *args, **kwargs):
        kwargs.pop("request_id", None)
        kwargs.pop("cancellation", None)
        kwargs.pop("origin", None)
        return operation(*args, **kwargs)
