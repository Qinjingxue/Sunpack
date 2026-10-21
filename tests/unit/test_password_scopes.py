import asyncio
import json
import os
import zipfile
from types import SimpleNamespace

from sunpack.core.passwords.directory_context import PasswordScopeContext, password_scope_for_path
from sunpack.core.passwords.internal.builtin import read_builtin_password_file
from sunpack.core.passwords.internal.store import PasswordStore, PasswordSnapshot
from sunpack.pipeline.coordinator.engine import PipelineEngine
from sunpack.pipeline.discovery.relations.internal.group_builder import RelationsGroupBuilder
from sunpack.pipeline.discovery.embedded.discovery import EmbeddedDiscovery
from tests.helpers.config_factory import make_config


def test_recursive_scope_and_all_discovery_candidates_share_request_store(tmp_path):
    # Unique coverage: recursive output scope reaches Relations before extraction.
    source, output = tmp_path / "source", tmp_path / "output"
    path = tmp_path / "passwords.json"
    path.write_text(json.dumps({"passwords": [{"value": "source-secret", "scopes": [str(source)]},
                                             {"value": "output-secret", "scopes": [str(output)]}]}), encoding="utf-8")
    store = PasswordStore.from_sources(password_snapshot=read_builtin_password_file(path), cli_passwords=["cli"])
    context = PasswordScopeContext()
    outer = SimpleNamespace(main_path=str(source / "outer.zip"), runtime={})
    context.annotate([outer])
    context.remember(str(output / "outer"), outer)
    inner = SimpleNamespace(main_path=str(output / "outer/child/inner.opaque"), runtime={})
    context.annotate([inner])
    config = make_config()
    config.update(password_store=store, password_scope_context=context)
    scope = password_scope_for_path(config, inner.main_path)
    relations = RelationsGroupBuilder(config)
    embedded = EmbeddedDiscovery(config)
    assert relations.password_store is store is embedded.password_store
    assert inner.runtime["password_scope_dir"] == str(source)
    assert embedded._password_candidates(inner.main_path) == store.candidates(scope) == ["source-secret", "cli"]
    assert context.for_path(str(output / "outer-other/inner.zip")) == str(output / "outer-other")


def test_pipeline_pins_snapshot_without_reading_password_files_or_copying_tables(tmp_path, monkeypatch):
    # Unique coverage: real pipeline tasks perform no password-file IO; snapshots stay shared.
    import sunpack.core.passwords.internal.builtin as builtin
    source = tmp_path / "source"
    source.mkdir()
    for name in ("first", "second"):
        with zipfile.ZipFile(source / f"{name}.zip", "w") as archive:
            archive.writestr("payload.txt", name)
    (source / "sunpack-passwords.txt").write_text("ignored", encoding="utf-8")
    path = tmp_path / "passwords.json"
    path.write_text(json.dumps({"passwords": [{"value": "secret", "scopes": [str(source)]}]}), encoding="utf-8")
    snapshot = read_builtin_password_file(path)
    config = make_config({"post_extract": {"archive_cleanup_mode": "k"}})
    config["password_snapshot"] = snapshot
    def forbidden(*args, **kwargs):
        raise AssertionError("password IO in request")
    monkeypatch.setattr(builtin, "read_shared_utf8_text", forbidden)
    async def run():
        async with PipelineEngine(config) as engine:
            factory = engine._request_runtime_factory
            entered, release = asyncio.Event(), asyncio.Event()
            snapshots = []
            def capture(services, submission, *args):
                snapshots.append(submission.password_store.snapshot)
                assert "password_snapshot" not in submission.config
                runtime = factory(services, submission, *args)
                execute = runtime.execute_async
                if len(snapshots) == 1:
                    async def held(*args, **kwargs):
                        entered.set()
                        await release.wait()
                        assert submission.password_store.snapshot is snapshot
                        return await execute(*args, **kwargs)
                    runtime.execute_async = held
                return runtime
            engine._request_runtime_factory = capture
            first = asyncio.create_task(engine.run([str(source / "first.zip")]))
            await entered.wait()
            latest = PasswordSnapshot(("new-secret",))
            engine.reconfigure_request({**engine.config, "password_snapshot": latest})
            second = asyncio.create_task(engine.run([str(source / "second.zip")]))
            release.set()
            responses = await asyncio.gather(first, second)
            assert snapshots == [snapshot, latest]
            assert all(response.summary.success_count == 1 for response in responses)
    asyncio.run(run())
    assert (source / "sunpack-passwords.txt").read_text(encoding="utf-8") == "ignored"
