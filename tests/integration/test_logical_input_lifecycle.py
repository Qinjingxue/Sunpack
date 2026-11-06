"""Independent logical blockers sharing physical ownership and durable output."""
from __future__ import annotations

import asyncio
import subprocess

import pytest

from sunpack.core.contracts.input_plan import InputCheckpoint, InputRecovery
from sunpack.core.contracts.failures import FailureInfo
from sunpack.pipeline.coordinator.engine import PipelineEngine
from sunpack.pipeline.coordinator.task_provider import ArchiveTaskProvider
from sunpack.pipeline.extraction.internal.workflow.single_archive_extractor import SingleArchiveExtractor
from sunpack.runtime.watch import scheduler as watch_module
from tests.helpers.config_factory import make_config
from tests.helpers.passwords import write_password_json
from tests.helpers.real_archives import ArchiveFixtureFactory, create_encrypted_rar_archive, create_rar4_archive
from tests.helpers.tool_config import require_7z
from tests.integration.test_embedded_volume_feedback import _sibling_zip


@pytest.mark.parametrize("password_first", [False, True])
def test_mixed_blockers_resume_only_the_affected_input_across_restart(tmp_path, monkeypatch, password_first):
    # Existing password-only and volume-only lifecycles cannot expose blocker
    # priority suppressing a sibling event, or re-extraction of the other waiter.
    # Both event orders exercise the same three tiny inputs, WAL and real worker.
    case = ArchiveFixtureFactory().create(
        tmp_path, "mixed", "rar", split=True, compression_level=0,
        payload_size=32 * 1024, split_volume_size=12 * 1024,
    )
    secret = "independent-input-password"
    encrypted_source = tmp_path / "encrypted.txt"
    encrypted_source.write_text("independent encrypted payload", encoding="utf-8")
    encrypted_zip = tmp_path / "encrypted.zip"
    subprocess.run([str(require_7z()), "a", "-tzip", "-mx=0", f"-p{secret}", "-mem=AES256",
                    str(encrypted_zip), encrypted_source.name], cwd=tmp_path, check=True, capture_output=True)
    parts = sorted(case.archive_dir.iterdir(), key=lambda path: (path != case.entry_path, path.name))
    parts[0].write_bytes(b"mixed-carrier-prefix" * 17 + parts[0].read_bytes()
                         + b"gap" * 31 + encrypted_zip.read_bytes() + b"gap" * 29 + _sibling_zip())
    missing = parts[1].read_bytes()
    parts[1].unlink()
    output = tmp_path / "out"
    config = make_config({
        "embedded_scan": {"enabled": True},
        "user_passwords": [], "builtin_passwords": [],
        "watch": {"clipboard_monitor_enabled": False, "password_retry_debounce_seconds": 0},
        "output": {"root": str(output)},
        "post_extract": {"archive_cleanup_mode": "d", "flatten_single_directory": False},
    })
    monkeypatch.setattr(watch_module, "validate_ntfs_watch_roots", lambda roots: None)
    attempts = []
    execute = SingleArchiveExtractor._extract_one_state_machine

    def record(self, task, *args, **kwargs):
        attempts.append(task.inputs[0].input_id)
        return (yield from execute(self, task, *args, **kwargs))

    monkeypatch.setattr(SingleArchiveExtractor, "_extract_one_state_machine", record)

    async def scenario():
        async with PipelineEngine(config) as engine:
            responses = []
            run = engine.run

            async def record_response(*args, **kwargs):
                response = await run(*args, **kwargs)
                responses.append(response)
                return response

            monkeypatch.setattr(engine, "run", record_response)

            def open_watcher():
                watcher = watch_module.WatchScheduler(
                    config, [str(case.archive_dir)], output_roots={str(case.archive_dir): str(output)},
                    state_path=str(tmp_path / "state.snapshot"), pipeline_engine=engine,
                )
                scope = next(iter(watcher.scopes.values()))
                watcher._scan_options_for(scope).catalog_update(watcher._catalog, scope.native)
                return watcher

            watcher = open_watcher()
            try:
                watcher.enqueue(str(parts[0]))
                await watcher.run_once()
                await watcher.drain()
                entry = watcher.state.latest_entry_for_path(str(parts[0]))
                assert entry.status == "suspended_missing_volume"
                recovery = InputRecovery.from_failure(FailureInfo.from_dict(entry.failure_payload))
                volume, password, complete = sorted(recovery.checkpoints, key=lambda item: item.input.position)
                assert volume.blockers == {"missing_volume"} and password.blockers == {"password"}
                assert complete.complete and complete.files_written == 1 and len(attempts) == 2
                sibling = next(output.rglob("sibling.txt"))
                sibling_stamp = sibling.stat().st_mtime_ns
                for change_password in (password_first, not password_first):
                    await watcher.aclose()
                    watcher = open_watcher()
                    watcher._reconcile_persisted_blockers()
                    before = len(attempts)
                    if change_password:
                        from sunpack.core.passwords.internal import builtin
                        write_password_json(builtin.builtin_password_path(), scopes=[(secret, [str(case.archive_dir)])])
                        watcher.notify_password_source_changed("builtin_password_file")
                    else:
                        parts[1].write_bytes(missing)
                        watch_module._WatchEventHandler(watcher)._handle_path(str(parts[1]), event_type="created")
                    await watcher.run_once()
                    await watcher.drain()
                    assert attempts[before:] == [password.input.input_id if change_password else volume.input.input_id]
                    assert sibling.stat().st_mtime_ns == sibling_stamp
                assert not watcher.state.entries
                assert len(list(output.rglob("encrypted.txt"))) == 1
                assert len(list(output.rglob(case.marker_name))) == 1
                assert all(not part.exists() for part in parts)
                final = responses[-1].summary.target_results[0]
                assert final.verification["output_file_count"] == len(list(output.rglob("*.*")))
            finally:
                await watcher.aclose()

    asyncio.run(scenario())


@pytest.mark.parametrize("encrypted", [False, True])
def test_each_volume_head_in_a_carrier_enters_the_input_plan(tmp_path, encrypted):
    # One physical anchor silently erased both logical waiters before this case.
    # No other discovery fixture contains two independent RAR heads in one file.
    # Only the heads and a tiny ZIP are needed; extraction is covered above.
    heads = []
    secret = "multiple-heads-header-password"
    for name in ("first", "second"):
        if encrypted:
            case = create_encrypted_rar_archive(tmp_path, name, password=secret, rar4=True, split=True,
                                                payload_size=16 * 1024, split_volume_size=8 * 1024)
        else:
            case = create_rar4_archive(tmp_path, name, split=True, compression_level=0,
                                      payload_size=16 * 1024, split_volume_size=8 * 1024)
        heads.append(case.entry_path.read_bytes())
    source = tmp_path / "inputs"
    source.mkdir()
    carrier = source / "multiple.opaque"
    carrier.write_bytes(b"prefix" * 19 + heads[0] + b"gap" * 23 + heads[1] + b"gap" * 17 + _sibling_zip())
    discovered = ArchiveTaskProvider(make_config({"embedded_scan": {"enabled": True}})).discover_targets([str(carrier)])
    assert len(discovered.tasks) == 1
    inputs = discovered.tasks[0].inputs
    assert len(inputs) == 3 and len({node.input_id for node in inputs}) == 3
    assert [node.volume_completeness for node in inputs] == [
        "unknown" if encrypted else "missing", "unknown" if encrypted else "missing", "complete"]
    if encrypted:
        # Encryption hides whether these are volumes. Preserve unknown until
        # the password refines this same input into its proven missing family.
        assert all(InputCheckpoint(node, (), failure=node.failure).blockers == {"password"}
                   for node in inputs[:2])
        unlocked = ArchiveTaskProvider(make_config({"embedded_scan": {"enabled": True}, "user_passwords": [secret]})).discover_targets([str(carrier)])
        assert [node.input_id for node in unlocked.tasks[0].inputs] == [node.input_id for node in inputs]
        assert all(InputCheckpoint(node, (), failure=node.failure).blockers == {"missing_volume"}
                   for node in unlocked.tasks[0].inputs[:2]), [
            (node.descriptor.analysis, node.failure) for node in unlocked.tasks[0].inputs[:2]]
