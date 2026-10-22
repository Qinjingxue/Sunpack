"""Real service coverage absent from scheduler/unit fixtures: persisted scan state,
file notifications, reload identity, and unfinished split work across restart.
Removing this scenario loses the end-to-end contract; three small archives share
one lifecycle rather than paying for a separate service per assertion.
"""
from __future__ import annotations

import asyncio
import io
import shutil
import zipfile
from copy import deepcopy

import pytest

from sunpack.pipeline.coordinator.engine import PipelineEngine
from sunpack.runtime.watch import service as service_module
from sunpack.runtime.watch.scheduler import WatchScheduler
from tests.helpers.marker_utils import marker_was_extracted
from tests.helpers.real_archives import ArchiveFixtureFactory
from tests.real.plan7_watch_downloads.plan7_support import PASSWORD, plan7_watch_config


pytestmark = pytest.mark.requires_watch_broker


def test_scan_flags_survive_live_edits_restart_and_split_recovery(tmp_path, monkeypatch):
    factory = ArchiveFixtureFactory()
    inner = factory.create(tmp_path / "fixtures", "nested", "7z", password=PASSWORD, payload_size=16 * 1024)
    ignored = factory.create(tmp_path / "fixtures", "already_scanned", "zip", payload_size=8 * 1024)
    split = factory.create(
        tmp_path / "fixtures", "partial", "7z", password=PASSWORD, split=True,
        payload_size=128 * 1024, split_volume_size=48 * 1024,
    )
    old_root, pending_root, added_root = [tmp_path / name for name in ("old", "pending", "added")]
    old_out, pending_out, added_out = [tmp_path / name for name in ("old-out", "pending-out", "added-out")]
    for root in (old_root, pending_root, added_root):
        root.mkdir()
    shutil.copy2(ignored.entry_path, old_root / "old.zip")
    # Nested encrypted archive inside a disguised carrier with both prefix and tail.
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as output:
        output.write(inner.entry_path, "hidden.payload")
    (pending_root / "carrier.data").write_bytes(b"carrier-prefix\0" + archive.getvalue() + b"carrier-tail\0")
    volumes = sorted(split.archive_dir.glob("*.7z.*"))
    assert len(volumes) >= 2
    for volume in volumes[:-1]:
        shutil.copy2(volume, added_root / volume.name.replace(".7z.", ".opaque."))

    roots_path = tmp_path / "sunpack_watch_roots.txt"
    roots_path.write_text(
        f"{old_root} | {old_out} | false | true\n{pending_root} | {pending_out} | true\n",
        encoding="utf-8",
    )
    config = plan7_watch_config(passwords=["wrong-password", PASSWORD])
    config["watch"].update(state_dir=str(tmp_path / "state"), tray_enabled=False, toast_enabled=False)
    monkeypatch.setattr(service_module, "watch_roots_path", lambda: roots_path)
    monkeypatch.setattr(service_module, "load_config", lambda: deepcopy(config))
    scans = []
    scan = WatchScheduler.scan_initial_roots

    async def observed_scan(self, roots):
        scans.append(tuple(service_module.path_key(root) for root in roots))
        return await scan(self, roots)

    monkeypatch.setattr(WatchScheduler, "scan_initial_roots", observed_scan)

    async def scenario():
        async def wait_until(task, condition):
            deadline = asyncio.get_running_loop().time() + 45
            while not condition():
                if task.done():
                    await task
                    pytest.fail("watch exited before the expected result")
                assert asyncio.get_running_loop().time() < deadline, "watch did not reach the expected state"
                await asyncio.sleep(0.01)

        async def start():
            service = service_module.WatchService(engine_factory=PipelineEngine)
            task = asyncio.create_task(service.run())
            try:
                await asyncio.wait_for(service.wait_ready(), 30)
            except BaseException:
                service.request_stop()
                await task
                raise
            return service, task

        async def stop(service, task):
            service.request_stop()
            assert await asyncio.wait_for(task, 30) == 0

        service, task = await start()
        try:
            await wait_until(task, lambda: marker_was_extracted(pending_out, inner.marker_name, inner.marker_text))
            assert scans == [(service_module.path_key(str(pending_root)),)]
            assert all(entry.initial_scanned for entry in service_module._read_watch_root_entries())
            assert not marker_was_extracted(old_out, ignored.marker_name, ignored.marker_text)
            scheduler = service.scheduler
            assert await service.reload() is False  # Own flag write is metadata only.
            assert service.scheduler is scheduler

            # Real file notification, equivalent paths, reordered roots and a comment.
            alias = str(pending_root).upper().replace("\\", "/") + "/."
            roots_path.write_text(
                f"# changed without changing policy\n{alias} | {str(pending_out).upper()} | true | true\n"
                f"{old_root} | {old_out} | false | true\n", encoding="utf-8",
            )
            await wait_until(task, lambda: service.service_config["root_entries"][0].input_root == service_module.normalize_root(alias))
            assert service.scheduler is scheduler and len(scans) == 1

            # Resetting only a flag scans on the live scheduler.
            roots_path.write_text(
                f"{pending_root} | {pending_out} | true | true\n{old_root} | {old_out} | false | false\n",
                encoding="utf-8",
            )
            await wait_until(task, lambda: marker_was_extracted(old_out, ignored.marker_name, ignored.marker_text))
            assert service.scheduler is scheduler
            assert len(scans) == 2 and scans[-1] == (service_module.path_key(str(old_root)),)

            # The CLI and GUI-file routes converge here; incomplete archives do
            # not keep the initial-scan flag false until extraction succeeds.
            await service.add_roots([str(added_root)], output_dir=str(added_out), deep_detect=True)
            await wait_until(task, lambda: any(
                entry.status == "suspended_missing_volume" for entry in service.scheduler.state.entries.values()
            ))
            assert all(entry.initial_scanned for entry in service_module._read_watch_root_entries())
            assert len(scans) == 3 and scans[-1] == (service_module.path_key(str(added_root)),)
        finally:
            await stop(service, task)

        service, task = await start()
        try:
            assert len(scans) == 3  # Persisted true flags suppress another first scan.
            last = volumes[-1]
            shutil.copy2(last, added_root / last.name.replace(".7z.", ".opaque."))
            await wait_until(task, lambda: marker_was_extracted(added_out, split.marker_name, split.marker_text))
            assert len(scans) == 3
            assert all(entry.initial_scanned for entry in service_module._read_watch_root_entries())
        finally:
            await stop(service, task)

    asyncio.run(scenario())
