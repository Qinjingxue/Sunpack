import asyncio

import pytest

from sunpack.core.contracts.failures import FailureKind
from sunpack.core.passwords.internal.store import PasswordStore
from sunpack.pipeline.coordinator.task_provider import ArchiveTaskProvider
from sunpack.pipeline.discovery.detection.input_planning import ArchiveInputPlanningStage
from sunpack.pipeline.extraction.scheduler import ExtractionScheduler
from tests.helpers.config_factory import make_config
from tests.helpers.real_archives import ArchiveFixtureFactory
from tests.helpers.real_archives import create_encrypted_rar_archive, create_rar4_archive, create_zip_multidisk_archive
from tests.helpers.passwords import write_password_json


@pytest.mark.parametrize("archive_format", ["rar", "rar4", "7z", "zip", "zip_spanned"])
@pytest.mark.parametrize("password", [None, "embedded-volume-password"])
def test_carrier_anchor_rejoins_native_volumes_and_missing_parts_can_arrive(tmp_path, archive_format, password):
    """Only this end-to-end case begins with an unrecognized carrier head.
    Existing SFX and split tests cannot catch losing Embedded's anchor or
    ignoring per-volume ranges. One small archive also checks late arrival,
    earlier missing-member decisions, disguised names and real extraction.
    """
    options = dict(payload_size=160 * 1024, split_volume_size=48 * 1024)
    if archive_format == "zip_spanned":
        case = create_zip_multidisk_archive(tmp_path, "carrier", password=password, **options)
    elif archive_format == "rar4":
        if password:
            case = create_encrypted_rar_archive(tmp_path, "carrier", password=password, rar4=True, split=True, **options)
        else:
            case = create_rar4_archive(tmp_path, "carrier", split=True, compression_level=0, **options)
    else:
        case = ArchiveFixtureFactory().create(
            tmp_path, "carrier", archive_format, split=True, password=password, compression_level=0, **options,
        )
    originals = sorted(case.archive_dir.iterdir(), key=lambda path: (path != case.entry_path, path.name))
    assert len(originals) >= 3
    parts = []
    for number, source in enumerate(originals, 1):
        target = case.archive_dir / ("shared.jpg" if number == 1 else f"shared.chunk{number}.opaque")
        source.rename(target)
        parts.append(target)
    prefix = b"unrecognized-carrier-prefix\0" * 211
    parts[0].write_bytes(prefix + parts[0].read_bytes())
    bounded_part = None
    if archive_format in {"rar", "rar4", "zip_spanned"}:
        bounded_part = 0 if archive_format.startswith("rar") else len(parts) - 1
        bounded_end = parts[bounded_part].stat().st_size
        parts[bounded_part].write_bytes(parts[bounded_part].read_bytes() + b"carrier-trailing-padding" * 37)
    missing = parts[1].read_bytes()
    parts[1].unlink()
    config = make_config({"embedded_scan": {"enabled": True}})
    if password:
        config["password_snapshot"] = write_password_json(tmp_path / "passwords.json", scopes=[
            (value, [str(case.archive_dir)]) for value in ["wrong-password", password]
        ])
    first = ArchiveTaskProvider(config).discover_targets([str(parts[0])])
    assert len(first.tasks) == 1
    assert first.tasks[0].discovery_failure.kind == FailureKind.MISSING_VOLUME

    parts[1].write_bytes(missing)
    found = ArchiveTaskProvider(config).discover_targets([str(case.archive_dir)])
    tasks = [task for task in found.tasks if not task.discovery_failure]
    assert len(tasks) == 1, [(task.main_path, task.discovery_reason) for task in found.tasks]
    assert len(found.tasks) == 1
    task = tasks[0]
    descriptor = task.archive_input()
    assert descriptor.open_mode == "native_volumes"
    assert [part.path for part in descriptor.parts] == [str(path) for path in parts]
    assert descriptor.parts[0].extent.start == len(prefix)
    if bounded_part is not None:
        # RAR may already pad the physical volume beyond ENDARC. Both that
        # padding and the added carrier suffix must remain outside the input.
        extent = descriptor.parts[bounded_part].extent
        assert extent.start < extent.end <= bounded_end
    assert all(part.extent.start == 0 for part in descriptor.parts[1:-1])
    assert not (found.claimed_paths & (found.blocked_paths | found.residual_paths))
    planned = ArchiveInputPlanningStage(config).plan_task_to_tasks(task)
    assert len(planned) == 1
    extractor = ExtractionScheduler(max_retries=0, password_store=PasswordStore.from_config(config))
    output = tmp_path / "out"
    try:
        extracted = extractor.extract(planned[0], str(output))
    finally:
        extractor.close()
    assert extracted.success, extracted.error
    assert next(output.rglob(case.marker_name)).read_text(encoding="utf-8") == case.marker_text


@pytest.mark.parametrize("rar4", [False, True])
def test_encrypted_standalone_carrier_keeps_boundary_and_password_failures(tmp_path, rar4):
    """Split fixtures cannot catch an encrypted standalone RAR entering Relations.
    This also distinguishes missing passwords, wrong passwords and a decrypted
    truncated tail; one small archive covers the fallback's independent states.
    """
    password = "standalone-carrier-password"
    case = create_encrypted_rar_archive(
        tmp_path, "standalone", password=password, rar4=rar4,
        header_encrypt=True, payload_size=8 * 1024,
    )
    prefix, suffix = b"carrier-prefix" * 83, b"carrier-suffix" * 47
    archive = case.entry_path.read_bytes()
    carrier = case.archive_dir / "capture.opaque"
    case.entry_path.unlink()
    carrier.write_bytes(prefix + archive + suffix)

    def discover(passwords):
        config = make_config({"embedded_scan": {"enabled": True}})
        config["password_snapshot"] = write_password_json(tmp_path / "passwords.json", scopes=[
            (value, [str(case.archive_dir)]) for value in passwords
        ])
        result = ArchiveTaskProvider(config).discover_targets([str(carrier)])
        assert len(result.tasks) == 1
        return config, result.tasks[0]

    for passwords, failure in [([], FailureKind.PASSWORD_REQUIRED), (["wrong"], FailureKind.WRONG_PASSWORD)]:
        _, task = discover(passwords)
        assert task.discovery_failure.kind == failure

    config, task = discover(["wrong", password])
    assert task.discovery_failure is None
    assert task.discovery_source == "embedded"
    planned = ArchiveInputPlanningStage(config).plan_task_to_tasks(task)
    extractor = ExtractionScheduler(max_retries=0, password_store=PasswordStore.from_config(config))
    output = tmp_path / "out"
    try:
        extracted = extractor.extract(planned[0], str(output))
    finally:
        extractor.close()
    assert extracted.success, extracted.error
    assert next(output.rglob(case.marker_name)).read_text(encoding="utf-8") == case.marker_text

    carrier.write_bytes(prefix + archive[:len(archive) // 2])
    _, task = discover([password])
    assert task.discovery_failure.kind == FailureKind.DAMAGED


def test_watch_waits_for_carrier_volume_then_extracts_on_arrival(tmp_path, monkeypatch):
    """Discovery checks cannot prove Watch persists and wakes this new family.
    Drive real scheduling and extraction with two explicit arrival events;
    no broker or timing loop is needed to cover the missing-volume lifecycle.
    """
    from sunpack.pipeline.coordinator.engine import PipelineEngine
    from sunpack.runtime.watch import scheduler as watch_module

    monkeypatch.setattr(watch_module, "validate_ntfs_watch_roots", lambda roots: None)
    case = ArchiveFixtureFactory().create(
        tmp_path, "watch_carrier", "7z", split=True, compression_level=0,
        payload_size=32 * 1024, split_volume_size=12 * 1024,
    )
    parts = []
    for index, source in enumerate(sorted(case.archive_dir.iterdir()), 1):
        path = source.with_name("shared.jpg" if index == 1 else f"shared.chunk{index}.opaque")
        source.rename(path)
        parts.append(path)
    parts[0].write_bytes(b"watch-carrier-prefix" * 51 + parts[0].read_bytes())
    missing = parts[1].read_bytes()
    parts[1].unlink()
    output = tmp_path / "out"
    config = make_config({
        "embedded_scan": {"enabled": True},
        "watch": {"clipboard_monitor_enabled": False},
        "output": {"root": str(output)},
        "post_extract": {"archive_cleanup_mode": "k"},
    })

    async def scenario():
        async with PipelineEngine(config) as engine:
            watcher = watch_module.WatchScheduler(
                config, [str(case.archive_dir)], output_roots={str(case.archive_dir): str(output)},
                state_path=str(tmp_path / "state.snapshot"), pipeline_engine=engine,
            )
            try:
                scope = next(iter(watcher.scopes.values()))
                assert not watcher._scan_options_for(scope).catalog_update(watcher._catalog, scope.native)
                watcher.enqueue(str(parts[0]))
                await watcher.run_once()
                await watcher.drain()
                entry = watcher.state.latest_entry_for_path(str(parts[0]))
                assert entry is not None and entry.status == "suspended_missing_volume"
                parts[1].write_bytes(missing)
                watch_module._WatchEventHandler(watcher)._handle_path(str(parts[1]), event_type="created")
                await watcher.run_once()
                await watcher.drain()
                markers = list(output.rglob(case.marker_name))
                assert len(markers) == 1, [(entry.path, entry.status, entry.failure_payload) for entry in watcher.state.entries.values()]
                assert markers[0].read_text(encoding="utf-8") == case.marker_text
                assert all(entry.status != "suspended_missing_volume" for entry in watcher.state.entries.values())
            finally:
                await watcher.aclose()

    asyncio.run(scenario())
