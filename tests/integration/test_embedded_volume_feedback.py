import asyncio
import io
import zipfile

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


def _sibling_zip(*, large=False):
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w") as archive:
        archive.writestr("sibling.txt", "independent embedded archive")
        if large:
            archive.writestr("padding.dat", b"large-independent-payload" * 16384)
    return data.getvalue()


@pytest.mark.parametrize("archive_format", ["rar", "rar4", "7z", "zip", "zip_spanned", "zip_two_disks"])
@pytest.mark.parametrize("password", [None, "embedded-volume-password"])
def test_carrier_anchor_rejoins_native_volumes_and_missing_parts_can_arrive(tmp_path, monkeypatch, archive_format, password):
    """Only this end-to-end case begins with an unrecognized carrier head.
    Existing SFX and split tests cannot catch losing Embedded's anchor or
    ignoring per-volume ranges. One small archive also checks late arrival,
    earlier missing-member decisions, disguised names and real extraction.
    """
    options = dict(payload_size=160 * 1024, split_volume_size=48 * 1024)
    if archive_format in {"zip_spanned", "zip_two_disks"}:
        if archive_format == "zip_two_disks":
            options["split_volume_size"] = None
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
    assert len(originals) >= 2
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
    volume_end = parts[0].stat().st_size
    parts[0].write_bytes(parts[0].read_bytes() + b"gap-padding" * 7
                         + _sibling_zip(large=archive_format == "7z") + b"tail-padding" * 5)
    missing = parts[1].read_bytes()
    parts[1].unlink()
    config = make_config({"embedded_scan": {"enabled": True}})
    if password:
        config["password_snapshot"] = write_password_json(tmp_path / "passwords.json", scopes=[
            (value, [str(case.archive_dir)]) for value in ["wrong-password", password]
        ])
    first = ArchiveTaskProvider(config).discover_targets([str(parts[0])])
    assert len(first.tasks) == 1
    assert first.tasks[0].discovery_failure is None
    first_segments = [node.projection() for node in first.tasks[0].inputs]
    assert len(first_segments) == 2
    assert first.tasks[0].inputs[0].failure.kind == FailureKind.MISSING_VOLUME

    parts[1].write_bytes(missing)
    found = ArchiveTaskProvider(config).discover_targets([str(case.archive_dir)])
    tasks = [task for task in found.tasks if not task.discovery_failure]
    assert len(tasks) == 1, [(task.main_path, task.discovery_reason) for task in found.tasks]
    assert len(found.tasks) == 1
    task = tasks[0]
    if password and archive_format in {"rar", "rar4"}:
        # The boundary resolver already decrypted this exact head. Losing that
        # proof repeats the expensive password search during real extraction.
        from sunpack.core.passwords.resolver import PasswordResolver

        assert task.inputs[0].password == password
        resolve = PasswordResolver.resolve

        def resolve_unproven(self, archive_path, task=None, **kwargs):
            if task is not None and task.archive_input().format_hint == "rar":
                pytest.fail("decrypted carrier volume repeated password planning")
            return resolve(self, archive_path, task, **kwargs)

        monkeypatch.setattr(PasswordResolver, "resolve", resolve_unproven)
    segments = [node.projection() for node in task.inputs]
    assert len(segments) == 2
    descriptor = task.archive_input()
    assert descriptor.open_mode == "native_volumes"
    assert [part.path for part in descriptor.parts] == [str(path) for path in parts]
    assert descriptor.parts[0].extent.start == len(prefix)
    assert len(prefix) < descriptor.parts[0].extent.end <= volume_end
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
    assert next(output.rglob("sibling.txt")).read_text() == "independent embedded archive"


@pytest.mark.parametrize("rar4", [False, True])
def test_multiple_encrypted_standalone_inputs_share_one_scan_projection(tmp_path, monkeypatch, rar4):
    # The existing standalone and split cases have only one encrypted head.
    # This catches duplicate carrier projection/re-probing and loss of a
    # sibling's independent password blocker with two tiny real archives.
    from sunpack.pipeline.discovery.embedded.discovery import EmbeddedDiscovery
    from sunpack.pipeline.discovery.embedded import discovery as embedded_module

    secrets = ["first-private-input", "second-private-input"]
    payloads = [create_encrypted_rar_archive(
        tmp_path, f"private-{index}", password=secret, rar4=rar4,
        header_encrypt=True, payload_size=4 * 1024,
    ).entry_path.read_bytes() for index, secret in enumerate(secrets)]
    source = tmp_path / "source"
    source.mkdir()
    carrier = source / "shared.opaque"
    carrier.write_bytes(b"prefix" * 19 + payloads[0] + b"gap" * 23
                        + payloads[1] + b"gap" * 17 + _sibling_zip())
    projections = []
    discover_into = EmbeddedDiscovery._discover_into

    def record(self, result, candidate, *args, **kwargs):
        projections.append(candidate.entry_path)
        return discover_into(self, result, candidate, *args, **kwargs)

    monkeypatch.setattr(EmbeddedDiscovery, "_discover_into", record)
    if not rar4:
        monkeypatch.setattr(embedded_module, "resolve_encrypted_rar_boundaries",
                            lambda *args: pytest.fail("already-resolved native headers were probed again"))
    for known in ([], secrets[:1], secrets):
        projections.clear()
        config = make_config({"embedded_scan": {"enabled": True}})
        config["password_snapshot"] = write_password_json(tmp_path / "passwords.json", scopes=[
            (secret, [str(source)]) for secret in known
        ])
        found = ArchiveTaskProvider(config).discover_targets([str(carrier)])
        assert projections == [str(carrier)]
        assert len(found.tasks) == 1
        nodes = found.tasks[0].inputs
        assert len(nodes) == 3 and len({node.input_id for node in nodes}) == 3
        for index, node in enumerate(nodes[:2]):
            if index < len(known):
                assert node.failure is None and node.password == secrets[index]
            else:
                assert node.failure.kind == (FailureKind.WRONG_PASSWORD if known else FailureKind.PASSWORD_REQUIRED)
        assert nodes[2].failure is None


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

    # A header password blocks only this logical archive, never its complete
    # sibling. Existing payload-password tests cannot detect this discovery gate.
    carrier.write_bytes(prefix + archive + suffix + _sibling_zip())
    config, task = discover([])
    assert task.discovery_failure is None
    assert len([node.projection() for node in task.inputs]) == 2
    extractor = ExtractionScheduler(max_retries=0, password_store=PasswordStore.from_config(config))
    sibling_output = tmp_path / "sibling-out"
    try:
        extracted = extractor.extract(task, str(sibling_output))
    finally:
        extractor.close()
    assert not extracted.success and extracted.failure.is_password_failure
    assert next(sibling_output.rglob("sibling.txt")).read_text() == "independent embedded archive"
    from sunpack.pipeline.coordinator.engine import PipelineEngine
    from sunpack.core.contracts.retry_targets import password_retry_failures

    async def password_continuation():
        run_config = {**config, "output": {"root": str(tmp_path / "continuation-out")}}
        async with PipelineEngine(run_config) as engine:
            response = await engine.run([str(carrier)])
            assert response.summary.failed_count == 1
            sibling = next((tmp_path / "continuation-out").rglob("sibling.txt"))
            identity = (sibling, sibling.stat().st_mtime_ns)
            response = await engine.run([str(carrier)], request_config={
                **run_config, "user_passwords": [password],
                "password_retry_failures": password_retry_failures(response.summary),
            })
            assert response.summary.failed_count == 0
            assert [(path, path.stat().st_mtime_ns)
                    for path in (tmp_path / "continuation-out").rglob("sibling.txt")] == [identity]

    asyncio.run(password_continuation())

    carrier.write_bytes(prefix + archive[:len(archive) // 2])
    _, task = discover([password])
    assert task.discovery_failure.kind == FailureKind.DAMAGED


@pytest.mark.parametrize("restart", [False, True])
@pytest.mark.parametrize("archive_format", ["rar", "rar4", "7z", "zip", "zip_spanned"])
def test_watch_waits_for_carrier_volume_then_extracts_on_arrival(tmp_path, monkeypatch, restart, archive_format):
    """Discovery checks cannot prove Watch persists and wakes this new family.
    Drive real scheduling and extraction with two explicit arrival events;
    no broker or timing loop is needed to cover the missing-volume lifecycle.
    """
    from sunpack.pipeline.coordinator.engine import PipelineEngine
    from sunpack.runtime.watch import scheduler as watch_module

    monkeypatch.setattr(watch_module, "validate_ntfs_watch_roots", lambda roots: None)
    options = dict(payload_size=32 * 1024, split_volume_size=12 * 1024)
    if archive_format == "zip_spanned":
        case = create_zip_multidisk_archive(tmp_path, "watch_carrier", **options)
    elif archive_format == "rar4":
        case = create_rar4_archive(tmp_path, "watch_carrier", split=True, compression_level=0, **options)
    else:
        case = ArchiveFixtureFactory().create(
            tmp_path, "watch_carrier", archive_format, split=True, compression_level=0, **options,
        )
    parts = []
    for index, source in enumerate(sorted(case.archive_dir.iterdir(),
                                        key=lambda path: (path != case.entry_path, path.name)), 1):
        path = source.with_name("shared.jpg" if index == 1 else f"shared.chunk{index}.opaque")
        source.rename(path)
        parts.append(path)
    parts[0].write_bytes(b"watch-carrier-prefix" * 51 + parts[0].read_bytes()
                         + b"gap-padding" * 7 + _sibling_zip())
    missing = parts[1].read_bytes()
    parts[1].unlink()
    output = tmp_path / "out"
    config = make_config({
        "embedded_scan": {"enabled": True},
        "watch": {"clipboard_monitor_enabled": False},
        "output": {"root": str(output)},
        "post_extract": {"archive_cleanup_mode": "d"},
    })

    async def scenario():
        async with PipelineEngine(config) as engine:
            factory = engine._request_runtime_factory

            def runtime_for(*args):
                runtime = factory(*args)
                retry = runtime._resolve_missing_volume_once

                def retry_physical_family(task, outcome):
                    # This fallback discards the whole output and logical plan.
                    # A carrier must preserve siblings through its continuation.
                    assert not outcome.result.input_results
                    return retry(task, outcome)

                runtime._resolve_missing_volume_once = retry_physical_family
                return runtime

            engine._request_runtime_factory = runtime_for
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
                siblings = list(output.rglob("sibling.txt"))
                assert len(siblings) == 1
                sibling_identity = (siblings[0], siblings[0].stat().st_mtime_ns)
                assert all(path.is_file() for path in parts if path != parts[1])
                if restart:
                    await watcher.aclose()
                    watcher = watch_module.WatchScheduler(
                        config, [str(case.archive_dir)], output_roots={str(case.archive_dir): str(output)},
                        state_path=str(tmp_path / "state.snapshot"), pipeline_engine=engine,
                    )
                    scope = next(iter(watcher.scopes.values()))
                    assert not watcher._scan_options_for(scope).catalog_update(watcher._catalog, scope.native)
                parts[1].write_bytes(missing)
                watch_module._WatchEventHandler(watcher)._handle_path(str(parts[1]), event_type="created")
                await watcher.run_once()
                await watcher.drain()
                markers = list(output.rglob(case.marker_name))
                assert len(markers) == 1, [(entry.path, entry.status, entry.failure_payload) for entry in watcher.state.entries.values()]
                assert markers[0].read_text(encoding="utf-8") == case.marker_text
                assert [(path, path.stat().st_mtime_ns) for path in output.rglob("sibling.txt")] == [sibling_identity]
                assert all(entry.status != "suspended_missing_volume" for entry in watcher.state.entries.values())
                assert all(not path.exists() for path in parts)
            finally:
                await watcher.aclose()

    asyncio.run(scenario())
