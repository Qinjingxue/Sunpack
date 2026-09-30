"""Physical generations, atomic source cleanup, and legal dot-dot names."""
import asyncio
import io
import os
import subprocess
from concurrent.futures import ThreadPoolExecutor

import pytest
import sunpack_native

from sunpack.core.contracts.results import OutcomeKind
from sunpack.core.contracts.run_state import RunState
from sunpack.core.passwords.fingerprint import build_archive_fingerprint
from sunpack.core.passwords.job import PasswordJob
from sunpack.core.passwords.scheduler import PasswordScheduler
from sunpack.core.passwords.verifier import PasswordBatchVerification, PasswordVerifierChain
from sunpack.core.support.path_keys import safe_relative_path
from sunpack.pipeline.coordinator.engine import _SourceCleanup
from sunpack.pipeline.coordinator.recursive_authorization import RecursiveAuthorization
from sunpack.pipeline.coordinator.scan_session import DiscoveryScanSession
from sunpack.pipeline.coordinator.task_scan import direct_file_task
from sunpack.pipeline.postprocess.actions import PostProcessActions
from tests.helpers.fake_pipeline_engine import _InlineBroker


def _quote(path):
    return "'" + str(path).replace("'", "''") + "'"


def _powershell(script):
    subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command",
         "$ErrorActionPreference='Stop'; " + script],
        check=True, capture_output=True, text=True,
    )


def _write(path, text="old!"):
    _powershell(f"[IO.File]::WriteAllText({_quote(path)}, '{text}')")


def _change(path, replace):
    script = f"$p={_quote(path)}; $m=[IO.File]::GetLastWriteTimeUtc($p);"
    if replace:
        script += "Move-Item -LiteralPath $p -Destination ($p+'.old');"
    script += "[IO.File]::WriteAllText($p, 'new!'); [IO.File]::SetLastWriteTimeUtc($p,$m)"
    _powershell(script)


@pytest.mark.parametrize("replace", [False, True])
@pytest.mark.parametrize("source", ["single", "split", "range"])
@pytest.mark.parametrize("cached_success", [False, True])
def test_password_cache_uses_each_physical_generation(tmp_path, replace, source, cached_success):
    main, part = tmp_path / "disguised.jpg", tmp_path / "volume.bin"
    _write(main)
    _write(part)
    parts = [str(main), str(part)] if source == "split" else None
    descriptor = (
        {"open_mode": "concat_ranges", "ranges": [{"path": str(part), "start": 0, "end": 4}]}
        if source == "range" else None
    )
    changed = part if source in {"split", "range"} else main

    class Verifier:
        password = "old-password"
        calls = 0

        def verify_batch(self, _path, passwords, **kwargs):
            self.calls += 1
            if self.password in passwords:
                return PasswordBatchVerification(
                    ok=True, status="match", matched_index=passwords.index(self.password),
                    attempts=len(passwords), final_confirmation_required=False,
                )
            return PasswordBatchVerification(ok=False, status="no_match", attempts=len(passwords))

    verifier = Verifier()
    scheduler = PasswordScheduler(PasswordVerifierChain([verifier]))
    first_candidates = ["old-password"] if cached_success else ["new-password"]
    first = scheduler.plan_for_extraction(PasswordJob(str(main), part_paths=parts, archive_input=descriptor, candidates=first_candidates))
    before = build_archive_fingerprint(str(main), parts, descriptor)
    calls = verifier.calls
    unchanged = scheduler.plan_for_extraction(PasswordJob(str(main), part_paths=parts, archive_input=descriptor, candidates=first_candidates))
    assert verifier.calls == calls
    assert unchanged.status == first.status
    _change(changed, replace)
    after = build_archive_fingerprint(str(main), parts, descriptor)
    assert before.key != after.key
    verifier.password = "new-password"
    result = scheduler.plan_for_extraction(PasswordJob(str(main), part_paths=parts, archive_input=descriptor, candidates=["new-password"]))
    assert result.password == "new-password"
    assert verifier.calls == calls + 1


def _scope(mode):
    return _SourceCleanup(
        RunState(), {"post_extract": {"archive_cleanup_mode": mode, "flatten_single_directory": False}},
        lambda config, stdout: PostProcessActions(config, stdout=io.StringIO()), "audit",
    )


@pytest.mark.parametrize("mode", ["delete", "recycle"])
@pytest.mark.parametrize("replace", [False, True])
@pytest.mark.parametrize("when", ["before_release", "after_release"])
def test_source_cleanup_preserves_changed_generation(tmp_path, monkeypatch, mode, replace, when):
    path = tmp_path / "carrier.dat"
    _write(path)
    scope = _scope(mode)
    first, second = direct_file_task(str(path)), direct_file_task(str(path))
    scope.register([first, second])
    scope.release_task(first, outcome_kind=OutcomeKind.COMPLETE_SUCCESS)
    if when == "before_release":
        _change(path, replace)
    request = scope.release_task(second, outcome_kind=OutcomeKind.COMPLETE_SUCCESS)
    if when == "after_release":
        _change(path, replace)
    recycled = []
    monkeypatch.setattr("sunpack.pipeline.postprocess.internal.cleanup.send2trash", recycled.append)
    outcome = asyncio.run(scope.apply(request, broker=_InlineBroker()))
    assert path.exists()
    assert outcome.deleted == ()
    assert recycled == []


def test_cleanup_cannot_delete_a_new_arrival_after_missing_input(tmp_path):
    path = tmp_path / "later.002"
    scope = _scope("delete")
    task = direct_file_task(str(path))
    scope.register([task])
    _write(path)
    request = scope.release_task(task, outcome_kind=OutcomeKind.COMPLETE_SUCCESS)
    outcome = asyncio.run(scope.apply(request, broker=_InlineBroker()))
    assert path.exists()
    assert outcome.deleted == ()


def test_recycle_stages_verified_file_before_new_arrival(tmp_path, monkeypatch):
    path = tmp_path / "source.zip"
    _write(path)
    scope = _scope("recycle")
    task = direct_file_task(str(path))
    scope.register([task])

    def recycle(staged):
        assert staged != str(path)
        assert not path.exists()
        assert sunpack_native.watch_candidate_for_path(staged) is None
        _write(path, "new!")
        token = sunpack_native.file_generation_tokens([staged])[0]
        assert sunpack_native.prepare_file_cleanup([(staged, token)], False)[0][0] == "deleted"

    monkeypatch.setattr("sunpack.pipeline.postprocess.internal.cleanup.send2trash", recycle)
    request = scope.release_task(task, outcome_kind=OutcomeKind.COMPLETE_SUCCESS)
    outcome = asyncio.run(scope.apply(request, broker=_InlineBroker()))
    assert outcome.deleted == (str(path),)
    assert path.exists()


@pytest.mark.parametrize("new_arrival", [False, True])
def test_recycle_failure_restores_without_overwriting_new_arrival(tmp_path, monkeypatch, new_arrival):
    path = tmp_path / "source.zip"
    _write(path)
    scope = _scope("recycle")
    task = direct_file_task(str(path))
    scope.register([task])
    staged_paths = []

    def recycle(staged):
        staged_paths.append(staged)
        if new_arrival:
            _write(path, "new!")
        raise OSError("recycle failed")

    monkeypatch.setattr("sunpack.pipeline.postprocess.internal.cleanup.send2trash", recycle)
    outcome = asyncio.run(scope.apply(scope.release_task(task, outcome_kind=OutcomeKind.COMPLETE_SUCCESS), broker=_InlineBroker()))
    assert path.exists()
    assert len(outcome.failed) == 1
    assert os.path.exists(staged_paths[0]) == new_arrival
    if new_arrival:
        assert staged_paths[0] in outcome.failed[0].message


def test_generation_snapshots_are_metadata_only_and_batch_safe(tmp_path):
    path = tmp_path / "source.dat"
    _write(path)
    before = dict(sunpack_native.reader_cache_stats())
    expected = sunpack_native.file_generation_tokens([str(path), str(tmp_path / "missing")])
    assert expected[0] and expected[1] is None
    with ThreadPoolExecutor(max_workers=8) as pool:
        rows = list(pool.map(lambda _: sunpack_native.file_generation_tokens([str(path)]), range(32)))
    assert all(row == expected[:1] for row in rows)
    after = dict(sunpack_native.reader_cache_stats())
    assert before == after


def test_generation_and_cleanup_handles_leave_no_lifecycle_records(tmp_path):
    path = tmp_path / "source.dat"
    _write(path)
    tokens = sunpack_native.file_generation_tokens([str(path), str(tmp_path / "missing")])
    assert len(tokens[0]) <= 100
    assert sunpack_native.native_resource_snapshot([str(tmp_path)]) == []
    session = sunpack_native.NativeArchiveSession(str(path))
    try:
        assert session.generation_token == tokens[0]
    finally:
        session.close()
    # Closing a session returns its handle to the bounded reader pool. Source
    # cleanup releases that pool through the existing scoped resource barrier.
    cached = sunpack_native.native_resource_snapshot([str(tmp_path)])
    assert len(cached) == 1 and cached[0]["kind"] == "reader_file"
    released = sunpack_native.release_reader_resources_under_roots([str(tmp_path)])
    assert released["handles"] == 1
    assert sunpack_native.native_resource_snapshot([str(tmp_path)]) == []
    for _ in range(50):
        rows = sunpack_native.prepare_file_cleanup([(str(path), "stale"), (str(tmp_path / "missing"), None)], False)
        assert [row[0] for row in rows] == ["changed", "missing"]
        assert sunpack_native.native_resource_snapshot([str(tmp_path)]) == []
    assert sunpack_native.prepare_file_cleanup([(str(path), tokens[0])], False)[0][0] == "deleted"
    assert sunpack_native.native_resource_snapshot([str(tmp_path)]) == []


def test_cancelled_cleanup_releases_ownership_and_preserves_source(tmp_path):
    path = tmp_path / "source.dat"
    _write(path)
    scope = _scope("delete")
    task = direct_file_task(str(path))
    scope.register([task])
    request = scope.release_task(task, outcome_kind=OutcomeKind.COMPLETE_SUCCESS)

    class CancelledBroker:
        async def run(self, *_args, **_kwargs):
            raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(scope.apply(request, broker=CancelledBroker()))
    assert path.exists()
    assert scope._table._generations == scope._table._owned == scope._table._counts == {}
    assert sunpack_native.native_resource_snapshot([str(tmp_path)]) == []


def test_cleanup_snapshots_reuse_shared_sources_and_refresh_new_ownership(tmp_path, monkeypatch):
    path = tmp_path / "shared.dat"
    _write(path)
    scope = _scope("delete")
    first, second = direct_file_task(str(path)), direct_file_task(str(path))
    batches = []
    native = sunpack_native.file_generation_tokens

    def capture(paths):
        batches.append(paths)
        return native(paths)

    monkeypatch.setattr(sunpack_native, "file_generation_tokens", capture)
    scope.register([first, second])
    scope.register([first])
    scope.register([second])
    assert len(batches) == 1 and len(batches[0]) == 1
    scope.release_task(first, outcome_kind=OutcomeKind.FAILURE)
    scope.release_task(second, outcome_kind=OutcomeKind.FAILURE)
    _change(path, True)
    scope.register([first])
    outcome = asyncio.run(scope.apply(scope.release_task(first, outcome_kind=OutcomeKind.COMPLETE_SUCCESS), broker=_InlineBroker()))
    assert len(batches) == 2
    assert outcome.deleted == (str(path),)


def test_password_cache_revalidates_real_encrypted_replacement(tmp_path):
    from tests.helpers.tool_config import require_7z
    from sunpack.core.contracts.archive_input import ArchiveInputDescriptor

    source = tmp_path / "payload.txt"
    _write(source)
    archives = [tmp_path / "old.dat", tmp_path / "new.dat"]
    for archive, password in zip(archives, ["old-password", "new-password"]):
        subprocess.run(
            [str(require_7z()), "a", "-tzip", "-mem=AES256", "-mx=0", f"-p{password}", str(archive), str(source)],
            check=True, capture_output=True,
        )
    old, new = archives
    assert old.stat().st_size == new.stat().st_size
    scheduler = PasswordScheduler.with_fast_verifiers()
    descriptor = ArchiveInputDescriptor.from_parts(archive_path=str(old), format_hint="zip")
    job = PasswordJob(str(old), archive_input=descriptor.to_dict(), candidates=["new-password"])
    assert scheduler.plan_for_extraction(job).status == "exhausted"
    _powershell(
        f"$p={_quote(old)}; $m=[IO.File]::GetLastWriteTimeUtc($p); "
        f"Move-Item -LiteralPath $p -Destination ($p+'.old'); Move-Item -LiteralPath {_quote(new)} -Destination $p; "
        "[IO.File]::SetLastWriteTimeUtc($p,$m)"
    )
    result = scheduler.plan_for_extraction(job)
    # AES header matches are forwarded for full extraction confirmation.
    assert result.extraction_candidates == ("new-password",)
    assert result.status != "exhausted"
    assert result.attempts > 0


@pytest.mark.parametrize("name", ["..nested.zip", "..资料/nested.jpg"])
def test_dotdot_prefix_is_inside_nested_scan_scope(tmp_path, name, monkeypatch):
    path = tmp_path / name
    task = direct_file_task(str(path))
    session = DiscoveryScanSession()
    session.set_scan_roots([str(tmp_path)])
    assert safe_relative_path(path, tmp_path) == os.path.normpath(name)
    assert session.is_within_scan_scope(str(path))
    session.snapshot_for_directory = lambda _root: type("Snapshot", (), {"raw_native_snapshot": None})()
    monkeypatch.setattr("sunpack.pipeline.coordinator.recursive_authorization._NATIVE_AUTHORIZE_NESTED_CANDIDATES", lambda *args: [{"allowed": True}])
    result = RecursiveAuthorization({}).authorize_batch([task], [str(tmp_path)], session, depth=2)
    assert result.allowed_tasks == [task]
    assert result.skipped == []
    assert safe_relative_path(tmp_path.parent / "outside.zip", tmp_path) is None
