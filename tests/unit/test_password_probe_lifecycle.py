from __future__ import annotations

import threading
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

import pytest

import sunpack.core.support.archive_sessions as sessions
from sunpack.core.passwords.verifier import rar_fast, seven_zip_fast, zip_fast
from sunpack.core.support.resource_lifecycle import (
    ResourceBusyError,
    TaskResourceScope,
    promotion_barrier,
    resource_snapshot,
)


@pytest.fixture(autouse=True)
def clear_sessions():
    sessions.clear_archive_sessions()
    yield
    sessions.clear_archive_sessions()


def borrows(paths):
    return [r for r in resource_snapshot(paths) if r['kind'] == 'archive_session_borrow']


@pytest.mark.parametrize('module,verifier,mode', [
    (rar_fast, rar_fast.RarFastVerifier, 'file'),
    (rar_fast, rar_fast.RarFastVerifier, 'ranges'),
    (rar_fast, rar_fast.RarFastVerifier, 'volumes'),
    (zip_fast, zip_fast.ZipFastVerifier, 'file'),
    (zip_fast, zip_fast.ZipFastVerifier, 'ranges'),
    (zip_fast, zip_fast.ZipFastVerifier, 'volumes'),
    (seven_zip_fast, seven_zip_fast.SevenZipFastVerifier, 'file'),
    (seven_zip_fast, seven_zip_fast.SevenZipFastVerifier, 'ranges'),
])
@pytest.mark.parametrize('raise_error', [False, True])
def test_password_probe_releases_only_its_own_borrows(tmp_path, monkeypatch, module, verifier, mode, raise_error):
    paths = [tmp_path / 'renamed.part1.jpg', tmp_path / 'renamed.part2.jpg']
    for path in paths:
        path.write_text('fixture', encoding='utf-8')
    physical = [str(path) for path in paths]
    outcome = {'status': 'no_match', 'matched_index': -1, 'attempts': 1}

    def probe(*args, **kwargs):
        assert len(borrows(physical)) == 1 + (1 if mode == 'file' else 2)
        if mode != 'file':
            assert len(kwargs['sessions']) == 2
        if raise_error:
            raise RuntimeError('probe failed')
        return outcome

    method = {'rar': 'rar_fast', 'zip': 'zip_fast', '7z': 'seven_zip_fast'}[verifier.format_hint]

    class FakeSession:
        generation_token = 'same-generation'
        def __init__(self, path):
            self.closed = False
        def close(self):
            self.closed = True

    setattr(FakeSession, method + '_verify_passwords', probe)
    monkeypatch.setattr(sessions, 'NativeArchiveSession', FakeSession)
    from sunpack.core.passwords.verifier.input import PasswordProbeInput
    ranges = [{'path': path, 'start': 13} for path in physical] if mode == 'ranges' else None
    style = 'rar_part' if module is rar_fast else 'zip_spanned'
    volumes = [{'path': path, 'volume_number': i} for i, path in enumerate(physical, 1)] if mode == 'volumes' else None
    prepared = PasswordProbeInput(None, physical[0], ranges=ranges, volumes=volumes,
        volume_style=style if volumes else '', volume_aware=bool(volumes),
        session_paths=tuple(physical if mode != 'file' else physical[:1]))
    monkeypatch.setattr(module, 'prepare_password_input', lambda *a, **k: prepared)
    if mode != 'file':
        monkeypatch.setattr(module, method + '_verify_passwords_from_' + mode, probe)
    scope = TaskResourceScope('existing-analysis-owner', files=physical)
    try:
        with scope.activate():
            original = sessions.get_archive_session(physical[0])
            if raise_error:
                with pytest.raises(RuntimeError, match='probe failed'):
                    verifier().verify_batch(physical[0], ['wrong'])
            else:
                assert verifier().verify_batch(physical[0], ['wrong']).status == 'no_match'
            assert len(borrows(physical)) == 1
            assert not original.closed
            assert len(scope._resource_ids) == 1
    finally:
        scope.close()


def test_concurrent_directory_probes_do_not_hold_each_others_cleanup_sources(tmp_path):
    paths = [tmp_path / 'encrypted.rar', tmp_path / 'split.part1.rar.jpg']
    for path in paths:
        path.write_text('not-an-archive', encoding='utf-8')
    rendezvous = threading.Barrier(2)

    def request(index):
        scope = TaskResourceScope(f'probe-request-{index}', files=(paths[index],))
        try:
            with scope.activate():
                # Directory relation probing touches all encrypted candidates,
                # even though this request extracts just one of them.
                for path in paths:
                    rar_fast.RarFastVerifier().verify_batch(str(path), ['wrong'])
                rendezvous.wait(timeout=2)
                with promotion_barrier(
                    (paths[index],), timeout=1,
                    cache_releasers=(sessions.release_archive_sessions_under_roots,),
                ):
                    paths[index].unlink()
                # Neither request may rely on the other's scope finalizer.
                rendezvous.wait(timeout=2)
        finally:
            scope.close()

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(request, index) for index in range(2)]
        for future in futures:
            future.result(timeout=5)
    assert not any(path.exists() for path in paths)


def test_overlapping_probes_in_one_task_remain_protected(tmp_path):
    path = tmp_path / 'input.jpg'
    path.write_text('fixture', encoding='utf-8')
    scope = TaskResourceScope('overlapping-probes', files=(path,))
    try:
        with sessions.archive_session_scope(), scope.activate():
            with sessions.borrow_archive_sessions((path,)) as first:
                with sessions.borrow_archive_sessions((path, str(path).upper())) as second:
                    assert first[0] is second[0]
                    assert len(borrows((path,))) == 2
                assert len(borrows((path,))) == 1
                # Even the owning request cannot promote an actively borrowed
                # probe session; the operation, not the request, owns it.
                with pytest.raises(ResourceBusyError):
                    with promotion_barrier((path,), timeout=0):
                        pytest.fail('promotion admitted an active probe')
            assert not borrows((path,))
            assert not scope._resource_ids
            # Reuse must not pin cache entries after a short probe. Remaining
            # tests do not retire/reopen an entry within one search scope.
            with promotion_barrier((path,), timeout=0,
                                   cache_releasers=(sessions.release_archive_sessions_under_roots,)):
                pass
            assert first[0].closed
            with sessions.borrow_archive_sessions((path,)) as reopened:
                assert reopened[0] is not first[0]
                assert not reopened[0].closed
    finally:
        scope.close()


def test_partial_volume_acquisition_releases_completed_borrows(tmp_path):
    path = tmp_path / 'first.jpg'
    path.write_text('fixture', encoding='utf-8')
    scope = TaskResourceScope('partial-probe')
    try:
        with scope.activate():
            with pytest.raises((OSError, RuntimeError)):
                with sessions.borrow_archive_sessions((path, tmp_path / 'missing.part2.jpg')):
                    pytest.fail('missing volume was acquired')
            assert not borrows((path,))
            assert not scope._resource_ids
    finally:
        scope.close()


@pytest.mark.parametrize("interrupt", [False, True])
def test_multibatch_password_job_releases_its_input_before_task_exit(tmp_path, monkeypatch, interrupt):
    """Catch job-wide borrow leaks that the single-probe cases cannot detect.

    A few fake batches exercise normal and exceptional completion; promotion
    while the surrounding task remains alive proves independent cleanup safety.
    """
    from sunpack.core.passwords.job import PasswordJob
    from sunpack.core.passwords.scheduler import PasswordScheduler
    from sunpack.core.passwords.verifier.registry import PasswordVerifierChain
    physical = [str(tmp_path / name) for name in ("first.bin", "second.bin")]
    for path in physical:
        Path(path).write_bytes(b"input")
    monkeypatch.setattr(zip_fast, "zip_fast_verify_passwords_from_ranges",
        lambda ranges, passwords, *a, **k: {"status": "no_match", "attempts": len(passwords)})

    def candidates():
        for index in range(600):
            if interrupt and index == 257:
                raise RuntimeError("candidate source failed after a batch")
            yield str(index)

    job = PasswordJob(physical[0], archive_input={
        "kind": "archive_input", "open_mode": "concat_ranges", "format_hint": "zip",
        "entry_path": physical[0], "ranges": [{"path": path, "start": 0, "end": 5} for path in physical],
    }, candidates=candidates())
    scope = TaskResourceScope("multibatch-password-job", files=physical)
    try:
        with scope.activate():
            scheduler = PasswordScheduler(PasswordVerifierChain([zip_fast.ZipFastVerifier()]))
            if interrupt:
                with pytest.raises(RuntimeError, match="candidate source failed"):
                    scheduler.plan_for_extraction(job)
            else:
                assert scheduler.plan_for_extraction(job).exhausted
            assert not borrows(physical)
            with promotion_barrier(physical, timeout=0,
                    cache_releasers=(sessions.release_archive_sessions_under_roots,)):
                for path in physical:
                    Path(path).unlink()
    finally:
        scope.close()
