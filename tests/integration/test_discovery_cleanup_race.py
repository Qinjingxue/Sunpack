"""Real source cleanup racing an older encrypted-volume discovery.

Ordinary split/archive tests do not hold discovery across another request's
successful cleanup. Events force that ordering without timing-based retries;
one small RAR fixture exercises the native probe, worker and cleanup together.
"""
import asyncio
import contextlib
import shutil
import threading

import pytest

from sunpack.core.passwords.verifier.input import PasswordProbeInput
from sunpack.core.contracts.discovery_scope import DiscoveryScope
from sunpack.core.contracts.failures import FailureKind
from sunpack.core.passwords.relation_prober import RelationsPasswordProber
from sunpack.core.support.archive_sessions import release_archive_sessions_under_roots
from sunpack.core.support.resource_lifecycle import promotion_barrier, resource_snapshot
from sunpack.pipeline.coordinator.engine import PipelineEngine
from sunpack.pipeline.postprocess.internal.cleanup import ArchiveCleanup
from tests.helpers.config_factory import make_config
from tests.helpers.real_archives import create_encrypted_rar_archive
from tests.real.plan1_real_archives.plan1_support import assert_expected_files_extracted


def _pause_first_probe(monkeypatch, phase="borrow"):
    loop = asyncio.get_running_loop()
    paused = asyncio.Event()
    resume = threading.Event()
    selection = threading.Lock()
    selected = False

    def pause_once():
        nonlocal selected
        with selection:
            pause = not selected
            selected = True
        if pause:
            # The old snapshot/fingerprint exist, but no borrow or path claim
            # may pin the inputs while the other request cleans up.
            loop.call_soon_threadsafe(paused.set)
            assert resume.wait(15), "competing cleanup did not finish"

    if phase == "admission":
        probe = RelationsPasswordProber.resolve_file

        def probe_after_cleanup(self, *args, **kwargs):
            pause_once()
            return probe(self, *args, **kwargs)

        monkeypatch.setattr(RelationsPasswordProber, "resolve_file", probe_after_cleanup)
    else:
        borrow = PasswordProbeInput.borrow_sessions

        @contextlib.contextmanager
        def borrow_after_cleanup(prepared):
            pause_once()
            with borrow(prepared) as sessions:
                yield sessions

        monkeypatch.setattr(PasswordProbeInput, "borrow_sessions", borrow_after_cleanup)
    return paused, resume


@pytest.mark.parametrize("origin", ["watch", "foreground"])
@pytest.mark.parametrize("probe_phase", ["admission", "borrow"])
def test_successful_cleanup_does_not_abort_older_volume_discovery(tmp_path, monkeypatch, origin, probe_phase):
    case = create_encrypted_rar_archive(
        tmp_path / "fixtures", "race", password="race-password",
        header_encrypt=True, split=True, split_volume_size=100 * 1024,
        payload_size=320 * 1024,
    )
    parts = sorted(case.archive_dir.glob("*.rar"))
    assert len(parts) == 4
    output = tmp_path / "output"
    config = make_config({
        "user_passwords": ["race-password"],
        "cli": {"quiet": True},
        "recursive_extract": "1",
        "post_extract": {"archive_cleanup_mode": "d"},
        "output": {"root": str(output), "common_root": str(case.archive_dir), "fixed_root": True},
    })

    async def scenario():
        paused, resume = _pause_first_probe(monkeypatch, probe_phase)
        async with PipelineEngine(config) as engine:
            scope = DiscoveryScope(str(case.archive_dir))
            older = asyncio.create_task(engine.run([str(parts[-1])], origin=origin, discovery_scope=scope))
            try:
                await asyncio.wait_for(paused.wait(), 10)
                successful = await asyncio.wait_for(
                    engine.run([str(parts[0])], origin=origin, discovery_scope=scope), 10,
                )
                assert successful.summary.success_count == 1
                assert not successful.summary.failed_tasks
                assert not successful.summary.cleanup_results
                assert not any(part.exists() for part in parts)
            finally:
                resume.set()
                # Always finish the blocked broker operation before engine
                # shutdown, including when an assertion above fails.
                results = await asyncio.gather(older, return_exceptions=True)
            [late] = results
            if isinstance(late, BaseException):
                raise late
            assert not late.summary.failed_tasks
            assert late.summary.success_count == 0
            assert_expected_files_extracted(case, output)
            for name in case.metadata["expected_files"]:
                assert len(list(output.rglob(name))) == 1

    asyncio.run(scenario())


def test_departed_middle_volume_remains_missing_and_recovers_when_restored(tmp_path, monkeypatch):
    """All-departed inputs cannot catch hiding a real missing-member failure.

    One small split set also checks partial-borrow release and password-cache
    recovery, which a fake verifier or a test deleting the whole set cannot prove.
    """
    case = create_encrypted_rar_archive(
        tmp_path / "fixtures", "partial", password="partial-password",
        header_encrypt=True, split=True, split_volume_size=100 * 1024, payload_size=320 * 1024,
    )
    root = tmp_path / "input"
    shutil.copytree(case.archive_dir, root)
    parts = sorted(root.glob("*.rar"))
    # Native structural resolution must survive camouflaged suffixes too.
    parts = [path.rename(path.with_name(path.name + ".jpg")) for path in parts]
    middle = parts[1]
    output = tmp_path / "output"
    config = make_config({
        "user_passwords": ["partial-password"], "cli": {"quiet": True},
        "recursive_extract": "1", "post_extract": {"archive_cleanup_mode": "d"},
        "output": {"root": str(output), "common_root": str(root), "fixed_root": True},
    })

    def remove_middle():
        with promotion_barrier(
            (middle,), cache_releasers=(release_archive_sessions_under_roots,), quiesce=False,
        ):
            [result] = ArchiveCleanup("delete", quiet=True).cleanup_success_archives([[str(middle)]])
            assert result.status == "deleted"

    async def scenario():
        paused, resume = _pause_first_probe(monkeypatch)
        async with PipelineEngine(config) as engine:
            scope = DiscoveryScope(str(root))
            older = asyncio.create_task(engine.run([str(parts[-1])], origin="watch", discovery_scope=scope))
            try:
                await asyncio.wait_for(paused.wait(), 10)
                await asyncio.wait_for(asyncio.to_thread(remove_middle), 10)
            finally:
                resume.set()
                results = await asyncio.gather(older, return_exceptions=True)
            [incomplete] = results
            if isinstance(incomplete, BaseException):
                raise incomplete
            assert incomplete.summary.success_count == 0
            assert any(failure.contains(FailureKind.MISSING_VOLUME) for failure in incomplete.summary.failures)
            assert all(part.exists() for part in parts if part != middle)
            assert not any(row["kind"] == "archive_session_borrow" for row in resource_snapshot(map(str, parts)))
            shutil.copyfile(case.archive_dir / middle.name.removesuffix(".jpg"), middle)
            restored = await engine.run([str(parts[0])], origin="watch", discovery_scope=scope)
            assert restored.summary.success_count == 1
            assert not restored.summary.failed_tasks
            assert not any(part.exists() for part in parts)
            assert_expected_files_extracted(case, output)

    asyncio.run(scenario())
