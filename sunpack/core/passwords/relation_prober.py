from __future__ import annotations

import os
from threading import RLock

from sunpack.core.passwords.candidates import PasswordCandidatePipeline
from sunpack.core.passwords.fingerprint import build_archive_fingerprint
from sunpack.core.passwords.internal.store import PasswordStore
from sunpack.core.passwords.job import PasswordJob
from sunpack.core.passwords.scheduler import PasswordScheduler, PasswordSearchStatus
from sunpack.core.passwords.verifier import (
    PasswordVerifierRegistry,
    RarFastVerifier,
    SevenZipFastVerifier,
    ZipFastVerifier,
)


# Process-wide memo so repeated directory scans never re-probe unchanged
# bytes.  The fingerprint includes path, size, and mtime_ns.
_RELATION_PROBE_CACHE_LOCK = RLock()
_RELATION_PROBE_CACHE = None


def _shared_attempt_cache():
    global _RELATION_PROBE_CACHE
    with _RELATION_PROBE_CACHE_LOCK:
        if _RELATION_PROBE_CACHE is None:
            from sunpack.core.passwords.cache import PasswordAttemptCache

            _RELATION_PROBE_CACHE = PasswordAttemptCache()
        return _RELATION_PROBE_CACHE


def relation_probe_cache_stats() -> dict[str, int]:
    with _RELATION_PROBE_CACHE_LOCK:
        if _RELATION_PROBE_CACHE is None:
            return {"successes": 0, "negative": 0}
        return _RELATION_PROBE_CACHE.stats()


def clear_relation_probe_cache() -> dict[str, int]:
    with _RELATION_PROBE_CACHE_LOCK:
        if _RELATION_PROBE_CACHE is None:
            return {"successes": 0, "negative": 0}
        return _RELATION_PROBE_CACHE.clear()


class RelationsPasswordProber:
    """Resolve passwords for header-encrypted RAR5 files with bounded probing.

    The RAR5 password check lives entirely in the first volume's prefix, so a
    probe never opens the full-payload sevenzip backend.  Results are cached
    per file fingerprint; successful probes can optionally notify a listener
    (the watch scheduler promotes them into its recent-password pool).
    """

    def __init__(
        self,
        password_store: PasswordStore,
        *,
        password_callback=None,
    ):
        self.password_store = password_store
        self.password_callback = password_callback
        self.scheduler = PasswordScheduler(
            PasswordVerifierRegistry(
                # RAR first: this prober exists for header-encrypted RAR5
                # files.  The ZIP bounded verifier returns a terminal
                # "needs_volume_or_tail_damaged" verdict for renamed/non-ZIP
                # inputs, which would otherwise shadow the RAR password check.
                fast_verifiers=[RarFastVerifier(), ZipFastVerifier(), SevenZipFastVerifier()],
            ).build(),
            cache=_shared_attempt_cache(),
        )

    def set_password_callback(self, callback) -> None:
        self.password_callback = callback

    def resolve_file(
        self,
        path: str,
        *,
        directory_passwords: list[str] | None = None,
        part_paths: list[str] | None = None,
        archive_input: dict | None = None,
    ) -> str | None:
        path = os.path.abspath(path)
        if not path or not os.path.isfile(path):
            return None
        probe_parts = list(part_paths) if part_paths is not None else [path]
        fingerprint = build_archive_fingerprint(path, probe_parts, archive_input)
        cached = self.scheduler.cache.get_success(fingerprint.key)
        if cached is not None:
            return cached
        candidates = PasswordCandidatePipeline.from_password_store(
            self.password_store,
            directory_passwords=directory_passwords,
        )
        result = self.scheduler.plan_for_extraction(PasswordJob(
            archive_path=path,
            part_paths=list(part_paths) if part_paths is not None else None,
            archive_input=archive_input,
            fingerprint=fingerprint,
            candidates=candidates,
        ))
        if result.status == PasswordSearchStatus.FOUND and result.password:
            self.password_store.remember_success(result.password)
            self._notify_found(result.password)
            return result.password
        return None

    def _notify_found(self, password: str) -> None:
        if not password or self.password_callback is None:
            return
        try:
            self.password_callback([password])
        except Exception:
            pass
