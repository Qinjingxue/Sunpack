from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass

from sunpack.core.passwords.internal.store import PasswordStore


@dataclass(frozen=True, slots=True)
class PasswordCandidate:
    value: str
    source: str = "unknown"
    rule: str = ""
    priority: int = 100


class PasswordCandidatePipeline:
    def __init__(self, sources: Iterable[Iterable[PasswordCandidate]] | None = None):
        self._sources = tuple(sources or ())
        self._store: PasswordStore | None = None
        self._scope_path = ""
        self._include_empty = False

    @classmethod
    def from_password_store(
        cls,
        store: PasswordStore,
        *,
        scope_path: str = "",
        include_empty: bool = False,
    ) -> "PasswordCandidatePipeline":
        pipeline = cls()
        pipeline._store = store
        pipeline._scope_path = scope_path
        pipeline._include_empty = include_empty
        return pipeline

    @classmethod
    def from_values(cls, passwords: Iterable[str], *, source: str = "manual") -> "PasswordCandidatePipeline":
        return cls([
            tuple(PasswordCandidate(str(password), source=source) for password in passwords),
        ])

    def allows(self, password: str) -> bool:
        if self._store is not None:
            return (password == "" and self._include_empty) or self._store.allows(password, self._scope_path)
        return any(candidate.value == password for candidate in self)

    def __iter__(self) -> Iterator[PasswordCandidate]:
        if self._store is not None:
            if self._include_empty:
                yield PasswordCandidate("", source="empty", priority=0)
            for candidate in _store_candidates(self._store, scope_path=self._scope_path):
                if not self._include_empty or candidate.value != "":
                    yield candidate
            return
        seen: set[str] = set()
        ordered = sorted((candidate for source in self._sources for candidate in source), key=lambda candidate: candidate.priority)
        for candidate in ordered:
            if candidate.value not in seen:
                seen.add(candidate.value)
                yield candidate


def _store_candidates(
    store: PasswordStore,
    *,
    scope_path: str = "",
) -> Iterator[PasswordCandidate]:
    for password, source, priority in store.candidate_values(scope_path):
        yield PasswordCandidate(password, source=source, priority=priority)
