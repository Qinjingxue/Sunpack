from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass

from sunpack.core.passwords.internal.store import PasswordStore


@dataclass(frozen=True)
class PasswordCandidate:
    value: str
    source: str = "unknown"
    rule: str = ""
    priority: int = 100


class PasswordCandidatePipeline:
    def __init__(self, sources: Iterable[Iterable[PasswordCandidate]] | None = None):
        self._sources = list(sources or [])

    @classmethod
    def from_password_store(
        cls,
        store: PasswordStore,
        *,
        directory_passwords: Iterable[str] | None = None,
        include_empty: bool = False,
    ) -> "PasswordCandidatePipeline":
        sources: list[Iterable[PasswordCandidate]] = []
        if include_empty:
            sources.append((PasswordCandidate("", source="empty", priority=0),))
        sources.append(_store_candidates(store, directory_passwords=directory_passwords))
        return cls(sources)

    @classmethod
    def from_values(cls, passwords: Iterable[str], *, source: str = "manual") -> "PasswordCandidatePipeline":
        return cls([
            (PasswordCandidate(str(password), source=source) for password in passwords),
        ])

    def __iter__(self) -> Iterator[PasswordCandidate]:
        seen: set[str] = set()
        for source in self._sources:
            for candidate in source:
                if candidate.value in seen:
                    continue
                seen.add(candidate.value)
                yield candidate


def _store_candidates(
    store: PasswordStore,
    *,
    directory_passwords: Iterable[str] | None = None,
) -> Iterator[PasswordCandidate]:
    for password in store.recent_passwords:
        yield PasswordCandidate(password, source="recent", priority=10)
    for password in directory_passwords or []:
        yield PasswordCandidate(password, source="directory", priority=15)
    for password in store.user_passwords:
        yield PasswordCandidate(password, source="user", priority=20)
    for password in store.clipboard_passwords:
        yield PasswordCandidate(password, source="clipboard", priority=30)
    for password in store.builtin_passwords:
        yield PasswordCandidate(password, source="builtin", priority=50)
