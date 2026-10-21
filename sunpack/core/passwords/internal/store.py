from __future__ import annotations

from dataclasses import dataclass, field
from threading import RLock
from collections.abc import Mapping
from types import MappingProxyType
import os

from sunpack.core.support.path_keys import absolute_path_key
from sunpack.core.passwords.internal.lists import dedupe_passwords

MAX_RECENT_PASSWORDS = 64


def password_scope_key(path: str) -> str:
    # UNC share roots can reach us with or without their final separator.
    return absolute_path_key(path).rstrip("\\/")


@dataclass(frozen=True, slots=True)
class PasswordSnapshot:
    global_passwords: tuple[str, ...] = ()
    scoped_index: Mapping[str, tuple[str, ...]] = field(default_factory=lambda: MappingProxyType({}))
    signature: str = ""

    def __post_init__(self):
        object.__setattr__(self, "global_passwords", tuple(self.global_passwords))
        if not isinstance(self.scoped_index, MappingProxyType):
            object.__setattr__(self, "scoped_index", MappingProxyType({k: tuple(v) for k, v in self.scoped_index.items()}))

    def __deepcopy__(self, memo):
        return self

    def scoped_passwords(self, scope_path: str):
        if not scope_path or not self.scoped_index:
            return
        key = absolute_path_key(scope_path)
        while True:
            yield from self.scoped_index.get(key.rstrip("\\/"), ())
            parent = os.path.dirname(key)
            if parent == key:
                break
            key = parent


EMPTY_PASSWORD_SNAPSHOT = PasswordSnapshot()


@dataclass
class PasswordStore:
    user_passwords: list[str] = field(default_factory=list)
    clipboard_passwords: list[str] = field(default_factory=list)
    recent_passwords: list[str] = field(default_factory=list)
    snapshot: PasswordSnapshot = EMPTY_PASSWORD_SNAPSHOT
    _lock: RLock = field(default_factory=RLock, repr=False)

    def __deepcopy__(self, memo):
        # Recursive configuration views belong to this same pinned request.
        return self

    @classmethod
    def from_sources(cls, *, cli_passwords=None, clipboard_passwords=None,
                     builtin_passwords=None, builtin_passwords_file=None, recent_passwords=None,
                     password_snapshot=None) -> "PasswordStore":
        if password_snapshot is None:
            if builtin_passwords_file:
                from sunpack.core.passwords.internal.builtin import read_builtin_password_file
                password_snapshot = read_builtin_password_file(builtin_passwords_file)
            else:
                password_snapshot = PasswordSnapshot(tuple(dedupe_passwords(builtin_passwords or ())))
        return cls(
            user_passwords=dedupe_passwords(cli_passwords or ()),
            clipboard_passwords=dedupe_passwords(clipboard_passwords or ()),
            recent_passwords=dedupe_passwords(recent_passwords or ())[:MAX_RECENT_PASSWORDS],
            snapshot=password_snapshot,
        )

    @classmethod
    def from_config(cls, config: dict) -> "PasswordStore":
        store = config.get("password_store")
        if store is not None:
            return store
        return cls.from_sources(
            cli_passwords=config.get("user_passwords"),
            clipboard_passwords=config.get("clipboard_passwords"),
            builtin_passwords=config.get("builtin_passwords"),
            password_snapshot=config.get("password_snapshot"),
        )

    @property
    def builtin_passwords(self) -> tuple[str, ...]:
        return self.snapshot.global_passwords

    def candidate_values(self, scope_path: str = ""):
        with self._lock:
            snapshot = self.snapshot
            user, clipboard, recent = self.user_passwords, self.clipboard_passwords, tuple(self.recent_passwords)
        scoped = tuple(snapshot.scoped_passwords(scope_path))
        sources = ((scoped, "scope", 15), (user, "user", 20),
                   (clipboard, "clipboard", 30), (snapshot.global_passwords, "builtin", 50))
        wanted = set(recent)
        eligible = set()
        if wanted:
            for values, _, _ in sources:
                eligible.update(wanted.intersection(values))
        seen = set()
        for value in recent:
            if value in eligible and value not in seen:
                seen.add(value)
                yield value, "recent", 10
        for values, source, priority in sources:
            for value in values:
                if value not in seen:
                    seen.add(value)
                    yield value, source, priority

    def allows(self, password: str, scope_path: str = "") -> bool:
        with self._lock:
            return (password in self.user_passwords or password in self.clipboard_passwords
                    or password in self.snapshot.global_passwords
                    or password in self.snapshot.scoped_passwords(scope_path))

    def candidates(self, scope_path: str = "") -> list[str]:
        return [value for value, _, _ in self.candidate_values(scope_path)]

    def has_candidates(self, scope_path: str = "") -> bool:
        with self._lock:
            return bool(self.user_passwords or self.clipboard_passwords or self.snapshot.global_passwords
                        or next(self.snapshot.scoped_passwords(scope_path), None) is not None)

    def remember_success(self, password: str) -> None:
        if not password:
            return
        with self._lock:
            self.recent_passwords = [password, *(v for v in self.recent_passwords if v != password)][:MAX_RECENT_PASSWORDS]
