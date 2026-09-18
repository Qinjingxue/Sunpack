from dataclasses import dataclass, field
from threading import RLock
from typing import List

from sunpack.passwords.internal.builtin import read_builtin_password_file
from sunpack.passwords.internal.lists import dedupe_passwords


MAX_RECENT_PASSWORDS = 64


@dataclass
class PasswordStore:
    user_passwords: List[str] = field(default_factory=list)
    clipboard_passwords: List[str] = field(default_factory=list)
    builtin_passwords: List[str] = field(default_factory=list)
    recent_passwords: List[str] = field(default_factory=list)
    _lock: RLock = field(default_factory=RLock, repr=False)

    @classmethod
    def from_sources(
        cls,
        *,
        cli_passwords: List[str] | None = None,
        clipboard_passwords: List[str] | None = None,
        builtin_passwords: List[str] | None = None,
        builtin_passwords_file: str | None = None,
        recent_passwords: List[str] | None = None,
    ) -> "PasswordStore":
        if builtin_passwords is None and builtin_passwords_file:
            try:
                builtin_passwords = read_builtin_password_file(builtin_passwords_file)
            except Exception:
                builtin_passwords = []
        return cls(
            user_passwords=dedupe_passwords(cli_passwords or []),
            clipboard_passwords=dedupe_passwords(clipboard_passwords or []),
            builtin_passwords=dedupe_passwords(builtin_passwords or []),
            recent_passwords=dedupe_passwords(recent_passwords or [])[:MAX_RECENT_PASSWORDS],
        )

    def candidates(self, directory_passwords: List[str] | None = None) -> List[str]:
        with self._lock:
            return dedupe_passwords(
                list(self.recent_passwords)
                + list(directory_passwords or [])
                + list(self.user_passwords)
                + list(self.clipboard_passwords)
                + list(self.builtin_passwords)
            )

    def has_candidates(self, directory_passwords: List[str] | None = None) -> bool:
        with self._lock:
            return bool(
                self.recent_passwords
                or directory_passwords
                or self.user_passwords
                or self.clipboard_passwords
                or self.builtin_passwords
            )

    def remember_success(self, password: str) -> None:
        if not password:
            return
        with self._lock:
            self.recent_passwords = [item for item in self.recent_passwords if item != password]
            self.recent_passwords.insert(0, password)
            del self.recent_passwords[MAX_RECENT_PASSWORDS:]

    def replace_sources(self, *, user_passwords: List[str], builtin_passwords: List[str]) -> None:
        """Atomically refresh dynamic sources without discarding learned passwords."""
        with self._lock:
            self.user_passwords = dedupe_passwords(user_passwords)
            self.builtin_passwords = dedupe_passwords(builtin_passwords)
