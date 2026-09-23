from dataclasses import dataclass, field
from threading import RLock
from typing import Optional


@dataclass
class PasswordSession:
    _resolved_passwords: dict[str, str | None] = field(default_factory=dict)
    _lock: RLock = field(default_factory=RLock)

    def get_resolved(self, archive_key: str) -> Optional[str]:
        if not archive_key:
            return None
        with self._lock:
            return self._resolved_passwords.get(archive_key)

    def has_resolved(self, archive_key: str) -> bool:
        if not archive_key:
            return False
        with self._lock:
            return archive_key in self._resolved_passwords

    def set_resolved(self, archive_key: str, password: str | None) -> None:
        if not archive_key:
            return
        with self._lock:
            self._resolved_passwords[archive_key] = password

