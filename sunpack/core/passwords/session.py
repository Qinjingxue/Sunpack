from dataclasses import dataclass, field
from threading import RLock


@dataclass
class PasswordSession:
    _resolved_passwords: dict[str, str] = field(default_factory=dict)
    _lock: RLock = field(default_factory=RLock)

    def get_resolved(self, archive_key: str) -> str | None:
        if not archive_key:
            return None
        with self._lock:
            return self._resolved_passwords.get(archive_key)

    def set_resolved(self, archive_key: str, password: str) -> None:
        if not archive_key:
            return
        with self._lock:
            self._resolved_passwords[archive_key] = password

