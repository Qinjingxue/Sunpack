from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
from threading import RLock


MAX_CACHED_SUCCESSES = 1024
MAX_CACHED_NEGATIVE_ATTEMPTS = 8192


@dataclass
class PasswordAttemptCache:
    _successes: OrderedDict[str, str] = field(default_factory=OrderedDict)
    _negative: OrderedDict[tuple[str, str], None] = field(default_factory=OrderedDict)
    _lock: RLock = field(default_factory=RLock, repr=False)

    def get_success(self, fingerprint_key: str) -> str | None:
        with self._lock:
            if fingerprint_key not in self._successes:
                return None
            self._successes.move_to_end(fingerprint_key)
            return self._successes[fingerprint_key]

    def remember_success(self, fingerprint_key: str, password: str) -> None:
        with self._lock:
            self._successes[fingerprint_key] = password
            self._successes.move_to_end(fingerprint_key)
            if len(self._successes) > MAX_CACHED_SUCCESSES:
                self._successes.popitem(last=False)

    def has_negative(self, fingerprint_key: str, password: str) -> bool:
        with self._lock:
            key = (fingerprint_key, password)
            if key not in self._negative:
                return False
            self._negative.move_to_end(key)
            return True

    def remember_negative(self, fingerprint_key: str, password: str) -> None:
        with self._lock:
            self._remember_negative_locked((fingerprint_key, password))

    def remember_negative_batch(self, fingerprint_key: str, passwords: list[str]) -> None:
        with self._lock:
            for password in passwords:
                self._remember_negative_locked((fingerprint_key, password))

    def _remember_negative_locked(self, key: tuple[str, str]) -> None:
        self._negative[key] = None
        self._negative.move_to_end(key)
        if len(self._negative) > MAX_CACHED_NEGATIVE_ATTEMPTS:
            self._negative.popitem(last=False)

    def stats(self) -> dict[str, int]:
        with self._lock:
            return {
                "successes": len(self._successes),
                "negative": len(self._negative),
            }

    def clear(self) -> dict[str, int]:
        with self._lock:
            result = {
                "successes": len(self._successes),
                "negative": len(self._negative),
            }
            self._successes.clear()
            self._negative.clear()
            return result
