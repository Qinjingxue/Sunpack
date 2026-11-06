import copy
import threading
from collections import OrderedDict
from typing import Any

from sunpack_native import batch_file_head_facts as _native_batch_file_head_facts

from sunpack.core.support.path_keys import path_key


DEFAULT_CACHE_CAPACITY = 512


class CacheManager:
    def __init__(self, default_capacity: int = DEFAULT_CACHE_CAPACITY):
        self.default_capacity = max(1, default_capacity)
        self._caches: dict[str, OrderedDict[tuple, Any]] = {}
        self._immutable_namespaces: frozenset[str] = frozenset()
        self._lock = threading.Lock()

    def register_immutable_namespace(self, namespace: str) -> None:
        with self._lock:
            self._immutable_namespaces = self._immutable_namespaces | {namespace}

    def get(self, namespace: str, key: tuple):
        with self._lock:
            cache = self._caches.get(namespace)
            if not cache or key not in cache:
                return None
            value = cache[key]
            cache.move_to_end(key)
            immutable = namespace in self._immutable_namespaces
        return value if immutable else copy.deepcopy(value)

    def set(self, namespace: str, key: tuple, value: Any):
        immutable = namespace in self._immutable_namespaces
        stored = value if immutable else copy.deepcopy(value)
        with self._lock:
            cache = self._caches.setdefault(namespace, OrderedDict())
            cache[key] = stored
            cache.move_to_end(key)
            while len(cache) > self.default_capacity:
                cache.popitem(last=False)

    def clear_namespace(self, namespace: str) -> int:
        with self._lock:
            cache = self._caches.pop(namespace, None)
            return len(cache) if cache is not None else 0

    def stats(self) -> dict[str, Any]:
        with self._lock:
            namespaces = {
                str(namespace): len(cache)
                for namespace, cache in self._caches.items()
            }
            return {
                "entries": int(sum(namespaces.values())),
                "namespaces": namespaces,
                "capacities": {
                    str(namespace): int(self.default_capacity)
                    for namespace in self._caches
                },
            }

    def clear_all(self) -> dict[str, Any]:
        with self._lock:
            namespaces = {
                str(namespace): len(cache)
                for namespace, cache in self._caches.items()
            }
            self._caches.clear()
            return {
                "entries": int(sum(namespaces.values())),
                "namespaces": namespaces,
            }


GLOBAL_CACHE = CacheManager()


def file_identity(path: str) -> tuple[str, int, int]:
    norm_path = path_key(path)
    rows = _native_batch_file_head_facts([norm_path], 0)
    if not rows or not isinstance(rows[0], dict):
        return norm_path, 0, 0
    return norm_path, int(rows[0].get("size") or 0), int(rows[0].get("mtime_ns") or 0)


def global_cache_stats() -> dict[str, Any]:
    return GLOBAL_CACHE.stats()


def clear_cache_namespace(namespace: str) -> int:
    return GLOBAL_CACHE.clear_namespace(namespace)


def clear_all_caches() -> dict[str, Any]:
    return GLOBAL_CACHE.clear_all()
