from dataclasses import dataclass
import threading

from sunpack.core.support.global_cache_manager import CacheManager


class _CountingLock:
    def __init__(self):
        self._lock = threading.Lock()
        self.acquisitions = 0

    def __enter__(self):
        self.acquisitions += 1
        self._lock.acquire()
        return self

    def __exit__(self, exc_type, exc, tb):
        self._lock.release()

    def locked(self) -> bool:
        return self._lock.locked()


class _CopyProbe:
    def __init__(self, manager: CacheManager, observations: list[bool]):
        self._manager = manager
        self._observations = observations

    def __deepcopy__(self, memo):
        self._observations.append(self._manager._lock.locked())
        return self


def test_mutable_set_copies_before_taking_cache_lock():
    manager = CacheManager()
    lock = _CountingLock()
    manager._lock = lock
    observations = []
    value = _CopyProbe(manager, observations)

    manager.set("probe", ("key",), value)

    assert observations == [False]
    assert lock.acquisitions == 1


def test_mutable_get_copies_after_releasing_cache_lock():
    manager = CacheManager()
    observations = []
    value = _CopyProbe(manager, observations)

    manager.set("probe", ("key",), value)
    observations.clear()
    assert manager.get("probe", ("key",)) is value

    assert observations == [False]


def test_mutable_cache_keeps_defensive_copy_semantics():
    manager = CacheManager()
    original = {"items": [1]}

    manager.set("mutable", ("key",), original)
    original["items"].append(2)

    first = manager.get("mutable", ("key",))
    assert first == {"items": [1]}

    first["items"].append(3)
    assert manager.get("mutable", ("key",)) == {"items": [1]}


@dataclass(frozen=True, slots=True)
class _FrozenValue:
    items: tuple[int, ...]


def test_immutable_namespace_returns_cached_object_directly():
    manager = CacheManager()
    manager.register_immutable_namespace("immutable")
    value = _FrozenValue((1, 2, 3))

    manager.set("immutable", ("key",), value)

    assert manager.get("immutable", ("key",)) is value
    assert manager.cached(
        "immutable",
        ("key",),
        lambda: _FrozenValue((4, 5)),
    ) is value
