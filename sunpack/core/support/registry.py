"""Small registry primitives shared by layer-specific registries."""

from __future__ import annotations

from typing import Generic, TypeVar


T = TypeVar("T")


class NamedRegistry(Generic[T]):
    """Ordered-by-registration name registry with defensive snapshots."""

    def __init__(self) -> None:
        self._items: dict[str, T] = {}

    def register_named(self, name: str, item: T) -> None:
        self._items[name] = item

    def get_named(self, name: str) -> T | None:
        return self._items.get(name)

    def all_named(self) -> dict[str, T]:
        return dict(self._items)
