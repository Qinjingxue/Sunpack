"""A discovery boundary, independent of archive recursion and output routing."""
import os
from sunpack_native import NativeDiscoveryScope
from sunpack.core.support.path_keys import normalized_path


class DiscoveryScope:
    __slots__ = ("native",)

    def __init__(self, root: str, *, recursive: bool = False,
                 excluded_subtrees=(), max_depth: int | None = None):
        self.native = NativeDiscoveryScope(os.path.abspath(root),
            max_depth if max_depth is not None else (None if recursive else 0),
            [normalized_path(path) for path in excluded_subtrees])

    @property
    def root(self) -> str:
        return self.native.root

    @property
    def max_depth(self) -> int | None:
        return self.native.max_depth

    def contains(self, path: str) -> bool:
        return self.native.contains(normalized_path(path))

    def __deepcopy__(self, memo):
        return self

    def to_record(self):
        return {"root": self.root, "max_depth": self.max_depth,
                "excluded_subtrees": sorted(self.native.excluded_subtrees)}

    @classmethod
    def from_record(cls, value):
        return cls(value["root"], recursive=value["max_depth"] is None,
                   max_depth=value["max_depth"], excluded_subtrees=value.get("excluded_subtrees", ()))
