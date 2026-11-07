"""Read-only, lazy projections for streaming and bounded failure diagnostics.

The views borrow failures and their existing diagnostic dictionaries. They do not
snapshot mutable dictionaries; consumers must finish before producers mutate them.
"""
from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from typing import Any, overload

from .failures import FailureInfo


class _FailureReportPayload(Mapping[str, Any]):
    __slots__ = ("_failure",)
    _FIELDS = (
        "kind", "stage", "message", "message_key", "message_params",
        "user_action", "causes", "details",
    )

    def __init__(self, failure: FailureInfo) -> None:
        self._failure = failure

    def __len__(self) -> int:
        return len(self._FIELDS)

    def __iter__(self) -> Iterator[str]:
        return iter(self._FIELDS)

    def __getitem__(self, key: str) -> Any:
        if key == "kind":
            return self._failure.kind.value
        if key == "causes":
            return FailureReportPayloads(self._failure.causes)
        if key in self._FIELDS:
            return getattr(self._failure, key)
        raise KeyError(key)


class FailureReportPayloads(Sequence[Mapping[str, Any]]):
    """Expose FailureInfo objects without copying their trees or diagnostics."""

    __slots__ = ("_failures", "_indices")

    def __init__(self, failures: Sequence[FailureInfo]) -> None:
        self._failures = failures
        self._indices = range(len(failures))

    def __len__(self) -> int:
        return len(self._indices)

    @overload
    def __getitem__(self, index: int) -> Mapping[str, Any]: ...

    @overload
    def __getitem__(self, index: slice) -> FailureReportPayloads: ...

    def __getitem__(self, index: int | slice) -> Mapping[str, Any] | FailureReportPayloads:
        if isinstance(index, slice):
            result = FailureReportPayloads(self._failures)
            result._indices = self._indices[index]
            return result
        return _FailureReportPayload(self._failures[self._indices[index]])

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Sequence):
            return NotImplemented
        return len(self) == len(other) and all(a == b for a, b in zip(self, other))
