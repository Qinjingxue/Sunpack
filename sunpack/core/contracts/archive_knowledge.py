from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from sunpack.core.support.json_values import jsonable_value as _jsonable


@dataclass
class ArchiveKnowledge:
    data: dict[str, Any] = field(default_factory=dict)
    _mutation_version: int = field(default=0, init=False, repr=False)
    _snapshot_cache: dict[str, Any] | None = field(default=None, init=False, repr=False)
    _snapshot_cache_version: int = field(default=-1, init=False, repr=False)

    @classmethod
    def from_any(cls, raw: Any | None) -> "ArchiveKnowledge":
        if isinstance(raw, ArchiveKnowledge):
            return cls(raw.to_dict())
        if isinstance(raw, dict):
            return cls(_jsonable(raw))
        return cls()

    def to_dict(self) -> dict[str, Any]:
        if self._snapshot_cache is None or self._snapshot_cache_version != self._mutation_version:
            self._snapshot_cache = _jsonable(self.data)
            self._snapshot_cache_version = self._mutation_version
        return deepcopy(self._snapshot_cache)

    def revision(self) -> int:
        meta = self.data.get("_meta")
        if not isinstance(meta, dict):
            return 0
        try:
            return int(meta.get("revision", 0) or 0)
        except (TypeError, ValueError):
            return 0

    def get(self, path: str, default: Any = None) -> Any:
        current: Any = self.data
        for part in _parts(path):
            if not isinstance(current, dict) or part not in current:
                return default
            current = current[part]
        return current

    def set(
        self,
        path: str,
        value: Any,
        *,
        source_layer: str = "",
        source_module: str = "",
        confidence: float | None = None,
        timestamp: str | None = None,
    ) -> "ArchiveKnowledge":
        if not path:
            return self
        current = self.data
        parts = _parts(path)
        for part in parts[:-1]:
            current = current.setdefault(part, {})
            if not isinstance(current, dict):
                return self
        normalized = _jsonable(value)
        current[parts[-1]] = normalized
        self._invalidate_snapshot()
        provenance = _provenance(
            source_layer=source_layer,
            source_module=source_module,
            confidence=confidence,
            timestamp=timestamp,
        )
        if provenance:
            self.add_evidence(path, value, provenance=provenance)
        return self

    def set_prepared(
        self,
        path: str,
        value: Any,
        *,
        source_layer: str = "",
        source_module: str = "",
        confidence: float | None = None,
        timestamp: str | None = None,
    ) -> "ArchiveKnowledge":
        """Transfer an already JSON-safe value into Knowledge without normalizing it again."""
        if not path:
            return self
        current = self.data
        parts = _parts(path)
        for part in parts[:-1]:
            current = current.setdefault(part, {})
            if not isinstance(current, dict):
                return self
        current[parts[-1]] = value
        self._invalidate_snapshot()
        provenance = _provenance(
            source_layer=source_layer,
            source_module=source_module,
            confidence=confidence,
            timestamp=timestamp,
        )
        if provenance:
            self.add_evidence(path, value, provenance=provenance)
        return self

    def merge(self, *payloads: Any, source_layer: str = "", source_module: str = "") -> "ArchiveKnowledge":
        for payload in payloads:
            raw = payload.to_dict() if isinstance(payload, ArchiveKnowledge) else payload
            if isinstance(raw, dict):
                _deep_merge(self.data, _jsonable(raw))
                self._invalidate_snapshot()
        if source_layer or source_module:
            self.add_evidence("knowledge.merge", True, provenance=_provenance(source_layer=source_layer, source_module=source_module))
        return self

    def add_flags(self, namespace: str, flags: list[str] | tuple[str, ...] | set[str], *, source_layer: str = "", source_module: str = "") -> "ArchiveKnowledge":
        key = f"{namespace}.flags" if namespace else "flags"
        current = [str(item) for item in self.get(key, []) or [] if str(item)]
        merged = _dedupe([*current, *[str(item) for item in flags if str(item)]])
        return self.set(key, merged, source_layer=source_layer, source_module=source_module)

    def flags(self, namespace: str = "") -> list[str]:
        if namespace:
            return [str(item) for item in self.get(f"{namespace}.flags", []) or [] if str(item)]
        output: list[str] = []
        self._collect_flags(self.data, output)
        return _dedupe(output)

    def features(self, prefix: str = "") -> dict[str, Any]:
        value = self.get(prefix) if prefix else self.data
        return _jsonable(value) if isinstance(value, dict) else {}

    def add_evidence(self, path: str, value: Any, *, provenance: dict[str, Any] | None = None) -> "ArchiveKnowledge":
        evidence = list(self.data.setdefault("_evidence", []))
        item = {"path": str(path), "value": compact_evidence_value(value)}
        if provenance:
            item["provenance"] = _jsonable(provenance)
        evidence.append(item)
        self.data["_evidence"] = evidence[-500:]
        self._invalidate_snapshot()
        return self

    def history(self, namespace: str = "") -> list[dict[str, Any]]:
        raw = self.get(f"{namespace}.history" if namespace else "history", [])
        return [dict(item) for item in raw if isinstance(item, dict)] if isinstance(raw, list) else []


    def _collect_flags(self, value: Any, output: list[str]) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                if key == "flags" and isinstance(item, list):
                    output.extend(str(flag) for flag in item if str(flag))
                else:
                    self._collect_flags(item, output)

    def _invalidate_snapshot(self) -> None:
        self._mutation_version += 1
        self._snapshot_cache = None
        self._snapshot_cache_version = -1


def merge_knowledge(*payloads: Any) -> dict[str, Any]:
    knowledge = ArchiveKnowledge()
    for payload in payloads:
        if payload:
            knowledge.merge(payload)
    return knowledge.to_dict()


def _parts(path: str) -> list[str]:
    return [part for part in str(path or "").split(".") if part]


def _provenance(
    *,
    source_layer: str = "",
    source_module: str = "",
    confidence: float | None = None,
    timestamp: str | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    if source_layer:
        payload["source_layer"] = source_layer
    if source_module:
        payload["source_module"] = source_module
    if confidence is not None:
        payload["confidence"] = float(confidence)
    if payload:
        payload["timestamp"] = timestamp or datetime.now(timezone.utc).isoformat()
    return payload


def _deep_merge(target: dict[str, Any], source: dict[str, Any]) -> dict[str, Any]:
    for key, value in source.items():
        if isinstance(value, dict) and isinstance(target.get(key), dict):
            _deep_merge(target[key], value)
        elif isinstance(value, list) and isinstance(target.get(key), list):
            target[key] = _merge_lists(target[key], value)
        else:
            target[key] = deepcopy(value)
    return target


def _merge_lists(left: list[Any], right: list[Any]) -> list[Any]:
    output: list[Any] = []
    seen: set[str] = set()
    for item in [*left, *right]:
        key = repr(_jsonable(item))
        if key in seen:
            continue
        seen.add(key)
        output.append(_jsonable(item))
    return output


def _dedupe(values: list[str]) -> list[str]:
    output: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        output.append(value)
    return output


def compact_evidence_value(value: Any) -> Any:
    if isinstance(value, ArchiveKnowledge):
        return {"kind": "archive_knowledge", "revision": value.revision()}
    if isinstance(value, dict):
        output: dict[str, Any] = {}
        for key, item in value.items():
            text_key = str(key)
            if text_key in {"stdout", "stderr"} and isinstance(item, str):
                output[text_key] = item[:4000]
            else:
                output[text_key] = compact_evidence_value(item)
        return output
    if isinstance(value, (list, tuple, set)):
        values = list(value)
        compacted = [compact_evidence_value(item) for item in values[:50]]
        if len(values) > 50:
            compacted.append({"truncated_count": len(values) - 50})
        return compacted
    return _jsonable(value)


def _compact_large_value(key: str, value: Any) -> Any:
    if isinstance(value, dict):
        return {
            "kind": key,
            "keys": sorted(str(item) for item in value.keys())[:50],
            "sha256": _stable_repr_digest(value),
        }
    if isinstance(value, list):
        return {"kind": key, "count": len(value), "sha256": _stable_repr_digest(value)}
    return _jsonable(value)


def _stable_repr_digest(value: Any) -> str:
    import hashlib
    import json

    try:
        payload = json.dumps(_jsonable(value), ensure_ascii=False, sort_keys=True, default=str)
    except Exception:
        payload = repr(value)
    return hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest()
