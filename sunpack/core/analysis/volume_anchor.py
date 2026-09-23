from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable
import os

from sunpack_native import probe_volume_anchors as _native_probe_volume_anchors


@dataclass(frozen=True, slots=True)
class VolumeAnchorEvidence:
    path: str
    size: int
    format: str = ""
    confidence: str = "none"
    standalone: bool = False
    multivolume: bool = False
    encrypted: bool = False
    needs_password: bool = False
    wrong_password: bool = False
    anchor_roles: tuple[str, ...] = ()
    internal_volume_number: int | None = None
    structure_offset: int | None = None
    expected_logical_size: int | None = None
    continuation_from_previous: bool = False
    continuation_to_next: bool = False
    sfx: bool = False
    evidence: tuple[str, ...] = ()
    error: str = ""
    bytes_read: int = 0

    @classmethod
    def from_mapping(cls, value: dict[str, Any]) -> "VolumeAnchorEvidence":
        return cls(
            path=str(value.get("path") or ""),
            size=int(value.get("size") or 0),
            format=str(value.get("format") or ""),
            confidence=str(value.get("confidence") or "none"),
            standalone=bool(value.get("standalone")),
            multivolume=bool(value.get("multivolume")),
            encrypted=bool(value.get("encrypted")),
            needs_password=bool(value.get("needs_password")),
            wrong_password=bool(value.get("wrong_password")),
            anchor_roles=tuple(str(item) for item in value.get("anchor_roles") or ()),
            internal_volume_number=int(value["internal_volume_number"]) if value.get("internal_volume_number") is not None else None,
            structure_offset=int(value["structure_offset"]) if value.get("structure_offset") is not None else None,
            expected_logical_size=int(value["expected_logical_size"]) if value.get("expected_logical_size") is not None else None,
            continuation_from_previous=bool(value.get("continuation_from_previous")),
            continuation_to_next=bool(value.get("continuation_to_next")),
            sfx=bool(value.get("sfx")),
            evidence=tuple(str(item) for item in value.get("evidence") or ()),
            error=str(value.get("error") or ""),
            bytes_read=int(value.get("bytes_read") or 0),
        )

    @property
    def structurally_confirmed(self) -> bool:
        return self.confidence == "strong" and bool(self.format) and not self.error

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "size": self.size,
            "format": self.format,
            "confidence": self.confidence,
            "standalone": self.standalone,
            "multivolume": self.multivolume,
            "encrypted": self.encrypted,
            "needs_password": self.needs_password,
            "wrong_password": self.wrong_password,
            "anchor_roles": list(self.anchor_roles),
            "internal_volume_number": self.internal_volume_number,
            "structure_offset": self.structure_offset,
            "expected_logical_size": self.expected_logical_size,
            "continuation_from_previous": self.continuation_from_previous,
            "continuation_to_next": self.continuation_to_next,
            "sfx": self.sfx,
            "evidence": list(self.evidence),
            "error": self.error,
            "bytes_read": self.bytes_read,
        }


@dataclass(frozen=True, slots=True)
class VolumeEvidenceIndex:
    by_path: dict[str, VolumeAnchorEvidence] = field(default_factory=dict)

    def get(self, path: str) -> VolumeAnchorEvidence | None:
        return self.by_path.get(_path_key(path))

    @property
    def total_bytes_read(self) -> int:
        return sum(item.bytes_read for item in self.by_path.values())


def probe_volume_anchor_paths(
    paths: Iterable[str],
    *,
    prefix_limit: int = 1024 * 1024,
    tail_limit: int = 65_557,
    path_passwords: dict[str, str] | None = None,
) -> VolumeEvidenceIndex:
    ordered = list(dict.fromkeys(str(path) for path in paths if path))
    password_pairs = (
        [
            (str(path), str(password))
            for path, password in path_passwords.items()
            if str(password)
        ]
        if path_passwords
        else None
    )
    rows = _native_probe_volume_anchors(
        ordered,
        max(64, int(prefix_limit)),
        max(22, int(tail_limit)),
        password_pairs,
    )
    evidences = [VolumeAnchorEvidence.from_mapping(row) for row in rows]
    return VolumeEvidenceIndex({_path_key(item.path): item for item in evidences})


def _path_key(path: str) -> str:
    return os.path.normcase(os.path.normpath(os.path.abspath(path)))
