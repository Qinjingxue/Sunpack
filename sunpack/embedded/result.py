from __future__ import annotations

from dataclasses import dataclass
from typing import Any


_HIT_FORMATS = {
    "zip_local": "zip",
    "zip_eocd": "zip",
    "rar4": "rar",
    "rar5": "rar",
    "7z": "7z",
    "gzip": "gzip",
    "bzip2": "bzip2",
    "xz": "xz",
    "zstd": "zstd",
    "tar_ustar": "tar",
}


@dataclass(frozen=True, slots=True)
class EmbeddedCandidate:
    format: str
    detected_ext: str
    offset: int
    end_offset: int | None
    confidence: float
    validation: str
    candidate_kind: str
    boundary_kind: str
    range_end_offset: int | None
    extractable: bool
    contained_anchor_count: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": self.format,
            "detected_ext": self.detected_ext,
            "offset": self.offset,
            "end_offset": self.end_offset,
            "confidence": self.confidence,
            "validation": self.validation,
            "candidate_kind": self.candidate_kind,
            "boundary_kind": self.boundary_kind,
            "range_end_offset": self.range_end_offset,
            "extractable": self.extractable,
            "contained_anchor_count": self.contained_anchor_count,
        }


@dataclass(frozen=True, slots=True)
class SignatureHit:
    name: str
    offset: int

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "offset": self.offset, "source": "embedded_scan"}


@dataclass(frozen=True, slots=True)
class EmbeddedScanResult:
    complete: bool
    candidates: tuple[EmbeddedCandidate, ...]
    hits: tuple[SignatureHit, ...]
    read_bytes: int
    file_size: int
    logical_resolution_complete: bool
    raw_hit_count: int
    budget_exhausted: bool

    @property
    def found(self) -> bool:
        return bool(self.candidates)

    @classmethod
    def empty(cls, *, complete: bool = False) -> "EmbeddedScanResult":
        return cls(
            complete=complete,
            candidates=(),
            hits=(),
            read_bytes=0,
            file_size=0,
            logical_resolution_complete=complete,
            raw_hit_count=0,
            budget_exhausted=False,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "found": self.found,
            "complete": self.complete,
            "candidates": [item.to_dict() for item in self.candidates],
            "hits": [item.to_dict() for item in self.hits],
            "read_bytes": self.read_bytes,
            "file_size": self.file_size,
            "signature_scan_complete": self.complete,
            "logical_resolution_complete": self.logical_resolution_complete,
            "raw_hit_count": self.raw_hit_count,
            "budget_exhausted": self.budget_exhausted,
        }

    def to_prepass(self) -> dict[str, Any]:
        validated_formats = {item.format for item in self.candidates}
        hits = [
            item.to_dict()
            for item in self.hits
            if _HIT_FORMATS.get(item.name) in validated_formats
        ]
        return {
            "hits": hits,
            "formats": sorted(validated_formats),
            "full_scan_bytes": self.read_bytes,
            "full_scan_complete": self.complete,
            "logical_resolution_complete": self.logical_resolution_complete,
            "raw_hit_count": self.raw_hit_count,
            "embedded_scan_budget_exhausted": self.budget_exhausted,
            "source": "embedded_scan",
            "embedded_candidates": [item.to_dict() for item in self.candidates],
        }
