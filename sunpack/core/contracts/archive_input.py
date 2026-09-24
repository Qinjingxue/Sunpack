from __future__ import annotations

from dataclasses import dataclass, field
import os
from typing import Any, Literal


ArchiveOpenMode = Literal[
    "file",
    "file_range",
    "concat_ranges",
    "native_volumes",
    "sfx_with_volumes",
]


@dataclass(frozen=True)
class ArchiveInputRange:
    path: str
    start: int = 0
    end: int | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "path": self.path,
            "start": int(self.start),
        }
        if self.end is not None:
            payload["end"] = int(self.end)
        return payload


@dataclass(frozen=True)
class ArchiveInputPart:
    path: str
    role: str = "main"
    volume_number: int | None = None
    canonical_name: str = ""
    range: ArchiveInputRange | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "path": self.path,
            "role": self.role,
        }
        if self.volume_number is not None:
            payload["volume_number"] = int(self.volume_number)
        if self.canonical_name:
            payload["canonical_name"] = self.canonical_name
        if self.range is not None:
            payload.update({
                "start": int(self.range.start),
            })
            if self.range.end is not None:
                payload["end"] = int(self.range.end)
        return payload


@dataclass(frozen=True)
class ArchiveInputSegment:
    start: int = 0
    end: int | None = None
    confidence: float | None = None
    source: str = "analysis"

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "start": int(self.start),
            "source": self.source,
        }
        if self.end is not None:
            payload["end"] = int(self.end)
        if self.confidence is not None:
            payload["confidence"] = float(self.confidence)
        return payload


@dataclass(frozen=True)
class ArchiveInputDescriptor:
    entry_path: str
    open_mode: ArchiveOpenMode = "file"
    format_hint: str = ""
    logical_name: str = ""
    volume_style: str = ""
    parts: list[ArchiveInputPart] = field(default_factory=list)
    ranges: list[ArchiveInputRange] = field(default_factory=list)
    segment: ArchiveInputSegment | None = None
    analysis: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "format_hint", str(self.format_hint or "").strip().lower().lstrip("."))
        if self.open_mode in {"native_volumes", "sfx_with_volumes"}:
            ordered = sorted(self.parts, key=lambda part: int(part.volume_number or 0))
            if not ordered:
                raise ValueError("structured volume inputs require parts")
            numbers = [int(part.volume_number or 0) for part in ordered]
            if any(number <= 0 for number in numbers) or len(set(numbers)) != len(numbers):
                raise ValueError("structured volume parts require unique positive volume numbers")
            if any(not part.canonical_name for part in ordered):
                raise ValueError("structured volume parts require canonical_name")
            canonical_keys = [part.canonical_name.casefold() for part in ordered]
            if len(set(canonical_keys)) != len(canonical_keys):
                raise ValueError("structured volume canonical names must be unique")
            if not self.volume_style:
                raise ValueError("structured volume inputs require volume_style")
            object.__setattr__(self, "parts", ordered)
            object.__setattr__(self, "entry_path", next((part.path for part in ordered if part.volume_number == 1), ordered[0].path))

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "kind": "archive_input",
            "entry_path": self.entry_path,
            "open_mode": self.open_mode,
        }
        if self.format_hint:
            payload["format_hint"] = self.format_hint
        if self.logical_name:
            payload["logical_name"] = self.logical_name
        if self.volume_style:
            payload["volume_style"] = self.volume_style
        if self.parts:
            payload["parts"] = [part.to_dict() for part in self.parts]
        if self.ranges:
            payload["ranges"] = [item.to_dict() for item in self.ranges]
        if self.segment is not None:
            payload["segment"] = self.segment.to_dict()
        if self.analysis:
            payload["analysis"] = dict(self.analysis)
        return payload

    def part_paths(self) -> list[str]:
        if self.open_mode == "concat_ranges" and self.ranges:
            return list(dict.fromkeys(item.path for item in self.ranges if item.path))
        if self.parts:
            return list(dict.fromkeys(part.path for part in self.parts if part.path))
        return [self.entry_path] if self.entry_path else []

    def with_path_mapping(self, mapper) -> "ArchiveInputDescriptor":
        parts = [
            ArchiveInputPart(
                path=mapper(part.path),
                role=part.role,
                volume_number=part.volume_number,
                canonical_name=part.canonical_name,
                range=ArchiveInputRange(
                    path=mapper(part.range.path),
                    start=part.range.start,
                    end=part.range.end,
                ) if part.range is not None else None,
            )
            for part in self.parts
        ]
        ranges = [
            ArchiveInputRange(path=mapper(item.path), start=item.start, end=item.end)
            for item in self.ranges
        ]
        return ArchiveInputDescriptor(
            entry_path=mapper(self.entry_path),
            open_mode=self.open_mode,
            format_hint=self.format_hint,
            logical_name=self.logical_name,
            volume_style=self.volume_style,
            parts=parts,
            ranges=ranges,
            segment=self.segment,
            analysis=dict(self.analysis),
        )

    def _primary_range(self) -> ArchiveInputRange | None:
        if self.parts:
            part = self.parts[0]
            if part.range is not None:
                return part.range
        if self.segment is not None:
            return ArchiveInputRange(path=self.entry_path, start=self.segment.start, end=self.segment.end)
        return None

    @classmethod
    def from_dict(cls, raw: dict[str, Any], *, archive_path: str = "", part_paths: list[str] | None = None) -> "ArchiveInputDescriptor":
        kind = str(raw.get("kind") or "archive_input")
        if kind != "archive_input":
            raise ValueError(f"unsupported archive input kind: {kind}")
        open_mode = str(raw.get("open_mode") or "file")
        format_hint = str(raw.get("format_hint") or "")
        entry_path = str(raw.get("entry_path") or archive_path)
        parts = []
        for item in raw.get("parts") or []:
            if not isinstance(item, dict):
                continue
            path = str(item.get("path") or entry_path)
            end_raw = item.get("end")
            start = int(item.get("start", 0) or 0)
            part_range = None
            if start or end_raw is not None:
                part_range = ArchiveInputRange(
                    path=path,
                    start=start,
                    end=int(end_raw) if end_raw is not None else None,
                )
            parts.append(ArchiveInputPart(
                path=path,
                role=str(item.get("role") or "main"),
                volume_number=int(item["volume_number"]) if item.get("volume_number") is not None else None,
                canonical_name=str(item.get("canonical_name") or ""),
                range=part_range,
            ))
        ranges = []
        for item in raw.get("ranges") or []:
            if not isinstance(item, dict):
                continue
            end_raw = item.get("end")
            ranges.append(ArchiveInputRange(
                path=str(item.get("path") or entry_path),
                start=int(item.get("start", 0) or 0),
                end=int(end_raw) if end_raw is not None else None,
            ))
        segment = None
        segment_raw = raw.get("segment")
        if isinstance(segment_raw, dict):
            end_raw = segment_raw.get("end")
            confidence_raw = segment_raw.get("confidence")
            segment = ArchiveInputSegment(
                start=int(segment_raw.get("start", 0) or 0),
                end=int(end_raw) if end_raw is not None else None,
                confidence=float(confidence_raw) if confidence_raw is not None else None,
                source=str(segment_raw.get("source") or "analysis"),
            )
        if not parts and not ranges and part_paths:
            if len(part_paths) > 1:
                raise ValueError("multi-volume inputs require serialized structured parts")
            parts = [ArchiveInputPart(path=str(part_paths[0]), role="main", volume_number=1)]
        return cls(
            entry_path=entry_path,
            open_mode=open_mode,  # type: ignore[arg-type]
            format_hint=format_hint,
            logical_name=str(raw.get("logical_name") or ""),
            volume_style=str(raw.get("volume_style") or ""),
            parts=parts,
            ranges=ranges,
            segment=segment,
            analysis=dict(raw.get("analysis") or {}) if isinstance(raw.get("analysis"), dict) else {},
        )

    @classmethod
    def from_parts(
        cls,
        *,
        archive_path: str,
        part_paths: list[str] | None = None,
        format_hint: str = "",
        logical_name: str = "",
    ) -> "ArchiveInputDescriptor":
        paths = list(part_paths or [archive_path])
        if len(paths) > 1:
            raise ValueError("multi-volume inputs require structured parts with volume_number and canonical_name")
        mode: ArchiveOpenMode = "file"
        return cls(
            entry_path=archive_path,
            open_mode=mode,
            format_hint=format_hint,
            logical_name=logical_name,
            parts=[
                ArchiveInputPart(path=str(path), role="main", volume_number=1)
                for index, path in enumerate(paths)
            ],
        )

    @classmethod
    def from_split_volumes(
        cls,
        *,
        archive_path: str,
        volumes: list[Any],
        format_hint: str,
        logical_name: str,
    ) -> "ArchiveInputDescriptor":
        normalized: list[dict[str, Any]] = []
        for raw in volumes:
            value = raw if isinstance(raw, dict) else vars(raw)
            path = str(value.get("path") or "")
            number = int(value.get("number") or 0)
            style = str(value.get("style") or "")
            prefix = str(value.get("prefix") or "")
            role = str(value.get("role") or ("first" if number == 1 else "member"))
            width = int(value.get("width") or 3)
            start = int(value.get("start", value.get("start_offset", 0)) or 0)
            if not path or number <= 0 or not style or not prefix:
                raise ValueError("split volume is missing path, number, style, or prefix")
            normalized.append({
                "path": path,
                "number": number,
                "style": style,
                "prefix": prefix,
                "role": role,
                "width": width,
                "start": start,
            })
        normalized.sort(key=lambda item: item["number"])
        numbers = [item["number"] for item in normalized]
        if not numbers or any(number <= 0 for number in numbers) or len(set(numbers)) != len(numbers):
            raise ValueError("split volumes require unique positive numbers")
        styles = {item["style"] for item in normalized}
        if len(styles) != 1:
            raise ValueError("split volumes must use one naming style")
        style = normalized[0]["style"]
        parts = [
            ArchiveInputPart(
                path=item["path"],
                role=item["role"],
                volume_number=item["number"],
                canonical_name=canonical_volume_name(
                    prefix=item["prefix"],
                    number=item["number"],
                    style=style,
                    width=item["width"],
                    role=item["role"],
                ),
                range=ArchiveInputRange(path=item["path"], start=item["start"])
                if item["start"] > 0 else None,
            )
            for item in normalized
        ]
        return cls(
            entry_path=next((part.path for part in parts if part.volume_number == 1), parts[0].path),
            open_mode="sfx_with_volumes" if style in {"rar_sfx_part", "sfx_numeric_suffix"} else "native_volumes",
            format_hint=format_hint,
            logical_name=logical_name,
            volume_style=style,
            parts=parts,
        )

    @classmethod
    def from_any(
        cls,
        raw: dict[str, Any] | None,
        *,
        archive_path: str,
        part_paths: list[str] | None = None,
        format_hint: str = "",
        logical_name: str = "",
    ) -> "ArchiveInputDescriptor":
        if isinstance(raw, dict):
            if raw.get("kind") not in (None, "archive_input") and not raw.get("open_mode"):
                raise ValueError("archive input must use the canonical archive_input schema")
            descriptor = cls.from_dict(raw, archive_path=archive_path, part_paths=part_paths)
            if not descriptor.format_hint and format_hint:
                return cls(
                    entry_path=descriptor.entry_path,
                    open_mode=descriptor.open_mode,
                    format_hint=format_hint,
                    logical_name=descriptor.logical_name or logical_name,
                    volume_style=descriptor.volume_style,
                    parts=list(descriptor.parts),
                    ranges=list(descriptor.ranges),
                    segment=descriptor.segment,
                    analysis=dict(descriptor.analysis),
                )
            return descriptor
        return cls.from_parts(
            archive_path=archive_path,
            part_paths=part_paths,
            format_hint=format_hint,
            logical_name=logical_name,
        )


def canonical_volume_name(*, prefix: str, number: int, style: str, width: int, role: str = "") -> str:
    base = os.path.basename(prefix)
    if style == "rar_part":
        return f"{base}.part{number:0{width}d}.rar"
    if style == "rar_sfx_part":
        extension = "exe" if number == 1 else "rar"
        return f"{base}.part{number:0{width}d}.{extension}"
    if style == "rar_oldstyle":
        return f"{base}.rar" if number == 1 else f"{base}.r{number - 2:02d}"
    if style == "zip_spanned":
        return f"{base}.zip" if role == "terminal" else f"{base}.z{number:02d}"
    if style == "zip_zero_numbered":
        return f"{base}.{number - 1:04d}"
    if style == "sfx_numeric_suffix":
        if number == 1:
            stem = os.path.splitext(base)[0]
            return f"{stem}.exe"
        return f"{base}.{number - 1:0{width}d}"
    return f"{base}.{number:03d}"
