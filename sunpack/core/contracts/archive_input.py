from __future__ import annotations

from dataclasses import dataclass, field, replace
import os
from typing import Any, Literal

from sunpack.core.support.path_keys import case_key


ArchiveOpenMode = Literal[
    "file",
    "file_range",
    "concat_ranges",
    "native_volumes",
    "sfx_with_volumes",
]

_SEGMENT_PROVENANCE = frozenset({"segment_source"})


@dataclass(frozen=True)
class InputExtent:
    path: str
    start: int = 0
    end: int | None = None

    def __post_init__(self) -> None:
        if not self.path or self.start < 0 or (self.end is not None and self.end < self.start):
            raise ValueError("input extent requires a path and an ordered nonnegative range")

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
    extent: InputExtent
    role: str = "main"
    volume_number: int | None = None
    canonical_name: str = ""

    @property
    def path(self) -> str:
        return self.extent.path

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "path": self.path,
            "role": self.role,
        }
        if self.volume_number is not None:
            payload["volume_number"] = int(self.volume_number)
        if self.canonical_name:
            payload["canonical_name"] = self.canonical_name
        if self.extent.start:
            payload["start"] = int(self.extent.start)
        if self.extent.end is not None:
            payload["end"] = int(self.extent.end)
        return payload


@dataclass(frozen=True, slots=True)
class VolumeAttemptSlot:
    number: int
    canonical_name: str
    choices: tuple[int, ...]

    def to_dict(self) -> dict:
        return {"number": self.number, "canonical_name": self.canonical_name, "choices": self.choices}


@dataclass(frozen=True, slots=True)
class VolumeAttemptPlan:
    sources: tuple[InputExtent, ...]
    layouts: tuple[tuple[VolumeAttemptSlot, ...], ...]
    head_size_from_total: int | None = None
    minimum_size: int | None = None

    def __post_init__(self) -> None:
        if not self.sources or not self.layouts:
            raise ValueError("volume attempts require sources and layouts")
        for layout in self.layouts:
            if not layout or layout[0].number != 1:
                raise ValueError("volume attempts require a structural head")
            previous = 0
            names = set()
            for slot in layout:
                if (slot.number <= previous or not slot.canonical_name
                        or case_key(slot.canonical_name) in names or not slot.choices
                        or any(i < 0 or i >= len(self.sources) for i in slot.choices)):
                    raise ValueError("invalid volume attempt slot")
                previous = slot.number
                names.add(case_key(slot.canonical_name))

    def to_dict(self) -> dict:
        result = {"sources": [source.to_dict() for source in self.sources],
                  "layouts": [{"slots": [slot.to_dict() for slot in layout]} for layout in self.layouts]}
        if self.head_size_from_total is not None:
            result["head_size_from_total"] = self.head_size_from_total
        if self.minimum_size is not None:
            result["minimum_size"] = self.minimum_size
        return result

    def remap(self, mapper) -> "VolumeAttemptPlan":
        return VolumeAttemptPlan(tuple(InputExtent(mapper(s.path), s.start, s.end) for s in self.sources),
                                 self.layouts, self.head_size_from_total, self.minimum_size)

    @classmethod
    def from_dict(cls, raw: dict) -> "VolumeAttemptPlan":
        return cls(tuple(InputExtent(**source) for source in raw["sources"]),
                   tuple(tuple(VolumeAttemptSlot(int(s["number"]), s["canonical_name"], tuple(s["choices"]))
                               for s in layout["slots"]) for layout in raw["layouts"]),
                   raw.get("head_size_from_total"), raw.get("minimum_size"))


@dataclass(frozen=True)
class ArchiveInputDescriptor:
    entry_path: str
    open_mode: ArchiveOpenMode = "file"
    format_hint: str = ""
    # Rust-provided filename; format and input identity belong to their own attributes.
    logical_name: str = ""
    volume_style: str = ""
    parts: list[ArchiveInputPart] = field(default_factory=list)
    extents: list[InputExtent] = field(default_factory=list)
    analysis: dict[str, Any] = field(default_factory=dict)
    volume_attempts: VolumeAttemptPlan | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "format_hint", str(self.format_hint or "").strip().lower().lstrip("."))
        if "segment_start" in self.analysis or "segment_end" in self.analysis:
            raise ValueError("archive input boundaries belong only to InputExtent")
        if self.open_mode == "concat_ranges" and not self.extents:
            raise ValueError("concat_ranges requires input extents")
        if self.open_mode == "file_range" and not self.parts:
            raise ValueError("file_range requires an input part")
        if self.open_mode in {"native_volumes", "sfx_with_volumes"}:
            ordered = sorted(self.parts, key=lambda part: int(part.volume_number or 0))
            if not ordered:
                raise ValueError("structured volume inputs require parts")
            numbers = [int(part.volume_number or 0) for part in ordered]
            if any(number <= 0 for number in numbers) or len(set(numbers)) != len(numbers):
                raise ValueError("structured volume parts require unique positive volume numbers")
            if any(not part.canonical_name for part in ordered):
                raise ValueError("structured volume parts require canonical_name")
            canonical_keys = [case_key(part.canonical_name) for part in ordered]
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
        if self.volume_attempts is not None:
            payload["volume_attempts"] = self.volume_attempts.to_dict()
        if self.parts:
            payload["parts"] = [part.to_dict() for part in self.parts]
        if self.open_mode == "concat_ranges":
            payload["ranges"] = [item.to_dict() for item in self.extents]
        analysis = {
            key: value
            for key, value in self.analysis.items()
            if key not in _SEGMENT_PROVENANCE
        }
        if analysis:
            payload["analysis"] = analysis
        return payload

    def same_retry_input(self, other: "ArchiveInputDescriptor") -> bool:
        """Compare execution facts without materializing every volume/range."""
        return (
            self.entry_path == other.entry_path
            and self.open_mode == other.open_mode
            and self.format_hint == other.format_hint
            and self.logical_name == other.logical_name
            and self.volume_style == other.volume_style
            and self.parts == other.parts
            and self.volume_attempts == other.volume_attempts
            and (self.open_mode != "concat_ranges" or self.extents == other.extents)
            and (self.analysis == other.analysis or (
                {key: value for key, value in self.analysis.items() if key not in _SEGMENT_PROVENANCE}
                == {key: value for key, value in other.analysis.items() if key not in _SEGMENT_PROVENANCE}
            ))
        )

    def part_paths(self) -> list[str]:
        if self.volume_attempts is not None:
            return list(dict.fromkeys(source.path for source in self.volume_attempts.sources))
        if self.open_mode == "concat_ranges" and self.extents:
            return list(dict.fromkeys(item.path for item in self.extents if item.path))
        if self.parts:
            return list(dict.fromkeys(part.path for part in self.parts if part.path))
        return [self.entry_path] if self.entry_path else []

    def select_volumes(self, selection: dict) -> "ArchiveInputDescriptor":
        plan = self.volume_attempts
        if plan is None:
            raise ValueError("volume selection requires an attempt plan")
        layout = plan.layouts[int(selection["layout"])]
        sources = tuple(int(i) for i in selection["sources"])
        if len(sources) != len(layout) or len(set(sources)) != len(sources):
            raise ValueError("volume selection must cover each slot once")
        parts = []
        for slot, source in zip(layout, sources):
            if source not in slot.choices:
                raise ValueError("worker selected an unplanned volume")
            parts.append(ArchiveInputPart(plan.sources[source], "first" if slot.number == 1 else "member",
                                          slot.number, slot.canonical_name))
        if plan.head_size_from_total is not None:
            # Execute the Rust extent formula, exactly as the worker did.
            length = plan.head_size_from_total - sum(p.extent.end - p.extent.start for p in parts[1:])
            head = parts[0].extent
            if length <= 0 or head.end is None or head.start + length > head.end:
                raise ValueError("invalid selected carrier extent")
            parts[0] = replace(parts[0], extent=InputExtent(head.path, head.start, head.start + length))
        return replace(self, parts=parts, volume_attempts=None,
                       analysis={**self.analysis, "volume_completeness": "complete"})

    def with_path_mapping(self, mapper) -> "ArchiveInputDescriptor":
        parts = [
            ArchiveInputPart(
                extent=InputExtent(
                    path=mapper(part.extent.path),
                    start=part.extent.start,
                    end=part.extent.end,
                ),
                role=part.role,
                volume_number=part.volume_number,
                canonical_name=part.canonical_name,
            )
            for part in self.parts
        ]
        extents = [
            InputExtent(path=mapper(item.path), start=item.start, end=item.end)
            for item in self.extents
        ]
        return ArchiveInputDescriptor(
            entry_path=mapper(self.entry_path),
            open_mode=self.open_mode,
            format_hint=self.format_hint,
            logical_name=self.logical_name,
            volume_style=self.volume_style,
            parts=parts,
            extents=extents,
            analysis=dict(self.analysis),
            volume_attempts=self.volume_attempts.remap(mapper) if self.volume_attempts else None,
        )

    @property
    def primary_extent(self) -> InputExtent | None:
        if self.parts:
            return self.parts[0].extent
        return self.extents[0] if self.extents else None

    @classmethod
    def from_dict(cls, raw: dict[str, Any], *, archive_path: str = "", part_paths: list[str] | None = None) -> "ArchiveInputDescriptor":
        kind = str(raw.get("kind") or "archive_input")
        if kind != "archive_input":
            raise ValueError(f"unsupported archive input kind: {kind}")
        if "segment" in raw:
            raise ValueError("legacy archive input segment field is not supported")
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
            parts.append(ArchiveInputPart(
                extent=InputExtent(path=path, start=start, end=int(end_raw) if end_raw is not None else None),
                role=str(item.get("role") or "main"),
                volume_number=int(item["volume_number"]) if item.get("volume_number") is not None else None,
                canonical_name=str(item.get("canonical_name") or ""),
            ))
        extents = []
        for item in raw.get("ranges") or []:
            if not isinstance(item, dict):
                continue
            end_raw = item.get("end")
            extents.append(InputExtent(
                path=str(item.get("path") or entry_path),
                start=int(item.get("start", 0) or 0),
                end=int(end_raw) if end_raw is not None else None,
            ))
        analysis = dict(raw.get("analysis") or {}) if isinstance(raw.get("analysis"), dict) else {}
        if open_mode == "file_range" and not parts:
            raise ValueError("file_range requires canonical parts with extent")
        if not parts and not extents and part_paths:
            if len(part_paths) > 1:
                raise ValueError("multi-volume inputs require serialized structured parts")
            parts = [ArchiveInputPart(extent=InputExtent(path=str(part_paths[0])), role="main", volume_number=1)]
        return cls(
            entry_path=entry_path,
            open_mode=open_mode,  # type: ignore[arg-type]
            format_hint=format_hint,
            logical_name=str(raw.get("logical_name") or ""),
            volume_style=str(raw.get("volume_style") or ""),
            parts=parts,
            extents=extents,
            analysis=analysis,
            volume_attempts=VolumeAttemptPlan.from_dict(raw["volume_attempts"]) if raw.get("volume_attempts") else None,
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
                ArchiveInputPart(extent=InputExtent(path=str(path)), role="main", volume_number=1)
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
                "end": int(value["end"]) if value.get("end") is not None else None,
            })
        normalized.sort(key=lambda item: item["number"])
        numbers = [item["number"] for item in normalized]
        if not numbers or any(number <= 0 for number in numbers) or len(set(numbers)) != len(numbers):
            raise ValueError("split volumes require unique positive numbers")
        styles = {item["style"] for item in normalized}
        if len(styles) == 1:
            style = normalized[0]["style"]
        elif styles == {"rar_sfx_part", "rar_part"}:
            head = next((item for item in normalized if item["number"] == 1), normalized[0])
            if head["style"] != "rar_sfx_part":
                raise ValueError("RAR SFX split family requires the SFX naming style on volume 1")
            style = "rar_sfx_part"
        else:
            raise ValueError("split volumes must use one compatible naming style")
        parts = [
            ArchiveInputPart(
                extent=InputExtent(path=item["path"], start=item["start"], end=item["end"]),
                role=item["role"],
                volume_number=item["number"],
                canonical_name=canonical_volume_name(
                    prefix=item["prefix"],
                    number=item["number"],
                    style=style,
                    width=item["width"],
                    role=item["role"],
                ),
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
                    extents=list(descriptor.extents),
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
