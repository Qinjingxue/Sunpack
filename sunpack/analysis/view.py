import os
import math
import weakref
from binascii import crc32
from dataclasses import dataclass
from collections import Counter

from sunpack_native import AnalysisMultiVolumeView as _NativeAnalysisMultiVolumeView
from sunpack_native import probe_rar_bytes as _probe_rar_bytes
from sunpack.support.archive_sessions import get_archive_session
from sunpack.support.resource_lifecycle import (
    ResourceKind,
    lifecycle_registration,
    register_current_task_resource,
)


@dataclass(frozen=True)
class ReadStats:
    read_bytes: int
    cache_hits: int


class SharedBinaryView:
    """Thread-safe random-access binary view with a small shared LRU cache."""

    def __init__(
        self,
        path: str,
        *,
        cache_bytes: int = 64 * 1024 * 1024,
        max_read_bytes: int | None = None,
        max_concurrent_reads: int = 1,
    ):
        self.path = path
        self.size = os.path.getsize(path)
        self.cache_bytes = max(0, int(cache_bytes or 0))
        self.max_read_bytes = max_read_bytes if max_read_bytes is None else max(0, int(max_read_bytes))
        with lifecycle_registration((path,)):
            self._session = get_archive_session(path)
            self._native = self._session.analysis_view(
                cache_bytes=self.cache_bytes,
                max_read_bytes=self.max_read_bytes,
                max_concurrent_reads=max_concurrent_reads,
            )
            native = self._native
            self._resource_lease = register_current_task_resource(
                self,
                (path,),
                lambda native=native: getattr(native, "close", lambda: None)(),
                kind=ResourceKind.NATIVE_ANALYSIS_VIEW,
                registration_held=True,
            )
        self._resource_finalizer = weakref.finalize(self, self._resource_lease.close)
        self.size = int(self._native.size)

    @property
    def closed(self) -> bool:
        return self._resource_lease.closed

    def close(self) -> None:
        self._resource_lease.close()
        self._resource_finalizer.detach()
        self._session = None

    def __enter__(self) -> "SharedBinaryView":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()

    def read_at(self, offset: int, size: int) -> bytes:
        return bytes(self._native.read_at(int(offset), int(size)))

    def read_tail(self, size: int) -> bytes:
        return bytes(self._native.read_tail(int(size)))

    def stats(self) -> ReadStats:
        stats = self._native.stats()
        return ReadStats(
            read_bytes=int(stats.get("read_bytes", 0) or 0),
            cache_hits=int(stats.get("cache_hits", 0) or 0),
        )

    def signature_prepass(self, *, head_bytes: int, tail_bytes: int) -> dict | None:
        return dict(self._native.signature_prepass(int(head_bytes), int(tail_bytes)))

    def probe_zip(self, *, eocd_offset: int, max_cd_entries_to_walk: int = 64) -> dict | None:
        return dict(self._native.probe_zip(int(eocd_offset), int(max_cd_entries_to_walk)))

    def probe_rar(self, *, start_offset: int, max_blocks_to_walk: int = 4096) -> dict | None:
        return dict(self._native.probe_rar(int(start_offset), int(max_blocks_to_walk)))

    def probe_seven_zip(self, *, start_offset: int, max_next_header_check_bytes: int = 1024 * 1024) -> dict | None:
        return dict(self._native.probe_seven_zip(int(start_offset), int(max_next_header_check_bytes)))

    def probe_tar(self, *, start_offset: int = 0, max_entries_to_walk: int = 64) -> dict | None:
        return dict(self._native.probe_tar(int(start_offset), int(max_entries_to_walk)))

    def probe_compression_stream(self, *, format: str) -> dict | None:
        return dict(self._native.probe_compression_stream(str(format)))

    def probe_compressed_tar(self, *, format: str, max_probe_bytes: int = 4 * 1024 * 1024) -> dict | None:
        return dict(self._native.probe_compressed_tar(str(format), int(max_probe_bytes)))

    def fuzzy_binary_profile(
        self,
        *,
        window_bytes: int = 64 * 1024,
        max_windows: int = 8,
        max_sample_bytes: int = 1024 * 1024,
        entropy_high_threshold: float = 6.8,
        entropy_low_threshold: float = 3.5,
        entropy_jump_threshold: float = 1.25,
        ngram_top_k: int = 8,
        max_ngram_sample_bytes: int = 256 * 1024,
    ) -> dict:
        return dict(self._native.fuzzy_binary_profile(
            int(window_bytes),
            int(max_windows),
            int(max_sample_bytes),
            float(entropy_high_threshold),
            float(entropy_low_threshold),
            float(entropy_jump_threshold),
            int(ngram_top_k),
            int(max_ngram_sample_bytes),
        ))

class MultiVolumeBinaryView:
    """Random-access logical view over ordered split-volume files."""

    def __init__(
        self,
        paths,
        *,
        cache_bytes: int = 64 * 1024 * 1024,
        max_read_bytes: int | None = None,
        max_concurrent_reads: int = 1,
    ):
        entries = _normalize_volume_entries(paths)
        self.volumes = [entry["path"] for entry in entries]
        if not self.volumes:
            raise ValueError("MultiVolumeBinaryView requires at least one volume")
        styles = {entry["style"] for entry in entries if entry["style"]}
        self.volume_style = next(iter(styles)) if len(styles) == 1 else ""
        self.volume_ranges = []
        logical_start = 0
        for index, entry in enumerate(entries):
            size = os.path.getsize(entry["path"])
            self.volume_ranges.append({
                "index": index,
                "number": entry["number"],
                "path": entry["path"],
                "start": logical_start,
                "end": logical_start + size,
            })
            logical_start += size
        self.path = self.volumes[0]
        self.cache_bytes = max(0, int(cache_bytes or 0))
        self.max_read_bytes = max_read_bytes if max_read_bytes is None else max(0, int(max_read_bytes))
        with lifecycle_registration(self.volumes):
            self._native = _NativeAnalysisMultiVolumeView(
                self.volumes,
                cache_bytes=self.cache_bytes,
                max_read_bytes=self.max_read_bytes,
                max_concurrent_reads=max_concurrent_reads,
            )
            native = self._native
            self._resource_lease = register_current_task_resource(
                self,
                self.volumes,
                lambda native=native: getattr(native, "close", lambda: None)(),
                kind=ResourceKind.NATIVE_MULTI_VOLUME_VIEW,
                registration_held=True,
            )
        self._resource_finalizer = weakref.finalize(self, self._resource_lease.close)
        self.path = str(self._native.path)
        self.size = int(self._native.size)

    @property
    def closed(self) -> bool:
        return self._resource_lease.closed

    def close(self) -> None:
        self._resource_lease.close()
        self._resource_finalizer.detach()

    def __enter__(self) -> "MultiVolumeBinaryView":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()

    def logical_offset_for_disk(self, disk_number: int, relative_offset: int) -> int | None:
        """Translate PKZIP's zero-based disk-relative offset into the logical view."""
        disk_number = int(disk_number)
        relative_offset = int(relative_offset)
        if disk_number < 0 or disk_number >= len(self.volume_ranges) or relative_offset < 0:
            return None
        volume = self.volume_ranges[disk_number]
        logical = int(volume["start"]) + relative_offset
        return logical if logical <= int(volume["end"]) else None

    def read_at(self, offset: int, size: int) -> bytes:
        return bytes(self._native.read_at(int(offset), int(size)))

    def read_tail(self, size: int) -> bytes:
        return bytes(self._native.read_tail(int(size)))

    def stats(self) -> ReadStats:
        stats = self._native.stats()
        return ReadStats(
            read_bytes=int(stats.get("read_bytes", 0) or 0),
            cache_hits=int(stats.get("cache_hits", 0) or 0),
        )

    def signature_prepass(self, *, head_bytes: int, tail_bytes: int) -> dict | None:
        return dict(self._native.signature_prepass(int(head_bytes), int(tail_bytes)))

    def probe_zip(self, *, eocd_offset: int, max_cd_entries_to_walk: int = 64) -> dict | None:
        result = _probe_zip_view(self, int(eocd_offset), int(max_cd_entries_to_walk))
        is_empty = (
            int(result.get("total_entries") or 0) == 0
            and int(result.get("central_directory_size") or 0) == 0
        )
        zip64_eocd_offset = (
            int(result.get("zip64_eocd_offset") or 0)
            if result.get("zip64_eocd_present")
            else None
        )
        result.update(dict(self._native.probe_zip_archive_start(
            bool(result.get("is_multi_disk")) or self.volume_style == "zip_spanned",
            is_empty,
            zip64_eocd_offset,
        )))
        return result

    def probe_rar(self, *, start_offset: int, max_blocks_to_walk: int = 4096) -> dict | None:
        return dict(self._native.probe_rar(int(start_offset), int(max_blocks_to_walk)))

    def probe_seven_zip(self, *, start_offset: int, max_next_header_check_bytes: int = 1024 * 1024) -> dict | None:
        return _probe_seven_zip_view(self, int(start_offset), int(max_next_header_check_bytes))

    def probe_tar(self, *, start_offset: int = 0, max_entries_to_walk: int = 64) -> dict | None:
        return _probe_tar_view(self, int(start_offset), int(max_entries_to_walk))

    def probe_compression_stream(self, *, format: str) -> dict | None:
        return _probe_compression_stream_view(self, str(format))

    def fuzzy_binary_profile(
        self,
        *,
        window_bytes: int = 64 * 1024,
        max_windows: int = 8,
        max_sample_bytes: int = 1024 * 1024,
        entropy_high_threshold: float = 6.8,
        entropy_low_threshold: float = 3.5,
        entropy_jump_threshold: float = 1.25,
        ngram_top_k: int = 8,
        max_ngram_sample_bytes: int = 256 * 1024,
    ) -> dict:
        return dict(self._native.fuzzy_binary_profile(
            int(window_bytes),
            int(max_windows),
            int(max_sample_bytes),
            float(entropy_high_threshold),
            float(entropy_low_threshold),
            float(entropy_jump_threshold),
            int(ngram_top_k),
            int(max_ngram_sample_bytes),
        ))


def _normalize_volume_entries(paths) -> list[dict]:
    entries = list(paths or [])
    if entries and all(isinstance(item, dict) for item in entries):
        entries = sorted(entries, key=lambda item: int(item.get("number") or 0))
        return [
            {
                "path": str(item.get("path") or ""),
                "number": int(item.get("number") or index + 1),
                "style": str(item.get("style") or ""),
            }
            for index, item in enumerate(entries)
            if item.get("path")
        ]
    return [
        {"path": str(item), "number": index + 1, "style": ""}
        for index, item in enumerate(entries)
        if str(item)
    ]


def _probe_zip_view(view, eocd_offset: int, max_cd_entries_to_walk: int) -> dict:
    result = _probe_base("zip", eocd_offset)
    result.update({
        "eocd_offset": eocd_offset,
        "archive_offset": 0,
        "segment_end": 0,
        "central_directory_offset": 0,
        "central_directory_size": 0,
        "total_entries": 0,
        "is_multi_disk": False,
        "disk_number": 0,
        "central_directory_disk": 0,
        "disk_entries": 0,
        "declared_total_disks": 1,
        "zip64": False,
        "zip64_locator_present": False,
        "zip64_eocd_present": False,
        "central_directory_present": False,
        "central_directory_walk_ok": False,
        "central_directory_entries_checked": 0,
        "central_directory_encrypted_entries": 0,
        "password_required": False,
        "password_state": "unknown",
        "encryption_scan_complete": False,
        "local_header_links_ok": False,
        "local_header_links_checked": 0,
        "archive_starts_at_zero": False,
        "archive_start_kind": "",
    })
    eocd = view.read_at(eocd_offset, 22)
    if len(eocd) < 22 or eocd[:4] != b"PK\x05\x06":
        result["error"] = "bad_eocd_signature"
        return result
    result["magic_matched"] = True
    disk_number = _u16(eocd, 4)
    central_directory_disk = _u16(eocd, 6)
    disk_entries = _u16(eocd, 8)
    total_entries = _u16(eocd, 10)
    cd_size = _u32(eocd, 12)
    cd_offset = _u32(eocd, 16)
    comment_length = _u16(eocd, 20)
    segment_end = eocd_offset + 22 + comment_length
    if segment_end > view.size:
        result["error"] = "comment_length_out_of_range"
        return result
    zip64_required = any((
        disk_number == 0xFFFF,
        central_directory_disk == 0xFFFF,
        disk_entries == 0xFFFF,
        total_entries == 0xFFFF,
        cd_size == 0xFFFFFFFF,
        cd_offset == 0xFFFFFFFF,
    ))
    # Read the ZIP64 tail whenever it is present, not only when the plain
    # EOCD fields carry the 0xFFFF/0xFFFFFFFF markers.  Some writers store
    # real values in the plain EOCD even though ZIP64 records exist; the
    # 8-byte fields in the ZIP64 record remain authoritative and the central
    # directory ends at the ZIP64 record, not at the EOCD (APPNOTE 4.3.14).
    zip64 = _read_zip64_tail(view, eocd_offset)
    if zip64_required and zip64 is None:
        result["error"] = "zip64_tail_missing_or_invalid"
        return result
    if zip64 is not None:
        disk_number = zip64["disk_number"]
        central_directory_disk = zip64["central_directory_disk"]
        disk_entries = zip64["disk_entries"]
        total_entries = zip64["total_entries"]
        cd_size = zip64["central_directory_size"]
        cd_offset = zip64["central_directory_offset"]
        result.update({
            "zip64": True,
            "zip64_locator_present": True,
            "zip64_eocd_present": True,
            "zip64_eocd_offset": zip64["physical_offset"],
            "zip64_locator_offset": eocd_offset - 20,
        })
    is_multi_disk = disk_number != 0 or central_directory_disk != 0
    result.update({
        "segment_end": segment_end,
        "central_directory_size": cd_size,
        "total_entries": total_entries,
        "is_multi_disk": is_multi_disk,
        "disk_number": disk_number,
        "central_directory_disk": central_directory_disk,
        "disk_entries": disk_entries,
        "declared_total_disks": zip64["declared_total_disks"] if zip64 is not None else disk_number + 1,
    })
    if disk_entries != total_entries:
        # A spanning central directory can legitimately have fewer entries on
        # the final disk than in the complete archive.
        if not is_multi_disk:
            result["error"] = "entry_count_mismatch"
            return result
    disk_mapper = getattr(view, "logical_offset_for_disk", None)
    spanned = getattr(view, "volume_style", "") == "zip_spanned" or is_multi_disk
    if spanned:
        if not callable(disk_mapper):
            result["error"] = "zip_disk_mapping_unavailable"
            return result
        physical_cd = disk_mapper(central_directory_disk, cd_offset)
        archive_offset = 0
        if physical_cd is None:
            result["error"] = "central_directory_disk_offset_out_of_range"
            return result
        expected_cd_end = zip64["physical_offset"] if zip64 is not None else eocd_offset
        if physical_cd + cd_size != expected_cd_end:
            result["error"] = "central_directory_size_mismatch"
            return result
        if zip64 is not None:
            volume_count = len(getattr(view, "volume_ranges", []))
            if zip64["declared_total_disks"] != volume_count or disk_number + 1 != volume_count:
                result["error"] = "zip64_disk_count_mismatch"
                return result
    else:
        cd_end = zip64["physical_offset"] if zip64 is not None else eocd_offset
        if cd_end < cd_size:
            result["error"] = "central_directory_size_out_of_range"
            return result
        physical_cd = cd_end - cd_size
        if physical_cd < cd_offset:
            result["error"] = "archive_offset_underflow"
            return result
        archive_offset = physical_cd - cd_offset
        if zip64 is not None and zip64["physical_offset"] - zip64["locator_declared_offset"] != archive_offset:
            result["error"] = "zip64_locator_offset_mismatch"
            return result
    result.update({"archive_offset": archive_offset, "central_directory_offset": physical_cd})
    if total_entries == 0 and cd_size == 0:
        result.update({
            "plausible": True,
            "central_directory_walk_ok": True,
            "local_header_links_ok": True,
            "password_state": "not_required",
            "encryption_scan_complete": True,
            "error": "",
            "evidence": ["zip:eocd"] + (["zip:zip64"] if zip64 is not None else []),
        })
        return result
    if view.read_at(physical_cd, 4) != b"PK\x01\x02":
        result["error"] = "bad_central_directory_signature"
        return result
    result["central_directory_present"] = True
    entries, cd_ok, links, links_ok, encrypted_entries, error = _walk_zip_cd(
        view, archive_offset, physical_cd, cd_size, total_entries,
        max_cd_entries_to_walk, spanned=spanned,
    )
    result.update({
        "central_directory_entries_checked": entries,
        "central_directory_encrypted_entries": encrypted_entries,
        "central_directory_walk_ok": cd_ok,
        "local_header_links_checked": links,
        "local_header_links_ok": links_ok,
        "error": error,
    })
    encryption_scan_complete = not error and cd_ok and entries == total_entries
    result["password_required"] = encrypted_entries > 0
    result["encryption_scan_complete"] = encryption_scan_complete
    result["password_state"] = (
        "required"
        if encrypted_entries > 0
        else "not_required"
        if encryption_scan_complete
        else "unknown"
    )
    if not error:
        result["plausible"] = True
        result["evidence"] = ["zip:eocd", "zip:central_directory", "zip:central_directory_walk", "zip:local_header_links"]
        if zip64 is not None:
            result["evidence"].append("zip:zip64")
        if spanned:
            result["evidence"].append("zip:multi_disk_offsets")
    return result


def _walk_zip_cd(view, archive_offset: int, cd_offset: int, cd_size: int, total_entries: int, max_entries: int, *, spanned: bool = False):
    cursor = cd_offset
    end = cd_offset + cd_size
    limit = min(total_entries, max_entries)
    links_checked = 0
    encrypted_entries = 0
    for index in range(limit):
        header = view.read_at(cursor, 46)
        if len(header) < 46 or header[:4] != b"PK\x01\x02":
            return index, False, links_checked, False, encrypted_entries, "bad_central_directory_entry_signature"
        if _u16(header, 8) & 0x0001:
            encrypted_entries += 1
        filename_len = _u16(header, 28)
        extra_len = _u16(header, 30)
        comment_len = _u16(header, 32)
        disk_start = _u16(header, 34)
        local_header_offset = _u32(header, 42)
        entry_size = 46 + filename_len + extra_len + comment_len
        if cursor + entry_size > end:
            return index, False, links_checked, False, encrypted_entries, "central_directory_variable_fields_out_of_range"
        extra = view.read_at(cursor + 46 + filename_len, extra_len)
        resolved = _resolve_zip64_central_fields(header, extra)
        if resolved is None:
            return index + 1, True, links_checked, False, encrypted_entries, "zip64_extra_missing_or_invalid"
        local_header_offset = resolved["local_header_offset"]
        disk_start = resolved["disk_start"]
        if spanned:
            mapper = getattr(view, "logical_offset_for_disk", None)
            local_logical = mapper(disk_start, local_header_offset) if callable(mapper) else None
        else:
            local_logical = archive_offset + local_header_offset
        if local_logical is None or view.read_at(local_logical, 4) != b"PK\x03\x04":
            return index + 1, True, links_checked, False, encrypted_entries, "local_header_link_mismatch"
        links_checked += 1
        cursor += entry_size
    return limit, True, links_checked, True, encrypted_entries, ""


def _read_zip64_tail(view, eocd_offset: int) -> dict | None:
    locator_offset = eocd_offset - 20
    if locator_offset < 0:
        return None
    locator = view.read_at(locator_offset, 20)
    if len(locator) != 20 or locator[:4] != b"PK\x06\x07":
        return None
    zip64_disk = _u32(locator, 4)
    declared_offset = _u64(locator, 8)
    total_disks = _u32(locator, 16)
    physical_offset = None
    mapper = getattr(view, "logical_offset_for_disk", None)
    if getattr(view, "volume_style", "") == "zip_spanned" and callable(mapper):
        physical_offset = mapper(zip64_disk, declared_offset)
    if physical_offset is None and _zip64_record_ends_at(view, declared_offset, locator_offset):
        physical_offset = declared_offset
    fixed_candidate = locator_offset - 56
    if physical_offset is None and _zip64_record_ends_at(view, fixed_candidate, locator_offset):
        physical_offset = fixed_candidate
    if physical_offset is None:
        # The extensible data sector makes the record variable length. Find
        # the record whose declared size ends exactly at the locator.
        search_size = min(locator_offset, 1024 * 1024)
        search_start = locator_offset - search_size
        data = view.read_at(search_start, search_size)
        cursor = data.rfind(b"PK\x06\x06")
        while cursor >= 0:
            candidate = search_start + cursor
            if _zip64_record_ends_at(view, candidate, locator_offset):
                physical_offset = candidate
                break
            cursor = data.rfind(b"PK\x06\x06", 0, cursor)
    if physical_offset is None:
        return None
    fixed = view.read_at(physical_offset, 56)
    if len(fixed) < 56 or fixed[:4] != b"PK\x06\x06" or _u64(fixed, 4) < 44 or physical_offset + 12 + _u64(fixed, 4) != locator_offset:
        return None
    return {
        "physical_offset": physical_offset,
        "locator_declared_offset": declared_offset,
        "zip64_disk": zip64_disk,
        "declared_total_disks": total_disks,
        "disk_number": _u32(fixed, 16),
        "central_directory_disk": _u32(fixed, 20),
        "disk_entries": _u64(fixed, 24),
        "total_entries": _u64(fixed, 32),
        "central_directory_size": _u64(fixed, 40),
        "central_directory_offset": _u64(fixed, 48),
    }


def _zip64_record_ends_at(view, offset: int, expected_end: int) -> bool:
    if offset < 0 or offset + 56 > expected_end:
        return False
    fixed = view.read_at(offset, 56)
    return bool(
        len(fixed) >= 56
        and fixed[:4] == b"PK\x06\x06"
        and _u64(fixed, 4) >= 44
        and offset + 12 + _u64(fixed, 4) == expected_end
    )


def _resolve_zip64_central_fields(header: bytes, extra: bytes) -> dict | None:
    values = {
        "uncompressed_size": _u32(header, 24),
        "compressed_size": _u32(header, 20),
        "local_header_offset": _u32(header, 42),
        "disk_start": _u16(header, 34),
    }
    needs = (
        ("uncompressed_size", 0xFFFFFFFF, 8),
        ("compressed_size", 0xFFFFFFFF, 8),
        ("local_header_offset", 0xFFFFFFFF, 8),
        ("disk_start", 0xFFFF, 4),
    )
    if not any(values[name] == sentinel for name, sentinel, _ in needs):
        return values
    cursor = 0
    payload = None
    while cursor + 4 <= len(extra):
        field_id = _u16(extra, cursor)
        field_size = _u16(extra, cursor + 2)
        cursor += 4
        if cursor + field_size > len(extra):
            return None
        if field_id == 0x0001:
            payload = extra[cursor:cursor + field_size]
            break
        cursor += field_size
    if payload is None:
        return None
    cursor = 0
    for name, sentinel, width in needs:
        if values[name] != sentinel:
            continue
        if cursor + width > len(payload):
            return None
        values[name] = int.from_bytes(payload[cursor:cursor + width], "little")
        cursor += width
    return values


def _probe_seven_zip_view(view, start_offset: int, max_next_header_check_bytes: int) -> dict:
    result = _probe_base("7z", start_offset)
    result.update({
        "archive_offset": start_offset,
        "segment_end": 0,
        "next_header_offset": 0,
        "next_header_size": 0,
        "start_header_crc_ok": False,
        "next_header_crc_checked": False,
        "next_header_crc_ok": False,
        "next_header_nid": 0,
        "next_header_nid_valid": False,
        "password_required": False,
        "encrypted_header": False,
        "encrypted_payload": False,
        "password_state": "unknown",
        "encryption_scan_complete": False,
    })
    header = view.read_at(start_offset, 32)
    if header[:6] != b"7z\xbc\xaf\x27\x1c":
        result["error"] = "7z_signature_not_found"
        return result
    result["magic_matched"] = True
    result["evidence"] = ["7z:signature"]
    if len(header) < 32:
        result["error"] = "file_too_small"
        return result
    start_header = header[12:32]
    result["start_header_crc_ok"] = _u32(header, 8) == crc32(start_header) & 0xFFFFFFFF
    if not result["start_header_crc_ok"]:
        result["error"] = "start_header_crc_mismatch"
        return result
    next_offset = _u64(start_header, 0)
    next_size = _u64(start_header, 8)
    next_crc = _u32(start_header, 16)
    next_start = start_offset + 32 + next_offset
    segment_end = next_start + next_size
    result.update({"next_header_offset": next_offset, "next_header_size": next_size, "segment_end": segment_end})
    if next_size == 0 or next_start < start_offset + 32 or segment_end < next_start or segment_end > view.size:
        result["segment_end"] = 0
        result["error"] = "next_header_out_of_range"
        return result
    result["plausible"] = True
    result["evidence"].extend(["7z:start_header_crc", "7z:next_header_range"])
    if next_size <= max_next_header_check_bytes:
        next_header = view.read_at(next_start, next_size)
        crc_ok = crc32(next_header) & 0xFFFFFFFF == next_crc
        nid = next_header[0] if next_header else 0
        nid_valid = nid in (0x01, 0x17)
        result.update({
            "next_header_crc_checked": True,
            "next_header_crc_ok": crc_ok,
            "next_header_nid": nid,
            "next_header_nid_valid": nid_valid,
        })
        if crc_ok:
            result["evidence"].append("7z:next_header_crc")
            if nid_valid:
                aes_method = b"\x06\xf1\x07\x01"
                encrypted = aes_method in next_header
                scan_complete = nid != 0x17
                result.update({
                    "password_required": encrypted,
                    "encrypted_header": encrypted and nid == 0x17,
                    "encrypted_payload": encrypted and nid == 0x01,
                    "password_state": (
                        "required"
                        if encrypted
                        else "not_required" if scan_complete else "unknown"
                    ),
                    "encryption_scan_complete": scan_complete,
                })
                result["strong_accept"] = True
                result["evidence"].append("7z:next_header_nid")
            else:
                result["error"] = "next_header_nid_unrecognized"
        else:
            result["error"] = "next_header_crc_mismatch"
    return result


def _probe_base(fmt: str, start_offset: int) -> dict:
    return {"format": fmt, "plausible": False, "magic_matched": False, "strong_accept": False, "error": "", "archive_offset": start_offset, "evidence": []}


def _probe_tar_view(view, start_offset: int, max_entries: int) -> dict:
    result = {
        **_probe_base("tar", start_offset),
        "file_size": int(view.size),
        "stored_checksum": 0,
        "computed_checksum": 0,
        "member_size": 0,
        "ustar_magic": False,
        "zero_block": False,
        "fuzzy_name_nonempty": False,
        "fuzzy_numeric_fields_valid": False,
        "fuzzy_typeflag_valid": False,
        "fuzzy_payload_in_range": False,
        "entries_checked": 0,
        "entry_walk_ok": False,
        "walk_complete": False,
        "walk_budget_exhausted": False,
        "end_zero_blocks": False,
        "segment_end": None,
        "boundary_confidence": "none",
        "integrity_confidence": "unknown",
        "damage_flags": [],
    }
    cursor = start_offset
    entries = 0
    zero_blocks = 0
    while entries < max_entries and cursor + 512 <= int(view.size):
        block = view.read_at(cursor, 512)
        if len(block) < 512:
            result["error"] = "short_tar_header"
            break
        if block == b"\x00" * 512:
            if entries == 0:
                result.update({"zero_block": True, "error": "leading_zero_block"})
                return result
            zero_blocks += 1
            cursor += 512
            if zero_blocks >= 2:
                result.update({
                    "plausible": True,
                    "entries_checked": entries,
                    "entry_walk_ok": True,
                    "walk_complete": True,
                    "end_zero_blocks": True,
                    "segment_end": cursor,
                    "boundary_confidence": "high",
                    "evidence": ["tar:header_checksum", "tar:block_walk", "tar:end_zero_blocks"],
                })
                return result
            continue

        result["magic_matched"] = True
        zero_blocks = 0
        stored_checksum = _tar_number_optional(block[148:156])
        member_size = _tar_number_optional(block[124:136])
        computed_checksum = _tar_checksum(block)
        ustar_magic = block[257:263] in {b"ustar\x00", b"ustar "}
        if entries == 0:
            numeric_fields_valid = (
                stored_checksum is not None
                and member_size is not None
                and all(_tar_number_optional(block[start:end]) is not None for start, end in (
                    (100, 108), (108, 116), (116, 124), (136, 148)
                ))
            )
            typeflag_valid = block[156] == 0 or 0x20 <= block[156] < 0x7f
            payload_in_range = bool(
                member_size is not None
                and cursor + 512 + member_size + _tar_padding(member_size) <= int(view.size)
            )
            result.update({
                "stored_checksum": stored_checksum or 0,
                "computed_checksum": computed_checksum,
                "member_size": member_size or 0,
                "ustar_magic": ustar_magic,
                "format": "ustar" if ustar_magic else "tar",
                "fuzzy_name_nonempty": any(block[0:100]),
                "fuzzy_numeric_fields_valid": numeric_fields_valid,
                "fuzzy_typeflag_valid": typeflag_valid,
                "fuzzy_payload_in_range": payload_in_range,
            })
        if stored_checksum is None:
            error = "invalid_checksum_field"
        elif member_size is None:
            error = "invalid_size_field"
        elif stored_checksum != computed_checksum:
            error = "checksum_mismatch"
        else:
            error = ""
        if error:
            flag = {
                ord("x"): "pax_header_bad",
                ord("g"): "pax_header_bad",
                ord("L"): "gnu_longname_bad",
                ord("K"): "gnu_longname_bad",
                ord("S"): "sparse_header_bad",
            }.get(block[156], "tar_checksum_bad" if error == "checksum_mismatch" else "tar_metadata_bad")
            result.update({"entries_checked": entries, "error": error, "damage_flags": [flag]})
            if entries > 0:
                result.update({
                    "plausible": True,
                    "entry_walk_ok": True,
                    "segment_end": None,
                    "boundary_confidence": "none",
                    "evidence": ["tar:header_checksum", "tar:block_walk_prefix"],
                })
            return result

        sparse_extension_span = 0
        if block[156] == ord("S"):
            sparse_extension_span, sparse_error = _tar_sparse_extension_span(view, block, cursor)
            if sparse_error:
                result.update({
                    "entries_checked": entries,
                    "error": sparse_error,
                    "damage_flags": ["sparse_header_bad"],
                    "plausible": entries > 0,
                    "entry_walk_ok": entries > 0,
                    "segment_end": None,
                    "boundary_confidence": "none",
                })
                return result
        next_cursor = cursor + 512 + sparse_extension_span + member_size + _tar_padding(member_size)
        if next_cursor > int(view.size):
            payload_start = cursor + 512 + sparse_extension_span
            requested = member_size + _tar_padding(member_size)
            read_error = {
                "code": "unexpected_eof",
                "operation": "read_declared_range",
                "field": "tar.member.payload",
                "location": "tail",
                "offset": payload_start,
                "requested": requested,
                "actual": max(0, int(view.size) - payload_start),
                "source_len": int(view.size),
                "volume_number": None,
                "io_kind": "unexpectedeof",
                "os_error": None,
                "detail": "declared TAR member payload extends beyond available input",
                "possible_missing_volume": True,
            }
            result.update({
                "entries_checked": entries,
                "error": "member_payload_out_of_range",
                "read_error": read_error,
                "error_field": "tar.member.payload",
                "possible_missing_volume": True,
                "damage_flags": ["probably_truncated", "read_error", "input_truncated", "missing_volume"],
            })
            if entries > 0:
                result.update({
                    "plausible": True,
                    "entry_walk_ok": True,
                    "segment_end": None,
                    "boundary_confidence": "none",
                })
            return result
        entries += 1
        cursor = next_cursor
        result["evidence"] = [
            "tar:header_checksum",
            "tar:ustar_magic" if ustar_magic else "tar:v7_header",
        ]

    if entries > 0 and entries >= max_entries and cursor + 512 <= int(view.size):
        result.update({
            "plausible": True,
            "entries_checked": entries,
            "entry_walk_ok": True,
            "walk_budget_exhausted": True,
            "segment_end": None,
            "boundary_confidence": "none",
            "error": "tar_walk_budget_exhausted",
            "damage_flags": [],
            "evidence": ["tar:header_checksum", "tar:block_walk_sample"],
        })
    elif entries > 0 and cursor == int(view.size):
        result.update({
            "plausible": True,
            "entries_checked": entries,
            "entry_walk_ok": True,
            "walk_complete": True,
            "segment_end": cursor,
            "boundary_confidence": "medium",
            "error": "tar_end_zero_blocks_missing_at_eof",
            "damage_flags": ["missing_end_block"],
            "evidence": ["tar:header_checksum", "tar:block_walk", "tar:eof_boundary"],
        })
    elif entries > 0:
        read_error = {
            "code": "unexpected_eof",
            "operation": "read_record",
            "field": "tar.archive.end_zero_blocks",
            "location": "tail",
            "offset": cursor,
            "requested": 1024,
            "actual": min(1024, max(0, int(view.size) - cursor)),
            "source_len": int(view.size),
            "volume_number": None,
            "io_kind": "unexpectedeof",
            "os_error": None,
            "detail": "TAR end zero blocks are unavailable",
            "possible_missing_volume": True,
        }
        result.update({
            "plausible": True,
            "entries_checked": entries,
            "entry_walk_ok": True,
            "segment_end": None,
            "boundary_confidence": "none",
            "error": "tar_end_zero_blocks_not_found",
            "read_error": read_error,
            "error_field": "tar.archive.end_zero_blocks",
            "possible_missing_volume": True,
            "damage_flags": ["missing_end_block", "read_error", "input_truncated", "probably_truncated", "missing_volume"],
            "evidence": ["tar:header_checksum", "tar:block_walk_prefix"],
        })
    return result


def _probe_compression_stream_view(view, fmt: str) -> dict:
    signatures = {
        "gzip": b"\x1f\x8b\x08",
        "bzip2": b"BZh",
        "xz": b"\xfd7zXZ\x00",
        "zstd": b"\x28\xb5\x2f\xfd",
    }
    signature = signatures.get(fmt, b"")
    head = view.read_at(0, max(8, len(signature)))
    matched = bool(signature and head.startswith(signature))
    return {
        "format": fmt,
        "magic_matched": matched,
        "plausible": matched,
        "confidence": 0.78 if matched else 0.0,
        "evidence": [f"{fmt}:signature"] if matched else [],
        "error": "" if matched else "signature_not_found",
    }


def _tar_number_optional(data: bytes) -> int | None:
    if not data:
        return None
    if data[0] & 0x80:
        value = data[0] & 0x7f
        for byte in data[1:]:
            value = value * 256 + byte
        return value
    text = data.split(b"\x00", 1)[0].strip() or b"0"
    try:
        return int(text, 8)
    except ValueError:
        return None


_tar_octal_optional = _tar_number_optional


def _tar_checksum(header: bytes) -> int:
    return sum(header[:148]) + 32 * 8 + sum(header[156:])


def _tar_padding(size: int) -> int:
    return (-size) % 512


def _tar_sparse_extension_span(view, header: bytes, header_offset: int) -> tuple[int, str]:
    previous_end = 0

    def validate_map(block: bytes, count: int) -> bool:
        nonlocal previous_end
        for index in range(count):
            base = index * 24
            offset = _tar_number_optional(block[base:base + 12])
            length = _tar_number_optional(block[base + 12:base + 24])
            if offset is None or length is None:
                return False
            if offset == 0 and length == 0:
                continue
            end = offset + length
            if end < offset or offset < previous_end:
                return False
            previous_end = end
        return True

    if not validate_map(header[386:482], 4):
        return 0, "invalid_oldgnu_sparse_map"
    span = 0
    extended = header[482] not in (0, ord("0"))
    while extended:
        if span >= 512 * 65536:
            return 0, "oldgnu_sparse_extension_limit"
        block = view.read_at(header_offset + 512 + span, 512)
        if len(block) != 512 or not validate_map(block[:504], 21):
            return 0, "invalid_oldgnu_sparse_extension"
        span += 512
        extended = block[504] not in (0, ord("0"))
    return span, ""


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    total = len(data)
    counts = Counter(data)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def _byte_class(data: bytes) -> dict:
    if not data:
        return {"printable_ratio": 0.0, "zero_ratio": 0.0, "ff_ratio": 0.0}
    total = len(data)
    printable = sum(1 for byte in data if byte in (9, 10, 13) or 32 <= byte <= 126)
    return {
        "printable_ratio": printable / total,
        "zero_ratio": data.count(0) / total,
        "ff_ratio": data.count(0xFF) / total,
    }


def _run_profile(data: bytes, base_offset: int) -> dict:
    zero = _longest_run(data, 0, base_offset)
    ff = _longest_run(data, 0xFF, base_offset)
    tail = zero if zero.get("offset", 0) + zero.get("length", 0) >= base_offset + len(data) else {}
    return {
        "longest_zero_run": zero,
        "longest_ff_run": ff,
        "tail_run": tail,
        "tail_padding_likely": int(tail.get("length", 0) or 0) >= 1024,
    }


def _longest_run(data: bytes, value: int, base_offset: int) -> dict:
    best_offset = 0
    best_length = 0
    current_offset = 0
    current_length = 0
    for index, byte in enumerate(data):
        if byte == value:
            if current_length == 0:
                current_offset = index
            current_length += 1
            if current_length > best_length:
                best_offset = current_offset
                best_length = current_length
        else:
            current_length = 0
    return {"offset": base_offset + best_offset, "length": best_length}


def _byte_histogram(data: bytes, top_k: int) -> list[dict]:
    return [
        {"byte": byte, "count": count}
        for byte, count in Counter(data).most_common(max(1, int(top_k)))
    ]


_KNOWN_SIGNATURES = {
    "zip_local": b"PK\x03\x04",
    "zip_eocd": b"PK\x05\x06",
    "rar4": b"Rar!\x1a\x07\x00",
    "rar5": b"Rar!\x1a\x07\x01\x00",
    "7z": b"7z\xbc\xaf\x27\x1c",
    "gzip": b"\x1f\x8b\x08",
    "bzip2": b"BZh",
    "xz": b"\xfd7zXZ\x00",
    "zstd": b"\x28\xb5\x2f\xfd",
    "tar_ustar": b"ustar",
}


def _find_all(data: bytes, needle: bytes):
    start = 0
    while True:
        index = data.find(needle, start)
        if index < 0:
            return
        yield index
        start = index + 1


def _formats_from_hits(hits: list[dict]) -> set[str]:
    formats = set()
    for hit in hits:
        name = str(hit.get("name") or "")
        if name.startswith("zip_"):
            formats.add("zip")
        elif name.startswith("rar"):
            formats.add("rar")
        elif name == "7z":
            formats.add("7z")
        elif name == "gzip":
            formats.add("gzip")
        elif name == "bzip2":
            formats.add("bzip2")
        elif name == "xz":
            formats.add("xz")
        elif name == "zstd":
            formats.add("zstd")
        elif name == "tar_ustar":
            formats.add("tar")
    return formats


def _read_vint(data: bytes, offset: int):
    value = 0
    shift = 0
    for index in range(offset, min(len(data), offset + 10)):
        byte = data[index]
        value |= (byte & 0x7F) << shift
        if byte & 0x80 == 0:
            return value, index + 1
        shift += 7
    return None


def _u16(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 2], "little")


def _u32(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 4], "little")


def _u64(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 8], "little")
