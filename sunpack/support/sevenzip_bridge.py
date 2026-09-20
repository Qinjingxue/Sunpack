import ctypes
import json
import sys
import threading
from dataclasses import dataclass
from pathlib import Path

from sunpack.support.resources import candidate_resource_roots, tool_dir_candidates
from sunpack.support.global_cache_manager import cached_value, file_identity


STATUS_OK = 0
STATUS_WRONG_PASSWORD = 1
STATUS_DAMAGED = 2
STATUS_UNSUPPORTED = 3
STATUS_BACKEND_UNAVAILABLE = 4
STATUS_ERROR = 5
STATUS_NEEDS_VOLUME_OR_TAIL_DAMAGED = 6
OPERATION_RESULT_HEADERS_ERROR = 8


@dataclass(frozen=True)
class NativeArchiveResourceAnalysis:
    status: int
    is_archive: bool
    is_encrypted: bool
    is_broken: bool
    solid: bool
    item_count: int
    file_count: int
    dir_count: int
    archive_size: int
    total_unpacked_size: int
    total_packed_size: int
    largest_item_size: int
    largest_dictionary_size: int
    archive_type: str
    dominant_method: str
    message: str

    @property
    def ok(self) -> bool:
        return self.status == STATUS_OK and self.is_archive and not self.is_broken


@dataclass(frozen=True)
class NativeArchiveCrcManifest:
    status: int
    is_archive: bool
    encrypted: bool
    damaged: bool
    checksum_error: bool
    item_count: int
    file_count: int
    files: list[dict]
    message: str

    @property
    def ok(self) -> bool:
        return self.status == STATUS_OK and self.is_archive and not self.damaged and not self.checksum_error


class _Sup7zArchiveResourceAnalysis(ctypes.Structure):
    _fields_ = [
        ("status", ctypes.c_int),
        ("is_archive", ctypes.c_int),
        ("is_encrypted", ctypes.c_int),
        ("is_broken", ctypes.c_int),
        ("solid", ctypes.c_int),
        ("item_count", ctypes.c_int),
        ("file_count", ctypes.c_int),
        ("dir_count", ctypes.c_int),
        ("archive_size", ctypes.c_ulonglong),
        ("total_unpacked_size", ctypes.c_ulonglong),
        ("total_packed_size", ctypes.c_ulonglong),
        ("largest_item_size", ctypes.c_ulonglong),
        ("largest_dictionary_size", ctypes.c_ulonglong),
        ("archive_type", ctypes.c_wchar * 32),
        ("dominant_method", ctypes.c_wchar * 128),
    ]


class NativeSevenZipBridge:
    def __init__(self, wrapper_path: str | None = None):
        self.wrapper_path = wrapper_path or self._default_wrapper_path()
        self._library = None
        self._load_lock = threading.Lock()

    def available(self) -> bool:
        return bool(self.wrapper_path and Path(self.wrapper_path).exists())

    def _part_array(self, archive_path: str, part_paths: list[str] | None):
        normalized_parts = list(dict.fromkeys(part_paths or [archive_path]))
        array_type = ctypes.c_wchar_p * len(normalized_parts)
        return normalized_parts, array_type(*normalized_parts)

    def analyze_archive_resources(self, archive_path: str, password: str = "", part_paths: list[str] | None = None) -> NativeArchiveResourceAnalysis:
        library = self._load()

        normalized_parts, part_array = self._part_array(archive_path, part_paths)
        analysis = _Sup7zArchiveResourceAnalysis()
        message = ctypes.create_unicode_buffer(512)

        status = library.sup7z_analyze_archive_resources_with_parts(
            ctypes.c_wchar_p(str(archive_path)),
            part_array,
            ctypes.c_int(len(normalized_parts)),
            ctypes.c_wchar_p(str(password or "")),
            ctypes.byref(analysis),
            message,
            ctypes.c_int(len(message)),
        )
        return NativeArchiveResourceAnalysis(
            status=int(status),
            is_archive=bool(analysis.is_archive),
            is_encrypted=bool(analysis.is_encrypted),
            is_broken=bool(analysis.is_broken),
            solid=bool(analysis.solid),
            item_count=int(analysis.item_count),
            file_count=int(analysis.file_count),
            dir_count=int(analysis.dir_count),
            archive_size=int(analysis.archive_size),
            total_unpacked_size=int(analysis.total_unpacked_size),
            total_packed_size=int(analysis.total_packed_size),
            largest_item_size=int(analysis.largest_item_size),
            largest_dictionary_size=int(analysis.largest_dictionary_size),
            archive_type=str(analysis.archive_type),
            dominant_method=str(analysis.dominant_method),
            message=message.value,
        )

    def read_archive_crc_manifest(
        self,
        archive_path: str,
        password: str = "",
        part_paths: list[str] | None = None,
        max_items: int = 200000,
    ) -> NativeArchiveCrcManifest:
        library = self._load()

        normalized_parts, part_array = self._part_array(archive_path, part_paths)
        manifest_json = ctypes.create_unicode_buffer(_manifest_buffer_chars(max_items))
        message = ctypes.create_unicode_buffer(512)

        status = library.sup7z_read_archive_crc_manifest_with_parts(
            ctypes.c_wchar_p(str(archive_path)),
            part_array,
            ctypes.c_int(len(normalized_parts)),
            ctypes.c_wchar_p(str(password or "")),
            ctypes.c_int(max(0, int(max_items or 0))),
            manifest_json,
            ctypes.c_int(len(manifest_json)),
            message,
            ctypes.c_int(len(message)),
        )
        payload = _parse_manifest_json(manifest_json.value)
        return NativeArchiveCrcManifest(
            status=int(status),
            is_archive=bool(payload.get("is_archive", False)),
            encrypted=bool(payload.get("encrypted", False)),
            damaged=bool(payload.get("damaged", False)),
            checksum_error=bool(payload.get("checksum_error", False)),
            item_count=int(payload.get("item_count", 0) or 0),
            file_count=int(payload.get("file_count", 0) or 0),
            files=list(payload.get("files") or []),
            message=message.value,
        )

    def _load(self):
        if self._library is not None:
            return self._library
        with self._load_lock:
            if self._library is not None:
                return self._library
            if not self.wrapper_path or not Path(self.wrapper_path).exists():
                raise FileNotFoundError("Required sunpack_sevenzip.dll was not found.")

            library = ctypes.WinDLL(str(self.wrapper_path))
            library.sup7z_analyze_archive_resources.argtypes = [
                ctypes.c_wchar_p,
                ctypes.c_wchar_p,
                ctypes.POINTER(_Sup7zArchiveResourceAnalysis),
                ctypes.c_wchar_p,
                ctypes.c_int,
            ]
            library.sup7z_analyze_archive_resources.restype = ctypes.c_int
            library.sup7z_analyze_archive_resources_with_parts.argtypes = [
                ctypes.c_wchar_p,
                ctypes.POINTER(ctypes.c_wchar_p),
                ctypes.c_int,
                ctypes.c_wchar_p,
                ctypes.POINTER(_Sup7zArchiveResourceAnalysis),
                ctypes.c_wchar_p,
                ctypes.c_int,
            ]
            library.sup7z_analyze_archive_resources_with_parts.restype = ctypes.c_int
            self._bind_optional_crc_manifest_api(library)
            self._library = library
            return library

    def _bind_optional_crc_manifest_api(self, library) -> None:
        library.sup7z_read_archive_crc_manifest.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.c_int,
            ctypes.c_wchar_p,
            ctypes.c_int,
            ctypes.c_wchar_p,
            ctypes.c_int,
        ]
        library.sup7z_read_archive_crc_manifest.restype = ctypes.c_int
        library.sup7z_read_archive_crc_manifest_with_parts.argtypes = [
            ctypes.c_wchar_p,
            ctypes.POINTER(ctypes.c_wchar_p),
            ctypes.c_int,
            ctypes.c_wchar_p,
            ctypes.c_int,
            ctypes.c_wchar_p,
            ctypes.c_int,
            ctypes.c_wchar_p,
            ctypes.c_int,
        ]
        library.sup7z_read_archive_crc_manifest_with_parts.restype = ctypes.c_int

    def _default_wrapper_path(self) -> str:
        candidates: list[Path] = []
        for root in candidate_resource_roots():
            candidates.extend(
                root / tool_dir / "sunpack_sevenzip.dll"
                for tool_dir in tool_dir_candidates()
            )
            candidates.append(root / "sunpack_sevenzip.dll")
        for candidate in candidates:
            if candidate.exists():
                return str(candidate)
        raise FileNotFoundError("Required sunpack_sevenzip.dll was not found under tools\\ or the application root.")


_DEFAULT_TESTER: NativeSevenZipBridge | None = None
_DEFAULT_TESTER_LOCK = threading.Lock()


def get_native_sevenzip_bridge() -> NativeSevenZipBridge:
    global _DEFAULT_TESTER
    if _DEFAULT_TESTER is not None:
        return _DEFAULT_TESTER
    with _DEFAULT_TESTER_LOCK:
        if _DEFAULT_TESTER is None:
            _DEFAULT_TESTER = NativeSevenZipBridge()
        return _DEFAULT_TESTER


def _cache_key(tester: NativeSevenZipBridge, archive_path: str, part_paths: list[str] | None = None) -> tuple:
    parts = tuple(file_identity(path) for path in list(dict.fromkeys(part_paths or [archive_path])))
    return (
        str(tester.wrapper_path),
        file_identity(archive_path),
        parts,
    )


def _parse_manifest_json(value: str) -> dict:
    try:
        parsed = json.loads(value or "{}")
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _manifest_buffer_chars(max_items: int) -> int:
    try:
        item_count = max(1, int(max_items or 0))
    except (TypeError, ValueError):
        item_count = 1
    return min(max(1024 * 1024, item_count * 256), 16 * 1024 * 1024)


def cached_analyze_archive_resources(archive_path: str, password: str = "", part_paths: list[str] | None = None) -> NativeArchiveResourceAnalysis:
    tester = get_native_sevenzip_bridge()
    password = password or ""
    return cached_value(
        "native_7z_resources",
        _cache_key(tester, archive_path, part_paths) + (password,),
        lambda: tester.analyze_archive_resources(archive_path, password=password, part_paths=part_paths),
    )


def cached_read_archive_crc_manifest(
    archive_path: str,
    password: str = "",
    part_paths: list[str] | None = None,
    max_items: int = 200000,
) -> NativeArchiveCrcManifest:
    tester = get_native_sevenzip_bridge()
    password = password or ""
    max_items = max(0, int(max_items or 0))
    return cached_value(
        "native_7z_crc_manifest",
        _cache_key(tester, archive_path, part_paths) + (password, max_items),
        lambda: tester.read_archive_crc_manifest(
            archive_path,
            password=password,
            part_paths=part_paths,
            max_items=max_items,
        ),
    )
