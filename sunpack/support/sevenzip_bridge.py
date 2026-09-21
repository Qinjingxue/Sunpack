import ctypes
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
            self._library = library
            return library

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


_DEFAULT_BRIDGE: NativeSevenZipBridge | None = None
_DEFAULT_BRIDGE_LOCK = threading.Lock()


def get_native_sevenzip_bridge() -> NativeSevenZipBridge:
    global _DEFAULT_BRIDGE
    if _DEFAULT_BRIDGE is not None:
        return _DEFAULT_BRIDGE
    with _DEFAULT_BRIDGE_LOCK:
        if _DEFAULT_BRIDGE is None:
            _DEFAULT_BRIDGE = NativeSevenZipBridge()
        return _DEFAULT_BRIDGE


def _cache_key(bridge: NativeSevenZipBridge, archive_path: str, part_paths: list[str] | None = None) -> tuple:
    parts = tuple(file_identity(path) for path in list(dict.fromkeys(part_paths or [archive_path])))
    return (
        str(bridge.wrapper_path),
        file_identity(archive_path),
        parts,
    )


def cached_analyze_archive_resources(archive_path: str, password: str = "", part_paths: list[str] | None = None) -> NativeArchiveResourceAnalysis:
    bridge = get_native_sevenzip_bridge()
    password = password or ""
    return cached_value(
        "native_7z_resources",
        _cache_key(bridge, archive_path, part_paths) + (password,),
        lambda: bridge.analyze_archive_resources(archive_path, password=password, part_paths=part_paths),
    )

