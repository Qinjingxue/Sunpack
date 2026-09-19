import ctypes
import json
import sys
import threading
from dataclasses import dataclass
from pathlib import Path

from sunpack.support.resources import candidate_resource_roots, get_7z_dll_path, tool_dir_candidates
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
class NativePasswordAttempt:
    status: int
    matched_index: int
    attempts: int
    message: str
    operation_result: int

    @property
    def ok(self) -> bool:
        return self.status == STATUS_OK and self.matched_index >= 0


@dataclass(frozen=True)
class NativeArchiveTest:
    status: int
    command_ok: bool
    encrypted: bool
    checksum_error: bool
    archive_type: str
    message: str

    @property
    def ok(self) -> bool:
        return self.status == STATUS_OK and self.command_ok


@dataclass(frozen=True)
class NativeArchiveProbe:
    status: int
    is_archive: bool
    is_encrypted: bool
    is_broken: bool
    checksum_error: bool
    offset: int
    item_count: int
    archive_type: str
    message: str
    password_required: bool = False
    missing_volume: bool = False
    missing_volume_suspected: bool = False
    missing_stub: bool = False
    volume_open_failed: bool = False
    missing_volume_name: str = ""
    missing_volume_evidence: str = ""

    @property
    def ok(self) -> bool:
        return (
            self.status == STATUS_OK
            and self.is_archive
            and not self.is_broken
            and not self.missing_volume
            and not self.missing_stub
            and not self.volume_open_failed
        )


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


SUP7Z_OPERATION_PROBE = 1
SUP7Z_OPERATION_TEST = 2
SUP7Z_OPERATION_TRY_PASSWORDS = 3


class _Sup7zInputRange(ctypes.Structure):
    _fields_ = [
        ("path", ctypes.c_wchar_p),
        ("start", ctypes.c_ulonglong),
        ("end", ctypes.c_ulonglong),
        ("has_end", ctypes.c_int),
    ]


class _Sup7zOperationRequest(ctypes.Structure):
    _fields_ = [
        ("operation", ctypes.c_int),
        ("seven_zip_dll_path", ctypes.c_wchar_p),
        ("archive_path", ctypes.c_wchar_p),
        ("part_paths", ctypes.POINTER(ctypes.c_wchar_p)),
        ("part_count", ctypes.c_int),
        ("canonical_names", ctypes.POINTER(ctypes.c_wchar_p)),
        ("volume_numbers", ctypes.POINTER(ctypes.c_int)),
        ("ranges", ctypes.POINTER(_Sup7zInputRange)),
        ("range_count", ctypes.c_int),
        ("format_hint", ctypes.c_wchar_p),
        ("password", ctypes.c_wchar_p),
        ("passwords", ctypes.POINTER(ctypes.c_wchar_p)),
        ("password_count", ctypes.c_int),
    ]


class _Sup7zOperationResult(ctypes.Structure):
    _fields_ = [
        ("status", ctypes.c_int),
        ("command_ok", ctypes.c_int),
        ("is_archive", ctypes.c_int),
        ("is_encrypted", ctypes.c_int),
        ("is_broken", ctypes.c_int),
        ("checksum_error", ctypes.c_int),
        ("matched_index", ctypes.c_int),
        ("attempts", ctypes.c_int),
        ("archive_offset", ctypes.c_ulonglong),
        ("item_count", ctypes.c_int),
        ("operation_result", ctypes.c_int),
        ("password_required", ctypes.c_int),
        ("missing_volume", ctypes.c_int),
        ("missing_volume_suspected", ctypes.c_int),
        ("missing_stub", ctypes.c_int),
        ("volume_open_failed", ctypes.c_int),
        ("archive_type", ctypes.c_wchar * 64),
        ("missing_volume_name", ctypes.c_wchar * 260),
        ("missing_volume_evidence", ctypes.c_wchar * 64),
        ("message", ctypes.c_wchar * 512),
    ]


class NativePasswordTester:
    def __init__(self, wrapper_path: str | None = None, seven_zip_dll_path: str | None = None):
        self.wrapper_path = wrapper_path or self._default_wrapper_path()
        # Inert compatibility field: the 7-Zip backend is embedded in
        # sunpack_sevenzip.dll, so this no longer selects the backend location.
        # It is still forwarded across the C ABI, which ignores it.
        self.seven_zip_dll_path = (
            seven_zip_dll_path if seven_zip_dll_path is not None else get_7z_dll_path()
        )
        self._library = None
        self._load_lock = threading.Lock()

    def available(self) -> bool:
        return bool(self.wrapper_path and Path(self.wrapper_path).exists())

    def _part_array(self, archive_path: str, part_paths: list[str] | None):
        normalized_parts = list(dict.fromkeys(part_paths or [archive_path]))
        array_type = ctypes.c_wchar_p * len(normalized_parts)
        return normalized_parts, array_type(*normalized_parts)

    def _archive_operation_input(
        self,
        archive_path: str,
        part_paths: list[str] | None = None,
        archive_input: dict | None = None,
    ) -> tuple[str, list[str], list[str], list[int], list[dict], str]:
        effective_archive = str(archive_path)
        effective_parts = list(dict.fromkeys(part_paths or [archive_path]))
        ranges: list[dict] = []
        canonical_names: list[str] = []
        volume_numbers: list[int] = []
        format_hint = ""
        if not isinstance(archive_input, dict):
            return effective_archive, effective_parts, canonical_names, volume_numbers, ranges, format_hint

        effective_archive = str(archive_input.get("entry_path") or effective_archive)
        format_hint = str(archive_input.get("format_hint") or archive_input.get("format") or "")
        mode = str(archive_input.get("open_mode") or archive_input.get("kind") or "file")
        raw_parts = [item for item in archive_input.get("parts") or [] if isinstance(item, dict)]
        part_paths_from_descriptor = [
            str(item.get("path") or effective_archive)
            for item in raw_parts
            if item.get("path") or effective_archive
        ]
        if part_paths_from_descriptor:
            effective_parts = list(dict.fromkeys(part_paths_from_descriptor))

        if mode in {"native_volumes", "sfx_with_volumes"}:
            ordered = sorted(raw_parts, key=lambda item: int(item.get("volume_number") or 0))
            volume_numbers = [int(item.get("volume_number") or 0) for item in ordered]
            canonical_names = [str(item.get("canonical_name") or "") for item in ordered]
            if volume_numbers != list(range(1, len(ordered) + 1)) or any(not name for name in canonical_names):
                raise ValueError("structured volume descriptor requires contiguous volume_number and canonical_name")
            effective_parts = [str(item.get("path") or "") for item in ordered]

        if mode == "file_range":
            ranges = self._ranges_from_objects(raw_parts, effective_archive)
            if not ranges and isinstance(archive_input.get("segment"), dict):
                segment = archive_input["segment"]
                ranges = [self._range_from_mapping(segment, effective_archive)]
        elif mode == "concat_ranges":
            raw_ranges = [item for item in archive_input.get("ranges") or [] if isinstance(item, dict)]
            ranges = self._ranges_from_objects(raw_ranges or raw_parts, effective_archive)
        return effective_archive, effective_parts, canonical_names, volume_numbers, ranges, format_hint

    def _ranges_from_objects(self, items: list[dict], default_path: str) -> list[dict]:
        return [
            self._range_from_mapping(item, default_path)
            for item in items
            if item.get("start") is not None or item.get("start_offset") is not None or item.get("end") is not None or item.get("end_offset") is not None
        ]

    def _range_from_mapping(self, item: dict, default_path: str) -> dict:
        end = item.get("end", item.get("end_offset"))
        return {
            "path": str(item.get("path") or default_path),
            "start": int(item.get("start", item.get("start_offset", 0)) or 0),
            "end": int(end) if end is not None else None,
        }

    def _run_operation(
        self,
        operation: int,
        archive_path: str,
        *,
        part_paths: list[str] | None = None,
        archive_input: dict | None = None,
        password: str = "",
        passwords: list[str] | None = None,
    ) -> _Sup7zOperationResult:
        library = self._load()
        effective_archive, effective_parts, canonical_names, volume_numbers, ranges, format_hint = self._archive_operation_input(
            archive_path,
            part_paths=part_paths,
            archive_input=archive_input,
        )
        part_array = None
        if effective_parts:
            part_array_type = ctypes.c_wchar_p * len(effective_parts)
            part_array = part_array_type(*effective_parts)
        canonical_array = None
        number_array = None
        if canonical_names:
            canonical_array_type = ctypes.c_wchar_p * len(canonical_names)
            canonical_array = canonical_array_type(*canonical_names)
            number_array_type = ctypes.c_int * len(volume_numbers)
            number_array = number_array_type(*volume_numbers)

        range_array = None
        if ranges:
            range_array_type = _Sup7zInputRange * len(ranges)
            range_array = range_array_type(*[
                _Sup7zInputRange(
                    str(item.get("path") or effective_archive),
                    int(item.get("start") or 0),
                    int(item["end"]) if item.get("end") is not None else 0,
                    1 if item.get("end") is not None else 0,
                )
                for item in ranges
            ])

        normalized_passwords = list(passwords or [])
        password_array = None
        if normalized_passwords:
            password_array_type = ctypes.c_wchar_p * len(normalized_passwords)
            password_array = password_array_type(*normalized_passwords)

        request = _Sup7zOperationRequest(
            operation,
            ctypes.c_wchar_p(str(self.seven_zip_dll_path)),
            ctypes.c_wchar_p(str(effective_archive)),
            part_array,
            ctypes.c_int(len(effective_parts)),
            canonical_array,
            number_array,
            range_array,
            ctypes.c_int(len(ranges)),
            ctypes.c_wchar_p(format_hint),
            ctypes.c_wchar_p(str(password or "")),
            password_array,
            ctypes.c_int(len(normalized_passwords)),
        )
        result = _Sup7zOperationResult()
        library.sup7z_run_operation(ctypes.byref(request), ctypes.byref(result))
        return result

    def try_passwords(
        self,
        archive_path: str,
        passwords: list[str],
        part_paths: list[str] | None = None,
        archive_input: dict | None = None,
    ) -> NativePasswordAttempt:
        normalized_passwords = list(passwords or [""])
        return self._try_passwords_ctypes(archive_path, normalized_passwords, part_paths, archive_input=archive_input)

    def _try_passwords_ctypes(
        self,
        archive_path: str,
        passwords: list[str],
        part_paths: list[str] | None = None,
        archive_input: dict | None = None,
    ) -> NativePasswordAttempt:
        if archive_input is None:
            library = self._load()
            normalized_parts, part_array = self._part_array(archive_path, part_paths)
            normalized_passwords = list(passwords or [""])
            password_array_type = ctypes.c_wchar_p * len(normalized_passwords)
            password_array = password_array_type(*normalized_passwords)
            matched_index = ctypes.c_int(-1)
            attempts = ctypes.c_int(0)
            message = ctypes.create_unicode_buffer(512)
            status = library.sup7z_try_passwords_with_parts(
                ctypes.c_wchar_p(str(self.seven_zip_dll_path)),
                ctypes.c_wchar_p(str(archive_path)),
                part_array,
                ctypes.c_int(len(normalized_parts)),
                password_array,
                ctypes.c_int(len(normalized_passwords)),
                ctypes.byref(matched_index),
                ctypes.byref(attempts),
                message,
                ctypes.c_int(len(message)),
            )
            return NativePasswordAttempt(
                status=int(status),
                matched_index=int(matched_index.value),
                attempts=int(attempts.value),
                message=message.value,
                operation_result=0,
            )
        result = self._run_operation(
            SUP7Z_OPERATION_TRY_PASSWORDS,
            archive_path,
            part_paths=part_paths,
            archive_input=archive_input,
            passwords=list(passwords or [""]),
        )
        return NativePasswordAttempt(
            status=int(result.status),
            matched_index=int(result.matched_index),
            attempts=int(result.attempts),
            message=result.message,
            operation_result=int(result.operation_result),
        )

    def test_archive(
        self,
        archive_path: str,
        password: str = "",
        part_paths: list[str] | None = None,
        archive_input: dict | None = None,
    ) -> NativeArchiveTest:
        if archive_input is None:
            library = self._load()
            normalized_parts, part_array = self._part_array(archive_path, part_paths)
            command_ok = ctypes.c_int(0)
            encrypted = ctypes.c_int(0)
            checksum_error = ctypes.c_int(0)
            archive_type = ctypes.create_unicode_buffer(64)
            message = ctypes.create_unicode_buffer(512)
            status = library.sup7z_test_archive_with_parts(
                ctypes.c_wchar_p(str(self.seven_zip_dll_path)),
                ctypes.c_wchar_p(str(archive_path)),
                part_array,
                ctypes.c_int(len(normalized_parts)),
                ctypes.c_wchar_p(str(password or "")),
                ctypes.byref(command_ok),
                ctypes.byref(encrypted),
                ctypes.byref(checksum_error),
                archive_type,
                ctypes.c_int(len(archive_type)),
                message,
                ctypes.c_int(len(message)),
            )
            return NativeArchiveTest(
                status=int(status),
                command_ok=bool(command_ok.value),
                encrypted=bool(encrypted.value),
                checksum_error=bool(checksum_error.value),
                archive_type=archive_type.value,
                message=message.value,
            )
        result = self._run_operation(
            SUP7Z_OPERATION_TEST,
            archive_path,
            part_paths=part_paths,
            archive_input=archive_input,
            password=password or "",
        )
        return NativeArchiveTest(
            status=int(result.status),
            command_ok=bool(result.command_ok),
            encrypted=bool(result.is_encrypted),
            checksum_error=bool(result.checksum_error),
            archive_type=result.archive_type,
            message=result.message,
        )

    def probe_archive(
        self,
        archive_path: str,
        part_paths: list[str] | None = None,
        archive_input: dict | None = None,
    ) -> NativeArchiveProbe:
        result = self._run_operation(
            SUP7Z_OPERATION_PROBE,
            archive_path,
            part_paths=part_paths,
            archive_input=archive_input,
        )
        return NativeArchiveProbe(
            status=int(result.status),
            is_archive=bool(result.is_archive),
            is_encrypted=bool(result.is_encrypted),
            is_broken=bool(result.is_broken),
            checksum_error=bool(result.checksum_error),
            offset=int(result.archive_offset),
            item_count=int(result.item_count),
            archive_type=result.archive_type,
            message=result.message,
            password_required=bool(result.password_required),
            missing_volume=bool(result.missing_volume),
            missing_volume_suspected=bool(result.missing_volume_suspected),
            missing_stub=bool(result.missing_stub),
            volume_open_failed=bool(result.volume_open_failed),
            missing_volume_name=str(result.missing_volume_name),
            missing_volume_evidence=str(result.missing_volume_evidence),
        )
    def analyze_archive_resources(self, archive_path: str, password: str = "", part_paths: list[str] | None = None) -> NativeArchiveResourceAnalysis:
        library = self._load()

        normalized_parts, part_array = self._part_array(archive_path, part_paths)
        analysis = _Sup7zArchiveResourceAnalysis()
        message = ctypes.create_unicode_buffer(512)

        status = library.sup7z_analyze_archive_resources_with_parts(
            ctypes.c_wchar_p(str(self.seven_zip_dll_path)),
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
            ctypes.c_wchar_p(str(self.seven_zip_dll_path)),
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
            library.sup7z_run_operation.argtypes = [
                ctypes.POINTER(_Sup7zOperationRequest),
                ctypes.POINTER(_Sup7zOperationResult),
            ]
            library.sup7z_run_operation.restype = ctypes.c_int
            library.sup7z_try_passwords.argtypes = [
                ctypes.c_wchar_p,
                ctypes.c_wchar_p,
                ctypes.POINTER(ctypes.c_wchar_p),
                ctypes.c_int,
                ctypes.POINTER(ctypes.c_int),
                ctypes.POINTER(ctypes.c_int),
                ctypes.c_wchar_p,
                ctypes.c_int,
            ]
            library.sup7z_try_passwords.restype = ctypes.c_int
            library.sup7z_try_passwords_with_parts.argtypes = [
                ctypes.c_wchar_p,
                ctypes.c_wchar_p,
                ctypes.POINTER(ctypes.c_wchar_p),
                ctypes.c_int,
                ctypes.POINTER(ctypes.c_wchar_p),
                ctypes.c_int,
                ctypes.POINTER(ctypes.c_int),
                ctypes.POINTER(ctypes.c_int),
                ctypes.c_wchar_p,
                ctypes.c_int,
            ]
            library.sup7z_try_passwords_with_parts.restype = ctypes.c_int
            library.sup7z_test_archive.argtypes = [
                ctypes.c_wchar_p,
                ctypes.c_wchar_p,
                ctypes.c_wchar_p,
                ctypes.POINTER(ctypes.c_int),
                ctypes.POINTER(ctypes.c_int),
                ctypes.POINTER(ctypes.c_int),
                ctypes.c_wchar_p,
                ctypes.c_int,
                ctypes.c_wchar_p,
                ctypes.c_int,
            ]
            library.sup7z_test_archive.restype = ctypes.c_int
            library.sup7z_test_archive_with_parts.argtypes = [
                ctypes.c_wchar_p,
                ctypes.c_wchar_p,
                ctypes.POINTER(ctypes.c_wchar_p),
                ctypes.c_int,
                ctypes.c_wchar_p,
                ctypes.POINTER(ctypes.c_int),
                ctypes.POINTER(ctypes.c_int),
                ctypes.POINTER(ctypes.c_int),
                ctypes.c_wchar_p,
                ctypes.c_int,
                ctypes.c_wchar_p,
                ctypes.c_int,
            ]
            library.sup7z_test_archive_with_parts.restype = ctypes.c_int
            library.sup7z_analyze_archive_resources.argtypes = [
                ctypes.c_wchar_p,
                ctypes.c_wchar_p,
                ctypes.c_wchar_p,
                ctypes.POINTER(_Sup7zArchiveResourceAnalysis),
                ctypes.c_wchar_p,
                ctypes.c_int,
            ]
            library.sup7z_analyze_archive_resources.restype = ctypes.c_int
            library.sup7z_analyze_archive_resources_with_parts.argtypes = [
                ctypes.c_wchar_p,
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


_DEFAULT_TESTER: NativePasswordTester | None = None
_DEFAULT_TESTER_LOCK = threading.Lock()


def get_native_password_tester() -> NativePasswordTester:
    global _DEFAULT_TESTER
    if _DEFAULT_TESTER is not None:
        return _DEFAULT_TESTER
    with _DEFAULT_TESTER_LOCK:
        if _DEFAULT_TESTER is None:
            _DEFAULT_TESTER = NativePasswordTester()
        return _DEFAULT_TESTER


def _cache_key(tester: NativePasswordTester, archive_path: str, part_paths: list[str] | None = None) -> tuple:
    parts = tuple(file_identity(path) for path in list(dict.fromkeys(part_paths or [archive_path])))
    return (
        str(tester.wrapper_path),
        str(tester.seven_zip_dll_path),
        file_identity(archive_path),
        parts,
    )


def _archive_input_cache_key(archive_input: dict | None) -> str | None:
    if not isinstance(archive_input, dict):
        return None
    return json.dumps(archive_input, ensure_ascii=True, sort_keys=True, separators=(",", ":"), default=str)


def cached_probe_archive(
    archive_path: str,
    part_paths: list[str] | None = None,
    archive_input: dict | None = None,
) -> NativeArchiveProbe:
    tester = get_native_password_tester()
    key = _cache_key(tester, archive_path, part_paths)
    archive_input_key = _archive_input_cache_key(archive_input)
    if archive_input_key is not None:
        key += (archive_input_key,)
    return cached_value(
        "native_7z_probe",
        key,
        lambda: tester.probe_archive(archive_path, part_paths=part_paths, archive_input=archive_input),
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


def cached_test_archive(
    archive_path: str,
    password: str = "",
    part_paths: list[str] | None = None,
    archive_input: dict | None = None,
) -> NativeArchiveTest:
    tester = get_native_password_tester()
    password = password or ""
    descriptor_key = json.dumps(archive_input, ensure_ascii=False, sort_keys=True) if archive_input else ""
    key = _cache_key(tester, archive_path, part_paths) + (password, descriptor_key)
    return cached_value(
        "native_7z_test",
        key,
        lambda: (
            tester.test_archive(archive_path, password=password, part_paths=part_paths, archive_input=archive_input)
            if archive_input is not None
            else tester.test_archive(archive_path, password=password, part_paths=part_paths)
        ),
    )


def cached_analyze_archive_resources(archive_path: str, password: str = "", part_paths: list[str] | None = None) -> NativeArchiveResourceAnalysis:
    tester = get_native_password_tester()
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
    tester = get_native_password_tester()
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
