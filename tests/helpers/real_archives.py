import bz2
import gzip
import io
import lzma
import random
import shutil
import struct
import subprocess
import tarfile
import zipfile
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from tests.helpers.tool_config import (
    get_optional_rar,
    get_optional_winrar,
    get_test_tools,
    require_7z,
    require_7z_zstd,
    require_zstd,
)


MINIMAL_JPEG_BYTES = bytes.fromhex(
    "ffd8ffe000104a46494600010100000100010000ffdb004300"
    "080606070605080707070909080a0c140d0c0b0b0c19120f13"
    "1d1a1f1e1d1a1c1c20242e2720222c231c1c2837292c303134"
    "34341f27393d38323c2e333432ffc0000b0800010001010111"
    "00ffc40014000100000000000000000000000000000008ffda"
    "0008010100003f00d2cf20ffd9"
)
MINIMAL_PNG_BYTES = bytes.fromhex(
    "89504e470d0a1a0a"
    "0000000d4948445200000001000000010802000000907753de"
    "0000000c49444154789c63f8ffff3f0005fe02fea7a6459b"
    "0000000049454e44ae426082"
)
MINIMAL_GIF_BYTES = bytes.fromhex(
    "47494638396101000100800000000000ffffff21f90401000000002c"
    "000000000100010000020144003b"
)
MINIMAL_PDF_BYTES = (
    b"%PDF-1.4\n"
    b"1 0 obj\n<< /Type /Catalog >>\nendobj\n"
    b"trailer\n<< /Root 1 0 R >>\n%%EOF\n"
)
MINIMAL_WEBP_BYTES = b"RIFF" + (16).to_bytes(4, "little") + b"WEBP" + b"VP8 " + (4).to_bytes(4, "little") + b"\0\0\0\0"
CORRUPT_TRUNCATE_BYTES = 16 * 1024
SUPPORTED_CARRIERS = {"jpg", "png", "gif", "pdf", "webp"}
TAR_FORMATS = {"tar", "tar.gz", "tar.bz2", "tar.xz", "tar.zst", "tar.lz4"}
STREAM_FORMATS = {"gzip", "bzip2", "xz", "zstd", "lz4"}
ARCHIVE_EXTENSIONS = {
    "7z": ".7z",
    "zip": ".zip",
    "rar": ".rar",
    "tar": ".tar",
    "tar.gz": ".tar.gz",
    "tar.bz2": ".tar.bz2",
    "tar.xz": ".tar.xz",
    "tar.zst": ".tar.zst",
    "tar.lz4": ".tar.lz4",
    "gzip": ".gz",
    "bzip2": ".bz2",
    "xz": ".xz",
    "zstd": ".zst",
    "lz4": ".lz4",
}
FORMAT_ALIASES = {
    "Tar": "tar",
    "TarGz": "tar.gz",
    "TarBz2": "tar.bz2",
    "TarXz": "tar.xz",
    "TarZst": "tar.zst",
    "TarLz4": "tar.lz4",
    "Gzip": "gzip",
    "Bzip2": "bzip2",
    "Xz": "xz",
    "Zstd": "zstd",
    "Lz4": "lz4",
}


@dataclass
class ArchiveCase:
    case_id: str
    archive_dir: Path
    entry_path: Path
    marker_name: str
    marker_text: str
    archive_format: str
    password: str | None = None
    split: bool = False
    sfx: bool = False
    carrier: str | None = None
    disguise_ext: str | None = None
    corruption: str | None = None
    split_issue: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __getitem__(self, key: str):
        return self.to_dict()[key]

    def __setitem__(self, key: str, value):
        if hasattr(self, key):
            setattr(self, key, value)
            return
        self.metadata[key] = value

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "archive_dir": self.archive_dir,
            "entry_path": self.entry_path,
            "marker_name": self.marker_name,
            "marker_text": self.marker_text,
            "archive_format": self.archive_format,
            "password": self.password,
            "split": self.split,
            "sfx": self.sfx,
            "carrier": self.carrier,
            "disguise_ext": self.disguise_ext,
            "corruption": self.corruption,
            "split_issue": self.split_issue,
            **self.metadata,
        }


class ArchiveFixtureFactory:
    def create(
        self,
        root: Path,
        case_id: str,
        archive_format: str = "7z",
        *,
        password: str | None = None,
        split: bool = False,
        sfx: bool = False,
        corruption: str | None = None,
        split_issue: str | None = None,
        carrier: str | None = None,
        disguise_ext: str | None = None,
        payload_size: int = 256 * 1024,
        split_volume_size: int = 100 * 1024,
        payload_profile: str = "default",
        compression_method: str | None = None,
        compression_level: int | None = None,
        solid: bool | None = None,
    ) -> ArchiveCase:
        if carrier and carrier not in SUPPORTED_CARRIERS:
            raise ValueError(f"Unsupported carrier: {carrier}")
        archive_format = normalize_archive_format(archive_format)
        if split_issue and not split:
            raise ValueError("split_issue requires split=True")
        if payload_profile not in {"default", "structured"}:
            raise ValueError(f"Unsupported payload profile: {payload_profile}")

        source_dir = root / f"{case_id}_src"
        payload = write_payload(
            source_dir,
            case_id,
            size_bytes=payload_size,
            profile=payload_profile,
        )
        archive_dir = root / case_id
        archive_dir.mkdir(parents=True, exist_ok=True)

        self._create_archive(
            source_dir,
            archive_dir,
            case_id,
            archive_format,
            password=password,
            split=split,
            sfx=sfx,
            split_volume_size=split_volume_size,
            compression_method=compression_method,
            compression_level=compression_level,
            solid=solid,
        )
        shutil.rmtree(source_dir, ignore_errors=True)

        entry_path = choose_entry_path(archive_dir, case_id, archive_format, sfx=sfx)
        expected_files = payload["expected_files"]
        if archive_format in STREAM_FORMATS:
            expected_files = {payload["marker_name"]: expected_files[payload["marker_name"]]}
        case = ArchiveCase(
            case_id=case_id,
            archive_dir=archive_dir,
            entry_path=entry_path,
            marker_name=payload["marker_name"],
            marker_text=payload["marker_text"],
            archive_format=archive_format,
            password=password,
            split=split,
            sfx=sfx,
            carrier=carrier,
            disguise_ext=disguise_ext,
            corruption=corruption,
            split_issue=split_issue,
            metadata={
                "expected_files": expected_files,
                "payload_profile": payload_profile,
                "compression_method": compression_method,
                "compression_level": compression_level,
                "solid": solid,
            },
        )

        if carrier:
            case.entry_path = wrap_case_with_carrier(case, carrier)
        if disguise_ext:
            case.entry_path = disguise_case_entry(case, disguise_ext)
        if corruption:
            corrupt_file(case.entry_path, mode=corruption)
        if split_issue:
            apply_split_issue(case, split_issue)
        return case

    def _create_archive(
        self,
        source_dir: Path,
        archive_dir: Path,
        case_id: str,
        archive_format: str,
        *,
        password: str | None,
        split: bool,
        sfx: bool,
        split_volume_size: int,
        compression_method: str | None,
        compression_level: int | None,
        solid: bool | None,
    ):
        archive_format = normalize_archive_format(archive_format)
        if archive_format in TAR_FORMATS | STREAM_FORMATS and (
            password
            or split
            or sfx
            or compression_method
            or compression_level is not None
            or solid is not None
        ):
            raise ValueError(
                f"{archive_format} fixtures do not support password, split, sfx, "
                "or container compression variants."
            )
        if archive_format == "7z":
            archive_path = archive_dir / f"{case_id}{'.exe' if sfx else '.7z'}"
            create_7z_archive(
                source_dir,
                archive_path,
                password=password,
                split=split,
                sfx=sfx,
                split_volume_size=split_volume_size,
                compression_method=compression_method,
                compression_level=compression_level,
                solid=solid,
            )
            return
        if archive_format == "zip":
            archive_path = archive_dir / f"{case_id}{'.exe' if sfx else '.zip'}"
            create_zip_archive(
                source_dir,
                archive_path,
                password=password,
                split=split,
                sfx=sfx,
                split_volume_size=split_volume_size,
                compression_method=compression_method,
                compression_level=compression_level,
            )
            return
        if archive_format == "rar":
            archive_path = archive_dir / f"{case_id}{'.exe' if sfx else '.rar'}"
            create_rar_archive(
                source_dir,
                archive_path,
                password=password,
                split=split,
                sfx=sfx,
                split_volume_size=split_volume_size,
                compression_level=compression_level or 0,
                solid=solid,
            )
            return
        if archive_format in TAR_FORMATS:
            archive_path = archive_dir / f"{case_id}{ARCHIVE_EXTENSIONS[archive_format]}"
            create_tar_archive(source_dir, archive_path, archive_format)
            return
        if archive_format in STREAM_FORMATS:
            marker_file = next(source_dir.glob("*.marker.txt"))
            archive_path = archive_dir / f"{marker_file.name}{ARCHIVE_EXTENSIONS[archive_format]}"
            create_compression_stream(marker_file, archive_path, archive_format)
            return
        raise ValueError(f"Unsupported archive format: {archive_format}")


def run_cmd(cmd: list[str], cwd: Path):
    result = subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(
            f"Command failed ({result.returncode}): {' '.join(cmd)}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


def _file_manifest(source_dir: Path) -> dict[str, dict[str, int | str]]:
    from tests.helpers.native_fixture import file_inventory

    return file_inventory(source_dir)


def write_payload(
    source_dir: Path,
    case_id: str,
    size_bytes: int = 256 * 1024,
    *,
    profile: str = "default",
) -> dict[str, Any]:
    source_dir.mkdir(parents=True, exist_ok=True)
    marker_name = f"{case_id}.marker.txt"
    marker_text = f"edge::{case_id}"
    (source_dir / marker_name).write_text(marker_text, encoding="utf-8")
    rng = random.Random(case_id)
    (source_dir / "payload.bin").write_bytes(bytes(rng.getrandbits(8) for _ in range(size_bytes)))
    if profile == "structured":
        (source_dir / "repeat.txt").write_bytes(
            (f"SUNPACK-REPEAT-{case_id}-".encode("utf-8") * 32) + b"\n"
        )
        (source_dir / "empty.bin").write_bytes(b"")
        nested = source_dir / "nested"
        nested.mkdir(exist_ok=True)
        (nested / "inner.txt").write_text(
            f"nested-content::{case_id}\n" * 8,
            encoding="utf-8",
        )
    elif profile != "default":
        raise ValueError(f"Unsupported payload profile: {profile}")
    return {
        "marker_name": marker_name,
        "marker_text": marker_text,
        "expected_files": _file_manifest(source_dir),
    }


def create_7z_archive(
    source_dir: Path,
    output_path: Path,
    password: str | None = None,
    split: bool = False,
    sfx: bool = False,
    split_volume_size: int = 100 * 1024,
    compression_method: str | None = None,
    compression_level: int | None = None,
    solid: bool | None = None,
):
    tools = get_test_tools()
    seven_zip = require_7z_zstd() if str(compression_method).upper() == "LZ4" else require_7z()
    level = 0 if compression_level is None else int(compression_level)
    if not 0 <= level <= 9:
        raise ValueError("7z compression level must be between 0 and 9")
    cmd = [str(seven_zip), "a", str(output_path), str(source_dir), f"-mx={level}", "-y"]
    if compression_method:
        cmd.append(f"-m0={compression_method}")
    if solid is not None:
        cmd.append(f"-ms={'on' if solid else 'off'}")
    if password:
        cmd.extend([f"-p{password}", "-mhe=on"])
    if split:
        cmd.append(f"-v{max(1024, int(split_volume_size))}b")
    if sfx:
        sfx_path = tools["seven_zip_sfx"]
        if not sfx_path or not sfx_path.is_file():
            raise FileNotFoundError("7z SFX module is required for SFX samples.")
        cmd.append(f"-sfx{sfx_path}")
    run_cmd(cmd, output_path.parent)


def create_zip_archive(
    source_dir: Path,
    output_path: Path,
    password: str | None = None,
    split: bool = False,
    sfx: bool = False,
    split_volume_size: int = 100 * 1024,
    compression_method: str | None = None,
    compression_level: int | None = None,
):
    tools = get_test_tools()
    seven_zip = require_7z()
    level = 0 if compression_level is None else int(compression_level)
    if not 0 <= level <= 9:
        raise ValueError("ZIP compression level must be between 0 and 9")
    cmd = [str(seven_zip), "a", str(output_path), str(source_dir), "-tzip", f"-mx={level}", "-y"]
    if compression_method:
        cmd.append(f"-mm={compression_method}")
    if password:
        cmd.append(f"-p{password}")
    if split:
        cmd.append(f"-v{max(1024, int(split_volume_size))}b")
    if sfx:
        sfx_path = tools["seven_zip_sfx"]
        if not sfx_path or not sfx_path.is_file():
            raise FileNotFoundError("7z SFX module is required for ZIP SFX samples.")
        cmd.append(f"-sfx{sfx_path}")
    run_cmd(cmd, output_path.parent)


def create_rar_archive(
    source_dir: Path,
    output_path: Path,
    password: str | None = None,
    split: bool = False,
    sfx: bool = False,
    split_volume_size: int = 100 * 1024,
    compression_level: int = 0,
    solid: bool | None = None,
):
    rar = get_optional_rar()
    if sfx and (rar is None or not (rar.parent / "Default.SFX").is_file()):
        rar = get_optional_winrar()
    if not rar:
        raise FileNotFoundError("RAR generator is not configured.")
    compression_level = int(compression_level)
    if not 0 <= compression_level <= 5:
        raise ValueError("RAR compression level must be between 0 and 5")
    cmd = [str(rar), "a", "-ep1", "-r", "-idq", f"-m{compression_level}", "-ma5", "-y"]
    if solid is True:
        cmd.append("-s")
    elif solid is False:
        cmd.append("-s-")
    if password:
        cmd.append(f"-hp{password}")
    if split:
        cmd.append(f"-v{max(1024, int(split_volume_size))}b")
    if sfx:
        cmd.append("-sfx")
    cmd.extend([str(output_path), str(source_dir)])
    run_cmd(cmd, output_path.parent)


def create_tar_archive(source_dir: Path, output_path: Path, archive_format: str):
    if archive_format in {"tar.zst", "tar.lz4"}:
        tar_path = output_path.with_suffix("")
        create_tar_archive(source_dir, tar_path, "tar")
        create_compression_stream(tar_path, output_path, "lz4" if archive_format == "tar.lz4" else "zstd")
        tar_path.unlink(missing_ok=True)
        return

    mode_by_format = {
        "tar": "w",
        "tar.gz": "w:gz",
        "tar.bz2": "w:bz2",
        "tar.xz": "w:xz",
    }
    mode = mode_by_format.get(archive_format)
    if not mode:
        raise ValueError(f"Unsupported TAR format: {archive_format}")
    with tarfile.open(output_path, mode) as archive:
        for path in sorted(source_dir.iterdir()):
            archive.add(path, arcname=path.name)


def create_compression_stream(
    source_path: Path,
    output_path: Path,
    archive_format: str,
    *,
    compression_level: int | None = None,
    gzip_filename: str | None = None,
    xz_check: str | None = None,
    zstd_checksum: bool = True,
):
    if archive_format == "lz4":
        from tests.helpers.native_fixture import create_lz4_frames

        if compression_level is not None:
            raise ValueError("the native real LZ4 fixture uses upstream's default level")
        create_lz4_frames(output_path, [source_path])
        return
    if archive_format == "gzip":
        level = 9 if compression_level is None else int(compression_level)
        with source_path.open("rb") as src, output_path.open("wb") as raw:
            with gzip.GzipFile(
                filename=source_path.name if gzip_filename is None else gzip_filename,
                mode="wb",
                fileobj=raw,
                compresslevel=level,
            ) as dst:
                shutil.copyfileobj(src, dst)
        return
    if archive_format == "bzip2":
        level = 9 if compression_level is None else int(compression_level)
        output_path.write_bytes(bz2.compress(source_path.read_bytes(), compresslevel=level))
        return
    if archive_format == "xz":
        level = 6 if compression_level is None else int(compression_level)
        check_by_name = {
            None: lzma.CHECK_CRC64,
            "crc32": lzma.CHECK_CRC32,
            "crc64": lzma.CHECK_CRC64,
            "sha256": lzma.CHECK_SHA256,
        }
        if xz_check not in check_by_name:
            raise ValueError(f"Unsupported XZ check: {xz_check}")
        output_path.write_bytes(
            lzma.compress(
                source_path.read_bytes(),
                format=lzma.FORMAT_XZ,
                preset=level,
                check=check_by_name[xz_check],
            )
        )
        return
    if archive_format == "zstd":
        zstd_exe = require_zstd()
        level = 3 if compression_level is None else int(compression_level)
        cmd = [str(zstd_exe), "-q", "-f", f"-{level}"]
        cmd.append("--check" if zstd_checksum else "--no-check")
        cmd.extend([str(source_path), "-o", str(output_path)])
        run_cmd(cmd, output_path.parent)
        return
    raise ValueError(f"Unsupported compression stream format: {archive_format}")


class _NonSeekableZipWriter(io.RawIOBase):
    """BytesIO proxy that reports itself as non-seekable, forcing data descriptors."""

    def __init__(self):
        self.buffer = io.BytesIO()

    def writable(self):
        return True

    def write(self, data):
        return self.buffer.write(data)

    def seekable(self):
        return False


def _case_from_payload(
    root: Path,
    case_id: str,
    archive_format: str,
    archive_dir: Path,
    archive_path: Path,
    payload: dict[str, str],
    **metadata,
) -> ArchiveCase:
    metadata = dict(metadata)
    metadata.setdefault("expected_files", payload.get("expected_files", {}))
    return ArchiveCase(
        case_id=case_id,
        archive_dir=archive_dir,
        entry_path=archive_path,
        marker_name=payload["marker_name"],
        marker_text=payload["marker_text"],
        archive_format=normalize_archive_format(archive_format),
        metadata=metadata,
    )


def create_streaming_zip_archive(
    root: Path,
    case_id: str,
    *,
    payload_size: int = 16 * 1024,
) -> ArchiveCase:
    """ZIP written through a non-seekable stream, so entries use data descriptors."""
    source_dir = root / f"{case_id}_src"
    payload = write_payload(source_dir, case_id, size_bytes=payload_size)
    archive_dir = root / case_id
    archive_dir.mkdir(parents=True, exist_ok=True)
    archive_path = archive_dir / f"{case_id}.zip"
    writer = _NonSeekableZipWriter()
    with zipfile.ZipFile(writer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(source_dir.iterdir()):
            archive.write(path, arcname=path.name)
    archive_path.write_bytes(writer.buffer.getvalue())
    shutil.rmtree(source_dir, ignore_errors=True)
    return _case_from_payload(
        root, case_id, "zip", archive_dir, archive_path, payload, data_descriptor=True
    )


def create_zip64_archive(
    root: Path,
    case_id: str,
    *,
    payload_size: int = 16 * 1024,
) -> ArchiveCase:
    """Tiny valid ZIP64 sample (few entries, ZIP64 end records, ~4KB)."""
    source_dir = root / f"{case_id}_src"
    payload = write_payload(source_dir, case_id, size_bytes=payload_size)
    archive_dir = root / case_id
    archive_dir.mkdir(parents=True, exist_ok=True)
    archive_path = archive_dir / f"{case_id}.zip"
    entries = {
        payload["marker_name"]: (source_dir / payload["marker_name"]).read_bytes(),
        "payload.bin": (source_dir / "payload.bin").read_bytes(),
    }
    archive_path.write_bytes(_craft_small_zip64(entries))
    shutil.rmtree(source_dir, ignore_errors=True)
    return _case_from_payload(
        root, case_id, "zip", archive_dir, archive_path, payload, zip64=True
    )


def create_zip_multidisk_archive(
    root: Path,
    case_id: str,
    *,
    payload_size: int = 512,
) -> ArchiveCase:
    """Create a tiny real PKZIP multi-disk archive (.z01 + .zip).

    The central directory is on the last disk and local entries are on disk 0;
    this is intentionally different from 7-Zip's generic ``-v`` split format.
    """
    source_dir = root / f"{case_id}_src"
    payload = write_payload(source_dir, case_id, size_bytes=payload_size, profile="structured")
    archive_dir = root / case_id
    archive_dir.mkdir(parents=True, exist_ok=True)
    entries = []
    local_body = bytearray()
    local_offsets: dict[str, int] = {}
    for path in sorted(path for path in source_dir.rglob("*") if path.is_file()):
        name = path.relative_to(source_dir).as_posix().encode("utf-8")
        data = path.read_bytes()
        offset = len(local_body)
        local_offsets[path.relative_to(source_dir).as_posix()] = offset
        local_body.extend(
            struct.pack(
                "<4s5H3I2H",
                b"PK\x03\x04",
                20,
                0,
                0,
                0,
                0,
                zlib.crc32(data) & 0xFFFFFFFF,
                len(data),
                len(data),
                len(name),
                0,
            )
        )
        local_body.extend(name)
        local_body.extend(data)
        entries.append((path.relative_to(source_dir).as_posix(), name, data))

    central_directory = bytearray()
    for entry_name, name, data in entries:
        central_directory.extend(
            struct.pack(
                "<4s6H3I5H2HI",
                b"PK\x01\x02",
                20,
                20,
                0,
                0,
                0,
                0,
                zlib.crc32(data) & 0xFFFFFFFF,
                len(data),
                len(data),
                len(name),
                0,
                0,
                0,
                0,
                0,
                0,
                local_offsets[entry_name],
            )
        )
        central_directory.extend(name)
    eocd = struct.pack(
        "<4sHHHHIIH",
        b"PK\x05\x06",
        1,
        1,
        len(entries),
        len(entries),
        len(central_directory),
        0,
        0,
    )
    (archive_dir / f"{case_id}.z01").write_bytes(bytes(local_body))
    archive_path = archive_dir / f"{case_id}.zip"
    archive_path.write_bytes(bytes(central_directory) + eocd)
    shutil.rmtree(source_dir, ignore_errors=True)
    return _case_from_payload(
        root,
        case_id,
        "zip",
        archive_dir,
        archive_dir / f"{case_id}.z01",
        payload,
        multidisk=True,
        disk_count=2,
    )


def _craft_small_zip64(entries: dict[str, bytes]) -> bytes:
    """Rewrite a normal small zip into a valid ZIP64 archive.

    Layout per APPNOTE: central directory, ZIP64 end-of-central-directory record,
    ZIP64 EOCD locator, classic EOCD with sentinel entry counts/offsets.
    Validated against 7-Zip and python zipfile (testzip).
    """
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    data = buffer.getvalue()
    eocd_offset = data.rfind(b"PK\x05\x06")
    if eocd_offset == -1:
        raise ValueError("generated zip has no end-of-central-directory record")
    comment_len = struct.unpack_from("<H", data, eocd_offset + 20)[0]
    eocd = data[eocd_offset : eocd_offset + 22 + comment_len]
    disk_no, cd_disk, entries_disk, entries_total, cd_size, cd_offset = struct.unpack_from(
        "<HHHHII", eocd, 4
    )
    body = data[:eocd_offset]
    zip64_eocd_offset = len(body)
    zip64_eocd = struct.pack(
        "<4sQHHLLQQQQ",
        b"PK\x06\x06",
        44,
        45,
        45,
        disk_no,
        cd_disk,
        entries_disk,
        entries_total,
        cd_size,
        cd_offset,
    )
    locator = struct.pack("<4sLQL", b"PK\x06\x07", 0, zip64_eocd_offset, 1)
    classic = struct.pack(
        "<4sHHHHIIH",
        b"PK\x05\x06",
        disk_no,
        cd_disk,
        0xFFFF,
        0xFFFF,
        0xFFFFFFFF,
        0xFFFFFFFF,
        0,
    )
    return body + zip64_eocd + locator + classic


def create_rar4_archive(
    root: Path,
    case_id: str,
    *,
    split: bool = False,
    payload_size: int = 16 * 1024,
    split_volume_size: int = 100 * 1024,
    compression_level: int = 0,
    solid: bool | None = None,
    payload_profile: str = "default",
) -> ArchiveCase:
    rar = get_optional_rar()
    if not rar:
        raise FileNotFoundError("RAR generator is not configured.")
    source_dir = root / f"{case_id}_src"
    payload = write_payload(
        source_dir,
        case_id,
        size_bytes=payload_size,
        profile=payload_profile,
    )
    archive_dir = root / case_id
    archive_dir.mkdir(parents=True, exist_ok=True)
    archive_path = archive_dir / f"{case_id}.rar"
    compression_level = int(compression_level)
    if not 0 <= compression_level <= 5:
        raise ValueError("RAR compression level must be between 0 and 5")
    cmd = [str(rar), "a", "-ep1", "-idq", f"-m{compression_level}", "-ma4", "-y"]
    if solid is True:
        cmd.append("-s")
    elif solid is False:
        cmd.append("-s-")
    if split:
        cmd.append(f"-v{max(1024, int(split_volume_size))}b")
    cmd.extend([str(archive_path), str(source_dir)])
    run_cmd(cmd, archive_dir)
    shutil.rmtree(source_dir, ignore_errors=True)
    entry_path = choose_entry_path(archive_dir, case_id, "rar")
    return _case_from_payload(
        root, case_id, "rar", archive_dir, entry_path, payload, rar4=True, split=split
    )


def create_encrypted_zip_archive(
    root: Path,
    case_id: str,
    *,
    password: str,
    encryption: str = "ZipCrypto",
    method: str | None = None,
    payload_size: int = 16 * 1024,
) -> ArchiveCase:
    """Encrypted ZIP with selectable encryption (ZipCrypto/AES) and compression method."""
    if encryption not in {"ZipCrypto", "AES128", "AES192", "AES256"}:
        raise ValueError(f"Unsupported ZIP encryption: {encryption}")
    source_dir = root / f"{case_id}_src"
    payload = write_payload(source_dir, case_id, size_bytes=payload_size)
    archive_dir = root / case_id
    archive_dir.mkdir(parents=True, exist_ok=True)
    archive_path = archive_dir / f"{case_id}.zip"
    cmd = [
        str(require_7z()),
        "a",
        str(archive_path),
        str(source_dir),
        "-tzip",
        "-mx=1",
        "-y",
        f"-p{password}",
    ]
    if encryption != "ZipCrypto":
        cmd.append(f"-mem={encryption}")
    if method:
        cmd.append(f"-mm={method}")
    run_cmd(cmd, archive_dir)
    shutil.rmtree(source_dir, ignore_errors=True)
    return _case_from_payload(
        root, case_id, "zip", archive_dir, archive_path, payload,
        encryption=encryption,
        method=method or "Deflate",
    )


def create_encrypted_rar_archive(
    root: Path,
    case_id: str,
    *,
    password: str,
    rar4: bool = False,
    header_encrypt: bool = True,
    split: bool = False,
    split_volume_size: int = 100 * 1024,
    payload_size: int = 16 * 1024,
) -> ArchiveCase:
    """Encrypted RAR: RAR4/RAR5, header+data (-hp) or data-only (-p)."""
    rar = get_optional_rar()
    if not rar:
        raise FileNotFoundError("RAR generator is not configured.")
    source_dir = root / f"{case_id}_src"
    payload = write_payload(source_dir, case_id, size_bytes=payload_size)
    archive_dir = root / case_id
    archive_dir.mkdir(parents=True, exist_ok=True)
    archive_path = archive_dir / f"{case_id}.rar"
    cmd = [str(rar), "a", "-ep1", "-idq", "-m0", "-y"]
    if rar4:
        cmd.append("-ma4")
    if split:
        cmd.append(f"-v{max(1024, int(split_volume_size))}b")
    cmd.append(f"-hp{password}" if header_encrypt else f"-p{password}")
    cmd.extend([str(archive_path), str(source_dir)])
    run_cmd(cmd, archive_dir)
    shutil.rmtree(source_dir, ignore_errors=True)
    entry_path = choose_entry_path(archive_dir, case_id, "rar")
    return _case_from_payload(
        root, case_id, "rar", archive_dir, entry_path, payload,
        rar4=rar4,
        split=split,
        header_encrypt=header_encrypt,
    )


def create_encrypted_7z_archive(
    root: Path,
    case_id: str,
    *,
    password: str,
    header_encrypt: bool = True,
    solid: bool = True,
    method: str | None = None,
    payload_size: int = 16 * 1024,
) -> ArchiveCase:
    """Encrypted 7z: header on/off (-mhe), solid on/off (-ms), selectable method."""
    source_dir = root / f"{case_id}_src"
    payload = write_payload(source_dir, case_id, size_bytes=payload_size)
    archive_dir = root / case_id
    archive_dir.mkdir(parents=True, exist_ok=True)
    archive_path = archive_dir / f"{case_id}.7z"
    cmd = [
        str(require_7z()),
        "a",
        str(archive_path),
        str(source_dir),
        "-mx=1",
        "-y",
        f"-p{password}",
    ]
    if header_encrypt:
        cmd.append("-mhe=on")
    if not solid:
        cmd.append("-ms=off")
    if method:
        cmd.append(f"-mm={method}")
    run_cmd(cmd, archive_dir)
    shutil.rmtree(source_dir, ignore_errors=True)
    return _case_from_payload(
        root, case_id, "7z", archive_dir, archive_path, payload,
        header_encrypt=header_encrypt,
        solid=solid,
        method=method,
    )


def create_multi_member_stream_archive(
    root: Path,
    case_id: str,
    stream_format: str,
    *,
    payload_size: int = 16 * 1024,
) -> ArchiveCase:
    """Concatenated gzip members, bzip2/XZ streams or Zstandard/LZ4 frames."""
    stream_format = normalize_archive_format(stream_format)
    if stream_format not in STREAM_FORMATS:
        raise ValueError(f"Unsupported multi-member stream format: {stream_format}")
    source_dir = root / f"{case_id}_src"
    payload = write_payload(source_dir, case_id, size_bytes=payload_size)
    archive_dir = root / case_id
    archive_dir.mkdir(parents=True, exist_ok=True)
    archive_path = archive_dir / f"{case_id}{ARCHIVE_EXTENSIONS[stream_format]}"
    second_content = f"SUNPACK-SECOND-MEMBER-{case_id}".encode("utf-8")
    stream_metadata = {}
    if stream_format != "lz4":
        marker_bytes = (source_dir / payload["marker_name"]).read_bytes()
    if stream_format == "lz4":
        from tests.helpers.native_fixture import create_lz4_frames

        extra_path = source_dir / "second_member.txt"
        extra_path.write_text(second_content.decode("utf-8"), encoding="utf-8")
        receipt = create_lz4_frames(archive_path, [source_dir / payload["marker_name"], extra_path])
        stream_metadata["expected_files"] = {
            case_id: {"size": receipt["source_bytes"], "crc32": receipt["source_crc32"]}
        }
    elif stream_format == "gzip":
        with archive_path.open("wb") as stream:
            with gzip.GzipFile(filename=payload["marker_name"], mode="wb", fileobj=stream) as member:
                member.write(marker_bytes)
            with gzip.GzipFile(filename="extra.bin", mode="wb", fileobj=stream) as member:
                member.write(second_content)
    elif stream_format == "bzip2":
        compressor = bz2.BZ2Compressor()
        data = compressor.compress(marker_bytes) + compressor.flush()
        compressor = bz2.BZ2Compressor()
        data += compressor.compress(second_content) + compressor.flush()
        archive_path.write_bytes(data)
    elif stream_format == "xz":
        data = lzma.compress(marker_bytes, format=lzma.FORMAT_XZ)
        data += lzma.compress(second_content, format=lzma.FORMAT_XZ)
        archive_path.write_bytes(data)
    else:
        extra_path = source_dir / "second_member.bin"
        extra_path.write_bytes(second_content)
        with archive_path.open("wb") as stream:
            for path in (source_dir / payload["marker_name"], extra_path):
                completed = subprocess.run(
                    [str(require_zstd()), "-q", "-c", str(path)],
                    capture_output=True,
                )
                if completed.returncode != 0:
                    raise RuntimeError(f"zstd frame creation failed for {path.name}")
                stream.write(completed.stdout)
    shutil.rmtree(source_dir, ignore_errors=True)
    return _case_from_payload(
        root, case_id, stream_format, archive_dir, archive_path, payload,
        multi_member=True,
        second_member_content=second_content.decode("utf-8"),
        **stream_metadata,
    )


def create_stream_variant_archive(
    root: Path,
    case_id: str,
    stream_format: str,
    *,
    payload_size: int = 256,
    compression_level: int | None = None,
    gzip_filename: str | None = None,
    xz_check: str | None = None,
    zstd_checksum: bool = True,
) -> ArchiveCase:
    stream_format = normalize_archive_format(stream_format)
    if stream_format not in STREAM_FORMATS:
        raise ValueError(f"Unsupported stream format: {stream_format}")
    source_dir = root / f"{case_id}_src"
    payload = write_payload(source_dir, case_id, size_bytes=payload_size)
    archive_dir = root / case_id
    archive_dir.mkdir(parents=True, exist_ok=True)
    marker_path = source_dir / payload["marker_name"]
    archive_path = archive_dir / f"{case_id}{ARCHIVE_EXTENSIONS[stream_format]}"
    create_compression_stream(
        marker_path,
        archive_path,
        stream_format,
        compression_level=compression_level,
        gzip_filename=gzip_filename,
        xz_check=xz_check,
        zstd_checksum=zstd_checksum,
    )
    shutil.rmtree(source_dir, ignore_errors=True)
    return _case_from_payload(
        root,
        case_id,
        stream_format,
        archive_dir,
        archive_path,
        payload,
        expected_files={payload["marker_name"]: payload["expected_files"][payload["marker_name"]]},
        compression_level=compression_level,
        gzip_filename=gzip_filename,
        xz_check=xz_check,
        zstd_checksum=zstd_checksum,
    )


def build_archive_case(
    root: Path,
    case_id: str,
    archive_format: str,
    password: str | None = None,
    split: bool = False,
    sfx: bool = False,
) -> dict:
    return ArchiveFixtureFactory().create(
        root,
        case_id,
        archive_format,
        password=password,
        split=split,
        sfx=sfx,
    ).to_dict()


def choose_entry_path(archive_dir: Path, case_id: str, archive_format: str, sfx: bool = False) -> Path:
    archive_format = normalize_archive_format(archive_format)
    files = sorted(path for path in archive_dir.iterdir() if path.is_file())
    if not files:
        raise RuntimeError(f"No generated files for {case_id}")
    if archive_format == "rar":
        for path in files:
            lower = path.name.lower()
            if sfx and ".part1.exe" in lower:
                return path
            if ".part1.rar" in lower or lower.endswith(".rar"):
                return path
    if sfx:
        return archive_dir / f"{case_id}.exe"
    expected_ext = ARCHIVE_EXTENSIONS.get(archive_format)
    for path in files:
        lower = path.name.lower()
        if lower.endswith(".001") or (expected_ext and lower.endswith(expected_ext)):
            return path
    return files[0]


def normalize_archive_format(archive_format: str) -> str:
    value = str(archive_format or "").strip()
    return FORMAT_ALIASES.get(value, value.lower())


def corrupt_file(path: Path, truncate: bool = False, mode: str | None = None):
    raw = bytearray(path.read_bytes())
    effective_mode = mode or ("truncate" if truncate else "byte_flip")
    if effective_mode == "truncate":
        if len(raw) <= CORRUPT_TRUNCATE_BYTES:
            raise RuntimeError(f"File too small to truncate safely: {path}")
        path.write_bytes(raw[:-CORRUPT_TRUNCATE_BYTES])
        return
    if effective_mode == "header_damage":
        if len(raw) < 32:
            raw.extend(b"x" * (32 - len(raw)))
        raw[:16] = b"\0" * 16
        path.write_bytes(raw)
        return
    if effective_mode in {"trailing_junk", "tail_junk"}:
        raw.extend(b"SUNPACK_TRAILING_JUNK")
        path.write_bytes(raw)
        return
    if effective_mode == "tail_header_damage":
        if len(raw) < 32:
            raw.extend(b"x" * (32 - len(raw)))
        raw[-16:] = b"\0" * 16
        path.write_bytes(raw)
        return
    if effective_mode != "byte_flip":
        raise ValueError(f"Unsupported corruption mode: {effective_mode}")
    if len(raw) < 128:
        raw.extend(b"x" * (128 - len(raw)))
    start = min(64, max(0, len(raw) - 32))
    raw[start : start + 16] = b"\0" * 16
    path.write_bytes(raw)


def remove_last_split_part(archive_dir: Path):
    files = sorted(path for path in archive_dir.iterdir() if path.is_file())
    if len(files) < 2:
        raise RuntimeError("Split archive did not generate multiple parts.")
    files[-1].unlink()


def corrupt_split_member(archive_dir: Path):
    parts = sorted(path for path in archive_dir.iterdir() if path.is_file())
    if len(parts) < 2:
        raise RuntimeError("Split archive did not generate multiple parts.")
    corrupt_file(parts[min(1, len(parts) - 1)], mode="byte_flip")


def apply_split_issue(case: ArchiveCase, issue: str):
    if issue == "missing_last":
        remove_last_split_part(case.archive_dir)
        return
    if issue == "corrupt_member":
        corrupt_split_member(case.archive_dir)
        return
    raise ValueError(f"Unsupported split issue: {issue}")


def disguise_case_entry(case: ArchiveCase, suffix_or_ext: str) -> Path:
    if suffix_or_ext.startswith("."):
        new_path = case.entry_path.with_name(f"{case.entry_path.name}{suffix_or_ext}")
    else:
        new_path = case.entry_path.with_name(f"{case.entry_path.name}.{suffix_or_ext}")
    case.entry_path.rename(new_path)
    return new_path


def wrap_case_with_carrier(case: ArchiveCase, carrier: str) -> Path:
    carrier_path = case.archive_dir / f"{case.case_id}.{carrier}"
    wrap_with_carrier_prefix(case.entry_path, carrier_path, carrier)
    case.entry_path.unlink()
    return carrier_path


def wrap_with_carrier_prefix(source_archive: Path, carrier_path: Path, carrier: str):
    prefixes = {
        "jpg": MINIMAL_JPEG_BYTES,
        "png": MINIMAL_PNG_BYTES,
        "gif": MINIMAL_GIF_BYTES,
        "pdf": MINIMAL_PDF_BYTES,
        "webp": MINIMAL_WEBP_BYTES,
    }
    carrier_path.write_bytes(prefixes[carrier] + source_archive.read_bytes())
