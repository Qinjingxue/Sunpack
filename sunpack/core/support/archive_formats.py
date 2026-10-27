from typing import Any


FORMAT_ALIASES = {
    "7zip": "7z",
    "seven_zip": "7z",
    "sevenzip": "7z",
    "gz": "gzip",
    "bz2": "bzip2",
    "zst": "zstd",
    "tgz": "gzip",
    "tbz": "bzip2",
    "tbz2": "bzip2",
    "txz": "xz",
    "tzst": "zstd",
    "tar.zstd": "zstd",
    # Legacy spelling aliases identify only the outer stream.
    "tar.gz": "gzip",
    "tar.bz2": "bzip2",
    "tar.xz": "xz",
    "tar.zst": "zstd",
    "tar.lz4": "lz4",
}


def canonical_format(value: Any, *, unknown: str = "unknown") -> str:
    text = str(value or "").strip().lower().lstrip(".")
    if not text:
        return unknown
    return FORMAT_ALIASES.get(text, text)
