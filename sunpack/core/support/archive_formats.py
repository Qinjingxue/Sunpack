from typing import Any


FORMAT_ALIASES = {
    "7zip": "7z",
    "seven_zip": "7z",
    "sevenzip": "7z",
    "gz": "gzip",
    "bz2": "bzip2",
    "zst": "zstd",
    "tgz": "tar.gz",
    "tbz": "tar.bz2",
    "tbz2": "tar.bz2",
    "txz": "tar.xz",
    "tzst": "tar.zst",
    "tar.zstd": "tar.zst",
}


def canonical_format(value: Any, *, unknown: str = "unknown") -> str:
    text = str(value or "").strip().lower().lstrip(".")
    if not text:
        return unknown
    return FORMAT_ALIASES.get(text, text)
