import unicodedata
from typing import Any


def clean_relative_archive_path(value: Any) -> str:
    text = str(value or "").replace("\\", "/").strip().strip("/")
    parts = [part for part in text.split("/") if part not in {"", ".", ".."}]
    return "/".join(parts)


def normalize_match_name(value: str) -> str:
    return unicodedata.normalize("NFC", str(value or "")).casefold()


def normalize_match_path(value: str) -> str:
    return "/".join(
        normalize_match_name(part)
        for part in clean_relative_archive_path(value).split("/")
        if part
    )
