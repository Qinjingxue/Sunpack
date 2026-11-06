import re


def normalize_error_text(err_text: str) -> str:
    return (err_text or "").lower()


def has_archive_damage_signals(err_text: str) -> bool:
    err_lower = normalize_error_text(err_text)
    return any(
        marker in err_lower
        for marker in (
            "unexpected end of archive",
            "unexpected end of data",
            "missing volume",
            "crc failed",
            "data error in encrypted file",
            "headers error",
            "data error",
            "can not open the file as archive",
            "cannot open the file as",
            "could not be opened by supported handlers",
            "is not archive",
            "archive is corrupted",
            "checksum error",
            "unsupported compression method",
            "unsupported method",
        )
    )


def looks_like_split_archive_name(archive_name: str) -> bool:
    if not archive_name:
        return False
    return bool(
        re.search(r"\.part\d+\.rar(?:\.[^.]+)?$", archive_name, re.IGNORECASE)
        or re.search(r"\.z\d{2}$", archive_name, re.IGNORECASE)
        or re.search(r"\.(7z|zip|rar)\.\d{3}(?:\.[^.]+)?$", archive_name, re.IGNORECASE)
        or re.search(r"\.\d{3}(?:\.[^.]+)?$", archive_name, re.IGNORECASE)
    )
