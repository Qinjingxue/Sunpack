import re


def normalize_error_text(err_text: str) -> str:
    return (err_text or "").lower()


def looks_like_split_archive_name(archive_name: str) -> bool:
    if not archive_name:
        return False
    return bool(
        re.search(r"\.part\d+\.rar(?:\.[^.]+)?$", archive_name, re.IGNORECASE)
        or re.search(r"\.z\d{2}$", archive_name, re.IGNORECASE)
        or re.search(r"\.(7z|zip|rar)\.\d{3}(?:\.[^.]+)?$", archive_name, re.IGNORECASE)
        or re.search(r"\.\d{3}(?:\.[^.]+)?$", archive_name, re.IGNORECASE)
    )
