import io
import zipfile
from typing import Any


def render_content(content: Any) -> bytes:
    if isinstance(content, str):
        return content.encode("utf-8")
    if isinstance(content, list):
        return b"".join(render_content(part) for part in content)
    if not isinstance(content, dict):
        raise TypeError(f"Unsupported file content: {content!r}")

    content_type = content.get("type", "text")
    if content_type == "text":
        return content.get("value", "").encode(content.get("encoding", "utf-8"))
    if content_type == "hex":
        return bytes.fromhex(content["value"])
    if content_type == "repeat":
        return render_content(content["value"]) * int(content["count"])
    if content_type == "zip":
        return make_zip(content.get("entries", {}))
    if content_type == "zip_with_prefix":
        return bytes.fromhex(content.get("prefix_hex", "")) + make_zip(content.get("entries", {}))
    if content_type == "valid_7z":
        return make_minimal_7z()
    if content_type == "parts":
        return b"".join(render_content(part) for part in content.get("items", []))
    raise ValueError(f"Unknown content type: {content_type}")


def make_zip(entries: dict[str, str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as archive:
        for name, value in entries.items():
            archive.writestr(name, value)
    return buffer.getvalue()


def make_minimal_7z() -> bytes:
    from binascii import crc32
    gap = b"abcde"
    next_header = b"\x01"
    start_header = len(gap).to_bytes(8, "little") + len(next_header).to_bytes(8, "little") + crc32(next_header).to_bytes(4, "little")
    return b"7z\xbc\xaf\x27\x1c" + b"\x00\x04" + crc32(start_header).to_bytes(4, "little") + start_header + gap + next_header
