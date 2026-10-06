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


def make_minimal_pe(
    marker: bytes = b"", *, pe_offset: int = 0x80, pe64: bool = False,
) -> bytes:
    """A bounded PE32/PE32+ fixture with one raw section and valid headers."""
    optional_size = 240 if pe64 else 224
    optional = pe_offset + 24
    section = optional + optional_size
    headers_size = (section + 40 + 511) & ~511
    image = bytearray(headers_size + 32)
    image[:2] = b"MZ"
    image[0x20:0x20 + len(marker)] = marker
    image[0x3C:0x40] = pe_offset.to_bytes(4, "little")
    image[pe_offset:pe_offset + 4] = b"PE\x00\x00"
    image[pe_offset + 4:pe_offset + 6] = (0x8664 if pe64 else 0x14C).to_bytes(2, "little")
    image[pe_offset + 6:pe_offset + 8] = (1).to_bytes(2, "little")
    image[pe_offset + 20:pe_offset + 22] = optional_size.to_bytes(2, "little")
    image[optional:optional + 2] = (0x20B if pe64 else 0x10B).to_bytes(2, "little")
    image[optional + 32:optional + 36] = (4096).to_bytes(4, "little")
    image[optional + 36:optional + 40] = (512).to_bytes(4, "little")
    image[optional + 56:optional + 60] = (8192).to_bytes(4, "little")
    image[optional + 60:optional + 64] = headers_size.to_bytes(4, "little")
    count_offset = 108 if pe64 else 92
    image[optional + count_offset:optional + count_offset + 4] = (16).to_bytes(4, "little")
    image[section:section + 5] = b".text"
    image[section + 16:section + 20] = (32).to_bytes(4, "little")
    image[section + 20:section + 24] = headers_size.to_bytes(4, "little")
    return bytes(image)
