"""Independent decoder for display-file integration fixtures (never production I/O)."""
import json
import struct
from pathlib import Path

import lz4.block
import msgpack


def iter_records(path):
    path = Path(path)
    manifest = json.loads(path.read_text(encoding="utf-8"))
    folder = path.with_name(path.name + ".store")
    for run in [*manifest["runs"], *([manifest["live"]] if manifest.get("live") else [])]:
        with (folder / (run["name"] + ".index")).open("rb") as index, (folder / (run["name"] + ".data")).open("rb") as data:
            index.seek(run["head"] * 64)
            for _ in range(run["head"], run["count"]):
                timestamp, offset, size, raw_size = struct.unpack_from("<qQII", index.read(64))
                if not timestamp and not offset and not size and not raw_size:
                    continue
                data.seek(offset)
                if size:
                    raw = lz4.block.decompress(data.read(size), uncompressed_size=raw_size)
                else:
                    magic, reserved, total, raw_size = struct.unpack("<4sIQQ", data.read(24))
                    assert magic == b"SPDC" and reserved == 0
                    end = offset + total
                    raw = bytearray()
                    while data.tell() < end:
                        packed, unpacked = struct.unpack("<II", data.read(8))
                        raw.extend(lz4.block.decompress(data.read(packed), uncompressed_size=unpacked))
                    assert data.tell() == end and len(raw) == raw_size
                row = msgpack.unpackb(raw, raw=False)
                if "group" in row:
                    group = row.pop("group")
                    yield {"event": "pipeline_sources_claimed", "groups": [group]}
                yield row


def records(path):
    return list(iter_records(path))


def storage_bytes(path):
    path = Path(path)
    folder = path.with_name(path.name + ".store")
    return path.stat().st_size + sum(file.stat().st_size for file in folder.iterdir() if file.is_file())
