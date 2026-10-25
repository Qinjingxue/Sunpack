"""Independent decoder for display-file integration fixtures (never production I/O)."""
import json
import struct
from pathlib import Path

import lz4.block
import msgpack


def records(path):
    path = Path(path)
    manifest = json.loads(path.read_text(encoding="utf-8"))
    folder = path.with_name(path.name + ".store")
    rows = []
    for run in [*manifest["runs"], *([manifest["live"]] if manifest.get("live") else [])]:
        with (folder / (run["name"] + ".index")).open("rb") as index, (folder / (run["name"] + ".data")).open("rb") as data:
            index.seek(run["head"] * 64)
            for _ in range(run["head"], run["count"]):
                timestamp, offset, size, raw_size = struct.unpack_from("<qQII", index.read(64))
                if not size or not raw_size:
                    continue
                data.seek(offset)
                row = msgpack.unpackb(lz4.block.decompress(data.read(size), uncompressed_size=raw_size), raw=False)
                if "group" in row:
                    group = row.pop("group")
                    rows.append({"event": "pipeline_sources_claimed", "groups": [group]})
                rows.append(row)
    return rows
