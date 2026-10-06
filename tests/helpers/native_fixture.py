from __future__ import annotations

import json
import subprocess
from functools import lru_cache
from pathlib import Path


@lru_cache(maxsize=1)
def _fixture_tool() -> Path:
    root = Path(__file__).resolve().parents[2]
    manifest = root / "native" / "Cargo.toml"
    command = ["cargo", "--manifest-path", str(manifest)]
    metadata = subprocess.run(
        [command[0], "metadata", *command[1:], "--no-deps", "--format-version", "1"],
        check=True, capture_output=True, text=True, encoding="utf-8",
    )
    subprocess.run(
        [command[0], "build", *command[1:], "--locked", "-p", "sunpack-native",
         "--example", "real_fixture"],
        check=True, capture_output=True, text=True, encoding="utf-8",
    )
    return Path(json.loads(metadata.stdout)["target_directory"]) / "debug/examples/real_fixture.exe"


def native_fixture(operation: str, **arguments) -> dict:
    result = subprocess.run(
        [str(_fixture_tool())], input=json.dumps({"operation": operation, **arguments}),
        check=True, capture_output=True, text=True, encoding="utf-8",
    )
    return json.loads(result.stdout)


def assemble_carrier(
    output: Path, paths: list[Path], *, seed: int = 0x5A17C0DE,
    junk_min: int = 192, junk_max: int = 6144,
    prefix_lengths: list[int] | None = None, decoys: bool = False,
) -> dict:
    return native_fixture(
        "assemble", output=str(output), paths=[str(path) for path in paths],
        seed=seed, junk_min=junk_min, junk_max=junk_max,
        prefix_lengths=prefix_lengths, decoys=decoys,
    )


def create_lz4_frames(output: Path, paths: list[Path]) -> dict:
    """Use the independent upstream encoder in the test-only native tool."""
    return native_fixture("lz4", output=str(output), paths=[str(path) for path in paths])


def file_inventory(root: Path) -> dict[str, dict]:
    return {
        item["path"]: {"size": item["size"], "crc32": item["crc32"]}
        for item in native_fixture("inventory", root=str(root))["files"]
    }


def assert_exact_tree(root: Path, expected: dict[str, dict]) -> None:
    actual = file_inventory(root)
    assert actual == expected, f"output tree mismatch: expected={expected!r}, actual={actual!r}"
