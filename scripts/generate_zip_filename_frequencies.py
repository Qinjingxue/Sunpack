"""Generate ZIP filename scores from a local copy of the pinned AOSP header."""

import argparse
import re
from pathlib import Path


SOURCE_URL = (
    "https://android.googlesource.com/platform/frameworks/av/+/"
    "03357add725340c290b10f50db090267bbf511b1/media/libmedia/"
    "CharacterEncodingDetectorTables.h"
)
OUTPUT = (
    Path(__file__).resolve().parents[1]
    / "sunpack/sunpack_runtime/src/formats/zip/filename_frequencies.bin"
)


def generate(source: str) -> bytes:
    # Each byte stores three 2-bit rank bands. Unlisted Han characters have band zero.
    first_han, last_han = 0x4E00, 0x9FFF
    table = bytearray(last_han - first_han + 1)
    for index, language in enumerate(("ja", "zhCN", "zhTW")):
        match = re.search(rf"frequent_{language}\[\] = \{{(.*?)\}};", source, re.S)
        if match is None:
            raise ValueError(f"Missing AOSP frequency data for {language}")
        entries = re.findall(r"0x([0-9A-F]+),\s*//.*?#(\d+)", match[1])
        if sorted(int(rank) for _, rank in entries) != list(range(1, 513)):
            raise ValueError(f"Expected 512 ranked AOSP characters for {language}")
        for codepoint, rank in entries:
            codepoint, rank = int(codepoint, 16), int(rank)
            if first_han <= codepoint <= last_han:
                band = 3 - int(rank > 128) - int(rank > 256)
                table[codepoint - first_han] |= band << (2 * index)
    return bytes(table)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, epilog=SOURCE_URL)
    parser.add_argument("header", type=Path, help="decoded CharacterEncodingDetectorTables.h")
    arguments = parser.parse_args()
    OUTPUT.write_bytes(generate(arguments.header.read_text(encoding="utf-8")))


if __name__ == "__main__":
    main()
