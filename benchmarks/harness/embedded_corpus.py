"""Share the historical mixed carrier between scan and hit-index benchmarks."""
from pathlib import Path
import shutil


def _write_repeated(stream, remaining, block):
    while remaining:
        count = min(remaining, len(block))
        stream.write(block[:count])
        remaining -= count


def mixed_carrier(root: Path, path: Path, size: int, segments: int = 128):
    from tests.real.enc_support import ENC_VECTOR
    from tests.real.plan5_embedded_archives.plan5_support import build_large_embedded_case

    case = build_large_embedded_case(root / "plan5", count=segments)
    enc_size = ENC_VECTOR.stat().st_size
    padding = size - case.file_path.stat().st_size - enc_size
    if padding < 0:
        raise ValueError("The requested carrier size cannot hold the mixed archives")
    prefix = padding // 2
    block = bytes(1024 * 1024)
    with path.open("wb") as output, case.file_path.open("rb") as source:
        _write_repeated(output, prefix, block)
        shutil.copyfileobj(source, output, len(block))
        _write_repeated(output, padding - prefix, block)
        with ENC_VECTOR.open("rb") as enc:
            shutil.copyfileobj(enc, output, len(block))
    return {(segment.archive_format, prefix + segment.offset) for segment in case.segments} | {
        ("enc", size - enc_size),
    }
