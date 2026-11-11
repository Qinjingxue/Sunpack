from __future__ import annotations

from pathlib import Path

from tests.helpers.native_fixture import native_fixture
from tests.helpers.real_archives import ArchiveCase


ROOT = Path(__file__).resolve().parents[2]
ENC_VECTOR = ROOT / "native" / "sunpack_enc" / "tests" / "data" / "algorithm_0.mov"
ENC_PASSWORD = "sunpack-test"
ENC_MARKER_NAME = "inside.txt"
ENC_MARKER_TEXT = "SunPack official ENC v4 compatibility\n"


def create_enc_case(
    root: Path,
    case_id: str,
    *,
    input_suffix: str = ".enc",
) -> ArchiveCase:
    """Copy the official ENC vector into an isolated integration-test case."""
    root.mkdir(parents=True, exist_ok=True)
    archive_dir = root / case_id
    archive_dir.mkdir(parents=True, exist_ok=True)
    entry_path = archive_dir / f"{case_id}{input_suffix}"
    native_fixture("copy", source=str(ENC_VECTOR), output=str(entry_path))
    return ArchiveCase(
        case_id=case_id,
        archive_dir=archive_dir,
        entry_path=entry_path,
        marker_name=ENC_MARKER_NAME,
        marker_text=ENC_MARKER_TEXT,
        archive_format="enc",
        password=ENC_PASSWORD,
    )


__all__ = [
    "ENC_PASSWORD",
    "create_enc_case",
]
