"""Independent 7-Zip-Zstandard interoperability fixtures; Python schedules tools."""
from __future__ import annotations

import shutil
from pathlib import Path

from tests.helpers.native_fixture import file_inventory
from tests.helpers.real_archives import ArchiveCase, choose_entry_path, run_cmd, write_payload
from tests.helpers.tool_config import require_7z, require_7z_zstd


def create_7z_lz4_case(
    root: Path, case_id: str, *, solid: bool = True, password: str | None = None,
    header_encrypt: bool = True, split: bool = False, disguise: bool = False,
    branch: str | None = None, payload_size: int = 256 * 1024,
    header_compress: bool = True,
) -> ArchiveCase:
    source = root / f"{case_id}_src"
    payload = write_payload(source, case_id, size_bytes=payload_size)
    (source / "empty.txt").write_text("", encoding="utf-8")
    (source / "路径 空格.txt").write_text("Unicode names through the existing 7z handler\n", encoding="utf-8")
    if branch:
        shutil.copyfile(require_7z(), source / "program.exe")
    expected = file_inventory(source)
    directory = root / case_id
    directory.mkdir(parents=True)
    archive = directory / f"{case_id}.7z"
    command = [str(require_7z_zstd()), "a", "-t7z", "-y", f"-ms={'on' if solid else 'off'}",
               f"-mhc={'on' if header_compress else 'off'}", "-mmt=2"]
    if branch == "BCJ2":
        command += ["-m0=BCJ2", "-m1=LZ4", "-m2=LZ4", "-m3=LZ4",
                    "-mb0:1", "-mb0s1:2", "-mb0s2:3"]
    elif branch:
        command += [f"-m0={branch}", "-m1=LZ4"]
    else:
        command += ["-m0=LZ4"]
    if password:
        command += [f"-p{password}", f"-mhe={'on' if header_encrypt else 'off'}"]
    if split:
        command += ["-v32k"]
    command += [str(archive), str(source)]
    run_cmd(command, directory)
    shutil.rmtree(source)
    entry = choose_entry_path(directory, case_id, "7z")
    if disguise:
        if split:
            for part in sorted(directory.iterdir()):
                renamed = part.rename(part.with_name(part.name.replace(".7z.", ".payload.")))
                if part == entry:
                    entry = renamed
        else:
            entry = entry.rename(entry.with_suffix(".payload"))
    return ArchiveCase(
        case_id, directory, entry, payload["marker_name"], payload["marker_text"], "7z",
        password=password, split=split, metadata={"expected_files": expected},
    )
