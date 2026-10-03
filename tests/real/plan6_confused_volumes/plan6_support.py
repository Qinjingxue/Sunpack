from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from tests.real.plan2_encrypted_archives.plan2_support import (
    assert_plan2_success,
    encrypted_password_list,
)


@dataclass(frozen=True)
class VolumeConfusionScenario:
    """分卷卷名混淆场景。

    所有场景都保证：卷号标识（.001 / partN 等）完整保留，只在其前后加无效
    数据；同一压缩包的卷保持相同前缀（stem），混在同一个目录里。
    name_for(base, fmt, volume_index, volume_count, is_launcher) 返回该卷最终文件名。
    """

    case_id: str
    description: str
    name_for: Callable[[str, str, int, int, bool], str]


def _canonical_name(base: str, fmt: str, index: int, _count: int, is_launcher: bool) -> str:
    """各格式的标准分卷名（7z/zip 数值后缀、rar partN、SFX 启动器）。"""
    if is_launcher:
        return f"{base}.exe"
    if fmt == "rar":
        return f"{base}.part{index}.rar"
    return f"{base}.{fmt}.{index:03d}"


SCENARIOS: tuple[VolumeConfusionScenario, ...] = (
    VolumeConfusionScenario(
        case_id="suffix-junk-some",
        description="部分卷（偶数卷）在卷号标识后附加无效后缀，头卷保持标准名",
        name_for=lambda base, fmt, index, count, launcher: (
            _canonical_name(base, fmt, index, count, launcher)
            if launcher or index % 2 == 1
            else f"{_canonical_name(base, fmt, index, count, launcher)}.junk{index:02d}.tmp"
        ),
    ),
    VolumeConfusionScenario(
        case_id="suffix-junk-all",
        description="每个数据卷都在卷号标识后附加各自的无效后缀",
        name_for=lambda base, fmt, index, count, launcher: (
            _canonical_name(base, fmt, index, count, launcher)
            if launcher
            else f"{_canonical_name(base, fmt, index, count, launcher)}.junk{index:02d}.tmp"
        ),
    ),
    VolumeConfusionScenario(
        case_id="prefix-suffix-junk-all",
        description="全部成员使用同一 first-dot 前缀，数据卷在卷号标识前后附加无效数据",
        name_for=lambda base, fmt, index, count, launcher: (
            f"noise.{_canonical_name(base, fmt, index, count, launcher)}"
            if launcher
            else f"noise.{_canonical_name(base, fmt, index, count, launcher)}.junk{index:02d}.tmp"
        ),
    ),
)


def apply_volume_confusion(
    case,
    scenario: VolumeConfusionScenario,
    *,
    add_distractors: bool = True,
) -> list[Path]:
    """把分卷改名为“部分混乱”形式，并放入几个同目录干扰文件。

    - 7z/zip SFX：`.exe` 只是启动器（不含数据），与数据卷保持同一 first-dot stem；
    - rar SFX：`part1.exe` 本身就是数据头卷，与其他分卷一样参与混淆；
    - 普通分卷：所有卷按卷号顺序命名。
    """
    archive_dir = case.archive_dir
    fmt = case.archive_format
    sfx = bool(case.sfx)
    parts = sorted(path for path in archive_dir.iterdir() if path.is_file())
    if not parts:
        raise RuntimeError(f"plan6 fixture has no volumes: {archive_dir}")

    if sfx and fmt != "rar":
        launcher = next(
            (path for path in parts if path.name.lower().endswith(".exe")),
            None,
        )
        if launcher is None:
            raise RuntimeError(f"SFX fixture is missing the launcher: {archive_dir}")
        data = sorted(path for path in parts if path is not launcher)
        numbered = [(launcher, 1, True), *[(path, index + 1, False) for index, path in enumerate(data)]]
    else:
        numbered = [(path, index + 1, False) for index, path in enumerate(parts)]

    names = [
        scenario.name_for(case.case_id, fmt, index, len(numbered), is_launcher)
        for _path, index, is_launcher in numbered
    ]
    if len(set(names)) != len(names):
        raise RuntimeError(f"plan6 scenario produced duplicate names: {names}")

    staged: list[Path] = []
    for slot, (path, _index, _is_launcher) in enumerate(numbered):
        tmp = path.with_name(f".__plan6_stage_{slot:03d}")
        path.rename(tmp)
        staged.append(tmp)
    renamed: list[Path] = []
    for tmp, name in zip(staged, names):
        target = archive_dir / name
        tmp.rename(target)
        renamed.append(target)

    case.entry_path = renamed[0]
    if add_distractors:
        (archive_dir / f"{case.case_id}.notes.txt").write_text(
            f"unrelated notes for {scenario.case_id}\n",
            encoding="utf-8",
        )
        (archive_dir / f"unrelated_{scenario.case_id}.bin").write_bytes(
            b"\x00unrelated\xff" * 64
        )
    return renamed


def assert_plan6_success(
    case,
    scenario: VolumeConfusionScenario,
    *,
    volume_count: int,
    expected_container: str | None = None,
    passwords: list[str] | None = None,
    error_info: dict[str, Any] | None = None,
) -> None:
    """第 6 条主断言：卷号标识完整的前提下，加密分卷被识别并完整解压。"""
    if error_info is not None:
        error_info["scenario"] = scenario.case_id
        error_info["scenario_description"] = scenario.description
        error_info["volume_count"] = volume_count
        error_info["renamed_volumes"] = sorted(
            path.name
            for path in case.archive_dir.iterdir()
            if path.is_file()
            and not path.name.startswith(f"{case.case_id}.notes")
            and not path.name.startswith(f"unrelated_{scenario.case_id}")
        )

    effective = passwords if passwords is not None else encrypted_password_list(case.password)
    assert_plan2_success(
        case,
        f".{case.archive_format}",
        expected_container=expected_container,
        expected_member_count=volume_count,
        passwords=effective,
        error_info=error_info,
    )


__all__ = [
    "VolumeConfusionScenario",
    "SCENARIOS",
    "apply_volume_confusion",
    "assert_plan6_success",
]
