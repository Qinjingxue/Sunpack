from __future__ import annotations

import pytest

from sunpack.pipeline.coordinator.task_provider import ArchiveTaskProvider
from sunpack.pipeline.discovery.detection.input_planning import ArchiveInputPlanningStage
from sunpack.core.support.archive_knowledge_projection import source_extractable_segments
from tests.helpers.real_archives import create_encrypted_rar_archive
from tests.helpers.tool_config import get_optional_rar
from tests.real.plan1_real_archives.plan1_support import plan1_config
from tests.real.plan5_embedded_archives.plan5_support import PASSWORD


def test_plan5_planner_plans_header_encrypted_rar4_embedded_segment(tmp_path, plan5_error):
    """RAR4 头加密（-hp）的嵌入段必须进入嵌入规划，而不是被当作截断段丢弃。

    回归：probe_rar4 曾把主头之后的加密文件头读成越界块，整段被归类为
    probably_truncated（end=None）而在 _extractable_segments 被丢弃，
    导致 plan5_mixed 的 rar4-header 段从不进入解压管线。
    """
    if get_optional_rar() is None:
        pytest.skip("Rar.exe is required for the rar4-header fixture")

    sources = tmp_path / "sources"
    case = create_encrypted_rar_archive(
        sources,
        "p5_rar4-header",
        password=PASSWORD,
        rar4=True,
        header_encrypt=True,
        payload_size=8 * 1024,
    )

    carrier_dir = tmp_path / "carrier"
    carrier_dir.mkdir(parents=True, exist_ok=True)
    prefix = b"PLAN5-CARRIER-PREFIX-"
    suffix = b"-PLAN5-CARRIER-SUFFIX"
    carrier = carrier_dir / "carrier.bin"
    carrier.write_bytes(prefix + case.entry_path.read_bytes() + suffix)

    config = plan1_config(passwords=[PASSWORD])
    provider = ArchiveTaskProvider(config)
    tasks = provider.scan_targets([str(carrier_dir)])
    assert len(tasks) == 1, f"expected one scan task, got {tasks}"

    planned = ArchiveInputPlanningStage(config).plan_task_to_tasks(tasks[0])
    assert len(planned) == 1
    segments = source_extractable_segments(planned[0])
    assert segments, "no embedded segments were planned"

    rar_segments = [segment for segment in segments if segment["format"] == "rar"]
    assert len(rar_segments) == 1, rar_segments

    segment = rar_segments[0]
    assert segment["start_offset"] == len(prefix), segment
    assert segment["end_offset"] is not None and segment["end_offset"] > segment["start_offset"], (
        "rar4-header segment must have an exact decrypted end offset "
        "(regression: encrypted boundaries must never fall back to guessed ranges)"
    )

    if plan5_error is not None:
        plan5_error["case_id"] = "plan5_rar4_header_planning"
        plan5_error["planned_segments"] = [
            {
                "segment_id": segment.get("segment_id"),
                "format": segment.get("format"),
                "start_offset": segment.get("start_offset"),
                "end_offset": segment.get("end_offset"),
            }
            for segment in segments
        ]
