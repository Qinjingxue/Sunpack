import zipfile
from io import BytesIO

from sunpack.core.analysis.embedded import scan_embedded_archives
from sunpack.core.support.archive_knowledge_writer import commit_task_knowledge, ensure_knowledge, write_payload
from sunpack.core.analysis.result import ArchiveAnalysisReport, ArchiveFormatEvidence, ArchiveSegment
from sunpack.core.contracts.archive_input import ArchiveInputDescriptor
from sunpack.pipeline.discovery.detection.input_planning import ArchiveInputPlanningStage
from sunpack.core.support import archive_knowledge_projection as knowledge_view
from tests.helpers.archive_tasks import make_archive_task, make_task_from_descriptor


class _FakeAnalyzer:
    def __init__(self, report):
        self.report = report
        self.calls = 0

    def analyze(self, source, request):
        self.calls += 1
        return self.report


def _task(path, *, parts=None, volumes=None, logical_name="case"):
    if parts and len(parts) > 1:
        return make_task_from_descriptor(ArchiveInputDescriptor.from_split_volumes(
            archive_path=str(path), volumes=volumes, logical_name=logical_name, format_hint="",
        ))
    return make_archive_task(path, logical_name=logical_name)


def _report(path, evidence, *, prepass=None):
    return _multi_report(path, [evidence], prepass=prepass, size=100, read_bytes=32)


def _multi_report(path, evidences, *, prepass=None, size=200, read_bytes=64):
    """Build a report carrying the native plan that input planning projects.

    Segment policy is decided and tested in Rust; these fixtures state the
    plan directly so the tests cover only the Python descriptor projection.
    """
    evidences = list(evidences)
    carved = tuple(
        (evidence, segment)
        for evidence in evidences
        for segment in evidence.segments
        if segment.end_offset is not None and segment.start_offset > 0
    )
    password = next(
        (
            (evidence, segment)
            for evidence in evidences
            if evidence.details.get("password_required")
            for segment in evidence.segments
            if segment.start_offset > 0
        ),
        None,
    )
    return ArchiveAnalysisReport(
        path=str(path),
        size=size,
        evidences=evidences,
        selected=evidences,
        prepass=prepass or {"formats": [evidence.format for evidence in evidences]},
        read_bytes=read_bytes,
        cache_hits=1,
        best_selected=max(evidences, key=lambda item: item.confidence) if evidences else None,
        extractable_segments=carved,
        password_segment=password,
    )


def test_input_planning_stage_writes_extractable_segment_without_switching_task_source(tmp_path):
    archive = tmp_path / "carrier.bin"
    archive.write_bytes(b"junk" + b"PK\x03\x04" + b"x" * 32 + b"tail")
    evidence = ArchiveFormatEvidence(
        format="zip",
        confidence=0.99,
        status="extractable",
        segments=[ArchiveSegment(start_offset=4, end_offset=40, confidence=0.99)],
    )
    task = _task(archive)
    stage = ArchiveInputPlanningStage({"input_planning": {"enabled": False}})
    stage.enabled = True
    stage.analyzer = _FakeAnalyzer(_report(archive, evidence))

    stage.plan_task(task)

    assert task.archive_input().format_hint == "zip"
    assert knowledge_view.source_selected_segment(task)["segment"]["start_offset"] == 4
    segments = knowledge_view.source_extractable_segments(task)
    assert len(segments) == 1
    assert segments[0]["archive_input"] == {
        "kind": "archive_input",
        "entry_path": str(archive),
        "open_mode": "file_range",
        "format_hint": "zip",
        "logical_name": "case",
        "parts": [{"path": str(archive), "role": "main", "start": 4, "end": 40}],
        "analysis": {"status": "extractable", "confidence": 0.99, "damage_flags": []},
    }
    assert task.archive_input().open_mode == "file"
    assert task.archive_input().format_hint == "zip"
    assert task.archive_input().open_mode == "file"
    assert task.archive_input().format_hint == "zip"


def test_input_planning_stage_keeps_sfx_segment_for_standard_archive_extension(tmp_path):
    archive = tmp_path / "carrier.zip"
    archive.write_bytes(b"MZ-stub" + b"PK\x03\x04" + b"x" * 64)
    evidence = ArchiveFormatEvidence(
        format="zip",
        confidence=0.99,
        status="extractable",
        segments=[
            ArchiveSegment(
                start_offset=7,
                end_offset=75,
                confidence=0.99,
                damage_flags=["carrier_prefix"],
                evidence=["zip:eocd", "fuzzy:carrier_prefix"],
            )
        ],
    )
    task = _task(archive)
    stage = ArchiveInputPlanningStage({"input_planning": {"enabled": False}})
    stage.enabled = True
    stage.analyzer = _FakeAnalyzer(_report(archive, evidence))

    stage.plan_task(task)

    segments = knowledge_view.source_extractable_segments(task)
    assert len(segments) == 1
    assert segments[0]["archive_input"]["open_mode"] == "file_range"
    assert segments[0]["archive_input"]["parts"][0]["path"] == str(archive)
    assert segments[0]["archive_input"]["parts"][0]["start"] == 7
    assert task.archive_input().open_mode == "file"


def test_input_planning_stage_keeps_embedded_scan_ranges_for_neutral_carrier(tmp_path):
    carrier = tmp_path / "carrier.bin"
    carrier.write_bytes(b"carrier-data" + b"PK\x03\x04" + b"x" * 64)
    evidence = ArchiveFormatEvidence(
        format="zip",
        confidence=0.94,
        status="extractable",
        segments=[ArchiveSegment(start_offset=12, end_offset=80, confidence=0.94)],
        details={
            "source": "embedded_scan",
            "validation": "local_header_and_data_range",
            "candidate_kind": "logical_archive",
        },
    )
    report = _report(carrier, evidence, prepass={"source": "embedded_scan", "formats": ["zip"]})
    task = _task(carrier)
    stage = ArchiveInputPlanningStage({"input_planning": {"enabled": False}})
    stage.enabled = True
    stage.analyzer = _FakeAnalyzer(report)

    stage.plan_task(task)

    assert len(knowledge_view.source_extractable_segments(task)) == 1


def test_input_planning_stage_records_multiple_segments_on_original_task(tmp_path):
    carrier = tmp_path / "carrier.bin"
    carrier.write_bytes(b"junk" + b"Rar!\x1a\x07\x01\x00" + b"x" * 20 + b"pad" + b"7z\xbc\xaf\x27\x1c" + b"y" * 20)
    rar = ArchiveFormatEvidence(
        format="rar",
        confidence=0.97,
        status="extractable",
        segments=[ArchiveSegment(start_offset=4, end_offset=32, confidence=0.97)],
    )
    seven = ArchiveFormatEvidence(
        format="7z",
        confidence=0.96,
        status="extractable",
        segments=[ArchiveSegment(start_offset=35, end_offset=61, confidence=0.96)],
    )
    task = _task(carrier)
    stage = ArchiveInputPlanningStage({"input_planning": {"enabled": False}})
    stage.enabled = True
    stage.analyzer = _FakeAnalyzer(_multi_report(carrier, [rar, seven]))

    tasks = stage.plan_tasks([task])

    assert tasks == [task]
    assert task.archive_input().format_hint == "rar"
    segments = knowledge_view.source_extractable_segments(task)
    assert [item["logical_name"] for item in segments] == ["case", "case"]
    assert [item["segment_id"] for item in segments] == ["embedded_01", "embedded_02"]
    assert segments[0]["archive_input"] == {
        "kind": "archive_input",
        "entry_path": str(carrier),
        "open_mode": "file_range",
        "format_hint": "rar",
        "logical_name": "case",
        "parts": [{"path": str(carrier), "role": "main", "start": 4, "end": 32}],
        "analysis": {"status": "extractable", "confidence": 0.97, "damage_flags": []},
    }
    assert segments[1]["archive_input"]["format_hint"] == "7z"
    assert segments[1]["archive_input"]["parts"][0]["start"] == 35


def test_input_planning_stage_reuses_batch_report_for_equivalent_inputs(tmp_path):
    archive = tmp_path / "same.zip"
    archive.write_bytes(b"zip")
    evidence = ArchiveFormatEvidence(
        format="zip",
        confidence=0.99,
        status="extractable",
        segments=[ArchiveSegment(start_offset=0, end_offset=3, confidence=0.99)],
    )
    first = _task(archive)
    second = _task(archive, logical_name="case_copy")
    stage = ArchiveInputPlanningStage({"input_planning": {"enabled": False, "task_parallel": False}})
    stage.enabled = True
    stage.analyzer = _FakeAnalyzer(_report(archive, evidence))

    tasks = stage.plan_tasks([first, second])

    assert tasks == [first, second]
    assert stage.analyzer.calls == 1
    assert first.archive_input().format_hint == "zip"
    assert second.archive_input().format_hint == "zip"
    assert knowledge_view.get(second, "input_planning.cache_hits") == 2


def test_input_planning_stage_uses_range_input_for_embedded_password_required_archive(tmp_path):
    carrier = tmp_path / "payload.exe"
    carrier.write_bytes(b"MZ" + b"x" * 198)
    evidence = ArchiveFormatEvidence(
        format="rar",
        confidence=0.72,
        status="damaged",
        segments=[
            ArchiveSegment(
                start_offset=64,
                end_offset=None,
                confidence=0.72,
                damage_flags=["valid_encrypted_but_unwalkable"],
            )
        ],
        details={"password_required": True, "header_encrypted": True},
    )
    task = _task(carrier)
    stage = ArchiveInputPlanningStage({"input_planning": {"enabled": False}})
    stage.enabled = True
    stage.analyzer = _FakeAnalyzer(_multi_report(carrier, [evidence]))

    stage.plan_task(task)

    assert task.archive_input().format_hint == "rar"
    segments = knowledge_view.source_extractable_segments(task)
    assert segments == []  # unresolved boundaries are not extractable segments
    assert knowledge_view.source_password_probe_input(task) == {
        "kind": "archive_input",
        "entry_path": str(carrier),
        "open_mode": "file_range",
        "format_hint": "rar",
        "logical_name": "case",
        "parts": [{"path": str(carrier), "role": "main", "start": 64, "end": 200}],
        "analysis": {
            "status": "damaged",
            "confidence": 0.72,
            "damage_flags": ["valid_encrypted_but_unwalkable"],
            "password_required": True,
        },
    }


def test_input_planning_stage_projects_rar_sfx_volume_password_probe(tmp_path):
    first = tmp_path / "case.part1.exe"
    second = tmp_path / "case.part2.rar"
    first.write_bytes(b"MZ-stub" + b"Rar!\x1a\x07\x01\x00" + b"header")
    second.write_bytes(b"Rar!\x1a\x07\x01\x00volume-two")
    start = len(b"MZ-stub")
    evidence = ArchiveFormatEvidence(
        format="rar",
        confidence=0.97,
        status="damaged",
        segments=[ArchiveSegment(start_offset=start, end_offset=None, confidence=0.97)],
        details={"password_required": True, "header_encrypted": True},
    )
    task = _task(first, parts=[first, second], volumes=[
        {"path": str(first), "number": 1, "style": "rar_sfx_part", "prefix": "case", "role": "first", "width": 1},
        {"path": str(second), "number": 2, "style": "rar_sfx_part", "prefix": "case", "role": "member", "width": 1},
    ])
    stage = ArchiveInputPlanningStage({"input_planning": {"enabled": False}})
    stage.enabled = True
    stage.analyzer = _FakeAnalyzer(_multi_report(first, [evidence]))

    stage.plan_task(task)

    assert knowledge_view.source_extractable_segments(task) == []
    probe = knowledge_view.source_password_probe_input(task)
    assert probe["open_mode"] == "file_range"
    assert probe["format_hint"] == "rar"
    assert probe["parts"] == [{
        "path": str(first),
        "role": "main",
        "start": start,
        "end": first.stat().st_size,
    }]
    assert task.archive_input().open_mode == "sfx_with_volumes"


def test_input_planning_preserves_structured_password_probe_for_split_segment_at_zero(tmp_path):
    first = tmp_path / "case.7z.001"
    second = tmp_path / "case.7z.002"
    first.write_bytes(b"7z-first")
    second.write_bytes(b"7z-second")
    evidence = ArchiveFormatEvidence(
        format="7z",
        confidence=0.99,
        status="extractable",
        segments=[ArchiveSegment(start_offset=0, end_offset=None, confidence=0.99)],
        details={"password_required": True},
    )
    task = _task(first)
    descriptor = ArchiveInputDescriptor.from_split_volumes(
        archive_path=str(first),
        volumes=[
            {"path": str(first), "number": 1, "style": "numeric_suffix", "prefix": "case.7z", "role": "first", "width": 3},
            {"path": str(second), "number": 2, "style": "numeric_suffix", "prefix": "case.7z", "role": "member", "width": 3},
        ],
        format_hint="7z",
        logical_name="case",
    )
    task.set_archive_input(descriptor)
    stage = ArchiveInputPlanningStage({"input_planning": {"enabled": False}})
    stage.enabled = True
    stage.analyzer = _FakeAnalyzer(_multi_report(first, [evidence]))

    stage.plan_task(task)

    probe = knowledge_view.source_password_probe_input(task)
    assert probe["open_mode"] == "native_volumes"
    assert [part["path"] for part in probe["parts"]] == [str(first), str(second)]


def test_input_planning_stage_maps_split_logical_segment_to_concat_ranges(tmp_path):
    part1 = tmp_path / "case.7z.001"
    part2 = tmp_path / "case.7z.002"
    part3 = tmp_path / "case.7z.003"
    part1.write_bytes(b"a" * 10)
    part2.write_bytes(b"b" * 10)
    part3.write_bytes(b"c" * 10)
    volumes = [
        {"path": str(part2), "number": 2, "style": "numeric_suffix", "prefix": "case.7z", "role": "member", "width": 3},
        {"path": str(part1), "number": 1, "style": "numeric_suffix", "prefix": "case.7z", "role": "first", "width": 3},
        {"path": str(part3), "number": 3, "style": "numeric_suffix", "prefix": "case.7z", "role": "member", "width": 3},
    ]
    evidence = ArchiveFormatEvidence(
        format="7z",
        confidence=0.97,
        status="extractable",
        segments=[ArchiveSegment(start_offset=8, end_offset=24, confidence=0.97)],
    )
    task = _task(part1, parts=[part1, part2, part3], volumes=volumes)
    stage = ArchiveInputPlanningStage({"input_planning": {"enabled": False}})
    stage.enabled = True
    stage.analyzer = _FakeAnalyzer(_report(part1, evidence))

    stage.plan_task(task)

    segments = knowledge_view.source_extractable_segments(task)
    assert len(segments) == 1
    assert segments[0]["archive_input"] == {
        "kind": "archive_input",
        "entry_path": str(part1),
        "open_mode": "concat_ranges",
        "format_hint": "7z",
        "logical_name": "case",
        "ranges": [
            {"path": str(part1), "start": 8, "end": 10},
            {"path": str(part2), "start": 0, "end": 10},
            {"path": str(part3), "start": 0, "end": 4},
        ],
        "analysis": {"status": "extractable", "confidence": 0.97, "damage_flags": []},
    }
    assert task.archive_input().open_mode == "native_volumes"


def test_input_planning_stage_plans_real_carrier_segments_in_offset_order(tmp_path):
    first = BytesIO()
    with zipfile.ZipFile(first, "w") as archive:
        archive.writestr("first.txt", "first")
    second = BytesIO()
    with zipfile.ZipFile(second, "w") as archive:
        archive.writestr("second.txt", "second")
    carrier = tmp_path / "carrier.jpg"
    first_start = 37
    second_start = first_start + len(first.getvalue()) + 11
    carrier.write_bytes(b"\xff\xd8" + b"j" * 35 + first.getvalue() + b"g" * 11 + second.getvalue() + b"tail")
    task = _task(carrier)
    knowledge = ensure_knowledge(task)
    write_payload(
        knowledge,
        "inspection",
        {"prepass": scan_embedded_archives(str(carrier)).to_prepass()},
        source_layer="tests",
        source_module="input_planning",
    )
    commit_task_knowledge(task, knowledge)
    stage = ArchiveInputPlanningStage({})

    stage.plan_task(task)

    segments = knowledge_view.source_extractable_segments(task)
    assert [(item["format"], item["start_offset"]) for item in segments] == [
        ("zip", first_start),
        ("zip", second_start),
    ]
    assert task.archive_input().open_mode == "file"
