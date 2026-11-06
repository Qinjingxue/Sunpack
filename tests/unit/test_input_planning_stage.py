import zipfile
from dataclasses import replace
from io import BytesIO

from sunpack.core.analysis.embedded import scan_embedded_archives
from sunpack.core.support.archive_knowledge_writer import commit_task_knowledge, ensure_knowledge, write_payload
from sunpack.core.analysis.result import ArchiveAnalysisReport, ArchiveFormatEvidence, ArchiveSegment
from sunpack.core.contracts.archive_input import ArchiveInputDescriptor, ArchiveInputPart, InputExtent
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


def test_input_planning_stage_reuses_report_for_equivalent_inputs(tmp_path):
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

    tasks = [*stage.plan_task_to_tasks(first), *stage.plan_task_to_tasks(second)]

    assert tasks == [first, second]
    assert stage.analyzer.calls == 1
    assert first.archive_input().format_hint == "zip"
    assert second.archive_input().format_hint == "zip"
    assert knowledge_view.get(second, "input_planning.cache_hits") == 2


def test_planning_cache_isolates_physical_layouts_and_invalidates_changed_sources(tmp_path, monkeypatch):
    # Equivalent-input reuse does not catch collisions between carrier ranges,
    # volume extents or descriptors without parts. One case checks all layouts
    # and a changed peer without archive payload scans or timing assertions.
    first, second = (str(tmp_path / name) for name in ("first", "second"))
    (tmp_path / "first").write_bytes(b"a" * 32)
    (tmp_path / "second").write_bytes(b"b" * 32)
    plain = ArchiveInputDescriptor(first, format_hint="zip")
    bounded = replace(plain, open_mode="file_range", parts=[ArchiveInputPart(InputExtent(first, 1, 10))])
    concat = replace(plain, open_mode="concat_ranges", extents=[InputExtent(first, 1, 10), InputExtent(second, 2, 11)])
    volumes = ArchiveInputDescriptor(first, open_mode="native_volumes", format_hint="rar", volume_style="rar_part", parts=[
        ArchiveInputPart(InputExtent(first, 1, 10), volume_number=1, canonical_name="case.part1.rar"),
        ArchiveInputPart(InputExtent(second, 2, 11), volume_number=2, canonical_name="case.part2.rar"),
    ])
    descriptors = [
        plain, replace(plain, entry_path=second), bounded,
        replace(bounded, parts=[ArchiveInputPart(InputExtent(first, 2, 10))]),
        concat, replace(concat, extents=list(reversed(concat.extents))),
        replace(concat, extents=[InputExtent(first, 1, 11), concat.extents[1]]),
        volumes, replace(volumes, parts=[replace(volumes.parts[0], extent=InputExtent(first, 1, 11)), volumes.parts[1]]),
    ]
    stage = ArchiveInputPlanningStage({})
    analyzed = []

    def analyze(task):
        analyzed.append(task.archive_input())
        return _multi_report(first, [], size=32, read_bytes=len(analyzed))

    monkeypatch.setattr(stage, "_analyze_task", analyze)
    tasks = [make_task_from_descriptor(descriptor) for descriptor in descriptors]
    copies = [make_task_from_descriptor(replace(descriptor, logical_name="display only")) for descriptor in descriptors]
    for task in (*tasks, *copies):
        stage.plan_task_to_tasks(task)
    assert [knowledge_view.get(task, "input_planning.read_bytes") for task in tasks] == list(range(1, len(descriptors) + 1))
    assert [knowledge_view.get(task, "input_planning.read_bytes") for task in copies] == list(range(1, len(descriptors) + 1))
    assert len(analyzed) == len(descriptors)
    (tmp_path / "second").write_bytes(b"changed peer")
    stage.plan_task(copies[7])
    assert len(analyzed) == len(descriptors) + 1


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

    probe = task.password_probe_input.to_dict()
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

    segments = [node.projection() for node in task.inputs]
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

    segments = [node.projection() for node in task.inputs]
    assert [(item["format"], item["start_offset"]) for item in segments] == [
        ("zip", first_start),
        ("zip", second_start),
    ]
    assert task.archive_input().open_mode == "file"
