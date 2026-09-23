import io
import zipfile

from sunpack.core.contracts.discovery import DiscoveryCandidate
from sunpack.pipeline.coordinator.task_provider import ArchiveTaskProvider
from sunpack.pipeline.discovery.detection.scheduler import DetectionScheduler
from sunpack.pipeline.discovery.embedded.discovery import select_single_candidate_ratio


def _zip_bytes() -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_STORED) as archive:
        archive.writestr("inside.txt", "hello")
    return output.getvalue()


def _candidate(path, size: int, *, format_hint: str = "", route: str = "residual", relation_anchor=None):
    value = str(path)
    return DiscoveryCandidate(
        entry_path=value,
        member_paths=(value,),
        logical_name=path.name,
        carrier_path=value,
        cleanup_paths=(value,),
        route=route,
        format_hint=format_hint,
        size=size,
        relation_anchor=dict(relation_anchor or {}),
    )


def test_disguised_zip_is_resolved_by_relations(tmp_path):
    path = tmp_path / "movie.dat"
    path.write_bytes(_zip_bytes())
    result = ArchiveTaskProvider({"detection": {"enabled": True}}).discover_targets([str(path)])
    assert len(result.resolved_inputs) == 1
    assert result.resolved_inputs[0].source == "relations"


def test_embedded_carrier_with_prefix_and_suffix_is_discovered(tmp_path):
    path = tmp_path / "carrier.bin"
    path.write_bytes(b"prefix" + _zip_bytes() + b"suffix")
    result = ArchiveTaskProvider({"embedded_scan": {"enabled": True}}).discover_targets([str(path)])
    assert len(result.resolved_inputs) == 1
    assert result.resolved_inputs[0].source == "embedded"
    assert result.resolved_inputs[0].archive_input.open_mode == "file_range"


def test_embedded_switch_prevents_carrier_scan(tmp_path):
    path = tmp_path / "carrier.bin"
    path.write_bytes(b"prefix" + _zip_bytes() + b"suffix")
    result = ArchiveTaskProvider({"embedded_scan": {"enabled": False}}).discover_targets([str(path)])
    assert result.resolved_inputs == []


def test_detection_does_not_accept_relation_metadata(tmp_path):
    path = tmp_path / "fake.zip"
    path.write_bytes(b"plain text")
    candidate = _candidate(
        path,
        path.stat().st_size,
        format_hint="zip",
        route="detection",
        relation_anchor={"format": "zip", "relation_confirmed": True},
    )

    accepted, _ = DetectionScheduler({}).confirm(candidate)

    assert accepted is False


def test_recursive_embedded_ratio_uses_individual_candidate_share(tmp_path):
    paths = [tmp_path / name for name in ("large", "medium", "small")]
    candidates = [
        _candidate(path, size)
        for path, size in zip(paths, (70, 25, 5))
    ]

    assert select_single_candidate_ratio(candidates, 0.3) == [candidates[0]]
    assert select_single_candidate_ratio(candidates, 0.05) == candidates
    assert select_single_candidate_ratio(candidates, 0) == []
