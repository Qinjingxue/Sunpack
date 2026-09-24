import gzip

from sunpack.core.analysis.embedded.result import EmbeddedCandidate, EmbeddedScanResult
from sunpack.core.contracts.archive_input import ArchiveInputDescriptor
from sunpack.core.contracts.discovery import DiscoveryCandidate
from sunpack.pipeline.discovery.embedded.discovery import EmbeddedDiscovery
from sunpack.pipeline.discovery.embedded.options import EmbeddedOptions


def _candidate(path):
    value = str(path)
    return DiscoveryCandidate(
        archive_input=ArchiveInputDescriptor.from_parts(archive_path=value, logical_name=path.name),
        carrier_path=value,
        cleanup_paths=(value,),
        route="residual",
        size=path.stat().st_size,
    )


def test_embedded_layer_finds_disguised_stream_after_junk(tmp_path):
    path = tmp_path / "carrier.bin"
    path.write_bytes(b"leading junk" + gzip.compress(b"payload") + b"trailing junk")
    result = EmbeddedDiscovery({}).discover([_candidate(path)])

    assert len(result.resolved_tasks) == 1
    assert result.resolved_tasks[0].discovery_source == "embedded"
    assert result.resolved_tasks[0].archive_input().format_hint == "gzip"


def test_embedded_layer_rejects_plain_data(tmp_path):
    path = tmp_path / "plain.bin"
    path.write_bytes(b"not an archive")
    result = EmbeddedDiscovery({}).discover([_candidate(path)])

    assert result.resolved_tasks == []
    assert result.residual_paths


def test_recursive_gate_may_exclude_small_residual_candidate(tmp_path):
    large = tmp_path / "large.bin"
    small = tmp_path / "small.bin"
    large.write_bytes(b"x" * 100)
    small.write_bytes(b"x")

    result = EmbeddedDiscovery({
        "embedded_scan": {"recursive_candidate_ratio": 0.3},
    }).discover([_candidate(large), _candidate(small)], is_recursive_scan=True)

    assert result.resolved_tasks == []
    assert any(trace.entry_path == str(small) and trace.status == "residual" for trace in result.traces)


def test_default_embedded_scan_honors_runtime_bundle_guard(tmp_path, monkeypatch):
    path = tmp_path / "installer.exe"
    path.write_bytes(b"x" * 128)

    monkeypatch.setattr(
        "sunpack.pipeline.discovery.embedded.discovery.inspect_runtime_bundle",
        lambda _path, _size: "nsis",
    )
    monkeypatch.setattr(
        "sunpack.pipeline.discovery.embedded.discovery.scan_embedded_archives",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("runtime bundle guard must reject before full embedded scan")
        ),
    )

    result = EmbeddedDiscovery({}).discover([_candidate(path)])

    assert result.resolved_tasks == []
    assert result.residual_paths


def test_force_scan_bypasses_all_runtime_bundle_guards(tmp_path, monkeypatch):
    path = tmp_path / "installer.exe"
    path.write_bytes(b"x" * 128)
    scan = EmbeddedScanResult(
        complete=True,
        candidates=(
            EmbeddedCandidate(
                format="7z",
                offset=32,
                end_offset=128,
                confidence=1.0,
                validation="start_header_crc",
                candidate_kind="logical_archive",
                boundary_kind="exact",
                range_end_offset=128,
                extractable=True,
                contained_anchor_count=1,
            ),
        ),
        hits=(),
        read_bytes=128,
        file_size=128,
        logical_resolution_complete=True,
        raw_hit_count=1,
        budget_exhausted=False,
    )

    monkeypatch.setattr(
        "sunpack.pipeline.discovery.embedded.discovery.inspect_runtime_bundle",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("deep scan must bypass every runtime/installer guard")
        ),
    )
    monkeypatch.setattr(
        "sunpack.pipeline.discovery.embedded.discovery.scan_embedded_archives",
        lambda *_args, **_kwargs: scan,
    )

    result = EmbeddedDiscovery({}, EmbeddedOptions(force_scan=True)).discover([_candidate(path)])

    assert len(result.resolved_tasks) == 1
    assert result.resolved_tasks[0].discovery_source == "embedded"
    assert result.resolved_tasks[0].archive_input().format_hint == "7z"


def test_embedded_discovery_uses_current_identity_size_not_stale_candidate_size(tmp_path, monkeypatch):
    path = tmp_path / "growing.gz"
    path.write_bytes(b"x" * 48)
    candidate = _candidate(path)
    candidate = DiscoveryCandidate(
        archive_input=candidate.archive_input,
        carrier_path=candidate.carrier_path,
        cleanup_paths=candidate.cleanup_paths,
        route=candidate.route,
        size=32,
    )
    observed = {}

    def fake_scan(scan_path, *, expected_size=0, identity=None):
        observed["path"] = scan_path
        observed["expected_size"] = expected_size
        observed["identity"] = identity
        return EmbeddedScanResult(
            complete=True,
            candidates=(),
            hits=(),
            read_bytes=48,
            file_size=48,
            logical_resolution_complete=True,
            raw_hit_count=0,
            budget_exhausted=False,
        )

    monkeypatch.setattr(
        "sunpack.pipeline.discovery.embedded.discovery.file_identity",
        lambda scan_path: (str(scan_path), 48, 123),
    )
    monkeypatch.setattr(
        "sunpack.pipeline.discovery.embedded.discovery.inspect_runtime_bundle",
        lambda _path, _size: None,
    )
    monkeypatch.setattr(
        "sunpack.pipeline.discovery.embedded.discovery.scan_embedded_archives",
        fake_scan,
    )

    EmbeddedDiscovery({}).discover([candidate])

    assert observed["expected_size"] == 48
    assert observed["identity"] == (str(path), 48, 123)


def test_embedded_rar_header_encryption_reaches_canonical_input(tmp_path, monkeypatch):
    path = tmp_path / "carrier.bin"
    path.write_bytes(b"x" * 128)
    scan = EmbeddedScanResult(
        complete=True,
        candidates=(
            EmbeddedCandidate(
                format="rar",
                offset=16,
                end_offset=None,
                confidence=1.0,
                validation="rar5_encryption_header_crc",
                candidate_kind="logical_archive",
                boundary_kind="bounded",
                range_end_offset=128,
                extractable=True,
                contained_anchor_count=1,
            ),
        ),
        hits=(),
        read_bytes=128,
        file_size=128,
        logical_resolution_complete=True,
        raw_hit_count=1,
        budget_exhausted=False,
    )
    monkeypatch.setattr(
        "sunpack.pipeline.discovery.embedded.discovery.inspect_runtime_bundle",
        lambda _path, _size: None,
    )
    monkeypatch.setattr(
        "sunpack.pipeline.discovery.embedded.discovery.scan_embedded_archives",
        lambda *_args, **_kwargs: scan,
    )

    result = EmbeddedDiscovery({}).discover([_candidate(path)])

    assert len(result.resolved_tasks) == 1
    descriptor = result.resolved_tasks[0].archive_input()
    assert descriptor.open_mode == "file_range"
    assert descriptor.analysis["password_required"] is True
