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


def test_default_embedded_scan_skips_exe_before_any_file_probe(tmp_path, monkeypatch):
    path = tmp_path / "application.EXE"
    path.write_bytes(b"x" * 128)

    monkeypatch.setattr(
        "sunpack.pipeline.discovery.embedded.discovery.file_identity",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("default embedded EXE gate must run before file probing")
        ),
    )
    monkeypatch.setattr(
        "sunpack.pipeline.discovery.embedded.discovery.scan_embedded_archives",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("default embedded EXE gate must reject before full scan")
        ),
    )

    result = EmbeddedDiscovery({}).discover([_candidate(path)])

    assert result.resolved_tasks == []
    assert result.residual_paths
    assert any(
        trace.reason == "embedded_executable_skipped" and trace.status == "residual"
        for trace in result.traces
    )


def test_force_scan_bypasses_exe_suffix_gate(tmp_path, monkeypatch):
    path = tmp_path / "application.exe"
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
                extractable=True,
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
                boundary_kind="unresolved",
                extractable=False,
            ),
        ),
        hits=(),
        read_bytes=128,
        file_size=128,
        logical_resolution_complete=False,
        raw_hit_count=1,
        budget_exhausted=False,
    )
    monkeypatch.setattr(
        "sunpack.pipeline.discovery.embedded.discovery.scan_embedded_archives",
        lambda *_args, **_kwargs: scan,
    )
    monkeypatch.setattr(
        "sunpack.pipeline.discovery.embedded.discovery.resolve_encrypted_rar_boundaries",
        lambda _path, _offsets, _passwords: {
            "status": "ok",
            "failed_offset": None,
            "resolved": [{"offset": 16, "end_offset": 128, "password": "secret"}],
        },
    )

    result = EmbeddedDiscovery({"user_passwords": ["secret"]}).discover([_candidate(path)])

    assert len(result.resolved_tasks) == 1
    descriptor = result.resolved_tasks[0].archive_input()
    assert descriptor.open_mode == "file_range"
    assert descriptor.primary_extent.end == 128
    assert descriptor.analysis["password_required"] is True
    assert result.resolved_tasks[0].runtime["embedded_segment_passwords"]["16"] == "secret"


def test_truncated_embedded_7z_is_reported_as_blocked_damage(tmp_path, monkeypatch):
    path = tmp_path / "carrier.bin"
    path.write_bytes(b"x" * 128)
    scan = EmbeddedScanResult(
        complete=True,
        candidates=(
            EmbeddedCandidate(
                format="7z",
                offset=16,
                end_offset=None,
                confidence=0.90,
                validation="start_header_crc_truncated_declared_range",
                candidate_kind="logical_archive",
                boundary_kind="unresolved",
                extractable=False,
            ),
        ),
        hits=(),
        read_bytes=128,
        file_size=128,
        logical_resolution_complete=False,
        raw_hit_count=1,
        budget_exhausted=False,
    )
    monkeypatch.setattr(
        "sunpack.pipeline.discovery.embedded.discovery.scan_embedded_archives",
        lambda *_args, **_kwargs: scan,
    )

    result = EmbeddedDiscovery({}).discover([_candidate(path)])

    assert result.resolved_tasks == []
    assert result.blocked_paths
    assert any(
        trace.reason == "embedded_truncated" and trace.status == "blocked"
        for trace in result.traces
    )
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.format == "7z"
    assert finding.offset == 16
    assert finding.status == "blocked"
    assert finding.reason == "embedded_truncated"
    assert finding.extractable is False


def test_truncated_7z_split_candidate_stays_residual_for_relations(tmp_path, monkeypatch):
    path = tmp_path / "archive.7z.001"
    path.write_bytes(b"x" * 128)
    scan = EmbeddedScanResult(
        complete=True,
        candidates=(
            EmbeddedCandidate(
                format="7z",
                offset=0,
                end_offset=None,
                confidence=0.90,
                validation="start_header_crc_truncated_declared_range",
                candidate_kind="logical_archive",
                boundary_kind="unresolved",
                extractable=False,
            ),
        ),
        hits=(),
        read_bytes=128,
        file_size=128,
        logical_resolution_complete=False,
        raw_hit_count=1,
        budget_exhausted=False,
    )
    monkeypatch.setattr(
        "sunpack.pipeline.discovery.embedded.discovery.scan_embedded_archives",
        lambda *_args, **_kwargs: scan,
    )
    base = _candidate(path)
    split = DiscoveryCandidate(
        archive_input=base.archive_input,
        carrier_path=base.carrier_path,
        cleanup_paths=base.cleanup_paths,
        route=base.route,
        size=base.size,
        is_split=True,
        relation_anchor={"format": "7z", "multivolume": True},
    )

    result = EmbeddedDiscovery({}).discover([split])

    assert result.resolved_tasks == []
    assert not result.blocked_paths
    assert result.residual_paths
    assert any(
        trace.reason == "no_complete_embedded_archive" and trace.status == "residual"
        for trace in result.traces
    )


def test_embedded_rar_wrong_password_blocks_whole_carrier(tmp_path, monkeypatch):
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
                boundary_kind="unresolved",
                extractable=False,
            ),
        ),
        hits=(),
        read_bytes=128,
        file_size=128,
        logical_resolution_complete=False,
        raw_hit_count=1,
        budget_exhausted=False,
    )
    monkeypatch.setattr(
        "sunpack.pipeline.discovery.embedded.discovery.scan_embedded_archives",
        lambda *_args, **_kwargs: scan,
    )
    monkeypatch.setattr(
        "sunpack.pipeline.discovery.embedded.discovery.resolve_encrypted_rar_boundaries",
        lambda _path, _offsets, _passwords: {
            "status": "wrong_password",
            "failed_offset": 16,
            "resolved": [],
        },
    )

    result = EmbeddedDiscovery({"user_passwords": ["wrong"]}).discover([_candidate(path)])

    assert result.resolved_tasks == []
    assert result.blocked_paths
    assert any(
        trace.reason == "embedded_wrong_password" and trace.status == "blocked"
        for trace in result.traces
    )
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.format == "rar"
    assert finding.offset == 16
    assert finding.end_offset is None
    assert finding.status == "blocked"
    assert finding.reason == "embedded_wrong_password"
    assert finding.extractable is False



def test_password_blocked_carrier_preserves_every_archive_finding(tmp_path, monkeypatch):
    path = tmp_path / "carrier.bin"
    path.write_bytes(b"x" * 160)
    scan = EmbeddedScanResult(
        complete=True,
        candidates=(
            EmbeddedCandidate(
                format="zip",
                offset=8,
                end_offset=32,
                confidence=1.0,
                validation="eocd_geometry_and_first_local_link",
                candidate_kind="logical_archive",
                boundary_kind="exact",
                extractable=True,
            ),
            EmbeddedCandidate(
                format="rar",
                offset=40,
                end_offset=None,
                confidence=1.0,
                validation="rar5_encryption_header_crc",
                candidate_kind="logical_archive",
                boundary_kind="unresolved",
                extractable=False,
            ),
            EmbeddedCandidate(
                format="7z",
                offset=96,
                end_offset=144,
                confidence=1.0,
                validation="start_header_crc_and_declared_end",
                candidate_kind="logical_archive",
                boundary_kind="exact",
                extractable=True,
            ),
        ),
        hits=(),
        read_bytes=160,
        file_size=160,
        logical_resolution_complete=False,
        raw_hit_count=3,
        budget_exhausted=False,
    )
    monkeypatch.setattr(
        "sunpack.pipeline.discovery.embedded.discovery.scan_embedded_archives",
        lambda *_args, **_kwargs: scan,
    )
    monkeypatch.setattr(
        "sunpack.pipeline.discovery.embedded.discovery.resolve_encrypted_rar_boundaries",
        lambda _path, _offsets, _passwords: {
            "status": "password_required",
            "failed_offset": 40,
            "resolved": [],
        },
    )

    result = EmbeddedDiscovery({}).discover([_candidate(path)])

    assert result.resolved_tasks == []
    assert result.blocked_paths
    assert [finding.format for finding in result.findings] == ["zip", "rar", "7z"]
    assert [finding.offset for finding in result.findings] == [8, 40, 96]
    assert [finding.end_offset for finding in result.findings] == [32, None, 144]
    assert [finding.reason for finding in result.findings] == [
        "embedded_carrier_blocked",
        "embedded_password_required",
        "embedded_carrier_blocked",
    ]
    assert all(finding.status == "blocked" for finding in result.findings)
    assert all(not finding.extractable for finding in result.findings)
