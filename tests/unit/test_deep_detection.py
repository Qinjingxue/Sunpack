import asyncio
import gzip
from types import SimpleNamespace

import pytest

from sunpack.core.analysis.embedded.result import EmbeddedCandidate, EmbeddedScanResult
from sunpack.core.contracts.archive_input import ArchiveInputDescriptor
from sunpack.core.contracts.discovery import DiscoveryCandidate
from sunpack.pipeline.discovery.embedded.discovery import EmbeddedDiscovery
from sunpack.pipeline.discovery.embedded.options import EmbeddedOptions
from tests.helpers.config_factory import make_config


@pytest.mark.parametrize("rule", [
    {"name": "blacklist", "enabled": True, "blocked_extensions": [".bin"]},
    {"name": "whitelist", "enabled": True, "allowed_extensions": [".zip"]},
    {"name": "size_range", "enabled": True, "gte": 1024},
    {"name": "mtime_range", "enabled": True, "lt": 1},
])
@pytest.mark.parametrize("recursive", [False, True])
def test_deep_discovery_disables_each_filesystem_filter(tmp_path, rule, recursive):
    from sunpack.core.contracts.run_state import RunState
    from sunpack.pipeline.coordinator.task_scan import ArchiveTaskScanner

    carrier = tmp_path / "carrier.bin"
    carrier.write_bytes(b"leading junk" + gzip.compress(b"payload") + b"trailing junk")
    config = make_config({"filesystem": {"scan_filters_enabled": True, "scan_filters": [rule]}})
    ordinary = ArchiveTaskScanner(config, RunState())
    deep = ArchiveTaskScanner(config, RunState(), EmbeddedOptions(force_scan=True))

    assert ordinary.discover_targets([str(tmp_path)], is_recursive_scan=recursive) == []
    [task] = deep.discover_targets([str(tmp_path)], is_recursive_scan=recursive)
    assert task.archive_input().format_hint == "gzip"
    assert config["filesystem"]["scan_filters_enabled"] is True


def test_one_engine_keeps_watch_and_cli_detection_modes_per_request(tmp_path, monkeypatch):
    import sunpack.pipeline.coordinator.engine as engine_module
    from sunpack.core.contracts.pipeline import PipelineArtifacts, PipelineResponse
    from sunpack.core.contracts.results import RunSummary

    class Services:
        def __init__(self, _config, _broker):
            self.output_reservations = SimpleNamespace(release=lambda _request_id: None)

        async def start(self):
            pass

        async def close(self, _broker):
            pass

    monkeypatch.setattr(engine_module, "_PipelineServices", Services)

    async def scenario():
        config = make_config({"filesystem": {"scan_filters_enabled": True}})
        observed = []
        both_started = asyncio.Event()

        class Runtime:
            def __init__(self, _services, submission, options, _leases):
                self.submission = submission
                assert submission.detection_options == options

            async def execute_async(self, _broker, _cancellation):
                observed.append(self.submission)
                if len(observed) >= 2:
                    both_started.set()
                await both_started.wait()
                return PipelineResponse(self.submission.request_id, RunSummary(), PipelineArtifacts())

        async with engine_module.PipelineEngine(config) as engine:
            engine._request_runtime_factory = Runtime
            await asyncio.gather(
                engine.run([str(tmp_path / "watch.bin")], origin="watch", detection_options=EmbeddedOptions(force_scan=True)),
                engine.run([str(tmp_path / "cli.bin")]),
            )
            await engine.run([str(tmp_path / "next-watch.bin")], origin="watch")
        assert [request.detection_options.force_scan for request in observed] == [True, False, False]
        assert [request.config["filesystem"]["scan_filters_enabled"] for request in observed] == [False, True, True]
        assert config["filesystem"]["scan_filters_enabled"] is True

    asyncio.run(scenario())


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


def test_default_embedded_scan_skips_confirmed_pe_before_full_scan(tmp_path, monkeypatch):
    from tests.helpers.fs_builder import make_minimal_pe

    path = tmp_path / "application.jpg"
    path.write_bytes(make_minimal_pe())

    monkeypatch.setattr(
        "sunpack.pipeline.discovery.embedded.discovery.file_identity",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("confirmed PE gate must run before file probing")
        ),
    )
    monkeypatch.setattr(
        "sunpack.pipeline.discovery.embedded.discovery.scan_embedded_archives",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("confirmed PE gate must reject before full scan")
        ),
    )

    result = EmbeddedDiscovery({}).discover([_candidate(path)])

    assert result.resolved_tasks == []
    assert result.residual_paths
    assert any(
        trace.reason == "embedded_executable_skipped" and trace.status == "residual"
        for trace in result.traces
    )


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


@pytest.mark.parametrize("status", ["password_required", "wrong_password"])
def test_password_blocked_carrier_preserves_every_archive_finding(tmp_path, monkeypatch, status):
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
            "status": status,
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
        f"embedded_{status}",
        "embedded_carrier_blocked",
    ]
    assert all(finding.status == "blocked" for finding in result.findings)
    assert all(not finding.extractable for finding in result.findings)
