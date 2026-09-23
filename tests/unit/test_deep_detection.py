import gzip

from sunpack.contracts.discovery import DiscoveryCandidate
from sunpack.embedded.discovery import EmbeddedDiscovery


def _candidate(path):
    value = str(path)
    return DiscoveryCandidate(
        entry_path=value,
        member_paths=(value,),
        logical_name=path.name,
        carrier_path=value,
        cleanup_paths=(value,),
        route="residual",
        size=path.stat().st_size,
    )


def test_embedded_layer_finds_disguised_stream_after_junk(tmp_path):
    path = tmp_path / "carrier.bin"
    path.write_bytes(b"leading junk" + gzip.compress(b"payload") + b"trailing junk")
    result = EmbeddedDiscovery({}).discover([_candidate(path)])

    assert len(result.resolved_inputs) == 1
    assert result.resolved_inputs[0].source == "embedded"
    assert result.resolved_inputs[0].format == "gzip"


def test_embedded_layer_rejects_plain_data(tmp_path):
    path = tmp_path / "plain.bin"
    path.write_bytes(b"not an archive")
    result = EmbeddedDiscovery({}).discover([_candidate(path)])

    assert result.resolved_inputs == []
    assert result.residual_paths


def test_recursive_gate_may_exclude_small_residual_candidate(tmp_path):
    large = tmp_path / "large.bin"
    small = tmp_path / "small.bin"
    large.write_bytes(b"x" * 100)
    small.write_bytes(b"x")

    result = EmbeddedDiscovery({
        "embedded_scan": {"recursive_candidate_ratio": 0.3},
    }).discover([_candidate(large), _candidate(small)], is_recursive_scan=True)

    assert result.resolved_inputs == []
    assert any(trace.entry_path == str(small) and trace.status == "residual" for trace in result.traces)
