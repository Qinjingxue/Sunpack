import gzip

from sunpack.contracts.detection import FactBag
from sunpack.embedded.discovery import EmbeddedDiscovery


def _bag(path):
    bag = FactBag()
    bag.set("file.path", str(path))
    bag.set("candidate.entry_path", str(path))
    bag.set("candidate.member_paths", [str(path)])
    bag.set("candidate.cleanup_paths", [str(path)])
    bag.set("file.size", path.stat().st_size)
    return bag


def test_embedded_layer_finds_disguised_stream_after_junk(tmp_path):
    path = tmp_path / "carrier.bin"
    path.write_bytes(b"leading junk" + gzip.compress(b"payload") + b"trailing junk")
    result, decisions = EmbeddedDiscovery({}).discover([_bag(path)])
    assert len(result.resolved_inputs) == 1
    assert decisions[0].decision.should_extract
    assert result.resolved_inputs[0].source == "embedded"


def test_embedded_layer_rejects_plain_data(tmp_path):
    path = tmp_path / "plain.bin"
    path.write_bytes(b"not an archive")
    result, decisions = EmbeddedDiscovery({}).discover([_bag(path)])
    assert result.resolved_inputs == []
    assert not decisions[0].decision.should_extract


def test_recursive_gate_may_exclude_small_residual_candidate(tmp_path):
    large = tmp_path / "large.bin"
    small = tmp_path / "small.bin"
    large.write_bytes(b"x" * 100)
    small.write_bytes(b"x")
    result, decisions = EmbeddedDiscovery({
        "embedded_scan": {"recursive_candidate_ratio": 0.3},
    }).discover([_bag(large), _bag(small)], is_recursive_scan=True)
    assert len(decisions) == 1
    assert result.resolved_inputs == []
