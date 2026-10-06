from concurrent.futures import ThreadPoolExecutor

from sunpack_native import fast_hash64, fast_hash128

from sunpack.core.passwords.fingerprint import build_archive_fingerprint
from sunpack.core.support.archive_knowledge_projection import _source_input_fingerprint
from sunpack.runtime.watch.scheduler import _password_source_signature
from sunpack.runtime.watch.service import watch_roots_mutex_name


def test_fast_hash_vectors_and_concurrent_memory_identities():
    assert fast_hash64(b"") == "ef46db3751d8e999"
    assert fast_hash64(b"a") == "d24ec4f1a98c6e5b"
    payloads = [bytes([i]) * 4096 for i in range(16)]
    expected = [fast_hash128(data) for data in payloads]
    with ThreadPoolExecutor(max_workers=4) as pool:
        assert list(pool.map(fast_hash128, payloads * 4)) == expected * 4
    assert len(set(expected)) == len(payloads)
    for data, digest in zip(payloads, expected):
        identity = _source_input_fingerprint({"kind": "memory", "data": data})
        assert identity["xxh128"] == digest
        assert identity["size"] == len(data)
        assert "sha256" not in identity


def test_password_signature_preserves_boundaries_order_and_unicode():
    values = [(["ab", "c"], []), (["a", "bc"], []),
              ([], ["ab", "c"]), (["c", "ab"], []), (["密码"], [])]
    signatures = [_password_source_signature(*value) for value in values]
    assert len(set(signatures)) == len(values)
    assert all(len(value) == 32 for value in signatures)
    assert signatures == [_password_source_signature(*value) for value in values]


def test_mutex_identity_normalizes_path_case(tmp_path):
    first = watch_roots_mutex_name(tmp_path / "Roots.json")
    assert first == watch_roots_mutex_name(tmp_path / "roots.JSON")
    assert first != watch_roots_mutex_name(tmp_path / "other.json")


def test_password_key_tracks_missing_volume_arrival_and_generation(tmp_path):
    archive = tmp_path / "disguised.001"
    part = tmp_path / "disguised.002"
    archive.write_bytes(b"first")
    before = build_archive_fingerprint(str(archive), [str(part)]).key
    assert before == build_archive_fingerprint(str(archive), [str(part)]).key
    part.write_bytes(b"second")
    arrived = build_archive_fingerprint(str(archive), [str(part)]).key
    assert arrived != before
    part.write_bytes(b"replacement volume")
    assert build_archive_fingerprint(str(archive), [str(part)]).key != arrived


def test_password_key_separates_top_level_ranges_and_concat_order(tmp_path):
    archive = tmp_path / "carrier.bin"
    archive.write_bytes(b"carrier")

    def key(descriptor):
        return build_archive_fingerprint(str(archive), archive_input=descriptor).key

    assert key({"kind": "file_range", "start": 0, "end": 3}) != key(
        {"kind": "file_range", "start": 3, "end": 6})
    ranges = [{"path": str(archive), "start": 0, "end": 3},
              {"path": str(archive), "start": 3, "end": 6}]
    assert key({"kind": "concat_ranges", "ranges": ranges}) != key(
        {"kind": "concat_ranges", "ranges": list(reversed(ranges))})
