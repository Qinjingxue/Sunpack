from concurrent.futures import ThreadPoolExecutor
import json

import pytest

from sunpack_native import (
    FastHash128,
    fast_hash64,
    fast_hash128,
    fast_hash128_file,
    native_resource_snapshot,
    runtime_binary_build_id,
)

from sunpack.core.passwords.fingerprint import build_archive_fingerprint
from sunpack.core.passwords.internal.store import PasswordSnapshot
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


def test_streaming_and_file_hashes_match_memory_and_release_resources(tmp_path):
    # Unique coverage: partial XXH blocks, multi-buffer files, independent concurrent
    # streams and handle cleanup on success/error. One-shot identity tests cannot
    # detect these failures; this bounded fixture also covers the CLI build ID.
    payload = bytes(range(256)) * 4097
    paths = []
    expected = []
    for size in (0, 1, 31, 32, 33, len(payload)):
        data = payload[:size]
        path = tmp_path / f"密码-{size}.bin"
        path.write_bytes(data)
        paths.append(path)
        expected.append(fast_hash128(data))
        digest = FastHash128()
        digest.update(b"")
        digest.update(data[:31])
        assert digest.hexdigest() == fast_hash128(data[:31])
        # Reading a digest must not consume/finalize the state.
        assert digest.hexdigest() == fast_hash128(data[:31])
        digest.update(data[31:33])
        digest.update(data[33:])
        assert digest.hexdigest() == expected[-1]
        assert runtime_binary_build_id(str(path)) == fast_hash64(data)
    with ThreadPoolExecutor(max_workers=4) as pool:
        assert list(pool.map(fast_hash128_file, paths * 4)) == expected * 4
    missing = tmp_path / "missing.bin"
    with pytest.raises(OSError):
        fast_hash128_file(missing)
    with pytest.raises(OSError):
        fast_hash128_file(tmp_path)
    assert list(native_resource_snapshot([str(tmp_path)])) == []


def test_password_signature_preserves_boundaries_order_and_unicode():
    values = [(["ab", "c"], []), (["a", "bc"], []),
              ([], ["ab", "c"]), (["c", "ab"], []), (["密码"], [])]
    def signature(user_passwords, builtin_passwords):
        return _password_source_signature(
            fast_hash128(json.dumps(user_passwords, ensure_ascii=False, separators=(",", ":")).encode("utf-8")),
            PasswordSnapshot(global_passwords=tuple(builtin_passwords)).signature,
        )

    signatures = [signature(*value) for value in values]
    assert len(set(signatures)) == len(values)
    assert all(len(value) == 32 for value in signatures)
    assert signatures == [signature(*value) for value in values]


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
