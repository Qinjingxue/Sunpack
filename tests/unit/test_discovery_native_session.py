import tarfile
from concurrent.futures import ThreadPoolExecutor
from io import BytesIO

from sunpack_native import reader_cache_stats

from sunpack.pipeline.coordinator.scan_session import DiscoveryScanSession
from sunpack.pipeline.coordinator.target_scan import build_native_table_for_targets
from tests.helpers.config_factory import make_config


def test_native_discovery_does_not_project_negative_embedded_candidates(tmp_path):
    for index in range(32):
        (tmp_path / f"fake_{index:03}.zip").write_bytes(b"not an archive")

    session = DiscoveryScanSession(config=make_config({}))
    table = build_native_table_for_targets([str(tmp_path)], session=session, config=make_config({}))
    assert len(table) == 32

    routes = table.resolve(include_residual_details=False)
    assert routes.relation_events == []
    assert routes.detection_events == []
    batch = table.scan_embedded(routes, include_residual_details=False)
    assert len(batch) == 32
    assert batch.scan_page(table, 0, 32) == []


def test_native_embedded_pages_scan_on_demand(tmp_path):
    path = tmp_path / "fake.zip"
    path.write_bytes(b"not an archive")
    table = build_native_table_for_targets([str(tmp_path)], config=make_config({}))
    batch = table.scan_embedded(table.resolve(), include_residual_details=True)

    path.unlink()
    assert batch.scan_page(table, 0, 1)[0][2] == "embedded_scan_io_error"


def test_native_head_fact_cache_accepts_concurrent_reads(tmp_path):
    path = tmp_path / "payload.bin"
    payload = b"PK\x03\x04" + b"x" * 1024
    path.write_bytes(payload)
    session = DiscoveryScanSession(config=make_config({}))

    def read(magic_size):
        return session.file_head_facts_for_path(str(path), magic_size=magic_size)

    with ThreadPoolExecutor(max_workers=8) as pool:
        rows = list(pool.map(read, [0, 16] * 32))

    assert all(row["size"] == len(payload) for row in rows)
    assert all(row["magic"].startswith(b"PK\x03\x04") for row in rows[1::2])


def test_native_detection_batches_keep_order_during_concurrent_resolves(tmp_path):
    buffer = BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        entry = tarfile.TarInfo("payload.txt")
        entry.size = 1
        archive.addfile(entry, BytesIO(b"x"))
    valid = buffer.getvalue()
    invalid = bytearray(valid)
    invalid[148] ^= 1
    for index in range(1100):
        (tmp_path / f"archive-{index:04}.tar").write_bytes(valid if index % 2 == 0 else invalid)

    table = build_native_table_for_targets([str(tmp_path)], config=make_config({}))
    cache_entries_before = reader_cache_stats()["cache_entries"]
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _index: table.resolve(include_residual_details=False), range(4)))

    expected = results[0].detection_resolved
    assert len(expected) == 550
    assert expected == sorted(expected)
    assert all(result.detection_resolved == expected for result in results)
    assert reader_cache_stats()["cache_entries"] == cache_entries_before
