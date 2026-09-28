from concurrent.futures import ThreadPoolExecutor

from sunpack.pipeline.coordinator.scan_session import DiscoveryScanSession
from sunpack.pipeline.coordinator.target_scan import build_native_table_for_targets


def test_native_discovery_does_not_project_negative_embedded_candidates(tmp_path):
    for index in range(32):
        (tmp_path / f"fake_{index:03}.zip").write_bytes(b"not an archive")

    session = DiscoveryScanSession(config={})
    table = build_native_table_for_targets([str(tmp_path)], session=session, config={})
    assert len(table) == 32

    routes = table.resolve(include_residual_details=False)
    assert routes.relation_events == []
    assert routes.detection_events == []
    batch = table.scan_embedded(routes, include_residual_details=False)
    assert len(batch) == 32
    assert batch.page(table, 0, 32) == []


def test_native_embedded_pages_scan_on_demand(tmp_path):
    path = tmp_path / "fake.zip"
    path.write_bytes(b"not an archive")
    table = build_native_table_for_targets([str(tmp_path)], config={})
    batch = table.scan_embedded(table.resolve(), include_residual_details=True)

    path.unlink()
    assert batch.page(table, 0, 1)[0][2] == "embedded_scan_io_error"


def test_native_head_fact_cache_accepts_concurrent_reads(tmp_path):
    path = tmp_path / "payload.bin"
    payload = b"PK\x03\x04" + b"x" * 1024
    path.write_bytes(payload)
    session = DiscoveryScanSession(config={})

    def read(magic_size):
        return session.file_head_facts_for_path(str(path), magic_size=magic_size)

    with ThreadPoolExecutor(max_workers=8) as pool:
        rows = list(pool.map(read, [0, 16] * 32))

    assert all(row["size"] == len(payload) for row in rows)
    assert all(row["magic"].startswith(b"PK\x03\x04") for row in rows[1::2])
