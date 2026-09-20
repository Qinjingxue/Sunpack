from sunpack.support import sevenzip_bridge as native
from sunpack.support.global_cache_manager import clear_cache_namespace


def _clear_native_7z_caches():
    clear_cache_namespace("native_7z_resources")
    clear_cache_namespace("native_7z_crc_manifest")


class FakeBridge:
    wrapper_path = "wrapper.dll"

    def __init__(self):
        self.resource_calls = 0
        self.crc_manifest_calls = 0

    def analyze_archive_resources(self, archive_path: str, password: str = "", part_paths=None):
        self.resource_calls += 1
        return native.NativeArchiveResourceAnalysis(
            status=native.STATUS_OK,
            is_archive=True,
            is_encrypted=False,
            is_broken=False,
            solid=False,
            item_count=1,
            file_count=1,
            dir_count=0,
            archive_size=100,
            total_unpacked_size=200,
            total_packed_size=100,
            largest_item_size=200,
            largest_dictionary_size=0,
            archive_type="zip",
            dominant_method="Store",
            message="ok",
        )

    def read_archive_crc_manifest(
        self,
        archive_path: str,
        password: str = "",
        part_paths=None,
        max_items: int = 200000,
    ):
        self.crc_manifest_calls += 1
        return native.NativeArchiveCrcManifest(
            status=native.STATUS_OK,
            is_archive=True,
            encrypted=False,
            damaged=False,
            checksum_error=False,
            item_count=1,
            file_count=1,
            files=[{"path": "inside.txt", "size": 5, "has_crc": True, "crc32": 907060870}],
            message="ok",
        )


def _install_fake_bridge(monkeypatch):
    fake = FakeBridge()
    monkeypatch.setattr(native, "_DEFAULT_BRIDGE", fake)
    _clear_native_7z_caches()
    return fake


def test_archive_resource_cache_is_password_specific(tmp_path, monkeypatch):
    fake = _install_fake_bridge(monkeypatch)
    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"PK")

    first = native.cached_analyze_archive_resources(str(archive), password="secret")
    second = native.cached_analyze_archive_resources(str(archive), password="secret")
    third = native.cached_analyze_archive_resources(str(archive), password="other")

    assert first.ok
    assert second.dominant_method == "Store"
    assert third.ok
    assert fake.resource_calls == 2
    _clear_native_7z_caches()


def test_archive_resource_cache_tracks_part_identity(tmp_path, monkeypatch):
    fake = _install_fake_bridge(monkeypatch)
    first = tmp_path / "payload.7z.001"
    second = tmp_path / "payload.7z.002"
    first.write_bytes(b"one")
    second.write_bytes(b"two")

    native.cached_analyze_archive_resources(str(first), part_paths=[str(first), str(second)])
    native.cached_analyze_archive_resources(str(first), part_paths=[str(first), str(second)])
    second.write_bytes(b"changed")

    native.cached_analyze_archive_resources(str(first), part_paths=[str(first), str(second)])

    assert fake.resource_calls == 2
    _clear_native_7z_caches()


def test_archive_crc_manifest_cache_is_password_and_limit_specific(tmp_path, monkeypatch):
    fake = _install_fake_bridge(monkeypatch)
    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"PK")

    first = native.cached_read_archive_crc_manifest(str(archive), password="secret", max_items=10)
    second = native.cached_read_archive_crc_manifest(str(archive), password="secret", max_items=10)
    third = native.cached_read_archive_crc_manifest(str(archive), password="secret", max_items=20)

    assert first.ok
    assert second.files[0]["path"] == "inside.txt"
    assert third.ok
    assert fake.crc_manifest_calls == 2
    _clear_native_7z_caches()
