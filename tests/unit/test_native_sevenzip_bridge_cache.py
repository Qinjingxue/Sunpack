from sunpack.support import sevenzip_bridge as native
from sunpack.support.global_cache_manager import clear_cache_namespace


def _clear_native_7z_caches():
    clear_cache_namespace("native_7z_resources")


class FakeBridge:
    wrapper_path = "wrapper.dll"

    def __init__(self):
        self.resource_calls = 0

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

