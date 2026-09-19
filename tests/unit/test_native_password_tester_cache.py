from sunpack.support import sevenzip_bridge as native
from sunpack.support.global_cache_manager import clear_cache_namespace


def _clear_native_7z_caches():
    clear_cache_namespace("native_7z_probe")
    clear_cache_namespace("native_7z_test")
    clear_cache_namespace("native_7z_resources")
    clear_cache_namespace("native_7z_crc_manifest")


class FakeTester:
    wrapper_path = "wrapper.dll"
    
    def __init__(self):
        self.probe_calls = 0
        self.probe_inputs = []
        self.test_calls = 0
        self.resource_calls = 0
        self.crc_manifest_calls = 0

    def probe_archive(self, archive_path: str, part_paths=None, archive_input=None):
        self.probe_calls += 1
        self.probe_inputs.append(archive_input)
        return native.NativeArchiveProbe(
            status=native.STATUS_OK,
            is_archive=True,
            is_encrypted=False,
            is_broken=False,
            checksum_error=False,
            offset=0,
            item_count=1,
            archive_type="zip",
            message="ok",
        )

    def test_archive(self, archive_path: str, password: str = "", part_paths=None):
        self.test_calls += 1
        return native.NativeArchiveTest(
            status=native.STATUS_OK,
            command_ok=True,
            encrypted=False,
            checksum_error=False,
            archive_type="zip",
            message="ok",
        )

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

    def read_archive_crc_manifest(self, archive_path: str, password: str = "", part_paths=None, max_items: int = 200000):
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


class UnsupportedProbeTester(FakeTester):
    def probe_archive(self, archive_path: str, part_paths=None, archive_input=None):
        self.probe_calls += 1
        self.probe_inputs.append(archive_input)
        return native.NativeArchiveProbe(
            status=native.STATUS_UNSUPPORTED,
            is_archive=True,
            is_encrypted=True,
            is_broken=False,
            checksum_error=False,
            offset=0,
            item_count=0,
            archive_type="7z",
            message="unsupported",
        )


def _install_fake_tester(monkeypatch):
    fake = FakeTester()
    monkeypatch.setattr(native, "_DEFAULT_TESTER", fake)
    _clear_native_7z_caches()
    return fake


def _install_tester(monkeypatch, tester):
    monkeypatch.setattr(native, "_DEFAULT_TESTER", tester)
    _clear_native_7z_caches()
    return tester


def test_cached_probe_reuses_result_for_unchanged_file(tmp_path, monkeypatch):
    fake = _install_fake_tester(monkeypatch)
    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"PK")

    first = native.cached_probe_archive(str(archive))
    second = native.cached_probe_archive(str(archive))

    assert first.archive_type == "zip"
    assert second.archive_type == "zip"
    assert fake.probe_calls == 1
    _clear_native_7z_caches()


def test_cached_probe_separates_and_reuses_archive_input_ranges(tmp_path, monkeypatch):
    fake = _install_fake_tester(monkeypatch)
    archive = tmp_path / "carrier.jpg"
    archive.write_bytes(b"jpeg-and-archive")
    first_input = {
        "entry_path": str(archive),
        "open_mode": "file_range",
        "format_hint": "rar",
        "parts": [{"path": str(archive), "start": 4}],
    }
    second_input = {
        "entry_path": str(archive),
        "open_mode": "file_range",
        "format_hint": "rar",
        "parts": [{"path": str(archive), "start": 8}],
    }

    native.cached_probe_archive(str(archive), archive_input=first_input)
    native.cached_probe_archive(str(archive), archive_input=dict(first_input))
    native.cached_probe_archive(str(archive), archive_input=second_input)

    assert fake.probe_calls == 2
    assert fake.probe_inputs == [first_input, second_input]
    _clear_native_7z_caches()


def test_empty_password_test_uses_test_api_directly(tmp_path, monkeypatch):
    fake = _install_fake_tester(monkeypatch)
    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"PK")

    probe = native.cached_probe_archive(str(archive))
    test = native.cached_test_archive(str(archive))

    assert probe.status == native.STATUS_OK
    assert test.ok
    assert test.archive_type == "zip"
    assert fake.probe_calls == 1
    assert fake.test_calls == 1
    _clear_native_7z_caches()


def test_password_test_keeps_password_specific_native_call(tmp_path, monkeypatch):
    fake = _install_fake_tester(monkeypatch)
    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"PK")

    first = native.cached_test_archive(str(archive), password="secret")
    second = native.cached_test_archive(str(archive), password="secret")

    assert first.ok
    assert second.ok
    assert fake.probe_calls == 0
    assert fake.test_calls == 1
    _clear_native_7z_caches()


def test_empty_password_test_uses_native_test_status(tmp_path, monkeypatch):
    fake = _install_tester(monkeypatch, UnsupportedProbeTester())
    archive = tmp_path / "sample.7z"
    archive.write_bytes(b"7z")

    test = native.cached_test_archive(str(archive))

    assert test.ok
    assert not test.encrypted
    assert test.status == native.STATUS_OK
    assert fake.probe_calls == 0
    assert fake.test_calls == 1
    _clear_native_7z_caches()


def test_archive_resource_cache_is_password_specific(tmp_path, monkeypatch):
    fake = _install_fake_tester(monkeypatch)
    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"PK")

    first = native.cached_analyze_archive_resources(str(archive), password="secret")
    second = native.cached_analyze_archive_resources(str(archive), password="secret")

    assert first.ok
    assert second.ok
    assert first.dominant_method == "Store"
    assert fake.resource_calls == 1
    _clear_native_7z_caches()


def test_archive_crc_manifest_cache_is_password_and_limit_specific(tmp_path, monkeypatch):
    fake = _install_fake_tester(monkeypatch)
    archive = tmp_path / "sample.zip"
    archive.write_bytes(b"PK")

    first = native.cached_read_archive_crc_manifest(str(archive), password="secret", max_items=10)
    second = native.cached_read_archive_crc_manifest(str(archive), password="secret", max_items=10)

    assert first.ok
    assert second.files[0]["path"] == "inside.txt"
    assert fake.crc_manifest_calls == 1
    _clear_native_7z_caches()
from sunpack.support.sevenzip_bridge import NativePasswordAttempt, NativePasswordTester, STATUS_OK


class _ArchiveInputAwareTester(NativePasswordTester):
    def __init__(self):
        self.ctypes_calls = []

    def _try_passwords_ctypes(self, archive_path, passwords, part_paths=None, archive_input=None):
        self.ctypes_calls.append((archive_path, list(passwords), part_paths, archive_input))
        return NativePasswordAttempt(
            status=STATUS_OK,
            matched_index=0,
            attempts=1,
            message="ctypes",
            operation_result=0,
        )


def test_native_password_tester_uses_dll_for_archive_input_even_for_small_batches():
    tester = _ArchiveInputAwareTester()
    archive_input = {
        "kind": "archive_input",
        "entry_path": "carrier.exe",
        "open_mode": "file_range",
        "format_hint": "zip",
        "parts": [{"path": "carrier.exe", "start": 4096, "end": 8192}],
    }

    result = tester.try_passwords("carrier.exe", ["secret"], archive_input=archive_input)

    assert result.ok
    assert tester.ctypes_calls == [("carrier.exe", ["secret"], None, archive_input)]
