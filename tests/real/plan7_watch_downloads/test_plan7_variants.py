import pytest

from tests.helpers.native_fixture import assemble_carrier
from tests.helpers.real_archives import (
    create_encrypted_7z_archive, create_encrypted_rar_archive, create_encrypted_zip_archive,
)
from tests.helpers.tool_config import get_optional_rar
from tests.real.plan7_watch_downloads.plan7_support import FACTORY, PASSWORD, assert_once, download, watch_setup


pytestmark = pytest.mark.requires_watch_broker


@pytest.mark.parametrize("family", ["encrypted_variants", "disguised", "embedded"])
def test_plan7_container_and_encryption_variants(package, tmp_path, family):
    fixtures = tmp_path / "fixtures"
    cases = []
    if family == "encrypted_variants":
        cases.extend([
            create_encrypted_7z_archive(fixtures, "seven-no-header", password=PASSWORD, header_encrypt=False),
            create_encrypted_zip_archive(fixtures, "zipcrypto", password=PASSWORD, encryption="ZipCrypto"),
            create_encrypted_zip_archive(fixtures, "zip-aes", password=PASSWORD, encryption="AES256"),
        ])
        if get_optional_rar():
            for header in (False, True):
                cases.append(create_encrypted_rar_archive(
                    fixtures, f"rar4-{header}", password=PASSWORD, rar4=True, header_encrypt=header,
                ))
    elif family == "disguised":
        shapes = [
            ("7z", {"disguise_ext": ".payload"}), ("zip", {"carrier": "jpg"}),
            ("rar", {"disguise_ext": ".payload"}), ("lz4", {"disguise_ext": ".payload"}),
            ("tar.lz4", {"carrier": "jpg"}),
        ]
        for archive_format, shape in shapes:
            if archive_format == "rar" and not get_optional_rar():
                continue
            cases.append(FACTORY.create(
                fixtures, f"disguised-{archive_format}", archive_format, **shape, payload_size=96 * 1024,
                password=PASSWORD if archive_format in {"7z", "zip", "rar"} else None,
            ))
    else:
        for archive_format in ("7z", "zip", "rar", "lz4"):
            if archive_format == "rar" and not get_optional_rar():
                continue
            case = FACTORY.create(
                fixtures, f"embedded-{archive_format}", archive_format, payload_size=64 * 1024,
                password=PASSWORD if archive_format != "lz4" else None,
            )
            wrapped = case.archive_dir / f"embedded-{archive_format}.bin"
            assemble_carrier(wrapped, [case.entry_path], seed=0x7004, decoys=True)
            case.entry_path.unlink()
            case.entry_path = wrapped
            cases.append(case)

    watch = watch_setup(package, tmp_path)
    for case in cases:
        download(watch, case.entry_path)
        watch.await_archive(case)
    watch.stop()
    for case in cases:
        assert_once(watch, case)
    watch.assert_no_terminal_failures()
