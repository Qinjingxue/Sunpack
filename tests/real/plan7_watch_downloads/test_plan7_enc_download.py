import pytest

from tests.real.enc_support import ENC_PASSWORD, create_enc_case
from tests.real.plan7_watch_downloads.plan7_support import assert_once, download, watch_setup


pytestmark = pytest.mark.requires_watch_broker


@pytest.mark.parametrize("mode", ["rename", "direct"])
def test_plan7_enc_download_decrypts_after_arrival(package, tmp_path, mode):
    case = create_enc_case(tmp_path / "fixtures", f"enc-{mode}")
    watch = watch_setup(package, tmp_path, passwords=["wrong", ENC_PASSWORD])
    download(watch, case.entry_path, mode=mode)
    watch.await_archive(case)
    watch.stop()
    assert_once(watch, case)
    watch.assert_no_terminal_failures()
