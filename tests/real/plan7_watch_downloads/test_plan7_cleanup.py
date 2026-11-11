import pytest

from tests.real.archive_boundary import require_generator
from tests.real.plan7_watch_downloads.plan7_support import (
    FACTORY, PASSWORD, assert_once, download, split_order, watch_setup,
)


pytestmark = pytest.mark.requires_watch_broker


def test_plan7_sfx_split_success_cleans_unique_validated_launcher(package, tmp_path):
    require_generator("7z", sfx=True)
    case = FACTORY.create(
        tmp_path / "fixtures", "p7_cleanup_sfx_split", "7z", password=PASSWORD, split=True,
        sfx=True, payload_size=192 * 1024,
    )
    watch = watch_setup(package, tmp_path, cleanup="d")
    delivered = [
        download(watch, part) for part in split_order(case, order="launcher_first")
    ]
    watch.await_archive(case)
    watch.stop()
    assert_once(watch, case)
    assert not any(path.exists() for path in delivered), delivered
