import pytest

from tests.helpers.real_archives import create_multi_member_stream_archive
from tests.helpers.seven_zip_lz4 import create_7z_lz4_case
from tests.real.archive_boundary import require_generator
from tests.real.plan7_watch_downloads.plan7_support import (
    assert_once, download, split_order, watch_setup,
)


pytestmark = pytest.mark.requires_watch_broker


@pytest.mark.parametrize("mode", ["rename", "direct"])
def test_plan7_concatenated_lz4_frames_download_and_verify_full_output(package, tmp_path, mode):
    case = create_multi_member_stream_archive(
        tmp_path / "fixtures", "lz4-concatenated", "lz4", payload_size=256 * 1024,
    )
    case.marker_text += case.metadata["second_member_content"]
    watch = watch_setup(package, tmp_path)
    download(watch, case.entry_path, mode=mode)
    watch.await_archive(case)
    watch.stop()
    assert_once(watch, case)


@pytest.mark.parametrize("split", [False, True], ids=["encrypted", "encrypted-disguised-split"])
def test_plan7_seven_zip_lz4_password_and_volume_chain(package, tmp_path, split):
    require_generator("7z", seven_zip_lz4=True)
    case = create_7z_lz4_case(
        tmp_path / "fixtures", "seven_zip_lz4", password="secret", split=split, disguise=split,
    )
    watch = watch_setup(package, tmp_path, passwords=["wrong", "secret"])
    for part in split_order(case):
        download(watch, part)
    watch.await_archive(case)
    watch.stop()
    assert_once(watch, case)
    watch.assert_no_terminal_failures()


def test_watch_sibling_trigger_survives_encrypted_head_rename(package, tmp_path):
    require_generator("7z", seven_zip_lz4=True)
    case = create_7z_lz4_case(
        tmp_path / "fixtures", "renamed-head", password="secret", split=True, disguise=True,
    )
    watch = watch_setup(package, tmp_path, passwords=["wrong", "secret"])
    parts = sorted(case.archive_dir.iterdir())
    head = parts[0]
    with head.open("rb") as source:
        from tests.real.plan7_watch_downloads.plan7_support import DOWNLOAD_CHUNK_SIZE
        temporary = watch.root / f"{head.name}.downloading"
        # Keep the temporary head open while the other volumes trigger
        # discovery. Renaming to its final name releases the final input.
        with temporary.open("wb") as writer:
            while data := source.read(DOWNLOAD_CHUNK_SIZE):
                writer.write(data)
            writer.flush()
            for part in parts[1:]:
                download(watch, part)
            watch.await_event("pipeline_request_started")
        temporary.replace(watch.root / head.name)
    watch.await_archive(case)
    watch.stop()
    assert_once(watch, case)
    watch.assert_no_terminal_failures()
