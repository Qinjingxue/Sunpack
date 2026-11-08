import io
import tarfile

from sunpack.pipeline.coordinator.task_provider import ArchiveTaskProvider
from tests.helpers.config_factory import make_config


def _tar_bytes() -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        info = tarfile.TarInfo("payload.txt")
        info.size = 5
        archive.addfile(info, io.BytesIO(b"hello"))
    return output.getvalue()


def test_routed_tar_is_confirmed_with_disguised_extension(tmp_path):
    target = tmp_path / "random.bin"
    target.write_bytes(_tar_bytes())

    result = ArchiveTaskProvider(make_config({})).discover_targets([str(target)])
    task, = result.tasks
    assert task.archive_input().format_hint == "tar"


def test_tar_extension_does_not_establish_format(tmp_path):
    target = tmp_path / "archive.tar"
    target.write_bytes(b"plain text")

    result = ArchiveTaskProvider(make_config({})).discover_targets([str(target)])
    assert not result.tasks
