from sunpack_native import encode_worker_frame
"""Cross-layer regressions that ordinary archive fixtures cannot exercise."""

import asyncio
import io
import subprocess
import tarfile
import zipfile

import pytest

from sunpack.core.contracts.archive_input import ArchiveInputDescriptor
from sunpack.core.contracts.failures import FailureKind
from sunpack.core.support.resources import get_sevenzip_bridge_worker_path
from sunpack.pipeline.coordinator.engine import PipelineEngine
from sunpack.pipeline.extraction.output_inventory import collect_output_inventory
from sunpack.pipeline.verification.archive_input_manifest import archive_input_manifest
from tests.helpers.config_factory import make_config


@pytest.mark.parametrize("archive_format", ["zip", "tar"])
@pytest.mark.parametrize("file_first", [True, False])
def test_file_directory_collisions_share_worker_and_manifest_names(tmp_path, archive_format, file_first):
    # Duplicate-file tests cannot expose a file blocking an implicit parent or
    # an explicit directory. One tiny archive checks both orderings and mapping.
    archive = tmp_path / "input.disguised"
    directory = [("node.txt/", None), ("node.txt/inner.bin", b"child")]
    flat = [("node.txt", b"flat")]
    members = (flat + directory if file_first else directory + flat) + [
        ("NODE.TXT(1)", b"literal"), ("other:dir", b"mapped-flat"),
        ("other?dir/inner.bin", b"mapped-child"),
    ]
    if archive_format == "zip":
        with zipfile.ZipFile(archive, "w") as stream:
            for name, payload in members:
                stream.writestr(name, payload or b"")
    else:
        with tarfile.open(archive, "w", format=tarfile.USTAR_FORMAT) as stream:
            for name, payload in members:
                info = tarfile.TarInfo(name)
                info.type = tarfile.DIRTYPE if payload is None else tarfile.REGTYPE
                info.size = len(payload or b"")
                stream.addfile(info, io.BytesIO(payload or b""))
    output = tmp_path / "out"
    completed = subprocess.run(
        [get_sevenzip_bridge_worker_path()],
        input=encode_worker_frame({
            "job_id": "collision",
            "archive_input": ArchiveInputDescriptor.from_parts(archive_path=str(archive), format_hint=archive_format).to_dict(),
            "output_dir": str(output),
        }),
        capture_output=True,   timeout=15,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert sorted(path.read_bytes() for path in output.rglob("*") if path.is_file()) == sorted(
        payload for _, payload in members if payload is not None
    )
    manifest = archive_input_manifest(ArchiveInputDescriptor(str(archive), format_hint=archive_format))
    assert manifest.ok
    matched = collect_output_inventory(str(output)).verification_match(
        manifest.entries, verify_crc=True, basename_mode="none",
    )
    assert matched["coverage"]["complete_files"] == 5
    assert matched["missing_count"] == matched["mismatch_count"] == matched["size_mismatch_count"] == 0


@pytest.mark.parametrize("origin", ["foreground", "watch"])
@pytest.mark.parametrize("sparse_version", ["0.1", "1.0"])
@pytest.mark.parametrize("verify_enabled", [True, False])
def test_unsupported_tar_payload_encoding_never_authorizes_source_cleanup(tmp_path, origin, sparse_version, verify_enabled):
    # A successful worker plus valid preceding members used to hide unsupported
    # sparse content. Exercise the shared watch/CLI pipeline with deletion on.
    archive = tmp_path / "input.disguised"
    target = tarfile.TarInfo("GNUSparseFile.0/payload.txt")
    content = b"abc"
    target.pax_headers = {"GNU.sparse.realsize": "3", "GNU.sparse.name": "payload.txt"}
    if sparse_version == "1.0":
        target.pax_headers.update({"GNU.sparse.major": "1", "GNU.sparse.minor": "0"})
        content = b"1\n0\n3\n".ljust(512, b"\0") + content
    else:
        target.pax_headers["GNU.sparse.map"] = "0,3"
    target.size = len(content)
    with tarfile.open(archive, "w", format=tarfile.PAX_FORMAT) as stream:
        regular = tarfile.TarInfo("regular.txt")
        regular.size = 3
        stream.addfile(regular, io.BytesIO(b"ok!"))
        stream.addfile(target, io.BytesIO(content))
    config = make_config({"cli": {"quiet": True}, "recursive_extract": 1,
                          "verification": {"enabled": verify_enabled},
                          "post_extract": {"archive_cleanup_mode": "d", "flatten_single_directory": False}})

    async def run():
        async with PipelineEngine(config) as engine:
            return await engine.run([str(archive)], origin=origin)

    response = asyncio.run(run())
    assert response.summary.success_count == 0
    assert response.summary.failed_count == 1
    assert all(failure.contains(FailureKind.UNSUPPORTED) for failure in response.summary.failures)
    assert archive.exists()


def test_tar_metadata_budget_ignores_unrelated_values_but_bounds_names(tmp_path):
    # Count caps do not bound a single metadata member. Large unknown values
    # remain valid, whereas a useful field cannot trigger an unbounded read.
    archive = tmp_path / "metadata.tar"
    with tarfile.open(archive, "w", format=tarfile.PAX_FORMAT) as stream:
        for name, values in [("first", {"comment": "x" * (2 * 1024 * 1024)}),
                             ("second", {"path": "y" * (2 * 1024 * 1024)})]:
            info = tarfile.TarInfo(name)
            info.pax_headers = values
            stream.addfile(info)
    manifest = archive_input_manifest(ArchiveInputDescriptor(str(archive), format_hint="tar"))
    assert manifest.file_count == 1
    assert manifest.expected_names == ["first"]
    assert not manifest.archive_walk_complete
