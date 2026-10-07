import asyncio
import bz2
import io
import shutil
import subprocess
import tarfile
from pathlib import Path

import pytest

from sunpack.core.config.schema import normalize_config
from sunpack.core.contracts.failures import FailureKind
from sunpack.core.contracts.results import OutcomeKind
from sunpack.core.contracts.retry_targets import failure_contains, result_failure
from sunpack.pipeline.coordinator.engine import PipelineEngine
from tests.helpers.detection_config import with_detection_pipeline
from tests.helpers.tool_config import get_optional_rar
from tests.helpers.native_fixture import assemble_carrier, file_inventory
from sunpack.pipeline.discovery.embedded.options import EmbeddedOptions


def _payload(root: Path) -> dict[str, bytes]:
    root.mkdir()
    files = {}
    for index in range(3):
        data = bytes((index * 31 + offset * 7) % 251 for offset in range(24 * 1024))
        (root / f"f{index}.bin").write_bytes(data)
        files[f"f{index}.bin"] = data
    return files


def _rar_volumes(tmp_path: Path, name: str, *switches: str) -> tuple[Path, dict[str, bytes]]:
    rar = get_optional_rar()
    if rar is None:
        pytest.skip("RAR generator is not configured")
    source = tmp_path / f"{name}_src"
    files = _payload(source)
    out = tmp_path / f"{name}_volumes"
    out.mkdir()
    subprocess.run(
        [str(rar), "a", "-ep1", "-idq", "-m0", "-y", "-v24k", *switches, str(out / f"{name}.rar"), str(source / "*")],
        check=True,
        capture_output=True,
    )
    return out, files


def _run(tmp_path: Path, inputs: Path):
    config = normalize_config(with_detection_pipeline({
        "output": {"root": str(tmp_path / "out")},
        "post_extract": {"archive_cleanup_mode": "k", "flatten_single_directory": False},
    }))

    async def run():
        async with PipelineEngine(config) as engine:
            return await engine.run([str(inputs)], origin="foreground")

    return asyncio.run(run()).summary.target_results


def _assert_extracted(results, files: dict[str, bytes], logical_name: str) -> None:
    assert len(results) == 1
    result = results[0]
    assert result.outcome_kind == OutcomeKind.COMPLETE_SUCCESS
    output = Path(result.output_dir)
    assert output.name == logical_name
    for name, data in files.items():
        assert (output / name).read_bytes() == data


def test_old_numbering_rar4_set_with_disguised_head_extracts(tmp_path):
    volumes, files = _rar_volumes(tmp_path, "oldset", "-ma4", "-vn")
    head = volumes / "oldset.rar"
    assert (volumes / "oldset.r00").is_file()
    head.rename(volumes / "oldset.jpg")

    _assert_extracted(_run(tmp_path, volumes), files, "oldset")


def test_old_numbering_rar4_set_renamed_to_part_names_extracts(tmp_path):
    volumes, files = _rar_volumes(tmp_path, "oldparts", "-ma4", "-vn")
    ordered = [volumes / "oldparts.rar", *sorted(volumes.glob("oldparts.r[0-9][0-9]"))]
    assert len(ordered) >= 3
    for number, path in enumerate(ordered, start=1):
        path.rename(volumes / f"oldparts.part{number}.rar")

    _assert_extracted(_run(tmp_path, volumes), files, "oldparts")


@pytest.mark.parametrize("missing", ["last", "middle"])
def test_incomplete_rar5_set_is_reported_as_missing_volume(tmp_path, missing):
    volumes, _files = _rar_volumes(tmp_path, "gap", "-ma5")
    parts = sorted(volumes.glob("gap.part*.rar"), key=lambda path: int(path.name[8:-4]))
    assert len(parts) >= 3
    (parts[-1] if missing == "last" else parts[1]).unlink()

    results = _run(tmp_path, volumes)

    # The set must reach Extraction, which makes the missing-volume decision;
    # it must never silently disappear from discovery.
    assert len(results) == 1
    assert results[0].outcome_kind != OutcomeKind.COMPLETE_SUCCESS
    assert failure_contains(result_failure(results[0]), FailureKind.MISSING_VOLUME)


def test_stream_and_detection_route_outputs_are_named_after_the_archive(tmp_path):
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    (inputs / "notes.bz2").write_bytes(bz2.compress(b"stream payload"))
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        info = tarfile.TarInfo("inside.txt")
        info.size = 3
        archive.addfile(info, io.BytesIO(b"tar"))
    (inputs / "bundle.tar").write_bytes(buffer.getvalue())
    shutil.copyfile(inputs / "bundle.tar", inputs / "movie.mp4")

    results = {Path(result.input_path).name: result for result in _run(tmp_path, inputs)}

    assert set(results) == {"notes.bz2", "bundle.tar", "movie.mp4"}
    for result in results.values():
        assert result.outcome_kind == OutcomeKind.COMPLETE_SUCCESS
    notes = Path(results["notes.bz2"].output_dir)
    assert notes.name == "notes"
    assert (notes / "notes").read_bytes() == b"stream payload"
    assert Path(results["bundle.tar"].output_dir).name == "bundle"
    assert Path(results["movie.mp4"].output_dir).name == "movie"


@pytest.mark.parametrize("embedded", [False, True])
@pytest.mark.parametrize("origin", ["foreground", "watch"])
def test_unnamed_xz_stream_keeps_input_name_under_output_collision(tmp_path, embedded, origin):
    sevenzip = Path(__file__).resolve().parents[2] / "tools" / "7z.exe"
    payload_root = tmp_path / "payload"
    payload_root.mkdir()
    payload = payload_root / "message.txt"
    payload.write_text("unnamed stream payload", encoding="utf-8")
    inner = tmp_path / "inner.7z"
    subprocess.run([str(sevenzip), "a", "-t7z", str(inner), str(payload)],
        check=True, capture_output=True)
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    stream = inputs / "inner.7z.xz"
    subprocess.run([str(sevenzip), "a", "-txz", str(stream), str(inner)],
        check=True, capture_output=True)
    if embedded:
        standalone = tmp_path / stream.name
        stream.rename(standalone)
        assembled = assemble_carrier(stream, [standalone], junk_min=1024, junk_max=2048)
        assert assembled
    output_root = tmp_path / "out"
    collision = output_root / "inner.7z"
    collision.mkdir(parents=True)
    (collision / "existing.txt").write_text("existing", encoding="utf-8")
    before = file_inventory(inputs)
    config = normalize_config(with_detection_pipeline({
        "recursive_extract": "3",
        "output": {"root": str(output_root)},
        "post_extract": {"archive_cleanup_mode": "k", "flatten_single_directory": False},
    }))

    async def run():
        async with PipelineEngine(config) as engine:
            return await engine.run([str(stream)], origin=origin,
                detection_options=EmbeddedOptions(force_scan=embedded))

    response = asyncio.run(run())
    results = response.summary.target_results
    assert not response.summary.failed_tasks, response.summary.failures
    assert len(results) == 2
    assert all(result.outcome_kind == OutcomeKind.COMPLETE_SUCCESS for result in results)
    outer = next(result for result in results if result.input_path == str(stream))
    assert Path(outer.output_dir) != collision
    recovered = Path(outer.output_dir) / inner.name
    assert recovered.is_file(), file_inventory(output_root)
    assert file_inventory(Path(outer.output_dir))[inner.name] == file_inventory(tmp_path)[inner.name]
    nested = next(result for result in results if result.input_path != str(stream))
    assert Path(nested.input_path) == recovered
    assert file_inventory(Path(nested.output_dir)) == file_inventory(payload_root)
    assert (collision / "existing.txt").read_text(encoding="utf-8") == "existing"
    assert file_inventory(inputs) == before
