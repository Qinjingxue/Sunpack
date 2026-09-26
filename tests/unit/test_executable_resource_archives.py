from __future__ import annotations

from io import BytesIO
from pathlib import Path
import os
import zipfile

import pytest

from sunpack.pipeline.coordinator.recursive_authorization import RecursiveAuthorization
from sunpack.pipeline.coordinator.scan_session import DiscoveryScanSession
from sunpack.pipeline.coordinator.task_provider import ArchiveTaskProvider
from sunpack.pipeline.discovery.embedded.options import EmbeddedOptions
from tests.helpers.fs_builder import make_minimal_7z


def _minimal_pe_stub() -> bytes:
    """Build a small PE image with a 0xE0-byte image/overlay boundary."""
    pe_end = 0xE0
    image = bytearray(pe_end)
    image[0:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\x00\x00"
    image[0x86:0x88] = (1).to_bytes(2, "little")
    image[0x94:0x96] = (0).to_bytes(2, "little")
    section = 0x98
    image[section + 16:section + 20] = (0x20).to_bytes(4, "little")
    image[section + 20:section + 24] = (0xC0).to_bytes(4, "little")
    return bytes(image)


def _zip_archive(entries: dict[str, bytes]) -> bytes:
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return buffer.getvalue()


_EXECUTABLE_RESOURCE_CASES = [
    pytest.param(
        "application_7z.exe",
        make_minimal_7z(),
        "7z",
        id="7z-overlay",
    ),
    pytest.param(
        "game_a.exe",
        _zip_archive({
            "builder_config.json": b"{}",
            "data/scenario/start.ks": b"*start",
            "node_modules/nw/package.json": b"{}",
            "tyrano/tyrano.js": b"window.TYRANO = {};",
        }),
        "zip",
        id="zip-overlay-a",
    ),
    pytest.param(
        "game_b.EXE",
        _zip_archive({
            "data/scenario/prologue.ks": b"*prologue",
            "data/bgm/theme.ogg": b"audio-data",
            "node_modules/nw/package.json": b"{}",
            "tyrano/tyrano.js": b"window.TYRANO = {};",
        }),
        "zip",
        id="zip-overlay-uppercase-extension",
    ),
]


def _config() -> dict:
    return {
        "embedded_scan": {"enabled": True, "recursive_candidate_ratio": 0.3},
        "recursive_authorization": {
            "enabled": True,
            "byte_ratio_exponent": 1.0,
            "project_ratio_exponent": 1.0,
            "authorization_bias": 0.0,
            "minimum_authorization_score": 0.85,
            "minimum_archive_byte_ratio": 0.1,
            "hard_maximum_other_projects": 1000,
        },
        "filesystem": {
            "scan_filters": [
                {"name": "size_range", "enabled": True, "gte": 0},
            ],
        },
    }


def _make_game_tree(
    root: Path,
    filename: str,
    embedded_archive: bytes,
) -> tuple[Path, Path]:
    game_dir = root / "game"
    game_dir.mkdir()
    executable = game_dir / filename
    executable.write_bytes(_minimal_pe_stub() + embedded_archive)

    resource_payload = "installed game resource entry\n" * 160
    for index in range(24):
        (game_dir / f"resource_{index:02}.txt").write_text(
            resource_payload,
            encoding="utf-8",
        )
    return game_dir, executable


def _task_paths(tasks) -> set[str]:
    return {
        os.path.normcase(os.path.abspath(task.main_path))
        for task in tasks
    }


@pytest.mark.parametrize(
    ("filename", "embedded_archive", "expected_format"),
    _EXECUTABLE_RESOURCE_CASES,
)
def test_default_embedded_scan_skips_executable_resources(
    tmp_path: Path,
    filename: str,
    embedded_archive: bytes,
    expected_format: str,
):
    game_dir, executable = _make_game_tree(tmp_path, filename, embedded_archive)
    tasks = ArchiveTaskProvider(_config()).scan_targets(
        [str(game_dir)],
        is_recursive_scan=False,
    )

    assert os.path.normcase(os.path.abspath(executable)) not in _task_paths(tasks)


@pytest.mark.parametrize(
    ("filename", "embedded_archive", "expected_format"),
    _EXECUTABLE_RESOURCE_CASES,
)
def test_deep_scan_explicitly_scans_executable_resources(
    tmp_path: Path,
    filename: str,
    embedded_archive: bytes,
    expected_format: str,
):
    game_dir, executable = _make_game_tree(tmp_path, filename, embedded_archive)
    config = _config()
    tasks = ArchiveTaskProvider(
        config,
        EmbeddedOptions(force_scan=True),
    ).scan_targets([str(game_dir)], is_recursive_scan=False)

    expected_path = os.path.normcase(os.path.abspath(executable))
    task = next(
        task for task in tasks
        if os.path.normcase(os.path.abspath(task.main_path)) == expected_path
    )
    assert task.discovery_source == "embedded"
    assert task.archive_input().format_hint == expected_format
    assert task.archive_input().open_mode == "file_range"


@pytest.mark.parametrize(
    ("filename", "embedded_archive", "expected_format"),
    _EXECUTABLE_RESOURCE_CASES,
)
def test_recursive_authorization_still_rejects_deep_detected_low_share_executables(
    tmp_path: Path,
    filename: str,
    embedded_archive: bytes,
    expected_format: str,
):
    game_dir, executable = _make_game_tree(tmp_path, filename, embedded_archive)
    config = _config()
    session = DiscoveryScanSession(config=config)
    tasks = ArchiveTaskProvider(
        config,
        EmbeddedOptions(force_scan=True),
    ).scan_targets(
        [str(game_dir)],
        scan_session=session,
        is_recursive_scan=False,
    )

    expected_path = os.path.normcase(os.path.abspath(executable))
    explicit_task = next(
        task for task in tasks
        if os.path.normcase(os.path.abspath(task.main_path)) == expected_path
    )
    assert explicit_task.archive_input().format_hint == expected_format

    recursive = RecursiveAuthorization(config).authorize_batch(
        tasks,
        [str(game_dir)],
        session,
        depth=2,
    )
    assert expected_path not in _task_paths(recursive.allowed_tasks)
