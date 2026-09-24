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


_TYRANO_GAME_A = {
    "builder_config.json": b"{}",
    "credits.html": b"credits",
    "data/scenario/start.ks": b"*start",
    "data/image/title.png": b"image-data",
    "node_modules/nw/package.json": b"{}",
    "tyrano/tyrano.js": b"window.TYRANO = {};",
}
_TYRANO_GAME_B = {
    "builder_config.json": b"{}",
    "credits.html": b"credits",
    "data/scenario/prologue.ks": b"*prologue",
    "data/bgm/theme.ogg": b"audio-data",
    "node_modules/nw/package.json": b"{}",
    "tyrano/tyrano.js": b"window.TYRANO = {};",
}

_NSIS_OVERLAY_HEADER = b"\x04\x00\x00\x00\xef\xbe\xad\xdeNullsoftInst\x00\x00\x00\x00"


_EXECUTABLE_RESOURCE_CASES = [
    pytest.param(
        "setup_nsis.exe",
        _minimal_pe_stub(),
        _NSIS_OVERLAY_HEADER + make_minimal_7z(),
        "7z",
        id="nsis-marker-with-7z-overlay",
    ),
    pytest.param(
        "tyrano_game_a.exe",
        _minimal_pe_stub(),
        _zip_archive(_TYRANO_GAME_A),
        "zip",
        id="tyrano-game-a-with-zip-overlay",
    ),
    pytest.param(
        "tyrano_game_b.exe",
        _minimal_pe_stub(),
        _zip_archive(_TYRANO_GAME_B),
        "zip",
        id="tyrano-game-b-with-zip-overlay",
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
    pe_image: bytes,
    embedded_archive: bytes,
) -> tuple[Path, Path]:
    game_dir = root / "game"
    game_dir.mkdir()
    executable = game_dir / filename
    executable.write_bytes(pe_image + embedded_archive)

    # Model the surrounding installed game files. These make the EXE a tiny
    # share of a recursive output directory, as in the real game tree.
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


@pytest.mark.parametrize("force_scan", [False, True], ids=["default", "deep-scan"])
def test_initial_directory_scan_requires_deep_scan_for_nsis(tmp_path: Path, force_scan: bool):
    game_dir, executable = _make_game_tree(
        tmp_path,
        "setup_nsis.exe",
        _minimal_pe_stub(),
        _NSIS_OVERLAY_HEADER + make_minimal_7z(),
    )
    config = _config()
    tasks = ArchiveTaskProvider(
        config,
        EmbeddedOptions(force_scan=force_scan),
    ).scan_targets([str(game_dir)], is_recursive_scan=False)
    matches = [
        task for task in tasks
        if os.path.normcase(os.path.abspath(task.main_path))
        == os.path.normcase(os.path.abspath(executable))
    ]

    if force_scan:
        assert len(matches) == 1
        assert matches[0].archive_input().format_hint == "7z"
    else:
        assert matches == []


@pytest.mark.parametrize(
    ("filename", "pe_image", "embedded_archive", "expected_format"),
    _EXECUTABLE_RESOURCE_CASES[1:],
)
def test_explicit_game_directory_scan_finds_tyrano_zip_overlay(
    tmp_path: Path,
    filename: str,
    pe_image: bytes,
    embedded_archive: bytes,
    expected_format: str,
):
    game_dir, executable = _make_game_tree(
        tmp_path,
        filename,
        pe_image,
        embedded_archive,
    )
    config = _config()
    session = DiscoveryScanSession(config=config)
    tasks = ArchiveTaskProvider(config).scan_targets(
        [str(game_dir)],
        scan_session=session,
        is_recursive_scan=False,
    )

    expected_path = os.path.normcase(os.path.abspath(executable))
    explicit_task = next(
        task for task in tasks
        if os.path.normcase(os.path.abspath(task.main_path)) == expected_path
    )
    descriptor = explicit_task.archive_input()
    assert descriptor.format_hint == expected_format
    assert descriptor.open_mode == "file_range"
    initial_scope = RecursiveAuthorization(config).authorize_batch(
        tasks,
        [str(game_dir)],
        session,
        round_index=1,
    )
    assert os.path.normcase(os.path.abspath(executable)) in _task_paths(
        initial_scope.allowed_tasks
    )


@pytest.mark.parametrize(
    ("filename", "pe_image", "embedded_archive", "expected_format"),
    _EXECUTABLE_RESOURCE_CASES,
)
def test_recursive_output_scan_does_not_promote_low_share_executable_resources(
    tmp_path: Path,
    filename: str,
    pe_image: bytes,
    embedded_archive: bytes,
    expected_format: str,
):
    game_dir, executable = _make_game_tree(
        tmp_path,
        filename,
        pe_image,
        embedded_archive,
    )
    config = _config()
    session = DiscoveryScanSession(config=config)
    tasks = ArchiveTaskProvider(config).scan_targets(
        [str(game_dir)],
        scan_session=session,
        is_recursive_scan=True,
    )

    file_sizes = {
        os.path.normcase(os.path.abspath(path)): size
        for path, size, _mtime_ns in session.snapshot_for_directory(
            str(game_dir)
        ).iter_file_columns()
    }
    expected_path = os.path.normcase(os.path.abspath(executable))
    assert expected_path in file_sizes
    assert file_sizes[expected_path] / sum(file_sizes.values()) < 0.3

    assert expected_path not in _task_paths(tasks), (
        f"recursive output scanning promoted the {expected_format} payload in "
        f"{filename} despite its low share "
        f"of the game directory: {[task.main_path for task in tasks]}"
    )


@pytest.mark.parametrize(
    ("filename", "pe_image", "embedded_archive", "expected_format"),
    _EXECUTABLE_RESOURCE_CASES,
)
def test_recursive_authorization_rejects_discovered_game_resource_executables(
    tmp_path: Path,
    filename: str,
    pe_image: bytes,
    embedded_archive: bytes,
    expected_format: str,
):
    game_dir, executable = _make_game_tree(
        tmp_path,
        filename,
        pe_image,
        embedded_archive,
    )
    config = _config()
    session = DiscoveryScanSession(config=config)
    provider = ArchiveTaskProvider(
        config,
        EmbeddedOptions(force_scan=filename == "setup_nsis.exe"),
    )
    tasks = provider.scan_targets(
        [str(game_dir)],
        scan_session=session,
        is_recursive_scan=False,
    )
    assert os.path.normcase(os.path.abspath(executable)) in _task_paths(tasks)
    explicit_task = next(
        task for task in tasks
        if os.path.normcase(os.path.abspath(task.main_path))
        == os.path.normcase(os.path.abspath(executable))
    )
    assert explicit_task.archive_input().format_hint == expected_format

    recursive = RecursiveAuthorization(config).authorize_batch(
        tasks,
        [str(game_dir)],
        session,
        round_index=2,
    )

    assert os.path.normcase(os.path.abspath(executable)) not in _task_paths(
        recursive.allowed_tasks
    )
