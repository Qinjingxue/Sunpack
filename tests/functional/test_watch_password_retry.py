from __future__ import annotations

import asyncio
import subprocess
import time
import uuid

import pytest
from sunpack_native import zip_fast_verify_passwords

import sunpack.core.passwords.internal.builtin as builtin_module
import sunpack.core.passwords.internal.clipboard_monitor as clipboard_monitor_module
import sunpack.runtime.watch.scheduler as scheduler_module
from sunpack.core.config.loader import load_config
from sunpack.pipeline.coordinator.engine import PipelineEngine
from sunpack.runtime.watch.scheduler import WatchScheduler
from tests.helpers.tool_config import get_test_tools


@pytest.fixture(autouse=True)
def _isolate_password_pipeline_from_installed_broker(monkeypatch):
    monkeypatch.setattr(scheduler_module, "validate_ntfs_watch_roots", lambda _roots: None)


async def _wait_for_completed_watch_run(watcher: WatchScheduler, *, timeout: float = 10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = await watcher.run_once()
        if result.processed:
            return result
        await asyncio.sleep(0.01)
    pytest.fail("watch pipeline did not complete before timeout")


@pytest.mark.parametrize("source", ["directory", "watch_clipboard"])
def test_watch_retries_real_encrypted_zip_after_password_source_update(tmp_path, monkeypatch, source):
    seven_zip = get_test_tools().get("seven_zip")
    if seven_zip is None or not seven_zip.is_file():
        pytest.skip("7z.exe is required for encrypted watch retry coverage")

    watch_root = tmp_path / "watch"
    source_dir = tmp_path / "source"
    output_root = tmp_path / "out"
    watch_root.mkdir()
    source_dir.mkdir()
    output_root.mkdir()
    payload = "watch password retry payload"
    (source_dir / "payload.txt").write_text(payload, encoding="utf-8")
    # A per-test password prevents a prior run, clipboard entry, or configured
    # password source from turning the intended first failure into a success.
    password = f"watch-retry-secret-{uuid.uuid4().hex}"
    archive = watch_root / "encrypted.zip"
    completed = subprocess.run(
        [
            str(seven_zip),
            "a",
            "-tzip",
            f"-p{password}",
            "-mem=ZipCrypto",
            str(archive),
            "payload.txt",
            "-y",
        ],
        cwd=str(source_dir),
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    if completed.returncode != 0:
        pytest.skip(f"encrypted ZIP fixture could not be created: {completed.stderr or completed.stdout}")

    builtin_path = tmp_path / "builtin_passwords.txt"
    monkeypatch.setattr(builtin_module, "builtin_password_path", lambda: builtin_path)
    directory_password_file = watch_root / "sunpack-passwords.txt"
    if source == "directory":
        wrong_password = "wrong-password"
        while zip_fast_verify_passwords(str(archive), [wrong_password]).get("status") != "no_match":
            # Traditional ZipCrypto has only a one-byte header check, so an
            # arbitrary wrong password has a 1/256 false-positive chance.
            wrong_password = f"wrong-password-{uuid.uuid4().hex}"
        directory_password_file.write_text(wrong_password + "\n", encoding="utf-8")

    config = load_config()
    config["cli"] = {**(config.get("cli") or {}), "quiet": True}
    config["post_extract"] = {**config.get("post_extract", {}), "archive_cleanup_mode": "keep"}
    config["watch"] = {
        **config.get("watch", {}),
        "clipboard_monitor_enabled": source == "watch_clipboard",
        "password_retry_debounce_seconds": 0,
    }
    async def scenario():
        async with PipelineEngine(config) as engine:
            watcher = WatchScheduler(
                config, [str(watch_root)], out_dir=str(output_root),
                state_path=str(tmp_path / "state.json"), cold_start_seconds=0,
                initial_scan=False, pipeline_engine=engine,
            )
            watcher.enqueue(str(archive))
            first = await _wait_for_completed_watch_run(watcher)
            assert first.failed == 1, first
            first_entries = list(watcher.state.entries.values())
            assert len(first_entries) == 1, first_entries
            assert first_entries[0].status == "failed_password"
            if source == "directory":
                directory_password_file.write_text(password + "\n", encoding="utf-8")
                watcher.notify_password_table_changed(str(directory_password_file))
            else:
                monkeypatch.setattr(
                    clipboard_monitor_module,
                    "read_clipboard_passwords",
                    lambda *, single_line: [password],
                )
                watcher._clipboard_monitor._handle_clipboard_update()
            second = await _wait_for_completed_watch_run(watcher)
            return second, watcher, list(output_root.rglob("payload.txt"))
    second, watcher, extracted = asyncio.run(scenario())

    assert second.succeeded == 1
    assert not watcher.state.entries
    assert len(extracted) == 1
    assert extracted[0].read_text(encoding="utf-8") == payload
    if source == "watch_clipboard":
        assert password in builtin_path.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    "include_real_password",
    [True, False],
    ids=["later-success", "all-candidates-rejected"],
)
def test_watch_aggregates_all_zipcrypto_fast_matches(tmp_path, monkeypatch, include_real_password):
    seven_zip = get_test_tools().get("seven_zip")
    if seven_zip is None or not seven_zip.is_file():
        pytest.skip("7z.exe is required for ZipCrypto collision coverage")

    watch_root = tmp_path / "watch"
    source_dir = tmp_path / "source"
    output_root = tmp_path / "out"
    watch_root.mkdir()
    source_dir.mkdir()
    output_root.mkdir()
    payload = "zipcrypto collision payload " * 512
    (source_dir / "payload.txt").write_text(payload, encoding="utf-8")
    password = f"collision-secret-{uuid.uuid4().hex}"
    archive = watch_root / "encrypted.zip"
    completed = subprocess.run(
        [
            str(seven_zip),
            "a",
            "-tzip",
            f"-p{password}",
            "-mem=ZipCrypto",
            "-mx=0",
            str(archive),
            "payload.txt",
            "-y",
        ],
        cwd=str(source_dir),
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    if completed.returncode != 0:
        pytest.skip(f"encrypted ZIP fixture could not be created: {completed.stderr or completed.stdout}")

    wrong_candidates = [f"collision-wrong-{index}" for index in range(4096)]
    collision_result = zip_fast_verify_passwords(str(archive), wrong_candidates)
    matched_indices = tuple(collision_result.get("matched_indices") or ())
    if not matched_indices:
        pytest.skip("no deterministic ZipCrypto one-byte collision found")
    collision = wrong_candidates[int(matched_indices[0])]
    supplied_passwords = [collision, *([password] if include_real_password else [])]
    combined = zip_fast_verify_passwords(str(archive), supplied_passwords)
    assert tuple(combined.get("matched_indices") or ()) == tuple(range(len(supplied_passwords)))

    builtin_path = tmp_path / "builtin_passwords.txt"
    monkeypatch.setattr(builtin_module, "builtin_password_path", lambda: builtin_path)
    (watch_root / "sunpack-passwords.txt").write_text(
        "".join(f"{candidate}\n" for candidate in supplied_passwords),
        encoding="utf-8",
    )
    config = load_config()
    config["cli"] = {**(config.get("cli") or {}), "quiet": True}
    config["post_extract"] = {**config.get("post_extract", {}), "archive_cleanup_mode": "keep"}
    config["watch"] = {
        **config.get("watch", {}),
        "clipboard_monitor_enabled": False,
        "password_retry_debounce_seconds": 0,
    }
    async def scenario():
        async with PipelineEngine(config) as engine:
            watcher = WatchScheduler(
                config, [str(watch_root)], out_dir=str(output_root),
                state_path=str(tmp_path / "state.json"), cold_start_seconds=0,
                initial_scan=False, pipeline_engine=engine,
            )
            watcher.enqueue(str(archive))
            result = await _wait_for_completed_watch_run(watcher)
            return result, watcher, list(output_root.rglob("payload.txt"))
    result, watcher, extracted = asyncio.run(scenario())

    assert result.succeeded == (1 if include_real_password else 0), result
    assert result.failed == (0 if include_real_password else 1), result
    if include_real_password:
        assert not watcher.state.entries
        assert len(extracted) == 1
        assert extracted[0].read_text(encoding="utf-8") == payload
    else:
        entries = list(watcher.state.entries.values())
        assert len(entries) == 1, entries
        assert entries[0].status == "failed_password"
        assert entries[0].failure_payload["kind"] == "wrong_password"
        assert entries[0].failure_payload["blockers"] == ["password"]
        assert extracted == []
