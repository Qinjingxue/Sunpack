"""Verify resource-event ordering and disk monitoring configuration."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from tests.helpers.archive_tasks import make_archive_task
from tests.helpers.worker_events import launch_python_worker
from sunpack.pipeline.extraction.internal.sevenzip.sevenzip_runner import (
    SevenZipRunner,
    _apply_native_environment,
    _is_stale_resource_event,
)

pytestmark = pytest.mark.skipif(
    __import__("sys").platform != "win32", reason="native sevenzip worker is Windows-only"
)

VOLUME_KEY = r"\\?\volume{f4a20636-0610-11f1-9d1a-8c1645b0a1b2}"


def _space_event(event: str, episode: int = 3, **extra) -> dict:
    payload = {
        "type": "progress",
        "job_id": "job-1",
        "event": event,
        "volume_key": VOLUME_KEY,
        "episode_id": episode,
        "win32_error": 112,
        "free_bytes": 0,
        "pending_bytes": 73400320,
        "blocked_seconds": 45.0,
        "volume_query_ok": True,
        "volume_query_error": 0,
    }
    payload.update(extra)
    return payload


def _task(archive: Path):
    return make_archive_task(archive, key=str(archive))


def _write_python_worker(tmp_path: Path, events: list[dict], monkeypatch, name: str = "space_worker") -> Path:
    """写一个从请求回显 job_id 的假 worker，供 dispatcher 路由。"""

    script = tmp_path / f"{name}.py"
    script.write_text(
        "import sys\nfrom sunpack_native import encode_worker_frame, NativeWorkerFrameDecoder\n"
        f"EVENTS = {events!r}\n"
        "def emit(event):\n"
        "    sys.stdout.buffer.write(encode_worker_frame(event))\n"
        "    sys.stdout.buffer.flush()\n"
        "emit({'type': 'worker_ready', 'process_mode': 'normal', 'process_mode_applied': True})\n"
        "decoder = NativeWorkerFrameDecoder()\n"
        "while block := sys.stdin.buffer.read1(65536):\n"
        "    for request in decoder.feed(block):\n"
        "        command = request.get('worker_command')\n"
        "        if command == 'shutdown': sys.exit(0)\n"
        "        if command == 'cancel':\n"
        "            emit({'type': 'cancel_ack', 'job_id': request.get('job_id', '')})\n"
        "            continue\n"
        "        for event in EVENTS:\n"
        "            emit({**event, 'job_id': request.get('job_id', '')})\n",
        encoding="utf-8",
    )
    return launch_python_worker(monkeypatch, script)


def test_space_poll_intervals_environment_mapping():
    environment = _apply_native_environment(
        {},
        {
            "space_poll_interval_ms": 250,
            "space_status_report_interval_ms": 4000,
        },
    )
    assert environment["SUNPACK_VOLUME_SPACE_POLL_MS"] == "250"
    assert environment["SUNPACK_VOLUME_SPACE_STATUS_REPORT_MS"] == "4000"

    # 低于最小值时必须被忽略（native 侧也有同样的下界校验）。
    environment = _apply_native_environment(
        {}, {"space_poll_interval_ms": 1, "space_status_report_interval_ms": 5}
    )
    assert "SUNPACK_VOLUME_SPACE_POLL_MS" not in environment
    assert "SUNPACK_VOLUME_SPACE_STATUS_REPORT_MS" not in environment


def test_advanced_config_only_exposes_space_poll_intervals():
    """Space gates are unconditional; only polling intervals are configurable."""

    import json
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[2]
    data = json.loads((root / "sunpack_advanced_config.json").read_text(encoding="utf-8"))
    worker = data["performance"]["worker"]
    assert "space_gate_enabled" not in worker
    assert int(worker["space_poll_interval_ms"]) >= 50
    assert int(worker["space_status_report_interval_ms"]) >= 1000


def test_new_space_episode_accepts_status_and_discards_previous_episode():
    # The worker end-to-end tests exercise same-episode reordering. An earlier
    # resume/status must also be ignored after a new blocking episode starts.
    state = {}
    assert not _is_stale_resource_event(state, _space_event("space_blocked", episode=2))
    assert not _is_stale_resource_event(state, _space_event("space_resumed", episode=2))
    assert not _is_stale_resource_event(state, _space_event("space_status", episode=3))
    assert _is_stale_resource_event(state, _space_event("space_resumed", episode=2))
    assert _is_stale_resource_event(state, _space_event("space_status", episode=2))
    assert not _is_stale_resource_event(state, _space_event("space_blocked", episode=3))


@pytest.mark.parametrize("resource", ["space", "memory"])
def test_stale_resource_event_is_not_forwarded_to_the_ui(tmp_path, resource, monkeypatch):
    """端到端：native 按 resumed(ep3) → blocked(ep3) 乱序发送时，
    progress_callback（UI/Toast 的唯一入口）只能看到 resumed。
    """

    archive = tmp_path / "archive.zip"
    archive.write_bytes(b"payload")
    def event(name):
        return _space_event(f"{resource}_{name}", episode=3,
                            type="native_memory" if resource == "memory" else "progress")
    worker = _write_python_worker(
        tmp_path,
        [
            event("blocked"),
            event("resumed"),
            # native 在 gate 锁外发送，这条 blocked(ep3) 晚到是合法的。
            event("blocked"),
            event("blocked"),
            # 正常收尾，避免用固定 5s 超时等待一个永不完结的假 job。
            {"type": "result", "status": "ok"},
            {"type": "native_event", "event": "job_finished"},
        ],
        monkeypatch,
        name="stale_worker",
    )

    runner = SevenZipRunner({})
    runner.worker_path = str(worker)
    seen: list[dict] = []
    runner.progress_callback = lambda task, event: seen.append(event)

    async def run_attempt():
        try:
            completed = await asyncio.wait_for(
                runner.submit_attempt_asyncio({"job_id": "event-job"}, task=_task(archive)),
                timeout=5,
            )
            assert completed.returncode == 0, completed.stderr
        finally:
            await runner.aclose()

    asyncio.run(run_attempt())

    forwarded = [
        str(event.get("event"))
        for event in seen
        if str(event.get("event", "")).startswith(f"{resource}_")
    ]
    assert forwarded == [f"{resource}_blocked", f"{resource}_resumed"], (
        "迟到的 blocked(ep3)/status(ep3) 必须在 dispatcher 层被拦下，"
        f"绝不能进 UI；实际转发序列：{forwarded}"
    )
