"""Python 侧空间事件消费（T-EVT-1..T-EVT-14）。

对应《SunPack Worker 磁盘空间不足自动暂停与恢复实现文档.md》§10.5。

两条被测路径：
  * 纯状态机（`_worker_job_deadline` / `_on_space_event` /
    `_apply_native_event_to_job_state` / `_apply_native_environment`）—— 确定性、无进程；
  * 假 worker `.cmd` 脚本走完整 asyncio 分发路径 —— 证明事件真的能送到
    progress_callback，并且**看门狗不会误杀合法暂停的 job**。

⚠️ 最关键的两条回归：
  * T-EVT-13 stale event：native 在 gate 锁外发送，resumed(ep) 可能先于 blocked(ep)
    到达。若照单全收，space_waiting 会被永久置回 True。
  * T-EVT-1 job 生命周期状态不得被空间事件污染
    （否则 watch_memory / 基准测试读到的 state 会失真）。
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
from pathlib import Path

import pytest

from sunpack.contracts.detection import FactBag
from sunpack.contracts.tasks import ArchiveTask
from sunpack.extraction.internal.sevenzip.sevenzip_runner import (
    SevenZipRunner,
    _apply_native_environment,
    _apply_native_event_to_job_state,
    _on_space_event,
    _worker_job_deadline,
    _worker_job_due_reason,
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


def _running_state(**overrides) -> dict:
    state = {
        "state": "running",
        "last_progress_at": time.monotonic(),
        "no_progress_timeout": 180.0,
    }
    state.update(overrides)
    return state


def _task(archive: Path) -> ArchiveTask:
    return ArchiveTask(
        fact_bag=FactBag(),
        score=100,
        main_path=str(archive),
        all_parts=[str(archive)],
        key=str(archive),
    )


def _write_script(path: Path, lines: list[str], job_id: str = "event-job") -> Path:
    body = ['@echo {"type":"worker_ready"}', "@set /p request="]
    body.extend(lines)
    path.write_text("\r\n".join(body) + "\r\n", encoding="utf-8")
    return path


def _json_line(payload: dict) -> str:
    # cmd 的 echo 不处理引号，JSON 必须单行且不含 & | < >
    rendered = json.dumps(payload, ensure_ascii=True)
    assert not any(char in rendered for char in "&|<>"), rendered
    return "@echo " + rendered


def _write_python_worker(tmp_path: Path, events: list[dict], name: str = "space_worker") -> Path:
    """写一个**能回显真实 job_id** 的假 worker。

    ⚠️ 为什么不能用纯 `.cmd`：runner 在 `_build_job()` 里**自己生成** job_id
    （`f"{task.key}:{time.monotonic_ns()}"`）并覆盖调用方传入的值。硬编码 job_id 的
    `.cmd` 会被两条 dispatcher 当成"未知 job_id"直接丢弃 —— 事件根本到不了
    `progress_callback`，测试会以"UI 什么都没收到"的方式**假绿**。
    因此这里用 Python 脚本从 stdin 的请求 JSON 里取出真实 job_id 再回显。
    """

    script = tmp_path / f"{name}.py"
    script.write_text(
        "import json, sys\n"
        f"EVENTS = {events!r}\n"
        "print(json.dumps({'type': 'worker_ready'}), flush=True)\n"
        "for line in sys.stdin:\n"
        "    line = line.strip()\n"
        "    if not line:\n"
        "        continue\n"
        "    try:\n"
        "        request = json.loads(line)\n"
        "    except ValueError:\n"
        "        request = {}\n"
        "    command = request.get('worker_command')\n"
        "    if command == 'shutdown':\n"
        "        break\n"
        "    if command == 'cancel':\n"
        "        print(json.dumps({'type': 'cancel_ack', 'job_id': request.get('job_id', '')}),"
        " flush=True)\n"
        "        continue\n"
        "    job_id = str(request.get('job_id') or '')\n"
        "    for event in EVENTS:\n"
        "        print(json.dumps({**event, 'job_id': job_id}), flush=True)\n",
        encoding="utf-8",
    )
    runner = tmp_path / f"{name}.cmd"
    runner.write_text(
        f'@echo off\r\n"{sys.executable}" "{script}"\r\n',
        encoding="utf-8",
    )
    return runner


# ---------------------------------------------------------------------------
# T-EVT-1 事件送达且不污染 job 状态
# ---------------------------------------------------------------------------
def test_space_event_reaches_callback_without_polluting_job_state():
    from sunpack.extraction.internal.sevenzip.sevenzip_runner import _SPACE_ACCEPTED

    for event in ("space_blocked", "space_status", "space_resumed"):
        state = _running_state()
        outcome = _apply_native_event_to_job_state(state, _space_event(event))
        assert outcome == _SPACE_ACCEPTED, event
        assert state["state"] == "running", event


def test_only_job_events_write_the_lifecycle_state():
    state = _running_state()
    _apply_native_event_to_job_state(state, {"type": "progress", "event": "job_started"})
    assert state["state"] == "started"
    state = _running_state()
    _apply_native_event_to_job_state(state, {"type": "progress", "event": "job_finished"})
    assert state["state"] == "finished"
    state = _running_state()
    _apply_native_event_to_job_state(state, {"type": "result", "job_id": "x"})
    assert state["state"] == "result_received"


# ---------------------------------------------------------------------------
# T-EVT-2 / T-EVT-3 看门狗：合法暂停不触发，正常运行仍会触发
# ---------------------------------------------------------------------------
def test_space_waiting_suspends_the_no_progress_deadline():
    state = _running_state(last_progress_at=time.monotonic() - 3600.0)
    assert _worker_job_deadline(state) is not None
    _on_space_event(state, "space_blocked", _space_event("space_blocked"))
    assert state["space_waiting"] is True
    assert _worker_job_deadline(state) is None


def test_deadline_is_independent_of_poll_interval():
    # 看门狗配 0.05s（测试里的极端值）也不会误杀 space-blocked 的 job：
    # 它根本不再计时（与 space_poll_interval 完全解耦）。
    state = _running_state(no_progress_timeout=0.05, last_progress_at=time.monotonic() - 10.0)
    _on_space_event(state, "space_blocked", _space_event("space_blocked"))
    assert _worker_job_deadline(state) is None


# ---------------------------------------------------------------------------
# T-EVT-4 多 job 同卷：两个都不被取消
# ---------------------------------------------------------------------------
def test_multiple_jobs_on_the_same_volume_are_all_suspended():
    states = [_running_state(last_progress_at=time.monotonic() - 3600.0) for _ in range(2)]
    for index, state in enumerate(states):
        _on_space_event(
            state, "space_blocked", _space_event("space_blocked", job_id=f"job-{index}")
        )
    assert all(state["space_waiting"] is True for state in states)
    assert all(_worker_job_deadline(state) is None for state in states)


# ---------------------------------------------------------------------------
# T-EVT-5 暂停期间不得出现 result
# ---------------------------------------------------------------------------
def test_space_events_never_imply_a_result():
    state = _running_state()
    for event in ("space_blocked", "space_status", "space_resumed", "space_status"):
        _apply_native_event_to_job_state(state, _space_event(event))
        assert state["state"] != "result_received"


# ---------------------------------------------------------------------------
# T-EVT-6 显式取消优先于 space_waiting
# ---------------------------------------------------------------------------
def test_cancel_request_wins_over_space_waiting():
    state = _running_state(
        space_waiting=True,
        cancel_requested=True,
        cancel_deadline=time.monotonic() + 5.0,
    )
    deadline = _worker_job_deadline(state)
    assert deadline is not None
    assert deadline == pytest.approx(float(state["cancel_deadline"]))


# ---------------------------------------------------------------------------
# T-EVT-7 卷身份键形态
# ---------------------------------------------------------------------------
def test_volume_key_shape_is_lowercase_without_trailing_backslash():
    payload = _space_event("space_blocked")
    key = payload["volume_key"]
    assert key.startswith("\\\\?\\volume{")
    assert not key.endswith("\\")


# ---------------------------------------------------------------------------
# T-EVT-8 开关关闭 → 环境变量为 0，且不产生空间事件
# ---------------------------------------------------------------------------
def test_space_gate_environment_mapping():
    environment = _apply_native_environment({}, {"space_gate_enabled": False})
    assert environment["SUNPACK_VOLUME_SPACE_GATE"] == "0"

    environment = _apply_native_environment({}, {"space_gate_enabled": True})
    assert environment["SUNPACK_VOLUME_SPACE_GATE"] == "1"

    environment = _apply_native_environment({}, {"space_gate_enabled": "off"})
    assert environment["SUNPACK_VOLUME_SPACE_GATE"] == "0"

    # 未配置时不写入：native 侧保持它自己的默认值（Phase 6c 之后为 true，
    # 见 native/sevenzip_bridge/src/internal/sevenzip_writer_meters.hpp）。
    environment = _apply_native_environment({}, {})
    assert "SUNPACK_VOLUME_SPACE_GATE" not in environment

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


def test_advanced_config_default_enables_the_space_gate():
    """Phase 6c / R22 验收：**默认开启**（"默认值忘改 → 功能永不生效"的唯一防线）。

    与 native 侧 tests/space_retry.cpp 的 "Phase 6c default enabled" 用例配对：
    一个守 C++ 侧的 `AsyncWriterConfig` 默认值，一个守 Python 侧配置文件的默认值。
    """

    import json
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[2]
    data = json.loads((root / "sunpack_advanced_config.json").read_text(encoding="utf-8"))
    worker = data["performance"]["worker"]
    assert worker["space_gate_enabled"] is True
    assert int(worker["space_poll_interval_ms"]) >= 50
    assert int(worker["space_status_report_interval_ms"]) >= 1000


# ---------------------------------------------------------------------------
# T-EVT-9 恢复后重新计时
# ---------------------------------------------------------------------------
def test_resume_restarts_the_no_progress_clock():
    state = _running_state(last_progress_at=time.monotonic() - 3600.0)
    _on_space_event(state, "space_blocked", _space_event("space_blocked"))
    assert _worker_job_deadline(state) is None

    time.sleep(0.01)
    # 分发路径对**每一行**都刷新 last_progress_at（事件本身也算一次可观测活动），
    # 这里显式模拟它，然后断言恢复后看门狗从恢复点重新计时。
    before = state["last_progress_at"]
    state["last_progress_at"] = time.monotonic()
    _apply_native_event_to_job_state(state, _space_event("space_resumed"))

    assert state["space_waiting"] is False
    assert state["last_progress_at"] > before
    deadline = _worker_job_deadline(state)
    assert deadline is not None
    assert deadline > time.monotonic()


# ---------------------------------------------------------------------------
# T-EVT-10 未知 type / 未知 event 产生 debug 日志
# ---------------------------------------------------------------------------
def test_unknown_native_events_are_logged(caplog):
    with caplog.at_level("DEBUG"):
        state = _running_state()
        _apply_native_event_to_job_state(
            state, {"type": "native_unknown", "job_id": "x"}, __import__("logging").getLogger("t")
        )
        _apply_native_event_to_job_state(
            state, {"type": "progress", "event": "mystery_event"}, __import__("logging").getLogger("t")
        )
    assert any("native_unknown" in record.message for record in caplog.records)
    assert any("mystery_event" in record.message for record in caplog.records)


# ---------------------------------------------------------------------------
# T-EVT-11 space_waiting 遗留不影响终态
# ---------------------------------------------------------------------------
def test_leftover_space_waiting_does_not_block_job_completion():
    state = _running_state()
    _on_space_event(state, "space_blocked", _space_event("space_blocked"))
    assert state["space_waiting"] is True
    # 没有 space_resumed 也必须有终态路径：result 事件照常生效。
    _apply_native_event_to_job_state(state, {"type": "result", "job_id": "job-1"})
    assert state["state"] == "result_received"


# ---------------------------------------------------------------------------
# T-EVT-13 stale event 拒绝（架构师第 6 条）
# ---------------------------------------------------------------------------
def test_stale_blocked_after_resumed_is_rejected():
    state = _running_state()
    _on_space_event(state, "space_resumed", _space_event("space_resumed", episode=3))
    assert state["space_waiting"] is False
    # 锁外乱序：blocked(ep3) 后到 —— 必须被拒绝，最终仍为 False。
    _on_space_event(state, "space_blocked", _space_event("space_blocked", episode=3))
    assert state["space_waiting"] is False
    _on_space_event(state, "space_status", _space_event("space_status", episode=3))
    assert state["space_waiting"] is False


def test_stale_status_after_resumed_is_rejected():
    state = _running_state()
    _on_space_event(state, "space_blocked", _space_event("space_blocked", episode=7))
    _on_space_event(state, "space_resumed", _space_event("space_resumed", episode=7))
    _on_space_event(state, "space_status", _space_event("space_status", episode=7))
    assert state["space_waiting"] is False


# ---------------------------------------------------------------------------
# T-EVT-14 旧 episode 丢弃
# ---------------------------------------------------------------------------
def test_old_episode_events_are_dropped():
    state = _running_state()
    _on_space_event(state, "space_blocked", _space_event("space_blocked", episode=5))
    assert state["space_waiting"] is True
    _on_space_event(state, "space_blocked", _space_event("space_blocked", episode=4))
    assert state["space_episode"] == 5
    _on_space_event(state, "space_resumed", _space_event("space_resumed", episode=4))
    assert state["space_waiting"] is True  # 旧 episode 的 resumed 不得清除等待


def test_new_episode_resets_resumed_seen():
    state = _running_state()
    _on_space_event(state, "space_blocked", _space_event("space_blocked", episode=1))
    _on_space_event(state, "space_resumed", _space_event("space_resumed", episode=1))
    _on_space_event(state, "space_blocked", _space_event("space_blocked", episode=2))
    assert state["space_waiting"] is True
    assert state["space_resumed_seen"] is False


# ---------------------------------------------------------------------------
# T-EVT-15 stale 空间事件必须被**中央拦下**，不得送到 UI/Toast
# ---------------------------------------------------------------------------
def test_on_space_event_reports_acceptance():
    """`_on_space_event` 的返回值是全系统**唯一**的 stale 判定。"""

    from sunpack.extraction.internal.sevenzip.sevenzip_runner import (
        _SPACE_ACCEPTED,
        _SPACE_NOT_APPLICABLE,
        _SPACE_STALE,
    )

    state = _running_state()
    # 非空间事件 → NOT_APPLICABLE（交给既有 job 状态机）
    assert (
        _apply_native_event_to_job_state(state, {"type": "progress", "event": "job_started"})
        == _SPACE_NOT_APPLICABLE
    )
    assert state["state"] == "started"
    # 当前空间事件 → ACCEPTED
    assert (
        _apply_native_event_to_job_state(state, _space_event("space_blocked", episode=3))
        == _SPACE_ACCEPTED
    )
    assert state["space_waiting"] is True
    # resumed 之后迟到的 blocked / status → STALE
    assert (
        _apply_native_event_to_job_state(state, _space_event("space_resumed", episode=3))
        == _SPACE_ACCEPTED
    )
    assert state["space_waiting"] is False
    assert (
        _apply_native_event_to_job_state(state, _space_event("space_blocked", episode=3))
        == _SPACE_STALE
    )
    assert (
        _apply_native_event_to_job_state(state, _space_event("space_status", episode=3))
        == _SPACE_STALE
    )
    # 旧 episode 也是 STALE
    assert (
        _apply_native_event_to_job_state(state, _space_event("space_resumed", episode=2))
        == _SPACE_STALE
    )
    assert state["space_waiting"] is False, "stale 事件绝不能改变等待状态"


def test_stale_space_event_is_not_forwarded_to_the_ui(tmp_path):
    """端到端：native 按 resumed(ep3) → blocked(ep3) 乱序发送时，
    progress_callback（UI/Toast 的唯一入口）**只能**看到 resumed。

    修好之前：watchdog 正确（`space_waiting=False`），但 UI 会被迟到的 blocked
    重新打回"磁盘暂停"——三方状态不一致。
    """

    archive = tmp_path / "archive.zip"
    archive.write_bytes(b"payload")
    worker = _write_python_worker(
        tmp_path,
        [
            _space_event("space_blocked", episode=3),
            _space_event("space_resumed", episode=3),
            # ★ native 在 gate 锁外发送，这条 blocked(ep3) 晚到是合法的。
            _space_event("space_blocked", episode=3),
            _space_event("space_status", episode=3),
        ],
        name="stale_worker",
    )

    runner = SevenZipRunner(
        {
            # 足够长的看门狗：本用例要的是"事件被过滤"，不是看门狗行为。
            "watchdog_no_progress_timeout_seconds": 30,
            "cancel_grace_seconds": 0.5,
        }
    )
    runner.worker_path = str(worker)
    seen: list[dict] = []
    runner.progress_callback = lambda task, event: seen.append(event)

    async def run_attempt():
        try:
            await asyncio.wait_for(
                runner.submit_attempt_asyncio({"job_id": "event-job"}, task=_task(archive)),
                timeout=5,
            )
        except (asyncio.TimeoutError, TimeoutError):
            pass
        finally:
            await runner.aclose()

    asyncio.run(run_attempt())

    forwarded = [
        str(event.get("event"))
        for event in seen
        if str(event.get("event", "")).startswith("space_")
    ]
    assert forwarded == ["space_blocked", "space_resumed"], (
        "迟到的 blocked(ep3)/status(ep3) 必须在 dispatcher 层被拦下，"
        f"绝不能进 UI；实际转发序列：{forwarded}"
    )


# ---------------------------------------------------------------------------
# 端到端：假 worker 走完整 asyncio 分发路径
#
# ⚠️ 假 worker 只能证明**失败**路径（既有测试套件也只这样用它）：它无法产出让
#    runner 认为 job 成功的 result，因为真正的成功路径需要完整的 native 握手。
#    因此这里断言两件事：
#      1) 同一个极端看门狗下，space_waiting 的 job 不被取消，而沉默的 job 被取消
#         （T-EVT-2 / T-EVT-3 的直接对照，前者是纯状态机、后者是真进程）；
#      2) 空间事件确实按序送达 progress_callback（真进程 + 真分发线程）。
#    真实的"满盘 → 暂停 → 恢复 → 解压成功"端到端由 L4 VHD 用例
#    （tests/integration/test_disk_full_pause_resume.py，T-WIN-*）覆盖。
# ---------------------------------------------------------------------------
def test_aggressive_watchdog_never_cancels_a_space_waiting_job():
    now = time.monotonic()
    plain = _running_state(no_progress_timeout=0.05, last_progress_at=now - 1.0)
    blocked = _running_state(no_progress_timeout=0.05, last_progress_at=now - 1.0)
    _on_space_event(blocked, "space_blocked", _space_event("space_blocked"))

    # 对照组：没有任何空间事件的 job 在同一个 0.05s 看门狗下**确实**到期。
    assert _worker_job_due_reason(plain, now) is not None
    # 合法暂停：完全不计时。
    assert _worker_job_due_reason(blocked, now) is None

    # 恢复之后必须重新开始计时（否则 job 会永久逃过看门狗）。
    _on_space_event(blocked, "space_resumed", _space_event("space_resumed"))
    blocked["last_progress_at"] = now - 1.0
    assert _worker_job_due_reason(blocked, now) is not None


def test_control_job_without_events_is_still_cancelled_by_the_watchdog(tmp_path):
    archive = tmp_path / "archive.zip"
    archive.write_bytes(b"payload")
    # 不发任何事件、也不回应取消 → 必须被看门狗杀掉。
    worker = _write_script(
        tmp_path / "silent_worker.cmd",
        ["@set /p cancellation=", "@set /p shutdown="],
    )
    runner = SevenZipRunner(
        {
            "watchdog_no_progress_timeout_seconds": 0.05,
            "cancel_grace_seconds": 0.2,
        }
    )
    runner.worker_path = str(worker)

    async def run_attempt():
        try:
            return await asyncio.wait_for(
                runner.submit_attempt_asyncio({"job_id": "silent-job"}, task=_task(archive)),
                timeout=10,
            )
        finally:
            await runner.aclose()

    completed = asyncio.run(run_attempt())
    assert completed.returncode != 0
    assert completed.worker_diagnostics["process_failure"]["failure_kind"] == "timeout"
