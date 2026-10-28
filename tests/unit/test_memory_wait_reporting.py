"""One coarse regression for independent memory/disk waits in CLI and watch.

The existing disk tests cannot detect a memory event being swallowed, becoming
a task failure, or clearing a simultaneous disk wait. No native process is needed.
"""
from io import StringIO
from types import SimpleNamespace

from sunpack.pipeline.coordinator.reporting import RunReporter
from sunpack.pipeline.extraction.internal.sevenzip.sevenzip_runner import _apply_native_event_to_job_state
from sunpack.runtime.watch.toast import WatchToastCoordinator


def test_memory_wait_reaches_both_presenters_without_owning_task_state(tmp_path):
    snapshots = []
    host = SimpleNamespace(publish=snapshots.append, clear=lambda: None)
    watch = WatchToastCoordinator(host, {"cli": {"language": "zh"}, "watch": {}}, str(tmp_path / "state"))
    task = SimpleNamespace(main_path=str(tmp_path / "a.zip"))
    output = StringIO()
    cli = RunReporter(language="zh", stdout=output)
    cli.tasks_discovered(1, [task])
    watch.submitted("request", task.main_path)
    state = {"state": "running"}

    def deliver(event, episode=1):
        payload = {"type": "native_memory" if event.startswith("memory_") else "progress",
                   "event": event, "episode_id": episode, "job_id": "job", "volume_key": "volume"}
        _apply_native_event_to_job_state(state, payload)
        cli.task_progress(task, payload)
        watch.progress("request", task, payload)

    deliver("space_blocked")
    deliver("memory_blocked")
    assert state["state"] == "running" and state["memory_waiting"] and state["space_waiting"]
    assert "等待内存/磁盘" in output.getvalue().splitlines()[-1]
    assert snapshots[-1].progress_value_text == "等待内存/磁盘"
    assert "内存和磁盘空间恢复后自动继续" in snapshots[-1].progress_status
    deliver("space_resumed")
    assert "内存" in snapshots[-1].progress_status
    assert "等待可用内存" in output.getvalue().splitlines()[-1]
    assert "磁盘" not in output.getvalue().splitlines()[-1]
    assert cli._task_rows[id(task)]["state"] == "memory_paused"
    deliver("memory_resumed")
    assert not state["memory_waiting"] and not state["space_waiting"]
    restored = output.getvalue().splitlines()[-1]
    assert "正在解压" in restored and "内存" not in restored and "磁盘" not in restored
    assert "内存" not in snapshots[-1].progress_status
    assert cli._task_rows[id(task)]["state"] == "extracting"
    # A late blocked event cannot resurrect an already-resumed wait.
    assert _apply_native_event_to_job_state(state, {
        "type": "native_memory", "event": "memory_blocked", "episode_id": 1,
    }) == "stale"
    assert state["state"] == "running" and not state["memory_waiting"]
    watch.stop()
