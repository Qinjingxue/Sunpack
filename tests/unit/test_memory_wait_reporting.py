"""One coarse regression for independent memory/disk waits in CLI and watch.

The existing disk tests cannot detect a memory event being swallowed, becoming
a task failure, or clearing a simultaneous disk wait. No native process is needed.
"""
from io import StringIO
from types import SimpleNamespace

from sunpack.pipeline.coordinator.reporting import RunReporter
from sunpack.pipeline.extraction.internal.sevenzip.sevenzip_runner import _is_stale_resource_event
from sunpack.runtime.watch.toast import WatchToastCoordinator


def test_memory_wait_reaches_both_presenters_without_owning_task_state(tmp_path, monkeypatch):
    monkeypatch.setattr("sunpack.pipeline.coordinator.reporting._terminal_supports_updates", lambda _stream: True)
    snapshots = []
    host = SimpleNamespace(publish=snapshots.append, clear=lambda: None)
    watch = WatchToastCoordinator(host, {"cli": {"language": "zh"}, "watch": {}}, str(tmp_path / "state"))
    task = SimpleNamespace(key=str(tmp_path / "a.zip"), main_path=str(tmp_path / "a.zip"))
    output = StringIO()
    cli = RunReporter(language="zh", stdout=output)
    cli.tasks_discovered(1, [task])
    watch.submitted("request", task.main_path)
    episode_state = {}

    def deliver(event, episode=1):
        payload = {"type": "native_memory" if event.startswith("memory_") else "progress",
                   "event": event, "episode_id": episode, "job_id": "job", "volume_key": "volume"}
        if _is_stale_resource_event(episode_state, payload):
            return
        cli.task_progress(task, payload)
        watch.progress("request", task, payload)

    deliver("space_blocked")
    deliver("memory_blocked")
    assert "等待内存/磁盘" in output.getvalue().splitlines()[-1]
    assert snapshots[-1].progress_value_text == "等待内存/磁盘"
    assert "内存和磁盘空间恢复后自动继续" in snapshots[-1].progress_status
    deliver("space_resumed")
    deliver("space_blocked")  # A late callback from the same episode stays filtered.
    assert "内存" in snapshots[-1].progress_status
    assert "等待可用内存" in output.getvalue().splitlines()[-1]
    assert "磁盘" not in output.getvalue().splitlines()[-1]
    assert cli._task_rows[task.key]["state"] == "memory_paused"
    deliver("memory_resumed")
    restored = output.getvalue().splitlines()[-1]
    assert "正在解压" in restored and "内存" not in restored and "磁盘" not in restored
    assert "内存" not in snapshots[-1].progress_status
    assert cli._task_rows[task.key]["state"] == "extracting"
    watch.stop()
