from types import SimpleNamespace
import threading

from benchmarks.scenarios import worker_concurrency_300m as benchmark


def test_submission_does_not_block_stdout_callback(tmp_path, monkeypatch):
    """A bounded pipe write may need its stdout callback to run before returning."""
    class Worker:
        process = object()

        def submit_async(self, payload, job_id, *, on_line, on_timeout, parsed_events):
            def dispatch():
                on_line("", {"type": "native_event", "event": "job_started", "job_id": job_id})
                on_line("", {"type": "result", "status": "ok", "job_id": job_id})
                assert on_line("", {"type": "native_event", "event": "job_finished", "job_id": job_id})
            reader = threading.Thread(target=dispatch, daemon=True)
            reader.start()
            reader.join(timeout=1)
            assert not reader.is_alive(), "submission held the completion lock while writing stdin"

        def is_alive(self):
            return True

    monkeypatch.setattr(benchmark, "cpu_ms", lambda _: 0)
    monkeypatch.setattr(benchmark, "resolve_output_volume_key", lambda _: "volume")
    monkeypatch.setattr(benchmark, "_case_job", lambda item, **kwargs: {"job_id": kwargs["job_id"]})
    monkeypatch.setattr(benchmark, "ProcessSampler", lambda **_: SimpleNamespace(
        start=lambda: None, stop=lambda: None, samples=[SimpleNamespace(children_rss_mib=1)]))
    row = benchmark.run_worker(Worker(), [{"item": {}}] * 4, tmp_path / "out", 4, tmp_path / "7z.dll", 5)
    assert row["passed"]
    assert len(row["timeline"]) == 4


def test_validation_rejects_success_with_truncated_output(tmp_path, monkeypatch):
    monkeypatch.setattr(benchmark, "_output_summary", lambda _: {"file_count": 2, "total_bytes": 299 * benchmark.MIB})
    row = {"passed": True, "wall_ms": 100}
    benchmark.validate(row, [{"format": "zip"}], tmp_path, 300 * benchmark.MIB + 2560)
    assert not row["passed"]


def test_stream_validation_includes_tar_padding(tmp_path, monkeypatch):
    tar_bytes = 300 * benchmark.MIB + 2560
    monkeypatch.setattr(benchmark, "_output_summary", lambda _: {"file_count": 1, "total_bytes": tar_bytes})
    row = {"passed": True, "wall_ms": 100}
    benchmark.validate(row, [{"format": "xz"}], tmp_path, tar_bytes)
    assert row["passed"]
