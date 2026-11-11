from __future__ import annotations

import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass

import psutil


def bytes_to_mib(value: int | float) -> float:
    return float(value) / 1024**2


@dataclass(frozen=True)
class ProcessSample:
    elapsed_ms: float
    rss_mib: float
    private_mib: float
    process_count: int
    threads: int
    handles: int
    broker_process_count: int
    broker_rss_mib: float
    broker_private_mib: float

    def to_dict(self) -> dict:
        return asdict(self)


class ProcessSampler:
    """Sample the staged runtime and, for Watch, its dedicated SCM service."""

    def __init__(
        self, interval_seconds: float = 0.1, *,
        processes: Callable[[], Iterable[psutil.Process]],
        broker_processes: Callable[[], Iterable[psutil.Process]] = tuple,
    ):
        if interval_seconds <= 0:
            raise ValueError("interval_seconds must be positive")
        self.interval_seconds = interval_seconds
        self.samples: list[ProcessSample] = []
        self._processes = processes
        self._broker_processes = broker_processes
        self._stop = threading.Event()
        self._sample_lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._started = 0.0

    def take(self) -> ProcessSample:
        with self._sample_lock:
            return self._take()

    def _take(self) -> ProcessSample:
        rss = private = threads = handles = count = 0
        broker_count = broker_rss = broker_private = 0
        seen = set()
        for broker, group in ((True, self._broker_processes()), (False, self._processes())):
            for process in group:
                if process.pid in seen:
                    continue
                seen.add(process.pid)
                try:
                    info = process.memory_info()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                rss += info.rss
                committed = int(getattr(info, "private", 0) or 0)
                private += committed
                count += 1
                if broker:
                    broker_count += 1
                    broker_rss += info.rss
                    broker_private += committed
                try:
                    threads += process.num_threads()
                    handles += process.num_handles()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        sample = ProcessSample(
            elapsed_ms=(time.perf_counter() - self._started) * 1000 if self._started else 0.0,
            rss_mib=bytes_to_mib(rss), private_mib=bytes_to_mib(private),
            process_count=count, threads=threads, handles=handles,
            broker_process_count=broker_count, broker_rss_mib=bytes_to_mib(broker_rss),
            broker_private_mib=bytes_to_mib(broker_private),
        )
        self.samples.append(sample)
        return sample

    def start(self) -> None:
        if self._thread is not None:
            raise RuntimeError("sampler is already running")
        self._started = time.perf_counter()
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="benchmark-native-sampler", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        self.take()
        while not self._stop.wait(self.interval_seconds):
            self.take()

    def stop(self) -> list[ProcessSample]:
        if self._thread is not None:
            self._stop.set()
            self._thread.join()
            self._thread = None
            self.take()
        return self.samples

    def __enter__(self) -> "ProcessSampler":
        self.start()
        return self

    def __exit__(self, *_exc) -> None:
        self.stop()
