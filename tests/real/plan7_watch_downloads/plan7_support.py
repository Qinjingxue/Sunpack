from __future__ import annotations

import json
import asyncio
import functools
import os
import random
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import pytest

from sunpack.pipeline.coordinator.engine import PipelineEngine
from sunpack.runtime.watch.scheduler import WatchRunResult, WatchScheduler
from tests.helpers.watch_memory import WatchMemorySampler as MemorySampler
from tests.helpers.marker_utils import marker_scan_state
from tests.helpers.real_archives import (
    ArchiveCase,
    ArchiveFixtureFactory,
    create_encrypted_7z_archive,
    create_encrypted_rar_archive,
    create_encrypted_zip_archive,
)
from tests.real.plan1_real_archives.plan1_support import (
    PLAIN_FORMATS as PLAN1_PLAIN_FORMATS,
    plan1_config,
)


PASSWORD = "sunpack-plan7-acceptance"
WRONG_PASSWORD_COUNT = 24
DOWNLOAD_CHUNK_SIZE = 16 * 1024
CHUNK_DELAY_SECONDS = 0.001
MAX_REACTION_LATENCY_SECONDS = 15.0
MAX_COMPLETION_LATENCY_SECONDS = 60.0
MAX_WATCH_TICK_LATENCY_SECONDS = 5.0
PLAIN_PAYLOAD_SIZE = 64 * 1024
SPLIT_PAYLOAD_SIZE = 420 * 1024

# 第 7 条格式矩阵：普通/SFX 单文件 + 分卷/SFX 分卷。
PLAIN_FORMATS = tuple(PLAN1_PLAIN_FORMATS)
SFX_FORMATS = ("7z", "zip", "rar")
SPLIT_FORMATS = ("7z", "zip", "rar")

FACTORY = ArchiveFixtureFactory()


class Plan7Timing:
    """按阶段记录一个 plan7 测试内部的耗时，用于定位测试慢的原因。"""

    def __init__(self) -> None:
        self._phases: dict[str, list[float]] = {}

    def record(self, phase: str, seconds: float) -> None:
        self._phases.setdefault(phase, []).append(seconds)

    @contextmanager
    def measure(self, phase: str):
        started = time.perf_counter()
        try:
            yield
        finally:
            self.record(phase, time.perf_counter() - started)

    def summary(self) -> dict[str, dict[str, float]]:
        return {
            name: {
                "calls": len(values),
                "total": round(sum(values), 4),
                "max": round(max(values), 4),
            }
            for name, values in self._phases.items()
        }

    def report(self, title: str = "plan7 timing") -> str:
        rows = sorted(
            (
                (name, len(values), sum(values), max(values))
                for name, values in self._phases.items()
            ),
            key=lambda row: row[2],
            reverse=True,
        )
        lines = [f"== {title} =="]
        for name, calls, total, peak in rows:
            lines.append(f"  {name:<42s} {calls:>4d}x  {total:9.3f}s  (max {peak:9.3f}s)")
        return "\n".join(lines)


# 归档夹具生成耗时（build_*_cases 在 start_watch 之前执行，单独累计）。
FIXTURE_BUILD_TIMING: dict[str, float] = {}
_FIXTURE_TIMING_LAST_PRINTED: dict[str, float] = {}


def fixture_build_deltas() -> dict[str, float]:
    """FIXTURE_BUILD_TIMING 自上次调用以来的增量（按 pytest 进程内测试划分）。"""
    deltas = {
        key: round(value - _FIXTURE_TIMING_LAST_PRINTED.get(key, 0.0), 3)
        for key, value in FIXTURE_BUILD_TIMING.items()
    }
    _FIXTURE_TIMING_LAST_PRINTED.update(FIXTURE_BUILD_TIMING)
    return deltas


def _recorded_fixture_build(key: str):
    def decorate(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            started = time.perf_counter()
            try:
                return func(*args, **kwargs)
            finally:
                FIXTURE_BUILD_TIMING[key] = (
                    FIXTURE_BUILD_TIMING.get(key, 0.0) + time.perf_counter() - started
                )

        return wrapper

    return decorate


@dataclass
class Plan7Case:
    key: str
    archive_format: str
    kind: str  # plain / sfx / split / sfx_split
    case: ArchiveCase
    stable_at: float = 0.0
    first_submission_at: float | None = None
    reaction_latency: float | None = None
    completion_latency: float | None = None


@dataclass(frozen=True)
class SubmissionEvent:
    at: float
    paths: tuple[str, ...]


@dataclass
class WatchHarness:
    watch_root: Path
    output_root: Path
    config: dict[str, Any]
    engine: Any
    watcher: WatchScheduler
    submit_times: list[float] = field(default_factory=list)
    submission_events: list[SubmissionEvent] = field(default_factory=list)
    stable_at_by_name: dict[str, float] = field(default_factory=dict)
    loop: asyncio.AbstractEventLoop | None = None
    delegate: PipelineEngine | None = None
    async_stop: Any = None
    run_durations: list[float] = field(default_factory=list)
    timer: Plan7Timing = field(default_factory=Plan7Timing)
    label: str = "watch"

    def close(self) -> None:
        if self.loop is None:
            return
        with self.timer.measure("watch_close"):
            if self.async_stop is not None:
                self.loop.run_until_complete(self.async_stop())
            if self.delegate is not None:
                self.loop.run_until_complete(self.delegate.aclose())
            self.loop.close()
            self.loop = None
        print(self.timer.report(f"plan7 timing ({self.label})"))


class _TimedPipelineEngine:
    """记录 pipeline 提交次数与每次提交耗时，用于断言与耗时分析。"""

    def __init__(
        self,
        delegate: PipelineEngine,
        submit_times: list[float],
        submission_events: list[SubmissionEvent],
        run_durations: list[float],
        timer: Plan7Timing,
    ):
        self.delegate = delegate
        self.submit_times = submit_times
        self.submission_events = submission_events
        self.run_durations = run_durations
        self.timer = timer

    async def run(self, *args, **kwargs):
        submitted_at = time.perf_counter()
        self.submit_times.append(submitted_at)
        targets = args[0] if args else kwargs.get("targets", ())
        self.submission_events.append(SubmissionEvent(
            at=submitted_at,
            paths=tuple(
                str(getattr(target, "path", target))
                for target in targets
            ),
        ))
        started = time.perf_counter()
        try:
            return await self.delegate.run(*args, **kwargs)
        finally:
            duration = time.perf_counter() - started
            self.run_durations.append(duration)
            self.timer.record("pipeline_run", duration)

    def __getattr__(self, name):
        return getattr(self.delegate, name)


def plan7_watch_config(passwords: list[str] | None = None) -> dict:
    """plan1 全检测配置 + watch 运行参数（保留持久 worker 以观察内存）。"""
    config = plan1_config(passwords=passwords or [PASSWORD])
    config["cli"] = {**(config.get("cli") or {}), "quiet": True}
    config["post_extract"] = {
        **(config.get("post_extract") or {}),
        "archive_cleanup_mode": "keep",
        "flatten_single_directory": False,
    }
    config["watch"] = {
        **(config.get("watch") or {}),
        "clipboard_monitor_enabled": False,
        "password_retry_debounce_seconds": 0,
    }
    config["user_passwords"] = [f"wrong-{index:02d}" for index in range(WRONG_PASSWORD_COUNT)]
    config["user_passwords"].extend(passwords or [PASSWORD])
    config["builtin_passwords"] = []
    return config


def expected_submission_names(plan7_case: Plan7Case) -> tuple[str, ...]:
    """Return the path names the watch pipeline should submit for this case."""
    case = plan7_case.case
    if not case.split or case.archive_format not in {"7z", "zip"}:
        return (case.entry_path.name,)
    suffix = f".{case.archive_format}.001"
    heads = sorted(
        path.name
        for path in case.archive_dir.iterdir()
        if path.is_file() and path.name.casefold().endswith(suffix)
    )
    if not heads:
        raise AssertionError(f"no data-volume head found for {plan7_case.key}")
    return (heads[0],)


def input_volume_names(plan7_case: Plan7Case) -> tuple[str, ...]:
    """Return archive input names, excluding launcher-only SFX companions."""
    case = plan7_case.case
    if not case.split:
        return (case.entry_path.name,)
    if case.archive_format in {"7z", "zip"} and case.sfx:
        return tuple(sorted(
            path.name
            for path in case.archive_dir.iterdir()
            if path.is_file() and path.suffix.casefold() != ".exe"
        ))
    return tuple(sorted(path.name for path in case.archive_dir.iterdir() if path.is_file()))


def owned_names(plan7_case: Plan7Case) -> tuple[str, ...]:
    return tuple(sorted(path.name for path in plan7_case.case.archive_dir.iterdir() if path.is_file()))


def wrong_password_list() -> list[str]:
    return [f"wrong-{index:02d}" for index in range(WRONG_PASSWORD_COUNT)]


@_recorded_fixture_build("plain_sfx")
def build_plain_sfx_cases(root: Path) -> tuple[dict[str, Plan7Case], list[str]]:
    """普通压缩包（zip/rar/7z 加密 + tar/流格式）与 SFX 压缩包。"""
    cases: dict[str, Plan7Case] = {}
    skipped: list[str] = []
    for fmt in PLAIN_FORMATS:
        encrypted = fmt in {"zip", "rar", "7z"}
        key = f"plain_{fmt}"
        try:
            case = FACTORY.create(
                root,
                f"p7_{key}",
                fmt,
                password=PASSWORD if encrypted else None,
                payload_size=PLAIN_PAYLOAD_SIZE,
            )
        except (FileNotFoundError, RuntimeError) as exc:
            skipped.append(f"{key}: {exc}")
            continue
        cases[key] = Plan7Case(key=key, archive_format=fmt, kind="plain", case=case)
    for fmt in SFX_FORMATS:
        key = f"sfx_{fmt}"
        try:
            case = FACTORY.create(
                root,
                f"p7_{key}",
                fmt,
                password=PASSWORD,
                sfx=True,
                payload_size=PLAIN_PAYLOAD_SIZE,
            )
        except (FileNotFoundError, RuntimeError) as exc:
            skipped.append(f"{key}: {exc}")
            continue
        cases[key] = Plan7Case(key=key, archive_format=fmt, kind="sfx", case=case)
    return cases, skipped


@_recorded_fixture_build("split")
def build_split_cases(root: Path) -> tuple[dict[str, Plan7Case], list[str]]:
    """各种形式分卷压缩包与 SFX 分卷压缩包（全部加密）。"""
    cases: dict[str, Plan7Case] = {}
    skipped: list[str] = []
    for fmt in SPLIT_FORMATS:
        for kind in ("split", "sfx_split"):
            key = f"{kind}_{fmt}"
            try:
                case = FACTORY.create(
                    root,
                    f"p7_{key}",
                    fmt,
                    password=PASSWORD,
                    split=True,
                    sfx=(kind == "sfx_split"),
                    payload_size=SPLIT_PAYLOAD_SIZE,
                )
            except (FileNotFoundError, RuntimeError) as exc:
                skipped.append(f"{key}: {exc}")
                continue
            cases[key] = Plan7Case(
                key=key,
                archive_format=fmt,
                kind=kind,
                case=case,
            )
    return cases, skipped


@_recorded_fixture_build("variants")
def build_encryption_variant_cases(root: Path) -> tuple[dict[str, Plan7Case], list[str]]:
    """Build watch cases for encryption/header and RAR generation variants."""
    root = Path(root)
    cases: dict[str, Plan7Case] = {}
    skipped: list[str] = []
    creators = (
        (
            "variant_7z_header_off",
            "7z",
            lambda: create_encrypted_7z_archive(
                root,
                "p7_variant_7z_header_off",
                password=PASSWORD,
                header_encrypt=False,
                payload_size=96 * 1024,
            ),
        ),
        (
            "variant_zipcrypto",
            "zip",
            lambda: create_encrypted_zip_archive(
                root,
                "p7_variant_zipcrypto",
                password=PASSWORD,
                encryption="ZipCrypto",
                payload_size=96 * 1024,
            ),
        ),
        (
            "variant_zip_aes256",
            "zip",
            lambda: create_encrypted_zip_archive(
                root,
                "p7_variant_zip_aes256",
                password=PASSWORD,
                encryption="AES256",
                payload_size=96 * 1024,
            ),
        ),
        (
            "variant_rar4_header",
            "rar",
            lambda: create_encrypted_rar_archive(
                root,
                "p7_variant_rar4_header",
                password=PASSWORD,
                rar4=True,
                header_encrypt=True,
                payload_size=96 * 1024,
            ),
        ),
        (
            "variant_rar4_data",
            "rar",
            lambda: create_encrypted_rar_archive(
                root,
                "p7_variant_rar4_data",
                password=PASSWORD,
                rar4=True,
                header_encrypt=False,
                payload_size=96 * 1024,
            ),
        ),
    )
    for key, archive_format, creator in creators:
        try:
            cases[key] = Plan7Case(
                key=key,
                archive_format=archive_format,
                kind="variant",
                case=creator(),
            )
        except (FileNotFoundError, RuntimeError) as exc:
            skipped.append(f"{key}: {exc}")
    return cases, skipped


@_recorded_fixture_build("disguised")
def build_disguised_cases(root: Path) -> tuple[dict[str, Plan7Case], list[str]]:
    """Build extension-disguised and carrier-prefixed watch inputs."""
    cases: dict[str, Plan7Case] = {}
    skipped: list[str] = []
    definitions = (
        ("disguised_7z", "7z", {"disguise_ext": ".payload"}),
        ("carrier_zip", "zip", {"carrier": "jpg"}),
        ("disguised_rar", "rar", {"disguise_ext": ".payload"}),
    )
    for key, archive_format, options in definitions:
        try:
            cases[key] = Plan7Case(
                key=key,
                archive_format=archive_format,
                kind="disguised",
                case=FACTORY.create(
                    root,
                    f"p7_{key}",
                    archive_format,
                    password=PASSWORD,
                    payload_size=96 * 1024,
                    **options,
                ),
            )
        except (FileNotFoundError, RuntimeError) as exc:
            skipped.append(f"{key}: {exc}")
    return cases, skipped


@_recorded_fixture_build("embedded")
def build_embedded_watch_cases(root: Path) -> tuple[dict[str, Plan7Case], list[str]]:
    """Build three independent files, each containing one archive format."""
    cases: dict[str, Plan7Case] = {}
    skipped: list[str] = []
    for archive_format in ("7z", "zip", "rar"):
        key = f"embedded_{archive_format}"
        try:
            case = FACTORY.create(
                root,
                f"p7_source_{key}",
                archive_format,
                password=PASSWORD,
                payload_size=64 * 1024,
            )
            raw = case.entry_path.read_bytes()
            embedded_path = case.archive_dir / f"p7_{key}.bin"
            embedded_path.write_bytes(
                f"PLAN7-EMBEDDED-{archive_format}-PREFIX".encode("ascii")
                + raw
                + f"-PLAN7-EMBEDDED-{archive_format}-SUFFIX".encode("ascii")
            )
            case.entry_path.unlink()
            case.entry_path = embedded_path
            cases[key] = Plan7Case(
                key=key,
                archive_format=archive_format,
                kind="embedded",
                case=case,
            )
        except (FileNotFoundError, RuntimeError) as exc:
            skipped.append(f"{key}: {exc}")
    return cases, skipped


def start_watch(
    tmp_path: Path,
    label: str,
    *,
    passwords: list[str],
    cleanup_mode: str = "keep",
    cold_start_seconds: float = 0.0,
    state_path: Path | None = None,
    initial_scan: bool = False,
    notification_sink: Any | None = None,
) -> WatchHarness:
    watch_root = tmp_path / label / "watch"
    output_root = tmp_path / label / "out"
    watch_root.mkdir(parents=True, exist_ok=True)
    output_root.mkdir(parents=True, exist_ok=True)
    (watch_root / "sunpack-passwords.txt").write_text(
        "\n".join(passwords) + "\n",
        encoding="utf-8",
    )
    config = plan7_watch_config(passwords=passwords)
    config["post_extract"]["archive_cleanup_mode"] = cleanup_mode
    submit_times: list[float] = []
    submission_events: list[SubmissionEvent] = []
    run_durations: list[float] = []
    timer = Plan7Timing()
    loop = asyncio.new_event_loop()
    delegate = PipelineEngine(config)
    with timer.measure("watch_engine_start"):
        loop.run_until_complete(delegate.__aenter__())
    engine = _TimedPipelineEngine(delegate, submit_times, submission_events, run_durations, timer)
    with timer.measure("watch_scheduler_init"):
        watcher = WatchScheduler(
            config,
            [str(watch_root)],
            out_dir=str(output_root),
            state_path=str(state_path or (tmp_path / label / "state.json")),
            cold_start_seconds=cold_start_seconds,
            initial_scan=initial_scan,
            pipeline_engine=engine,
            notification_sink=notification_sink,
        )
    async_run_once = watcher.run_once
    async_start = watcher.start
    async_stop = watcher.stop

    async def _timed_run_once() -> WatchRunResult:
        with timer.measure("watch_tick"):
            return await async_run_once()

    watcher.run_once = lambda: loop.run_until_complete(_timed_run_once())
    watcher.start = lambda: loop.run_until_complete(async_start())
    watcher.stop = lambda: loop.run_until_complete(async_stop())
    watcher._plan7_timer = timer
    if initial_scan:
        with timer.measure("watch_initial_scan"):
            watcher.start()
    return WatchHarness(
        watch_root=watch_root,
        output_root=output_root,
        config=config,
        engine=engine,
        watcher=watcher,
        submit_times=submit_times,
        submission_events=submission_events,
        stable_at_by_name={},
        loop=loop,
        delegate=delegate,
        async_stop=async_stop,
        run_durations=run_durations,
        timer=timer,
        label=label,
    )


def arrive_slowly(
    harness: WatchHarness,
    source: Path,
    *,
    tick_latencies: list[float] | None = None,
    write_mode: str = "rename_commit",
    interrupt_after_chunks: int | None = None,
    resume: bool = False,
) -> WatchRunResult:
    """模拟真实下载，支持临时文件改名、最终路径直写和断点续传。"""
    if write_mode not in {"rename_commit", "direct_final_path"}:
        raise ValueError(f"unknown write mode: {write_mode}")
    tmp = harness.watch_root / f"{source.name}.downloading"
    destination = harness.watch_root / source.name
    write_path = tmp if write_mode == "rename_commit" else destination
    existing_size = write_path.stat().st_size if resume and write_path.exists() else 0
    open_mode = "ab" if existing_size else "wb"
    arrived_at = time.perf_counter()
    with source.open("rb") as reader, write_path.open(open_mode) as writer:
        if existing_size:
            reader.seek(existing_size)
        chunks_seen = 0
        while chunk := reader.read(DOWNLOAD_CHUNK_SIZE):
            write_started_at = time.perf_counter()
            writer.write(chunk)
            writer.flush()
            os.fsync(writer.fileno())
            harness.timer.record("arrive_write", time.perf_counter() - write_started_at)
            chunks_seen += 1
            enqueue_started_at = time.perf_counter()
            harness.watcher.enqueue(str(write_path), event_type="modified")
            harness.timer.record("arrive_enqueue", time.perf_counter() - enqueue_started_at)
            tick_started_at = time.perf_counter()
            harness.watcher.run_once()
            if tick_latencies is not None:
                tick_latencies.append(time.perf_counter() - tick_started_at)
            if interrupt_after_chunks is not None and chunks_seen >= interrupt_after_chunks:
                harness.timer.record(
                    f"arrive:{source.name}",
                    time.perf_counter() - arrived_at,
                )
                return WatchRunResult(pending=harness.watcher.pending_count)
            time.sleep(CHUNK_DELAY_SECONDS)
    if write_mode == "rename_commit":
        os.replace(tmp, destination)
        harness.watcher.notify_path_departed(str(tmp))
    stable_at = time.perf_counter()
    harness.stable_at_by_name[destination.name] = stable_at
    harness.watcher.enqueue(
        str(destination),
        event_type="moved" if write_mode == "rename_commit" else "modified",
        src_path=str(tmp) if write_mode == "rename_commit" else "",
    )
    tick_started_at = time.perf_counter()
    result = harness.watcher.run_once()
    if tick_latencies is not None:
        tick_latencies.append(time.perf_counter() - tick_started_at)
    harness.timer.record(f"arrive:{source.name}", time.perf_counter() - arrived_at)
    return result


def arrive_interleaved(
    harness: WatchHarness,
    sources: list[Path],
    *,
    tick_latencies: list[float] | None = None,
    write_mode: str = "rename_commit",
) -> dict[str, float]:
    """Write several downloads round-robin so their quiet windows overlap."""
    if write_mode not in {"rename_commit", "direct_final_path"}:
        raise ValueError(f"unknown write mode: {write_mode}")
    states = []
    for source in sources:
        tmp = harness.watch_root / f"{source.name}.downloading"
        destination = harness.watch_root / source.name
        states.append({
            "source": source,
            "reader": source.open("rb"),
            "writer": (tmp if write_mode == "rename_commit" else destination).open("wb"),
            "tmp": tmp,
            "destination": destination,
            "write_mode": write_mode,
            "started_at": time.perf_counter(),
        })
    stable: dict[str, float] = {}
    try:
        active = list(states)
        while active:
            for state in list(active):
                chunk = state["reader"].read(DOWNLOAD_CHUNK_SIZE)
                if chunk:
                    write_started_at = time.perf_counter()
                    state["writer"].write(chunk)
                    state["writer"].flush()
                    os.fsync(state["writer"].fileno())
                    harness.timer.record("arrive_write", time.perf_counter() - write_started_at)
                    path = state["tmp"] if write_mode == "rename_commit" else state["destination"]
                    enqueue_started_at = time.perf_counter()
                    harness.watcher.enqueue(str(path), event_type="modified")
                    harness.timer.record("arrive_enqueue", time.perf_counter() - enqueue_started_at)
                    tick_started_at = time.perf_counter()
                    harness.watcher.run_once()
                    if tick_latencies is not None:
                        tick_latencies.append(time.perf_counter() - tick_started_at)
                    continue
                state["writer"].close()
                state["reader"].close()
                if write_mode == "rename_commit":
                    os.replace(state["tmp"], state["destination"])
                    harness.watcher.notify_path_departed(str(state["tmp"]))
                    event_type = "moved"
                    src_path = str(state["tmp"])
                else:
                    event_type = "modified"
                    src_path = ""
                stable_at = time.perf_counter()
                stable[state["destination"].name] = stable_at
                harness.stable_at_by_name[state["destination"].name] = stable_at
                harness.timer.record(
                    f"arrive:{state['source'].name}",
                    stable_at - state["started_at"],
                )
                harness.watcher.enqueue(
                    str(state["destination"]),
                    event_type=event_type,
                    src_path=src_path,
                )
                tick_started_at = time.perf_counter()
                harness.watcher.run_once()
                if tick_latencies is not None:
                    tick_latencies.append(time.perf_counter() - tick_started_at)
                active.remove(state)
    finally:
        for state in states:
            for key in ("reader", "writer"):
                handle = state[key]
                if not handle.closed:
                    handle.close()
    return stable


def split_arrival_order(
    plan7_case: Plan7Case,
    rng: random.Random,
    *,
    policy: str = "non_head_then_head",
) -> list[Path]:
    """Return a deterministic arrival order for one split case."""
    case = plan7_case.case
    parts = sorted(
        (path for path in case.archive_dir.iterdir() if path.is_file()),
        key=lambda path: path.name.lower(),
    )
    resolved = [path.resolve() for path in parts]
    companions = [
        path for path in resolved
        if case.sfx and case.archive_format in {"7z", "zip"} and path.suffix.casefold() == ".exe"
    ]
    inputs = [path for path in resolved if path not in companions]
    if case.archive_format in {"7z", "zip"}:
        input_head = next((path for path in inputs if path.name.casefold().endswith(f".{case.archive_format}.001")), None)
    else:
        input_head = case.entry_path.resolve()
    if input_head is None:
        input_head = inputs[0]
    other_inputs = [path for path in inputs if path != input_head]
    rng.shuffle(other_inputs)
    if policy == "non_head_then_head":
        return [*other_inputs, input_head, *companions]
    if policy == "launcher_first":
        return [*companions, *other_inputs, input_head]
    if policy == "data_first_launcher_last":
        return [*other_inputs, input_head, *companions]
    if policy == "head_first":
        return [input_head, *other_inputs, *companions]
    raise ValueError(f"unknown split arrival policy: {policy}")


def marker_text_extracted(
    root: Path,
    marker_name: str,
    marker_text: str,
    *,
    retries: int = 4,
) -> bool:
    """marker_was_extracted 的容错版：只在候选 marker 文件存在但读取失败时重试。

    解压完成瞬间文件可能仍被占用（读失败），此时短暂重试。文件不存在则立即
    返回 False、不 sleep——否则轮询阶段每 10ms 一次的条件检查会反复阻塞驱动
    事件循环的线程，饿死正在后台执行的 pipeline 任务。
    """
    for _ in range(retries):
        state = marker_scan_state(root, marker_name, marker_text)
        if state != "locked":
            return state == "found"
        time.sleep(0.05)
    return marker_scan_state(root, marker_name, marker_text) == "found"


def drive_watch_until(
    watcher: WatchScheduler,
    condition: Callable[[], bool],
    *,
    timeout_seconds: float = MAX_COMPLETION_LATENCY_SECONDS,
) -> WatchRunResult:
    """轮询 run_once 直到条件成立且无在途/待收尾请求。"""
    timer = getattr(watcher, "_plan7_timer", None)
    deadline = time.perf_counter() + timeout_seconds
    combined = WatchRunResult()
    while time.perf_counter() < deadline:
        result = watcher.run_once()
        combined.processed += result.processed
        combined.succeeded += result.succeeded
        combined.failed += result.failed
        combined.pending = result.pending
        combined.errors.extend(result.errors)
        with watcher._lock:
            inflight = bool(watcher._inflight_requests)
        condition_started_at = time.perf_counter()
        settled = condition()
        if timer is not None:
            timer.record("drive_condition", time.perf_counter() - condition_started_at)
        if settled and watcher.pending_count == 0 and not inflight:
            return combined
        time.sleep(0.01)
    pytest.fail(
        "watch condition did not settle before timeout: "
        f"pending={watcher.pending_count}, entries={watcher.state.entries}"
    )


def assert_plan7_success(
    harness: WatchHarness,
    cases: dict[str, Plan7Case],
    *,
    sampler: MemorySampler,
    tick_latencies: list[float],
    expect_exact_submissions: bool = True,
    error_info: dict[str, Any] | None = None,
    record_property: Callable[[str, Any], None] | None = None,
) -> None:
    """第 7 条主断言：全部归档完成、无失败、不重复提交，且内存随到达数量被记录。"""
    root = harness.output_root
    with harness.timer.measure("assert_marker_checks"):
        for plan7_case in cases.values():
            assert marker_text_extracted(root, plan7_case.case.marker_name, plan7_case.case.marker_text), (
                f"marker missing for {plan7_case.key}: {plan7_case.case.marker_name}"
            )
    assert not any(harness.watcher.state.entries.values()), "watch state must not retain failures"
    assert harness.submit_times, "pipeline never submitted any archive"

    completed_count = len(cases)
    for plan7_case in cases.values():
        stable_at = plan7_case.stable_at
        matching_events = [
            event
            for event in harness.submission_events
            if event.at >= stable_at
            and any(Path(path).name in expected_submission_names(plan7_case) for path in event.paths)
        ]
        assert matching_events, f"watch did not react after final stability for {plan7_case.key}"
        first_event = matching_events[0]
        plan7_case.first_submission_at = first_event.at
        plan7_case.reaction_latency = first_event.at - stable_at
        assert plan7_case.reaction_latency >= 0, (
            f"{plan7_case.key} submitted before its final file became stable: "
            f"stable={stable_at}, submit={first_event.at}"
        )
        assert plan7_case.reaction_latency < MAX_REACTION_LATENCY_SECONDS, (
            f"{plan7_case.key} was stable but watch did not react within "
            f"{MAX_REACTION_LATENCY_SECONDS:.1f}s: {plan7_case.reaction_latency:.3f}s"
        )
        assert plan7_case.completion_latency is not None
        assert plan7_case.completion_latency < MAX_COMPLETION_LATENCY_SECONDS, (
            f"{plan7_case.key} took {plan7_case.completion_latency:.3f}s after its final "
            "volume became stable (file complete but watch did not react)"
        )

    # 单文件归档每个恰好提交一次；分卷乱序到达时，watch 会对“已到头卷但还
    # 缺尾卷”的不完整组做探测性提交（借后端确认缺卷），所以分卷场景只要求
    # 每个归档至少提交一次。持久化 snapshot 去重已移除，成功文件收到新的
    # enqueue 事件后应按新事件再次处理。
    if expect_exact_submissions:
        assert len(harness.submit_times) == completed_count, harness.submit_times
    else:
        assert len(harness.submit_times) >= completed_count, harness.submit_times
    # Repeated-event behavior is covered by the scheduler unit tests. Do not
    # replay the entire real fixture matrix here: after snapshot dedupe is
    # removed, that would intentionally launch a second full extraction pass
    # and turn the performance scenario into an unrelated stress test.

    assert max(tick_latencies) < MAX_WATCH_TICK_LATENCY_SECONDS, tick_latencies
    memory = sampler.summary()
    assert memory["samples"] >= completed_count + 1, memory
    assert memory["arrival_samples"] >= completed_count, memory
    assert memory["completion_samples"] >= completed_count, memory
    assert memory["parent_growth"] < 128 * 1024 * 1024, memory
    assert memory["worker_growth"] < 64 * 1024 * 1024, memory
    assert memory["child_count_range"][1] - memory["child_count_range"][0] <= 1, memory

    if error_info is not None:
        error_info.update({
            "completed_archives": completed_count,
            "pipeline_submissions": len(harness.submit_times),
            "pipeline_run_seconds": [round(duration, 3) for duration in harness.run_durations],
            "fixture_build_seconds": dict(FIXTURE_BUILD_TIMING),
            "timing": harness.timer.summary(),
            "tick_count": len(tick_latencies),
            "max_tick_latency_ms": round(max(tick_latencies) * 1000, 3),
            "completion_latencies": {
                key: round(case.completion_latency or 0.0, 3)
                for key, case in cases.items()
            },
            "reaction_latencies": {
                key: round(case.reaction_latency or 0.0, 3)
                for key, case in cases.items()
            },
            "submission_events": [
                {"at": round(event.at, 3), "paths": list(event.paths)}
                for event in harness.submission_events
            ],
            "memory_summary": memory,
        })
    if record_property is not None:
        record_property("archive_count", completed_count)
        record_property("pipeline_submissions", len(harness.submit_times))
        record_property(
            "pipeline_run_seconds",
            json.dumps([round(duration, 3) for duration in harness.run_durations], ensure_ascii=False),
        )
        record_property(
            "fixture_build_seconds",
            json.dumps(FIXTURE_BUILD_TIMING, ensure_ascii=False),
        )
        record_property(
            "plan7_timing",
            json.dumps(harness.timer.summary(), ensure_ascii=False),
        )
        record_property(
            "reaction_latencies",
            json.dumps({
                key: round(case.reaction_latency or 0.0, 3)
                for key, case in cases.items()
            }, ensure_ascii=False),
        )
        record_property("max_watch_tick_latency_ms", round(max(tick_latencies) * 1000, 3))
        record_property("memory_summary", json.dumps(memory, ensure_ascii=False))
        timeline = [item.to_dict() for item in sampler.samples]
        record_property(
            "memory_timeline",
            json.dumps(timeline, ensure_ascii=False),
        )
        print(
            "\nplan7 memory timeline (archives completed -> parent/worker RSS):\n"
            + "\n".join(
                f"  {str(item['label']):<18s} "
                f"completed={item['completed_archives']:>2d} -> "
                f"parent={item['parent_rss'] / 1024 / 1024:7.1f}MB "
                f"worker={item['worker_rss'] / 1024 / 1024:6.1f}MB "
                f"children={item['child_count']} "
                f"volumes={item['installed_volumes']}"
                for item in timeline
            )
        )
    print(
        f"\nplan7 pipeline runs ({len(harness.run_durations)} submissions): "
        + ", ".join(f"{duration:.2f}s" for duration in harness.run_durations)
    )
    build_deltas = fixture_build_deltas()
    if build_deltas:
        print(
            "plan7 fixture build: "
            + ", ".join(f"{key}={seconds:.2f}s" for key, seconds in build_deltas.items())
        )


__all__ = [
    "PASSWORD",
    "WRONG_PASSWORD_COUNT",
    "DOWNLOAD_CHUNK_SIZE",
    "MAX_COMPLETION_LATENCY_SECONDS",
    "MAX_REACTION_LATENCY_SECONDS",
    "MAX_WATCH_TICK_LATENCY_SECONDS",
    "PLAIN_FORMATS",
    "SFX_FORMATS",
    "SPLIT_FORMATS",
    "Plan7Case",
    "Plan7Timing",
    "FIXTURE_BUILD_TIMING",
    "fixture_build_deltas",
    "WatchHarness",
    "SubmissionEvent",
    "MemorySampler",
    "wrong_password_list",
    "build_plain_sfx_cases",
    "build_split_cases",
    "build_encryption_variant_cases",
    "build_disguised_cases",
    "build_embedded_watch_cases",
    "start_watch",
    "expected_submission_names",
    "input_volume_names",
    "owned_names",
    "arrive_slowly",
    "split_arrival_order",
    "marker_text_extracted",
    "drive_watch_until",
    "assert_plan7_success",
]
