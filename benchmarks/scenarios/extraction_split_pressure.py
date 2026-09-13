import argparse
import asyncio
import json
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from sunpack.coordinator.engine import PipelineEngine
from sunpack.coordinator.scanner import ScanOrchestrator
from tests.helpers.performance_config import archive_pressure_config
from benchmarks.harness import BenchmarkWorkspace, render_report, report_from_payload
from tests.helpers.real_archives import ArchiveCase, ArchiveFixtureFactory, normalize_archive_format
from tests.helpers.tool_config import get_optional_rar, require_7z


PASSWORD = "pressure-secret"
WRONG_PASSWORDS = ["wrong-password", "123456", "letmein"]
PASSWORD_TRY_LIST = [*WRONG_PASSWORDS[:2], PASSWORD]
PAYLOAD_SIZE = 180 * 1024
PASSWORD_ARCHIVE_FORMATS = ("7z", "zip", "rar")
PLAIN_ARCHIVE_FORMATS = ("tar", "tar.gz", "tar.bz2", "tar.xz", "tar.zst", "gzip", "bzip2", "xz", "zstd")
FORMATS = (*PASSWORD_ARCHIVE_FORMATS, *PLAIN_ARCHIVE_FORMATS)
PLAIN_ONLY_FORMATS = set(PLAIN_ARCHIVE_FORMATS)
UNLISTED_PASSWORD = "pressure-secret-not-in-list"
PASSWORD_VIEWS = [
    ("no_password", [], "failure"),
    ("wrong_passwords", list(WRONG_PASSWORDS), "failure"),
    ("correct_after_wrong_passwords", list(PASSWORD_TRY_LIST), "success"),
]


@dataclass
class PressureCase:
    name: str
    archive_format: str
    variant: str
    case: ArchiveCase | None
    passwords: list[str]
    expected: str
    build_seconds: float
    skip_reason: str | None = None


class TimingRecorder:
    def __init__(self):
        self._lock = threading.Lock()
        self._totals: dict[str, float] = {}
        self._counts: dict[str, int] = {}
        self._details: dict[str, dict[str, dict[str, float | int]]] = {}
        self._restore_callbacks: list[Callable[[], None]] = []

    def measure(self, label: str, callback: Callable, *args, detail: Callable | None = None, **kwargs):
        started = time.perf_counter()
        result = None
        detail_key = ""
        try:
            result = callback(*args, **kwargs)
            if detail is not None:
                detail_key = detail(args, kwargs, result) or ""
            return result
        finally:
            elapsed = time.perf_counter() - started
            with self._lock:
                self._totals[label] = self._totals.get(label, 0.0) + elapsed
                self._counts[label] = self._counts.get(label, 0) + 1
                if detail_key:
                    bucket = self._details.setdefault(label, {}).setdefault(detail_key, {"ms": 0.0, "count": 0})
                    bucket["ms"] = float(bucket["ms"]) + elapsed * 1000
                    bucket["count"] = int(bucket["count"]) + 1

    def ms(self, label: str) -> float:
        return round(self._totals.get(label, 0.0) * 1000, 2)

    def snapshot(self) -> dict:
        labels = sorted(self._totals)
        return {
            label: {
                "ms": round(self._totals[label] * 1000, 2),
                "count": self._counts.get(label, 0),
                "details": self.details(label),
            }
            for label in labels
        }

    def details(self, label: str) -> dict:
        details = self._details.get(label, {})
        return {
            key: {"ms": round(float(value["ms"]), 2), "count": int(value["count"])}
            for key, value in sorted(details.items())
        }

    def add_restore(self, callback: Callable[[], None]) -> None:
        self._restore_callbacks.append(callback)

    def restore(self) -> None:
        while self._restore_callbacks:
            self._restore_callbacks.pop()()


def _path_ext(path: str) -> str:
    name = Path(str(path)).name.lower()
    suffixes = Path(name).suffixes
    if name.endswith(".part1.exe"):
        return ".part1.exe"
    if len(suffixes) >= 2 and suffixes[-1] == ".001":
        return "".join(suffixes[-2:])
    return suffixes[-1] if suffixes else "<none>"


def _password_try_detail(args, kwargs, result) -> str:
    archive = args[0] if args else kwargs.get("archive_path", "")
    passwords = args[1] if len(args) > 1 else kwargs.get("passwords", [])
    return (
        f"ext={_path_ext(archive)}|status={getattr(result, 'status', '')}"
        f"|attempts={getattr(result, 'attempts', '')}"
        f"|matched={getattr(result, 'matched_index', '')}"
        f"|candidates={len(passwords or [])}"
    )


def _task_path_from_arg(value) -> str:
    return str(getattr(value, "main_path", value) or "")


def _password_resolve_detail(args, kwargs, result) -> str:
    archive = _task_path_from_arg(args[0] if args else kwargs.get("task", ""))
    status = getattr(result, "status", "")
    password = getattr(result, "password", None)
    matched = password is not None
    return f"ext={_path_ext(archive)}|status={status}|matched={matched}"


def wrap_method(owner, method_name: str, recorder: TimingRecorder, label: str, detail: Callable | None = None):
    original = getattr(owner, method_name)

    def wrapped(*args, **kwargs):
        return recorder.measure(label, original, *args, detail=detail, **kwargs)

    setattr(owner, method_name, wrapped)
    recorder.add_restore(lambda: setattr(owner, method_name, original))


class PipelineTimingProbe:
    """Instrument every per-request runtime created by the async PipelineEngine.

    The engine no longer exposes ``task_scanner``/``batch_runner`` as public
    attributes, so the probe hooks the private ``_request_runtime_factory``
    seam (the same one the large-archive profiler uses) and wraps the sync
    pipeline stages that still exist after the async refactor.  Stages that no
    longer exist are skipped silently so a stale probe can never abort a
    pressure run; their columns report 0.0 in ``timing_columns``.
    """

    def __init__(self) -> None:
        self.recorder = TimingRecorder()
        self._factory_restore: tuple[Any, Callable[..., Any]] | None = None

    def install(self, runner: PipelineEngine) -> None:
        original_factory = runner._request_runtime_factory
        self._factory_restore = (runner, original_factory)

        def profiled_factory(*args: Any, **kwargs: Any):
            runtime = original_factory(*args, **kwargs)
            self._instrument_runtime(runtime)
            return runtime

        runner._request_runtime_factory = profiled_factory

    def restore(self) -> None:
        if self._factory_restore is not None:
            runner, factory = self._factory_restore
            runner._request_runtime_factory = factory
            self._factory_restore = None

    def _wrap(self, owner: Any, method_name: str, label: str, detail: Callable | None = None) -> None:
        if owner is None or not hasattr(owner, method_name):
            return
        wrap_method(owner, method_name, self.recorder, label, detail=detail)

    def _instrument_runtime(self, runtime: Any) -> None:
        scanner = getattr(runtime, "task_scanner", None)
        planning = getattr(runtime, "input_planning_stage", None)
        batch = getattr(runtime, "batch_runner", None)
        extractor = getattr(runtime, "extractor", None)
        output_scan = getattr(runtime, "output_scan_policy", None)

        self._wrap(scanner, "scan_targets", "pipeline_scan")
        self._wrap(scanner, "direct_file_tasks", "pipeline_direct_scan")
        self._wrap(planning, "plan_tasks", "input_planning")
        self._wrap(batch, "prepare_tasks", "batch_prepare")
        self._wrap(batch, "_skip_tasks_inside_batch_outputs", "batch_skip_inside_outputs")
        self._wrap(batch, "_inspect_tasks_before_extract", "batch_password_preflight")
        self._wrap(batch, "_inspect_resource_profiles", "batch_resource_profiles")
        self._wrap(batch, "collect_result", "batch_collect_result")
        self._wrap(batch, "_report_task_started", "batch_report_task_started")
        self._wrap(batch, "_report_task_finished", "batch_report_task_finished")
        self._wrap(output_scan, "scan_roots_from_outputs", "output_scan")
        self._wrap(output_scan, "take_scan_session", "output_take_scan_session")
        self._wrap(extractor, "inspect", "password_preflight")
        self._wrap(extractor, "extract", "extract")
        self._wrap(extractor, "close", "extractor_close")
        password_resolver = getattr(extractor, "password_resolver", None)
        self._wrap(password_resolver, "resolve", "password_resolve", detail=_password_resolve_detail)
        password_tester = getattr(extractor, "password_tester", None)
        self._wrap(password_tester, "test_password", "password_native_test_archive")
        native_tester = getattr(password_tester, "native_password_tester", None) if password_tester is not None else None
        self._wrap(native_tester, "try_passwords", "password_native_try", detail=_password_try_detail)
        resource_inspector = getattr(batch, "resource_inspector", None)
        self._wrap(resource_inspector, "inspect", "resource_preflight")
        self._wrap(resource_inspector, "record_estimated_single_task_profile", "resource_estimate")
        verifier = getattr(batch, "verifier", None)
        self._wrap(verifier, "verify", "verify")


def timing_columns(recorder: TimingRecorder | None, pipeline_ms: float = 0.0) -> dict[str, float | dict]:
    if recorder is None:
        return {
            "pipeline_scan_ms": 0.0,
            "batch_execute_ms": 0.0,
            "prepare_ms": 0.0,
            "analysis_ms": 0.0,
            "execute_ready_ms": 0.0,
            "execute_all_wall_ms": 0.0,
            "preflight_ms": 0.0,
            "password_resolve_ms": 0.0,
            "password_native_test_ms": 0.0,
            "resource_ms": 0.0,
            "extract_ms": 0.0,
            "verify_ms": 0.0,
            "collect_result_ms": 0.0,
            "output_scan_ms": 0.0,
            "postprocess_ms": 0.0,
            "final_summary_ms": 0.0,
            "extractor_close_ms": 0.0,
            "timings": {},
        }
    batch_execute_ms = round(
        recorder.ms("batch_prepare")
        + recorder.ms("batch_skip_inside_outputs")
        + recorder.ms("batch_password_preflight")
        + recorder.ms("batch_resource_profiles")
        + recorder.ms("batch_collect_result")
        + recorder.ms("batch_report_task_started")
        + recorder.ms("batch_report_task_finished")
        + recorder.ms("output_scan")
        + recorder.ms("output_take_scan_session"),
        2,
    )
    measured_stages = (
        recorder.ms("pipeline_scan")
        + recorder.ms("input_planning")
        + batch_execute_ms
        + recorder.ms("password_preflight")
        + recorder.ms("password_resolve")
        + recorder.ms("password_native_test_archive")
        + recorder.ms("password_native_try")
        + recorder.ms("resource_preflight")
        + recorder.ms("resource_estimate")
        + recorder.ms("verify")
        + recorder.ms("extractor_close")
    )
    # The native extraction itself runs asynchronously through the worker and
    # has no synchronous probe; report it as the pipeline wall minus every
    # measured stage (the un-attributed residual).
    extract_ms = round(max(0.0, pipeline_ms - measured_stages), 2)
    return {
        "pipeline_scan_ms": recorder.ms("pipeline_scan"),
        "batch_execute_ms": batch_execute_ms,
        "prepare_ms": recorder.ms("batch_prepare"),
        "analysis_ms": recorder.ms("input_planning"),
        "execute_ready_ms": 0.0,
        "execute_all_wall_ms": round(pipeline_ms, 2),
        "preflight_ms": recorder.ms("password_preflight"),
        "password_resolve_ms": recorder.ms("password_resolve"),
        "password_native_test_ms": round(
            recorder.ms("password_native_test_archive") + recorder.ms("password_native_try"),
            2,
        ),
        "resource_ms": recorder.ms("resource_preflight") + recorder.ms("resource_estimate"),
        "extract_ms": extract_ms,
        "verify_ms": recorder.ms("verify"),
        "collect_result_ms": recorder.ms("batch_collect_result"),
        "output_scan_ms": recorder.ms("output_scan"),
        "postprocess_ms": 0.0,
        "final_summary_ms": 0.0,
        "extractor_close_ms": recorder.ms("extractor_close"),
        "timings": recorder.snapshot(),
    }


def timed(factory: Callable[[], ArchiveCase]) -> tuple[ArchiveCase, float]:
    started = time.perf_counter()
    case = factory()
    return case, time.perf_counter() - started


def create_case(root: Path, case_id: str, archive_format: str, **kwargs) -> tuple[ArchiveCase, float]:
    factory = ArchiveFixtureFactory()
    return timed(lambda: factory.create(root, case_id, archive_format, payload_size=PAYLOAD_SIZE, **kwargs))


def build_or_skip(
    root: Path,
    archive_format: str,
    variant: str,
    *,
    passwords: list[str] | None = None,
    expected: str = "success",
    case_id: str | None = None,
    **kwargs,
) -> PressureCase:
    effective_case_id = case_id or f"{archive_format}_{variant}".replace("-", "_")
    name = f"{archive_format}:{variant}"
    try:
        case, build_seconds = create_case(root, effective_case_id, archive_format, **kwargs)
        return PressureCase(name, archive_format, variant, case, passwords or [], expected, build_seconds)
    except (FileNotFoundError, RuntimeError) as exc:
        return PressureCase(name, archive_format, variant, None, passwords or [], "skip", 0.0, str(exc))


def build_password_case(
    root: Path,
    archive_format: str,
    variant: str,
    *,
    case_id: str | None = None,
    views: list[tuple[str, list[str], str]] | None = None,
    **kwargs,
) -> list[PressureCase]:
    base_case_id = case_id or f"{archive_format}_{variant}_password".replace("-", "_")
    cases: list[PressureCase] = []
    for suffix, passwords, expected in views or PASSWORD_VIEWS:
        view_variant = f"{variant}:{suffix}"
        try:
            case, build_seconds = create_case(
                root,
                f"{base_case_id}_{suffix}",
                archive_format,
                password=PASSWORD,
                **kwargs,
            )
        except (FileNotFoundError, RuntimeError) as exc:
            cases.append(PressureCase(
                f"{archive_format}:{view_variant}",
                archive_format,
                view_variant,
                None,
                passwords,
                "skip",
                0.0,
                str(exc),
            ))
            continue
        cases.append(PressureCase(
            f"{archive_format}:{view_variant}",
            archive_format,
            view_variant,
            case,
            passwords,
            expected,
            build_seconds,
        ))
    return cases


def build_correct_password_case(root: Path, archive_format: str, variant: str, **kwargs) -> list[PressureCase]:
    return build_password_case(
        root,
        archive_format,
        variant,
        views=[PASSWORD_VIEWS[2]],
        **kwargs,
    )


def build_format_cases(root: Path, archive_format: str) -> list[PressureCase]:
    if archive_format in PLAIN_ONLY_FORMATS:
        return [build_or_skip(root, archive_format, "single_plain")]

    cases: list[PressureCase] = []

    cases.append(build_or_skip(root, archive_format, "single_plain"))
    cases.extend(build_password_case(root, archive_format, "single_password"))

    cases.append(build_or_skip(root, archive_format, "split_plain", split=True))
    cases.extend(build_password_case(root, archive_format, "split_password", split=True))

    cases.append(build_or_skip(root, archive_format, "sfx_single_plain", sfx=True))
    cases.extend(build_password_case(root, archive_format, "sfx_single_password", sfx=True))

    cases.append(build_or_skip(root, archive_format, "sfx_split_plain", split=True, sfx=True))
    cases.extend(build_password_case(root, archive_format, "sfx_split_password", split=True, sfx=True))

    cases.append(build_or_skip(root, archive_format, "jpg_carrier_plain", carrier="jpg"))
    cases.extend(build_password_case(root, archive_format, "jpg_carrier_password", carrier="jpg"))

    cases.append(build_or_skip(root, archive_format, "wrong_suffix_plain", disguise_ext=".wrongext"))
    header_expected = "success" if archive_format == "zip" else "failure"
    cases.append(build_or_skip(root, archive_format, "corrupt_single_header", expected=header_expected, corruption="header_damage"))
    tail_expected = "success" if archive_format in {"rar", "zip"} else "failure"
    cases.append(build_or_skip(root, archive_format, "corrupt_single_tail", expected=tail_expected, corruption="tail_header_damage"))
    cases.append(build_or_skip(root, archive_format, "missing_split_member", expected="failure", split=True, split_issue="missing_last"))
    split_corruption_expected = "success" if archive_format in {"7z", "zip", "rar"} else "failure"
    cases.append(build_or_skip(
        root,
        archive_format,
        "corrupt_split_member",
        expected=split_corruption_expected,
        split=True,
        split_issue="corrupt_member",
    ))

    return cases


def build_acceptance_format_cases(root: Path, archive_format: str) -> list[PressureCase]:
    if archive_format in PLAIN_ONLY_FORMATS:
        return [build_or_skip(root, archive_format, "single_plain")]

    cases: list[PressureCase] = []
    if archive_format == "7z":
        cases.append(build_or_skip(root, archive_format, "single_plain"))
        cases.extend(build_correct_password_case(root, archive_format, "split_password", split=True))
        cases.extend(build_correct_password_case(root, archive_format, "sfx_single_password", sfx=True))
        cases.extend(build_correct_password_case(root, archive_format, "jpg_carrier_password", carrier="jpg"))
        cases.append(build_or_skip(root, archive_format, "corrupt_single_header", expected="failure", corruption="header_damage"))
        return cases
    if archive_format == "zip":
        cases.append(build_or_skip(root, archive_format, "split_plain", split=True))
        cases.extend(build_correct_password_case(root, archive_format, "single_password"))
        cases.append(build_or_skip(root, archive_format, "wrong_suffix_plain", disguise_ext=".wrongext"))
        cases.append(build_or_skip(root, archive_format, "corrupt_single_tail", expected="success", corruption="tail_header_damage"))
        return cases
    if archive_format == "rar":
        cases.extend(build_correct_password_case(root, archive_format, "single_password"))
        cases.extend(build_correct_password_case(root, archive_format, "sfx_split_password", split=True, sfx=True))
        cases.append(build_or_skip(root, archive_format, "missing_split_member", expected="failure", split=True, split_issue="missing_last"))
        return cases
    raise ValueError(f"Unsupported archive format: {archive_format}")


def build_acceptance_batch_format_cases(root: Path, archive_format: str) -> list[PressureCase]:
    if archive_format in PLAIN_ONLY_FORMATS:
        return [build_or_skip(root, archive_format, "single_plain")]

    cases: list[PressureCase] = []
    cases.append(build_or_skip(root, archive_format, "single_plain"))
    cases.append(build_or_skip(root, archive_format, "single_password", passwords=PASSWORD_TRY_LIST, password=PASSWORD))
    cases.append(build_or_skip(
        root,
        archive_format,
        "single_password_unlisted",
        passwords=PASSWORD_TRY_LIST,
        expected="failure",
        password=UNLISTED_PASSWORD,
    ))

    cases.append(build_or_skip(root, archive_format, "split_plain", split=True))
    cases.append(build_or_skip(root, archive_format, "split_password", passwords=PASSWORD_TRY_LIST, password=PASSWORD, split=True))

    cases.append(build_or_skip(root, archive_format, "sfx_single_plain", sfx=True))
    cases.append(build_or_skip(root, archive_format, "sfx_single_password", passwords=PASSWORD_TRY_LIST, password=PASSWORD, sfx=True))

    cases.append(build_or_skip(root, archive_format, "sfx_split_plain", split=True, sfx=True))
    cases.append(build_or_skip(root, archive_format, "sfx_split_password", passwords=PASSWORD_TRY_LIST, password=PASSWORD, split=True, sfx=True))

    cases.append(build_or_skip(root, archive_format, "jpg_carrier_plain", carrier="jpg"))
    cases.append(build_or_skip(root, archive_format, "jpg_carrier_password", passwords=PASSWORD_TRY_LIST, password=PASSWORD, carrier="jpg"))

    cases.append(build_or_skip(root, archive_format, "wrong_suffix_plain", disguise_ext=".wrongext"))
    header_expected = "success" if archive_format == "zip" else "failure"
    cases.append(build_or_skip(root, archive_format, "corrupt_single_header", expected=header_expected, corruption="header_damage"))
    tail_expected = "success" if archive_format in {"rar", "zip"} else "failure"
    cases.append(build_or_skip(root, archive_format, "corrupt_single_tail", expected=tail_expected, corruption="tail_header_damage"))
    cases.append(build_or_skip(root, archive_format, "missing_split_member", expected="failure", split=True, split_issue="missing_last"))
    split_corruption_expected = "success" if archive_format in {"7z", "zip", "rar"} else "failure"
    cases.append(build_or_skip(
        root,
        archive_format,
        "corrupt_split_member",
        expected=split_corruption_expected,
        split=True,
        split_issue="corrupt_member",
    ))
    return cases


def build_cases(root: Path, requested_formats: list[str], profile: str) -> list[PressureCase]:
    cases: list[PressureCase] = []
    for archive_format in requested_formats:
        if archive_format == "rar" and not get_optional_rar():
            cases.append(PressureCase(
                "rar:all",
                "rar",
                "all",
                None,
                [],
                "skip",
                0.0,
                "RAR generator is not configured. Set sunpack_TEST_RAR or tests/test_tools.json rar_exe.",
            ))
            continue
        if profile == "acceptance":
            cases.extend(build_acceptance_format_cases(root, archive_format))
        elif profile == "acceptance-batch":
            cases.extend(build_acceptance_batch_format_cases(root, archive_format))
        else:
            cases.extend(build_format_cases(root, archive_format))
    return cases


def marker_extracted(case: ArchiveCase) -> bool:
    marker_bytes = case.marker_text.encode("utf-8")
    for path in case.archive_dir.rglob(case.marker_name):
        try:
            if path.read_text(encoding="utf-8") == case.marker_text:
                return True
        except OSError:
            pass
    for path in case.archive_dir.rglob("*"):
        try:
            if path.is_file() and path.stat().st_size == len(marker_bytes) and path.read_bytes() == marker_bytes:
                return True
        except OSError:
            pass
    return False


def clean_outputs(case: ArchiveCase):
    for path in case.archive_dir.iterdir():
        if path.is_dir():
            shutil.rmtree(path, ignore_errors=True)


def _run_engine(targets: list[str], config: dict) -> dict[str, Any]:
    """Run one async PipelineEngine submission and return summary + timing.

    The engine now owns a single event loop per run; every per-request runtime
    it creates is instrumented through the factory probe so the phase columns
    reflect the current async pipeline (removed stages report 0.0).
    """
    runner = PipelineEngine(config)
    probe = PipelineTimingProbe()
    probe.install(runner)
    started = time.perf_counter()
    try:
        async def run() -> Any:
            async with runner:
                response = await runner.run(targets)
                return response.summary

        summary = asyncio.run(run())
    finally:
        probe.restore()
    pipeline_seconds = time.perf_counter() - started
    return {
        "summary": summary,
        "pipeline_seconds": pipeline_seconds,
        "timings": timing_columns(probe.recorder, pipeline_seconds * 1000),
    }


def run_case(pressure_case: PressureCase) -> dict:
    if pressure_case.case is None:
        return {
            "case": pressure_case.name,
            "format": pressure_case.archive_format,
            "variant": pressure_case.variant,
            "expected": pressure_case.expected,
            "observed": "skip",
            "pipeline_status": "skip",
            "marker_extracted": False,
            "password_count": len(pressure_case.passwords),
            "build_ms": 0.0,
            "scan_ms": 0.0,
            "pipeline_ms": 0.0,
            "scan_results": 0,
            "success_count": 0,
            "failed_count": 0,
            "failed_tasks": [],
            "skip_reason": pressure_case.skip_reason,
            "files": [],
            **timing_columns(None),
        }

    clean_outputs(pressure_case.case)

    scan_config = archive_pressure_config(passwords=pressure_case.passwords)
    started = time.perf_counter()
    scan_results = ScanOrchestrator(scan_config).scan(str(pressure_case.case.archive_dir))
    scan_seconds = time.perf_counter() - started

    pipeline_result = _run_engine([str(pressure_case.case.archive_dir)], scan_config)
    summary = pipeline_result["summary"]
    pipeline_seconds = pipeline_result["pipeline_seconds"]
    pipeline_timing = pipeline_result["timings"]

    extracted = marker_extracted(pressure_case.case)
    observed = "success" if summary.success_count > 0 and extracted else "failure"
    pipeline_status = "success" if summary.success_count > 0 else "failure"
    return {
        "case": pressure_case.name,
        "format": pressure_case.archive_format,
        "variant": pressure_case.variant,
        "expected": pressure_case.expected,
        "observed": observed,
        "pipeline_status": pipeline_status,
        "marker_extracted": extracted,
        "password_count": len(pressure_case.passwords),
        "build_ms": round(pressure_case.build_seconds * 1000, 2),
        "scan_ms": round(scan_seconds * 1000, 2),
        "pipeline_ms": round(pipeline_seconds * 1000, 2),
        "scan_results": len(scan_results),
        "success_count": summary.success_count,
        "failed_count": len(summary.failed_tasks),
        "failed_tasks": list(summary.failed_tasks),
        "skip_reason": pressure_case.skip_reason,
        "files": sorted(path.name for path in pressure_case.case.archive_dir.iterdir() if path.is_file()),
        **pipeline_timing,
    }


def move_case_files_to_batch(pressure_case: PressureCase, batch_dir: Path):
    case = pressure_case.case
    if case is None:
        return
    original_entry_name = case.entry_path.name
    moved_names: list[str] = []
    for path in sorted(case.archive_dir.iterdir()):
        if not path.is_file():
            continue
        destination = batch_dir / path.name
        if destination.exists():
            raise RuntimeError(f"Batch fixture file collision: {destination.name}")
        shutil.move(str(path), str(destination))
        moved_names.append(destination.name)
    case.archive_dir = batch_dir
    case.entry_path = batch_dir / original_entry_name
    case.metadata["batch_files"] = moved_names


def failure_reported_for_case(summary_failed_tasks: list[str], pressure_case: PressureCase) -> bool:
    case = pressure_case.case
    if case is None:
        return False
    candidates = set(case.metadata.get("batch_files") or [])
    candidates.add(case.entry_path.name)
    return any(any(candidate in failed_task for candidate in candidates) for failed_task in summary_failed_tasks)


def failed_tasks_for_case(summary_failed_tasks: list[str], pressure_case: PressureCase) -> list[str]:
    case = pressure_case.case
    if case is None:
        return []
    candidates = set(case.metadata.get("batch_files") or [])
    candidates.add(case.entry_path.name)
    return [
        failed_task
        for failed_task in summary_failed_tasks
        if any(candidate in failed_task for candidate in candidates)
    ]


def run_batch_cases(pressure_cases: list[PressureCase]) -> list[dict]:
    batch_dir = pressure_cases[0].case.archive_dir.parent / "acceptance_batch_input"
    batch_dir.mkdir(parents=True, exist_ok=True)
    for pressure_case in pressure_cases:
        move_case_files_to_batch(pressure_case, batch_dir)

    scan_config = archive_pressure_config(passwords=PASSWORD_TRY_LIST)
    # A batch request owns one TaskResourceScope.  Extraction promotion can
    # quiesce that scope while another per-file task is still entering its
    # password verifier, which makes the benchmark fail before it can emit a
    # report.  This acceptance batch is a mixed-directory correctness probe;
    # native concurrency is covered by the worker scheduling benchmarks, so
    # keep this probe serial and let it record expected/unexpected outcomes.
    worker_config = scan_config.setdefault("performance", {}).setdefault("worker", {})
    worker_config.update(
        {
            "thread_capacity": 1,
            "max_inflight_files": 1,
            "initial_active_jobs": 1,
        }
    )
    started = time.perf_counter()
    scan_results = ScanOrchestrator(scan_config).scan(str(batch_dir))
    scan_seconds = time.perf_counter() - started

    pipeline_result = _run_engine([str(batch_dir)], scan_config)
    summary = pipeline_result["summary"]
    pipeline_seconds = pipeline_result["pipeline_seconds"]
    timing_data = pipeline_result["timings"]

    rows: list[dict] = []
    case_rows: list[dict] = []
    attributed_failed_tasks: set[str] = set()
    batch_files = sorted(path.name for path in batch_dir.iterdir() if path.is_file())

    for pressure_case in pressure_cases:
        case = pressure_case.case
        if case is None:
            continue
        extracted = marker_extracted(case)
        failure_reported = failure_reported_for_case(list(summary.failed_tasks), pressure_case)
        if extracted:
            observed = "success"
        elif failure_reported:
            observed = "failure"
        else:
            observed = "missing"
        case_failed_tasks = failed_tasks_for_case(list(summary.failed_tasks), pressure_case)
        attributed_failed_tasks.update(case_failed_tasks)
        case_rows.append({
            "case": pressure_case.name,
            "format": pressure_case.archive_format,
            "variant": pressure_case.variant,
            "expected": pressure_case.expected,
            "observed": observed,
            "pipeline_status": "batch",
            "marker_extracted": extracted,
            "password_count": len(PASSWORD_TRY_LIST),
            "build_ms": round(pressure_case.build_seconds * 1000, 2),
            "scan_ms": round(scan_seconds * 1000, 2),
            "pipeline_ms": round(pipeline_seconds * 1000, 2),
            "scan_results": len(scan_results),
            "success_count": summary.success_count,
            "failed_count": len(summary.failed_tasks),
            "failed_tasks": case_failed_tasks,
            "skip_reason": pressure_case.skip_reason,
            "files": list(case.metadata.get("batch_files") or [case.entry_path.name]),
            **timing_data,
        })
    unexpected_failed_tasks = [
        failed_task for failed_task in summary.failed_tasks if failed_task not in attributed_failed_tasks
    ]
    summary_observed = (
        "success"
        if all(row["expected"] == row["observed"] for row in case_rows) and not unexpected_failed_tasks
        else "failure"
    )
    rows.append({
        "case": "batch:summary",
        "format": "batch",
        "variant": "acceptance-batch",
        "expected": "success",
        "observed": summary_observed,
        "pipeline_status": f"{summary.success_count} success / {len(summary.failed_tasks)} failed",
        "marker_extracted": summary_observed == "success",
        "password_count": len(PASSWORD_TRY_LIST),
        "build_ms": round(sum(pressure_case.build_seconds for pressure_case in pressure_cases) * 1000, 2),
        "scan_ms": round(scan_seconds * 1000, 2),
        "pipeline_ms": round(pipeline_seconds * 1000, 2),
        "scan_results": len(scan_results),
        "success_count": summary.success_count,
        "failed_count": len(summary.failed_tasks),
        "failed_tasks": unexpected_failed_tasks or list(summary.failed_tasks),
        "skip_reason": None,
        "files": batch_files,
        **timing_data,
    })
    rows.extend(case_rows)
    return rows


def print_table(rows: list[dict]):
    headers = [
        "case",
        "expected",
        "observed",
        "pipeline_status",
        "marker_extracted",
        "password_count",
        "build_ms",
        "scan_ms",
        "pipeline_ms",
        "pipeline_scan_ms",
        "batch_execute_ms",
        "analysis_ms",
        "execute_ready_ms",
        "execute_all_wall_ms",
        "preflight_ms",
        "password_resolve_ms",
        "password_native_test_ms",
        "resource_ms",
        "extract_ms",
        "verify_ms",
        "collect_result_ms",
        "output_scan_ms",
        "postprocess_ms",
        "final_summary_ms",
        "extractor_close_ms",
        "scan_results",
        "success_count",
        "failed_count",
    ]
    widths = {header: len(header) for header in headers}
    for row in rows:
        for header in headers:
            widths[header] = max(widths[header], len(str(row[header])))
    print(" | ".join(header.ljust(widths[header]) for header in headers))
    print("-+-".join("-" * widths[header] for header in headers))
    for row in rows:
        print(" | ".join(str(row[header]).ljust(widths[header]) for header in headers))


def parse_formats(value: str) -> list[str]:
    requested = [normalize_archive_format(item) for item in value.split(",") if item.strip()]
    unknown = sorted(set(requested) - set(FORMATS))
    if unknown:
        raise argparse.ArgumentTypeError(f"Unsupported formats: {', '.join(unknown)}")
    return requested or list(FORMATS)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate and pressure-test broad real archive edge cases.")
    parser.add_argument("--strict", action="store_true", help="Return non-zero when expected and observed results differ.")
    parser.add_argument("--no-json", action="store_true", help="Only print the table summary.")
    parser.add_argument("--results-root", type=Path, help="Durable benchmark result root.")
    parser.add_argument("--keep-workdir", action="store_true", help="Keep generated archives and extraction outputs.")
    parser.add_argument(
        "--formats",
        type=parse_formats,
        default=list(FORMATS),
        help="Comma-separated formats to cover: 7z,zip,rar,tar,tar.gz,tar.bz2,tar.xz,tar.zst,gzip,bzip2,xz,zstd.",
    )
    parser.add_argument(
        "--profile",
        choices=["full", "acceptance", "acceptance-batch"],
        default="full",
        help="Case matrix to run. Use acceptance-batch for a mixed-directory routine acceptance check.",
    )
    args = parser.parse_args()

    require_7z()
    with BenchmarkWorkspace(
        "extraction.split-pressure",
        results_root=args.results_root,
        keep_workdir=args.keep_workdir,
    ) as workspace:
        root = workspace.corpus
        cases = build_cases(root, args.formats, args.profile)
        if args.profile == "acceptance-batch":
            skipped_cases = [pressure_case for pressure_case in cases if pressure_case.case is None]
            runnable_cases = [pressure_case for pressure_case in cases if pressure_case.case is not None]
            rows = [run_case(pressure_case) for pressure_case in skipped_cases]
            if runnable_cases:
                rows.extend(run_batch_cases(runnable_cases))
        else:
            rows = [run_case(pressure_case) for pressure_case in cases]
        print_table(rows)
        rendered = render_report(report_from_payload("extraction.split-pressure", rows))
        workspace.write_result_text("report.json", rendered)
        if not args.no_json:
            print("\nJSON:")
            print(rendered)

    failures = [
        row for row in rows
        if row["expected"] != "skip" and row["expected"] != row["observed"]
    ]
    if failures:
        print(f"\nUnexpected results: {len(failures)}", file=sys.stderr)
        if args.strict:
            return 1
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except FileNotFoundError as exc:
        print(f"SKIP: {exc}")
        raise SystemExit(0)
    except subprocess.TimeoutExpired as exc:
        print(f"ERROR: command timed out: {exc}", file=sys.stderr)
        raise SystemExit(2)
