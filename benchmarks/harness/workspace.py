from __future__ import annotations

import json
import os
import shutil
import tempfile
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_RESULTS_ROOT = REPO_ROOT / "benchmarks" / "results"
DEFAULT_TEMP_ROOT = REPO_ROOT / "benchmarks" / ".work"
BENCHMARK_RUN_ID_ENV = "SUNPACK_BENCH_RUN_ID"


def _safe_name(value: str) -> str:
    rendered = "".join(character if character.isalnum() or character in "-." else "-" for character in value)
    return rendered.strip("-.") or "benchmark"


def benchmark_temp_dir(prefix: str, *, temp_root: Path | None = None) -> Path:
    """Create a temporary benchmark directory under the shared work root."""
    root = (temp_root or DEFAULT_TEMP_ROOT).resolve()
    root.mkdir(parents=True, exist_ok=True)
    requested_run_id = os.environ.get(BENCHMARK_RUN_ID_ENV)
    run_id = _safe_name(requested_run_id) if requested_run_id else None
    tagged_prefix = f"{prefix}{run_id}-" if run_id else prefix
    return Path(tempfile.mkdtemp(prefix=tagged_prefix, dir=root))


@dataclass(frozen=True)
class WorkspacePaths:
    root: Path
    corpus: Path
    work: Path
    outputs: Path
    result: Path


class BenchmarkWorkspace:
    """Own one benchmark run's temporary corpus and durable result directory."""

    def __init__(
        self,
        scenario: str,
        *,
        results_root: Path | None = None,
        temp_root: Path | None = None,
        keep_workdir: bool = False,
        run_id: str | None = None,
    ):
        self.scenario = scenario
        self.results_root = (results_root or DEFAULT_RESULTS_ROOT).resolve()
        self.temp_root = (temp_root or DEFAULT_TEMP_ROOT).resolve()
        self.keep_workdir = keep_workdir
        requested_run_id = run_id or os.environ.get(BENCHMARK_RUN_ID_ENV)
        self.run_id = _safe_name(requested_run_id) if requested_run_id else None
        self.paths: WorkspacePaths | None = None
        self.started_at = datetime.now(timezone.utc)

    def __enter__(self) -> "BenchmarkWorkspace":
        scenario_name = _safe_name(self.scenario)
        run_id = f"{self.started_at.strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:8]}"
        result = self.results_root / scenario_name / run_id
        result.mkdir(parents=True, exist_ok=False)
        self.temp_root.mkdir(parents=True, exist_ok=True)
        work_prefix = f"{scenario_name}-{self.run_id}-" if self.run_id else f"{scenario_name}-"
        root = Path(tempfile.mkdtemp(prefix=work_prefix, dir=self.temp_root))
        corpus = root / "corpus"
        work = root / "work"
        outputs = root / "outputs"
        for path in (corpus, work, outputs):
            path.mkdir()
        self.paths = WorkspacePaths(root=root, corpus=corpus, work=work, outputs=outputs, result=result)
        self._write_manifest(status="running")
        return self

    @property
    def root(self) -> Path:
        return self._require_paths().root

    @property
    def corpus(self) -> Path:
        return self._require_paths().corpus

    @property
    def work(self) -> Path:
        return self._require_paths().work

    @property
    def outputs(self) -> Path:
        return self._require_paths().outputs

    @property
    def result_dir(self) -> Path:
        return self._require_paths().result

    def write_result_text(self, name: str, content: str) -> Path:
        target = self._result_target(name)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        return target

    def write_result_json(self, name: str, payload: Any) -> Path:
        return self.write_result_text(name, json.dumps(payload, ensure_ascii=False, indent=2, default=str))

    def preserve(self, source: Path, name: str | None = None) -> Path:
        """Copy a small durable artifact out of the temporary workspace."""
        source = source.resolve()
        root = self.root.resolve()
        if source != root and root not in source.parents:
            raise ValueError(f"artifact is outside benchmark workspace: {source}")
        target = self._result_target(name or source.name)
        target.parent.mkdir(parents=True, exist_ok=True)
        if source.is_dir():
            shutil.copytree(source, target)
        else:
            shutil.copy2(source, target)
        return target

    def __exit__(self, exc_type, exc, _traceback) -> None:
        status = "failed" if exc is not None else "completed"
        try:
            self._write_manifest(
                status=status,
                error=None if exc is None else repr(exc),
                retained=self.keep_workdir,
            )
        finally:
            if not self.keep_workdir:
                shutil.rmtree(self.root, ignore_errors=True)

    def _require_paths(self) -> WorkspacePaths:
        if self.paths is None:
            raise RuntimeError("benchmark workspace has not been entered")
        return self.paths

    def _result_target(self, name: str) -> Path:
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError(f"result name must stay inside result directory: {name}")
        return self.result_dir / relative

    def _write_manifest(self, *, status: str, error: str | None = None, retained: bool = False) -> None:
        paths = self._require_paths()
        payload = {
            "schema_version": 1,
            "scenario": self.scenario,
            "status": status,
            "started_at": self.started_at.isoformat(),
            "finished_at": None if status == "running" else datetime.now(timezone.utc).isoformat(),
            "temporary_workdir": str(paths.root) if self.keep_workdir or retained else None,
            "temporary_workdir_retained": bool(self.keep_workdir or retained),
            "result_dir": str(paths.result),
            "error": error,
        }
        (paths.result / "manifest.json").write_text(
            json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
        )
