from __future__ import annotations

import ast
from pathlib import Path

from sunpack.support.output_cleanup import (
    OutputCleanupEvent,
    OutputCleanupExecutor,
    OutputCleanupManager,
    OutputRole,
)


def test_terminal_failure_preserves_nonempty_canonical_output(tmp_path):
    output = tmp_path / "output"
    output.mkdir()
    (output / "payload.bin").write_bytes(b"payload")

    result = OutputCleanupManager().cleanup_canonical(
        str(output),
        event=OutputCleanupEvent.TERMINAL_FAILURE,
        planned_output_dir=str(output),
    )

    assert result.reason == "nonempty_payload"
    assert result.payload_bytes == len(b"payload")
    assert output.is_dir()


def test_policy_rejected_partial_can_remove_nonempty_canonical_output(tmp_path):
    output = tmp_path / "output"
    output.mkdir()
    (output / "payload.bin").write_bytes(b"payload")

    result = OutputCleanupManager().cleanup_canonical(
        str(output),
        event=OutputCleanupEvent.POLICY_REJECTED_PARTIAL,
        planned_output_dir=str(output),
    )

    assert result.cleaned is True
    assert result.reason == "policy_rejected_partial_cleaned"
    assert not output.exists()


def test_canonical_cleanup_refuses_unowned_and_root_paths(tmp_path):
    output = tmp_path / "output"
    output.mkdir()

    unowned = OutputCleanupManager().cleanup_canonical(
        str(output),
        event=OutputCleanupEvent.EXTRACT_RETRY,
        planned_output_dir=str(tmp_path / "different"),
    )
    root = OutputCleanupManager().cleanup_canonical(
        str(Path(tmp_path.anchor)),
        event=OutputCleanupEvent.EXTRACT_RETRY,
        planned_output_dir=str(Path(tmp_path.anchor)),
    )

    assert unowned.reason == "unowned_output"
    assert root.reason == "filesystem_root_refused"
    assert output.is_dir()


def test_partial_file_cleanup_is_limited_to_output_root(tmp_path):
    output = tmp_path / "output"
    output.mkdir()
    inside = output / "partial.bin"
    outside = tmp_path / "outside.bin"
    inside.write_bytes(b"inside")
    outside.write_bytes(b"outside")

    cleaned = OutputCleanupManager().cleanup_partial_file(str(inside), output_root=str(output))
    refused = OutputCleanupManager().cleanup_partial_file(str(outside), output_root=str(output))

    assert cleaned.cleaned is True
    assert refused.reason == "unowned_output"
    assert not inside.exists()
    assert outside.is_file()


def test_executor_failure_is_reported_without_claiming_cleanup(tmp_path):
    class FailingExecutor(OutputCleanupExecutor):
        @staticmethod
        def remove_tree(path: str) -> None:
            raise OSError("locked")

    output = tmp_path / "output"
    output.mkdir()
    result = OutputCleanupManager(FailingExecutor()).cleanup_canonical(
        str(output),
        event=OutputCleanupEvent.EXTRACT_RETRY,
        planned_output_dir=str(output),
    )

    assert result.eligible is True
    assert result.cleaned is False
    assert result.reason == "cleanup_failed"
    assert result.error == "locked"
    assert output.is_dir()


def test_output_deletion_primitives_are_confined_to_approved_infrastructure():
    project_root = Path(__file__).resolve().parents[2]
    allowed = {
        Path("sunpack/support/output_cleanup.py"),
        Path("sunpack/cli/persistent_process.py"),
        Path("sunpack/coordinator/reporting.py"),
        Path("sunpack/filesystem/watcher/scheduler.py"),
        Path("sunpack/filesystem/watcher/service.py"),
        Path("sunpack/filesystem/watcher/state.py"),
        Path("sunpack/support/resource_lifecycle.py"),
    }
    violations: list[str] = []
    for path in (project_root / "sunpack").rglob("*.py"):
        relative = path.relative_to(project_root)
        if relative in allowed:
            continue
        source = path.read_text(encoding="utf-8")
        if not any(token in source for token in ("rmtree", "unlink", "remove")):
            continue
        tree = ast.parse(source, filename=str(relative))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            is_delete = node.func.attr in {"rmtree", "unlink"}
            is_os_remove = (
                node.func.attr == "remove"
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "os"
            )
            if is_delete or is_os_remove:
                violations.append(f"{relative}:{node.lineno}")
    assert violations == []
