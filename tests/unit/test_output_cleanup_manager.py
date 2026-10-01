from __future__ import annotations

from pathlib import Path

import pytest

from sunpack.pipeline.postprocess.output_cleanup import (
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


def test_cleanup_admits_unrelated_sibling_operation_in_same_request(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from sunpack.core.support.resource_lifecycle import TaskResourceScope

    output = tmp_path / "output"
    output.mkdir()
    sibling = tmp_path / "sibling.txt"
    sibling.write_text("unrelated input", encoding="utf-8")
    scope = TaskResourceScope("cleanup-sibling", files=(sibling,))

    class ConcurrentExecutor(OutputCleanupExecutor):
        @staticmethod
        def remove_tree(path):
            def sibling_operation():
                with scope.operation(files=(sibling,)):
                    return True

            with ThreadPoolExecutor(max_workers=1) as pool:
                assert pool.submit(sibling_operation).result(timeout=2)
            OutputCleanupExecutor.remove_tree(path)

    try:
        with scope.activate():
            result = OutputCleanupManager(ConcurrentExecutor()).cleanup_canonical(
                str(output), event=OutputCleanupEvent.EXTRACT_RETRY,
            )
        assert result.cleaned
        assert sibling.is_file()
    finally:
        scope.close()


@pytest.mark.parametrize("role", [OutputRole.CANONICAL, OutputRole.PARTIAL_FILE])
def test_scoped_cleanup_authorizes_only_strict_workspace_descendants(tmp_path, role):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    inside = workspace / "owned"
    outside = tmp_path / "outside"
    if role == OutputRole.CANONICAL:
        inside.mkdir()
        outside.mkdir()
    else:
        inside.write_text("partial")
        outside.write_text("unowned")
    manager = OutputCleanupManager()

    for path in (workspace, outside, workspace / ".." / "outside"):
        result = manager.cleanup_scoped_path(
            str(path), event=OutputCleanupEvent.EXTRACT_RETRY,
            role=role, workspace_root=str(workspace),
        )
        assert result.reason == "unowned_output"
        assert path.exists()

    result = manager.cleanup_scoped_path(
        str(inside), event=OutputCleanupEvent.EXTRACT_RETRY,
        role=role, workspace_root=str(workspace),
    )
    assert result.cleaned
    assert not inside.exists()
    assert workspace.exists() and outside.exists()
