from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from sunpack.core.contracts.failures import FailureKind
from tests.helpers.pipeline_engine import execute_pipeline
from tests.helpers.tool_config import get_optional_rar
from tests.real.nested_cases import assert_nested_outputs, build_nested_case
from tests.real.plan1_real_archives.plan1_support import plan1_config


@pytest.mark.parametrize("outer_format", ["7z", "zip", "rar"])
@pytest.mark.parametrize("leaf_password_known", [False, True])
def test_cli_disguised_split_carrier_multilevel_passwords(tmp_path, plan_error, outer_format, leaf_password_known):
    if outer_format == "rar" and get_optional_rar() is None:
        pytest.skip("RAR writer is required")
    case = build_nested_case(tmp_path, f"cli-{outer_format}", outer_format)
    out_dir = tmp_path / "out"
    passwords = case.passwords if leaf_password_known else case.passwords[:2]
    root = Path(__file__).resolve().parents[2]
    overrides = {
        "filesystem": {"scan_filters": [{"name": "size_range", "enabled": False}]},
        "embedded_scan": {"enabled": True},
        "verification": {"enabled": True},
        "post_extract": {"flatten_single_directory": False},
        "extraction": {"content_requirement": "complete"},
    }
    environment = {**os.environ, "SUNPACK_CONFIG_OVERRIDES": json.dumps(overrides)}
    command = [
        sys.executable, "-B", str(root / "sunpack.py"), "extract", "--json", "--no-pause",
        "--no-builtin-pw", "--no-dir-pw", "--cleanup", "k", "--recur", "*", "--deep-detect",
        "--out-dir", str(out_dir), "-p", "definitely-wrong",
    ]
    for password in passwords:
        command.extend(["-p", password])
    command.append(str(case.outer.archive_dir))
    result = subprocess.run(command, cwd=root, env=environment, capture_output=True, text=True, encoding="utf-8", timeout=60)
    plan_error.update({"outer_format": outer_format, "leaf_password_known": leaf_password_known,
                       "layout": case.layout, "stdout": result.stdout, "stderr": result.stderr})
    assert result.returncode == (0 if leaf_password_known else 1), result.stdout + result.stderr
    report = json.loads(result.stdout)
    assert report["summary"]["partial_success_count"] == 0
    assert report["summary"]["failed_count"] == (0 if leaf_password_known else 1)
    assert report["summary"]["success_count"] == (5 if leaf_password_known else 4)
    if not leaf_password_known:
        failed = [task for task in report["tasks"] if task.get("wrong_password_failure")]
        assert len(failed) == 1
        assert case.blocked_name in report["errors"][0]
    assert_nested_outputs(out_dir, case, leaf_success=leaf_password_known)
    assert all(path.is_file() for path in case.parts), "keep policy must preserve all outer volumes"


def test_concurrent_nested_groups_isolate_password_failure_and_cleanup(tmp_path, plan_error):
    healthy = build_nested_case(tmp_path, "healthy", "7z")
    blocked = build_nested_case(tmp_path, "blocked", "zip")
    config = plan1_config(passwords=[*healthy.passwords, *blocked.passwords[:2]])
    config["output"] = {"root": str(tmp_path / "out")}
    config["post_extract"].update(archive_cleanup_mode="delete", flatten_single_directory=True)
    summary = execute_pipeline(config, [str(healthy.outer.archive_dir), str(blocked.outer.archive_dir)])
    plan_error.update({"failed_tasks": summary.failed_tasks, "failures": [item.to_dict() for item in summary.failures]})
    assert summary.partial_success_count == 0
    assert summary.success_count == 9
    assert len(summary.failed_tasks) == 1
    failure = next(result for result in summary.target_results if result.failure is not None)
    assert Path(failure.input_path).name == blocked.blocked_name
    assert failure.failure.contains(FailureKind.WRONG_PASSWORD)
    assert Path(failure.input_path).is_file(), "flatten/cleanup must retain the actual retry input"
    assert_nested_outputs(tmp_path / "out", healthy, leaf_success=True)
    assert_nested_outputs(tmp_path / "out", blocked, leaf_success=False)
    assert not any(path.exists() for path in healthy.parts), "successful outer volume cleanup must finish"
