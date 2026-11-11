from __future__ import annotations

import json

import pytest

from tests.helpers.tool_config import get_optional_rar
from tests.real.nested_cases import assert_nested_outputs, build_nested_case


@pytest.mark.parametrize("outer_format", ["7z", "zip", "rar"])
@pytest.mark.parametrize("leaf_password_known", [False, True])
def test_cli_disguised_split_carrier_multilevel_passwords(package, tmp_path, outer_format, leaf_password_known):
    if outer_format == "rar" and get_optional_rar() is None:
        pytest.skip("RAR writer is required")
    case = build_nested_case(tmp_path, f"cli-{outer_format}", outer_format)
    output = tmp_path / "out"
    package.configure(filesystem={"scan_filters": [{"name": "size_range", "enabled": False}]})
    passwords = ["definitely-wrong", *(case.passwords if leaf_password_known else case.passwords[:2])]
    candidates = [arg for password in passwords for arg in ("-p", password)]
    report = package.json(
        "extract", "-c", "k", "-r", "*", "-d", "-F", "--no-bpw", "-o", output,
        *candidates, case.outer.archive_dir, code=0 if leaf_password_known else 1,
    )
    assert report["summary"]["partial_success_count"] == 0, report
    assert report["summary"]["failed_count"] == (0 if leaf_password_known else 1), report
    assert report["summary"]["success_count"] == (5 if leaf_password_known else 4), report
    if not leaf_password_known:
        assert report["tasks"][0]["wrong_password_failure"]
        assert case.blocked_name in report["errors"][0]
    assert_nested_outputs(output, case, leaf_success=leaf_password_known)
    assert all(path.is_file() for path in case.parts)


def test_concurrent_nested_groups_isolate_password_failure_and_cleanup(package, tmp_path):
    healthy = build_nested_case(tmp_path, "healthy", "7z")
    blocked = build_nested_case(tmp_path, "blocked", "zip")
    output = tmp_path / "out"
    package.configure(filesystem={"scan_filters": [{"name": "size_range", "enabled": False}]})
    scopes = [
        {"value": value, "scopes": [str(case.outer.archive_dir)]}
        for case, values in ((healthy, healthy.passwords), (blocked, blocked.passwords[:2]))
        for value in values
    ]
    (package.data / "builtin_passwords.json").write_text(json.dumps({"passwords": scopes}), encoding="utf-8")
    report = package.json(
        "extract", "-d", "-r", "*", "-c", "d", "-f", "-o", output,
        healthy.outer.archive_dir, blocked.outer.archive_dir, code=1,
    )
    assert report["summary"]["partial_success_count"] == 0, report
    assert report["summary"]["success_count"] == 9, report
    assert len(report["errors"]) == 1 and blocked.blocked_name in report["errors"][0], report
    assert report["tasks"][0]["wrong_password_failure"]
    assert (blocked.outer.archive_dir / blocked.blocked_name).is_file()
    assert_nested_outputs(output, healthy, leaf_success=True)
    assert_nested_outputs(output, blocked, leaf_success=False)
    assert not any(path.exists() for path in healthy.parts)
