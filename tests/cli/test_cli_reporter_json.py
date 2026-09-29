import io
from dataclasses import fields

import pytest

from sunpack.core.support.json_format import to_json_text
from sunpack.runtime.cli.cli_reporter import CliReporter
from sunpack.runtime.cli.cli_types import CliCommandResult


def _expected(result):
    return to_json_text({field.name: getattr(result, field.name) for field in fields(result)}) + "\n"


@pytest.mark.parametrize("count", [0, 127, 128, 129, 1000])
def test_large_cli_json_matches_existing_output_exactly(count):
    rows = [
        {
            "main_path": f"C:/压缩包/伪装-{index:04d}.jpg",
            "format": "7z",
            "status": "blocked" if index % 3 == 0 else "resolved",
            "offset": index * 512,
            "all_parts": [f"part.{index:03d}.001", f"part.{index:03d}.002"],
            "details": {"nested": ["zip", "rar"], "password_required": index % 3 == 0},
        }
        for index in range(count)
    ]
    result = CliCommandResult(
        command="scan", inputs={"paths": ["C:/压缩包"]},
        summary={"finding_count": count}, items=rows, tasks=rows,
    )
    output = io.StringIO()
    CliReporter(json_mode=True, stdout=output).emit_result(result)
    assert output.getvalue() == _expected(result)


def test_large_cli_json_preserves_normalization():
    rows = [{"main_path": str(index)} for index in range(128)]
    rows[-1]["raw"] = b"\x00\xff"
    result = CliCommandResult(
        command="scan", inputs={1: {b"\xff"}, "tuple": ("中", 2)},
        summary={}, items=rows,
    )
    output = io.StringIO()
    CliReporter(json_mode=True, stdout=output).emit_result(result)
    assert output.getvalue() == _expected(result)
