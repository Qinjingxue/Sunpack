"""Run the acceptance process boundary without building or installing SunPack."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows process/PowerShell boundary")


def test_acceptance_runs_native_commands_and_rejects_incomplete_reports(tmp_path, repo_root):
    # One real-process check covers the non-Python cargo route, argv quoting,
    # failure propagation, and mandatory coverage/report validation. It never
    # executes acceptance's top-level setup or installs a broker/service.
    def literal(value):
        return "'" + str(value).replace("'", "''") + "'"

    directory = tmp_path / "arguments with spaces 中文"
    directory.mkdir()
    arguments = ["a b", 'embedded"quote', "trailing space \\", ""]
    probe = directory / "probe.py"
    probe.write_text(
        f"import sys\nassert sys.argv[1:] == {arguments!r}, sys.argv\n", encoding="utf-8",
    )
    # A local stub produces controlled JUnit reports; no nested pytest session.
    (directory / "pytest.py").write_text(
        "import pathlib, sys\n"
        "path = next(arg.split('=', 1)[1] for arg in sys.argv if arg.startswith('--junitxml='))\n"
        "xml = '<testsuites><testsuite><testcase><skipped/></testcase></testsuite></testsuites>'\n"
        "if '--broken' in sys.argv: xml = '<broken'\n"
        "pathlib.Path(path).write_text(xml, encoding='utf-8')\n", encoding="utf-8",
    )
    result_path = directory / "result.json"
    harness = directory / "harness.ps1"
    harness.write_text(f"""
$ErrorActionPreference = 'Stop'
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile({literal(repo_root / 'run_acceptance_tests.ps1')}, [ref]$tokens, [ref]$errors)
if ($errors.Count) {{ throw ($errors | Out-String) }}
$names = @('Initialize-ExitCodeProbe', 'Get-ChildExitCode', 'ConvertTo-WindowsCommandLineArgument', 'Invoke-TestStep')
$definitions = $ast.FindAll({{ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -in $names }}, $true)
foreach ($definition in $definitions) {{ . ([scriptblock]::Create($definition.Extent.Text)) }}
$python = {literal(sys.executable)}
$repoRoot = {literal(directory)}
$unelevatedRunner = {literal(repo_root / 'scripts/run_unelevated_process.py')}
$StepTimeoutSeconds = 30
$script:AcceptanceProcessIsAdministrator = $false
$script:StepResults = @()
Invoke-TestStep -Label 'Native failure' -Command @($env:ComSpec, '/c', 'exit', '7')
Invoke-TestStep -Label 'Quoted argv' -Command @($python, {literal(probe)}, {', '.join(map(literal, arguments))})
Invoke-TestStep -Label 'Required coverage' -RequireExecutedTests -Command @($python, '-m', 'pytest')
Invoke-TestStep -Label 'Invalid report' -Command @($python, '-m', 'pytest', '--broken')
[IO.File]::WriteAllText({literal(result_path)}, (ConvertTo-Json -InputObject $script:StepResults))
""", encoding="utf-8-sig")
    env = {**os.environ, "PYTHONPATH": str(directory)}
    env.pop("SUNPACK_ACCEPTANCE_DIAGNOSTICS_DIR", None)
    completed = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(harness)],
        capture_output=True, text=True, errors="replace", env=env, timeout=150,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    results = json.loads(result_path.read_text(encoding="utf-8-sig"))
    assert [row["ExitCode"] for row in results] == [7, 0, 1, -2], completed.stdout + completed.stderr
