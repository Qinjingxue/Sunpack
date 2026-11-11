"""Exercise crash cleanup selection without attaching disks or elevating."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import uuid

import pytest


pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="PowerShell cleanup boundary")


def test_vhd_cleanup_recovers_current_and_legacy_names_only(tmp_path, repo_root):
    # Existing disk-full tests clean up through their finally blocks, so they
    # cannot detect a naming mismatch in the recovery path after a hard kill.
    # Run that real recovery function with only disk dismount mocked out.
    def literal(value):
        return "'" + str(value).replace("'", "''") + "'"

    root = tmp_path / "test artifacts 中文"
    nested = root / "nested"
    nested.mkdir(parents=True)
    external = tmp_path / "custom vhd directory"
    external.mkdir()
    current = nested / f"SP{uuid.uuid4().hex[:12]}.vhdx"
    legacy = root / "space-interrupted.vhdx"
    custom = external / f"SP{uuid.uuid4().hex[:12]}.vhdx"
    unrelated = [nested / name for name in ("personal.vhdx", "SP01234.vhdx", "SPnot-a-test00.vhdx")]
    for path in [current, legacy, custom, *unrelated]:
        path.write_bytes(b"not a mounted disk")
    result_path = tmp_path / "dismounted.json"
    harness = tmp_path / "cleanup.ps1"
    harness.write_text(f"""
$ErrorActionPreference = 'Stop'
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile({literal(repo_root / 'scripts/cleanup_test_artifacts.ps1')}, [ref]$tokens, [ref]$errors)
if ($errors.Count) {{ throw ($errors | Out-String) }}
$definition = $ast.Find({{ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Remove-StaleTestVhds' }}, $true)
if ($null -eq $definition) {{ throw 'Missing VHD cleanup function' }}
. ([scriptblock]::Create($definition.Extent.Text))
$testTempRoot = {literal(root)}
$script:CleanupFailures = 0
$script:Dismounted = @()
function Dismount-DiskImage {{ param([string]$ImagePath) $script:Dismounted += $ImagePath }}
Remove-StaleTestVhds
if ($script:CleanupFailures) {{ throw 'Cleanup failed' }}
[IO.File]::WriteAllText({literal(result_path)}, (ConvertTo-Json -InputObject @($script:Dismounted)))
""", encoding="utf-8-sig")
    completed = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(harness)],
        capture_output=True, text=True, errors="replace", timeout=30,
        env={**os.environ, "SUNPACK_SPACE_TEST_VHD_DIR": str(external)},
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert set(json.loads(result_path.read_text(encoding="utf-8-sig"))) == {
        str(current), str(legacy), str(custom),
    }
    assert not any(path.exists() for path in (current, legacy, custom))
    assert all(path.exists() for path in unrelated)
