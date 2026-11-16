"""Shipped GUI text and real installer-to-GUI permission contracts."""
import base64
import ctypes
import ntpath
import shutil
from ctypes import wintypes
import json
import os
import platform
import re
import subprocess
from pathlib import Path

import pytest

from tests.helpers.installer import inno_compiler
from tests.unit.test_context_menu_registration import _windows_argv


def test_gui_template_texts_exist_in_both_languages():
    # Conditional error actions need not appear in ordinary UI runs. Checking
    # the shipped template/catalog boundary catches missing labels cheaply.
    resources = Path(__file__).resolve().parents[2] / "gui" / "resources"
    catalog = json.loads((resources / "catalog.json").read_text(encoding="utf-8"))["ui"]
    for template in resources.glob("*.uix"):
        for key in set(re.findall(r"\btexts\.([A-Za-z_][A-Za-z0-9_]*)", template.read_text(encoding="utf-8"))):
            assert key in catalog, (template.name, key)
            assert all(catalog[key].get(language) for language in ("zh", "en")), (template.name, key)


@pytest.mark.requires_watch_broker
def test_encrypted_rar5_recovery_keeps_one_gui_card(package, tmp_path, repo_root):
    # Reuse the real archive lifecycle. Runtime-only assertions cannot catch
    # stale cards, lost member chips, or C++ status projection after head changes.
    from tests.blackbox.test_format_volume_matrix import _watch_encrypted_rar5_recovery

    arch = "arm64" if platform.machine().lower() in {"arm64", "aarch64"} else "x64"
    binary = Path(os.environ.get("SUNPACK_GUI_TEST_BINARY", repo_root / ".cache" / f"gui-{arch}" / "Release" / "sunpack_gui_tests.exe"))
    assert binary.is_file(), "Build the native GUI with scripts/build_gui.ps1"

    def project(phase, parts, head):
        result = subprocess.run(
            [str(binary), "--project", str(package.data / ".sunpack_watch" / "events.json")],
            capture_output=True, text=True, encoding="utf-8", check=True, timeout=30,
        )
        rows = json.loads(result.stdout)["tasks"]["rows"]
        assert len(rows) == 1, rows
        row = rows[0]
        assert row["status"] == ("taskSucceeded" if phase == "done" else "taskWaiting"), row
        assert row["statusText"] == {"password": "等待密码", "volumes": "等待分卷", "done": "成功"}[phase], row
        assert set(row["parts"]) == {part.name for part in parts}, row
        if head:
            assert Path(row["path"]) == head and row["name"] == head.name, row
        assert not row["error"] and not row["errorType"], row
        if phase == "done":
            assert row["outputs"] and all(Path(path).is_dir() for path in row["outputs"]), row

    _watch_encrypted_rar5_recovery(package, tmp_path, project)


def _ps_string(value) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def _powershell(script: str):
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    result = subprocess.run(
        ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_installer_repairs_existing_and_new_data_permissions(tmp_path, repo_root):
    # This real install hook also catches a skipped ACL repair after [Dirs]/[Files]
    # create the data directory. Runtime tests cannot detect that install order.
    arch = "arm64" if platform.machine().lower() in {"arm64", "aarch64"} else "x64"
    binary = Path(os.environ.get("SUNPACK_GUI_TEST_BINARY", repo_root / ".cache" / f"gui-{arch}" / "Release" / "sunpack_gui_tests.exe"))
    assert binary.is_file(), "Build the native GUI with scripts/build_gui.ps1"
    compiler = inno_compiler()

    existing = tmp_path / "existing ' [data]"
    fresh = tmp_path / "fresh"
    nested = existing / "nested"
    nested.mkdir(parents=True)
    fresh.mkdir()
    password_file = existing / "builtin_passwords.json"
    password_file.write_text('{"passwords":[],"clipboard_history":[]}', encoding="utf-8")
    backup = nested / "builtin_passwords.txt.bak"
    backup.write_text("preserved", encoding="utf-8")
    original = password_file.read_bytes()
    _powershell(f"""
$ErrorActionPreference = 'Stop'
$data = {_ps_string(existing)}
$acl = [IO.Directory]::GetAccessControl($data)
$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
    [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'), 'Modify', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
[IO.Directory]::SetAccessControl($data, $acl)
$directory = {_ps_string(nested)}
$acl = [IO.Directory]::GetAccessControl($directory)
$acl.SetAccessRuleProtection($true, $true)
[IO.Directory]::SetAccessControl($directory, $acl)
foreach ($path in @({_ps_string(password_file)}, {_ps_string(backup)})) {{
    $acl = [IO.File]::GetAccessControl($path)
    foreach ($sid in @('S-1-1-0', 'S-1-5-11', 'S-1-5-32-545')) {{
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($sid), 'Modify', 'Allow'))
    }}
    [IO.File]::SetAccessControl($path, $acl)
}}
'true'
""")

    source = (repo_root / "installer/SunPack.iss").read_text(encoding="utf-8-sig")
    routines = []
    for name in ("PowerShellSingleQuotedString", "ConfigureDataDirectoryPermissions",
                 "AppendTextLine", "SaveUTF8TextLines", "EnsureLocalizedEditableConfigFiles"):
        match = re.search(rf"^(?:function|procedure) {name}\b.*?^end;", source, re.M | re.S)
        assert match is not None, name
        routines.append(match.group().replace(r"{commonappdata}\SunPack", "{param:Data}"))
    marker = tmp_path / "completed"
    harness = tmp_path / "permissions.iss"
    harness.write_text(f"""
[Setup]
AppName=SunPack permission regression
AppVersion=1
DefaultDirName={{tmp}}\\SunPackPermissionRegression
PrivilegesRequired=lowest
Uninstallable=no
CreateAppDir=no
DisableWelcomePage=yes
DisableFinishedPage=yes
OutputDir={tmp_path}
OutputBaseFilename=permissions
[Dirs]
Name: "{{param:Data}}"
[CustomMessages]
DataDirectoryPermissionsFailed=Cannot secure %s
EditableConfigCreateFailed=Cannot create %s
WatchRootsFileHeader=# Watched folders
WatchRootsFileMapping=# Mapping
WatchRootsFileDeepDetect=# Deep detect
WatchRootsFileExample=# Example
[Code]
{chr(10).join(routines)}
procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    EnsureLocalizedEditableConfigFiles;
    SaveStringToFile({_ps_string(marker)}, 'ok', False);
  end;
end;
""", encoding="utf-8-sig")
    result = subprocess.run([compiler, "/Qp", str(harness)], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    for directory in (existing, fresh, existing):
        result = subprocess.run(
            [str(harness.with_suffix(".exe")), "/VERYSILENT", "/SUPPRESSMSGBOXES", "/SP-",
             "/NORESTART", f"/Data={directory}", f"/LOG={tmp_path / 'setup.log'}"],
            capture_output=True, text=True, timeout=30,
        )
        assert result.returncode == 0 and marker.exists(), (tmp_path / "setup.log").read_text(encoding="utf-8-sig", errors="replace")
    assert password_file.read_bytes() == original
    assert backup.read_text(encoding="utf-8") == "preserved"

    # Verify effective non-elevated IO as well as exact root and inherited child grants.
    for directory in (existing, fresh):
        roots_file = directory / "sunpack_watch_roots.txt"
        roots_file.write_text("C:\\Downloads\n", encoding="utf-8")
        temp = directory / ".clipboard.tmp"
        temp.write_text('{"passwords":[],"clipboard_history":["updated"]}', encoding="utf-8")
        temp.replace(directory / "builtin_passwords.json")
        assert json.loads((directory / "builtin_passwords.json").read_text(encoding="utf-8"))["clipboard_history"] == ["updated"]
        # Python rename succeeds with Modify, while ReplaceFile without a
        # backup requires DELETE_CHILD here. Exercise the actual GUI writer;
        # ACL shape and runtime-only writes cannot detect this failure.
        result = subprocess.run([str(binary), "--password-add", str(directory / "builtin_passwords.json"), "GUI saved"],
                                capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stdout + result.stderr
        assert json.loads((directory / "builtin_passwords.json").read_text(encoding="utf-8")) == {
            "passwords": [{"value": "GUI saved"}], "clipboard_history": ["updated"],
        }
    security = _powershell(f"""
$ErrorActionPreference = 'Stop'
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$items = foreach ($root in @({_ps_string(existing)}, {_ps_string(fresh)})) {{
    $root
    [IO.Directory]::GetFileSystemEntries($root, '*', [IO.SearchOption]::AllDirectories)
}}
$entries = @($items | ForEach-Object {{
    $acl = if ([IO.Directory]::Exists($_)) {{ [IO.Directory]::GetAccessControl($_) }} else {{ [IO.File]::GetAccessControl($_) }}
    @{{ path = $_; protected = $acl.AreAccessRulesProtected; rules = @(
        $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | ForEach-Object {{
            @{{ sid = $_.IdentityReference.Value; rights = [int]$_.FileSystemRights;
               inherited = $_.IsInherited; type = [string]$_.AccessControlType;
               inheritance = [int]$_.InheritanceFlags; propagation = [int]$_.PropagationFlags }}
        }}
    ) }}
}})
@{{ sid = $sid; entries = $entries }} | ConvertTo-Json -Depth 6 -Compress
""")
    roots = {str(existing), str(fresh)}
    expected = {"S-1-5-32-545": 0x1301BF, "S-1-5-18": 0x1F01FF, "S-1-5-32-544": 0x1F01FF}
    assert len(security["entries"]) == 8
    for entry in security["entries"]:
        is_root = entry["path"] in roots
        assert entry["protected"] is is_root
        assert {rule["sid"]: rule["rights"] for rule in entry["rules"]} == expected
        assert len(entry["rules"]) == 3
        assert all(rule["type"] == "Allow" and rule["inherited"] is not is_root for rule in entry["rules"])
        if is_root:
            assert all(rule["inheritance"] == 3 and rule["propagation"] == 0 for rule in entry["rules"])


@pytest.mark.parametrize("contract", [
    "event_log::gui_contract::rust_writer_cpp_query_lifecycle",
    "event_log::gui_contract::rust_writer_cpp_query_publication_conflict",
    "runtime::watch::journal::tests::cpp_query_recovers_durable_blocker_after_writer_death",
], ids=["lifecycle", "publication-conflict", "crash-recovery"])
def test_rust_writer_cpp_query_contract(repo_root, contract):
    # The existing Rust decoder cannot detect C++ query/index/filter mistakes.
    # This prebuilt test drives the real writer and invokes --project itself;
    # no Python pipeline, copied store decoder, or build-on-test fallback.
    writer = os.environ.get("SUNPACK_GUI_WRITER_TEST_BINARY")
    if not writer:
        pytest.skip("Set SUNPACK_GUI_WRITER_TEST_BINARY to the prebuilt Rust lib test executable")
    binary = Path(writer)
    assert binary.is_file(), "Set SUNPACK_GUI_WRITER_TEST_BINARY to the Rust lib test executable in the Cargo cache"
    arch = "arm64" if platform.machine().lower() in {"arm64", "aarch64"} else "x64"
    gui = Path(os.environ.get("SUNPACK_GUI_TEST_BINARY", repo_root / ".cache" / f"gui-{arch}" / "Release" / "sunpack_gui_tests.exe"))
    assert gui.is_file(), "Build the actual C++ GUI reader with scripts/build_gui.ps1"
    environment = {**os.environ, "SUNPACK_GUI_TEST_BINARY": str(gui)}
    result = subprocess.run(
        [str(binary), "--ignored", "--exact", contract, "--nocapture"],
        capture_output=True, text=True, encoding="utf-8", env=environment, timeout=120,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "1 passed" in result.stdout, "the real writer/GUI boundary test was not selected"


@pytest.mark.parametrize(
    ("menu_key", "expected_args"),
    [
        ("folder_watch", ["watch", "add", "--start"]),
        ("background_watch", ["watch", "add", "--start"]),
        ("folder_recursive_watch", ["watch", "add", "--start", "--recursive"]),
        ("background_recursive_watch", ["watch", "add", "--start", "--recursive"]),
        ("folder_unwatch", ["watch", "remove"]),
        ("background_unwatch", ["watch", "remove"]),
    ],
)
def test_context_menu_watch_passes_literal_complex_paths_to_child(tmp_path, menu_key, expected_args, native_argument_recorder):
    # Exercise Explorer command -> actual GUI -> hidden native CLI, not merely
    # registry text. No admin rights or live Watch service needed.
    scripts_dir = tmp_path / "menu scripts"
    scripts_dir.mkdir()
    for name in ("register_context_menu.ps1",):
        shutil.copyfile(Path(__file__).resolve().parents[2] / "scripts" / name, scripts_dir / name)
    arch = "arm64" if os.environ.get("PROCESSOR_ARCHITECTURE", "").lower() == "arm64" else "x64"
    target = {"arm64": "aarch64-pc-windows-msvc", "x64": "x86_64-pc-windows-msvc"}[arch]
    stub = tmp_path / ".cache" / "native" / arch / "ci" / "sevenzip_bridge" / "Release" / "sunpack_launcher.exe"
    stub.parent.mkdir(parents=True)
    shutil.copyfile(native_argument_recorder, stub)
    runtime = tmp_path / ".cache" / "rust-target" / target / "ci" / "sunpack-runtime.exe"
    runtime.parent.mkdir(parents=True)
    runtime.touch()
    gui = Path(__file__).resolve().parents[2] / ".cache" / f"gui-{arch}" / "Release" / "SunPackGUI.exe"
    assert gui.is_file(), "Build scripts/build_gui.ps1 before running GUI shell integration"
    shutil.copyfile(gui, tmp_path / "SunPackGUI.exe")
    folder = tmp_path / "WeChat's 中文 Files & (2026)"
    folder.mkdir()
    completed = subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
         "-File", str(scripts_dir / "register_context_menu.ps1"), "-DryRun"],
        check=True, capture_output=True, text=True, encoding="utf-8-sig", timeout=30,
    )
    commands = json.loads(completed.stdout.strip().splitlines()[-1])
    command = commands[menu_key].replace("%1", str(folder)).replace("%V", str(folder))
    # Hold the real manager's singleton name on one route. Shell actions must
    # still run rather than activating the existing window and dropping work.
    mutex = None
    kernel = ctypes.windll.kernel32
    if menu_key == "folder_recursive_watch":
        probe = gui.with_name("sunpack_gui_tests.exe")
        names = subprocess.check_output([str(probe), "--mutex", str(tmp_path)], text=True)
        name = names.splitlines()[0].replace("SunPack.EditableFile", "SunPack.GUI")
        kernel.CreateMutexW.restype = wintypes.HANDLE
        kernel.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        mutex = kernel.CreateMutexW(None, False, name)
        assert mutex
        command += ' --data-dir "' + str(tmp_path) + '"'
    try:
        launched = subprocess.run(
            _windows_argv(command), capture_output=True, text=True, timeout=30,
        )
    finally:
        if mutex:
            kernel.CloseHandle(mutex)
    assert launched.returncode == 0, launched.stderr
    actual = stub.with_suffix(".args").read_text(encoding="utf-8-sig").splitlines()
    assert actual[:2] == expected_args[:2]
    assert ntpath.normpath(actual[2]) == ntpath.normpath(str(folder))
    assert actual[3:] == expected_args[2:]
    assert stub.with_suffix(".console").read_text() == "False"


@pytest.fixture(scope="session")
def native_argument_recorder(tmp_path_factory):
    workspace = tmp_path_factory.mktemp("native-arguments")
    framework = Path(os.environ.get("WINDIR", r"C:\Windows")) / "Microsoft.NET"
    compiler = next((path for path in (
        framework / "Framework64/v4.0.30319/csc.exe",
        framework / "Framework/v4.0.30319/csc.exe",
    ) if path.is_file()), None)
    if compiler is None:
        pytest.skip("Windows .NET Framework C# compiler is required for the native argv fixture")
    source = workspace / "Arguments.cs"
    source.write_text("""
using System.IO;
using System.Reflection;
using System.Text;
using System;
using System.Runtime.InteropServices;
class Arguments {
    [DllImport("kernel32.dll")] static extern IntPtr GetConsoleWindow();
    static void Main(string[] args) {
        string path = Path.ChangeExtension(Assembly.GetExecutingAssembly().Location, "args");
        File.WriteAllLines(path, args, new UTF8Encoding(false));
        File.WriteAllText(Path.ChangeExtension(path, "console"), (GetConsoleWindow() != IntPtr.Zero).ToString());
    }
}
""", encoding="ascii")
    executable = workspace / "Arguments.exe"
    completed = subprocess.run(
        [str(compiler), "/nologo", "/target:exe", "/out:" + str(executable), str(source)],
        capture_output=True, text=True, timeout=30,
    )
    assert completed.returncode == 0, (completed.stdout, completed.stderr)
    return executable
