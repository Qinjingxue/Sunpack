"""Coarse tests of the installer's on-disk upgrade policy, not runtime shims."""
import json
import subprocess


def _upgrade(repo_root, user, version, advanced=None):
    command = ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive",
               "-ExecutionPolicy", "Bypass", "-File", str(repo_root / "scripts/upgrade_config.ps1"),
               "-UserConfig", str(user), "-TemplateConfig", str(repo_root / "sunpack_config.json"),
               "-PreviousVersion", version]
    if advanced is not None:
        command += ["-AdvancedConfig", str(advanced)]
    return subprocess.run(command, capture_output=True)


def _snapshot(directory):
    return {str(p.relative_to(directory)): (p.read_bytes(), p.stat().st_mtime_ns)
            for p in directory.rglob("*") if p.is_file()}


def test_pre_140_upgrade_retains_user_inputs_and_retires_state(tmp_path, repo_root):
    # Only this real script transaction covers template projection, advanced
    # promotion, byte-safe input repairs and selective state deletion together.
    # Removing it loses the on-disk contract; one process plus retry is cheap.
    data, custom = tmp_path / "data ' [old]", tmp_path / "custom ' [watch]"
    data.mkdir()
    custom.mkdir()
    advanced = tmp_path / "advanced.json"
    advanced.write_text(json.dumps({
        "watch": {"state_dir": str(custom), "tray_enabled": False, "toast_enabled": False,
                  "clipboard_monitor_enabled": False, "clipboard_builtin_max_entries": 17,
                  "toast_report_retention_days": 61},
        "passwords": {"clipboard_passwords_enabled": False},
        "extraction": {"content_requirement": "allow_partial"},
        "analysis": {"shared_cache_mb": 4},
    }), encoding="utf-8")
    user = data / "sunpack_config.json"
    user.write_text(json.dumps({"cli": {"language": "en"}, "runtime": {"process_mode": ""},
        "watch": {"clipboard_monitor_enabled": True, "clipboard_builtin_max_entries": 0,
                  "toast_report_retention_days": None, "event_log_retention_days": 0,
                  "obsolete": 1},
        "recursive_authorization": {"enabled": False}, "unknown": "discard",
        "filesystem": {"scan_filters": []}}), encoding="utf-8")
    roots = data / "sunpack_watch_roots.txt"
    roots.write_bytes(('\ufeff# 保留注释 | output | true | true | false\r\n'
                       'C:\\Downloads | D:\\输出 | true | true | false\r'
                       'C:\\Other | | false | true | true\n').encode())
    passwords = data / "builtin_passwords.json"
    good_lines = [b'\xef\xbb\xbf{', '  "passwords": [{"value": " 密码\\r\\n ", "scopes": ["D:/工作"]}],'.encode(),
                  '  "clipboard_history": ["历史"]'.encode(), b'}']
    passwords.write_bytes(b'\r' * 100 + b'\n \t\r\n'.join(good_lines) + b'\r\n\r\n')
    for directory in (data / ".sunpack_watch", data / "unknown", custom):
        directory.mkdir(exist_ok=True)
        (directory / "state.snapshot").write_bytes(b"old continuation")
        (directory / "state.journal.00000000000000000001.wal").write_bytes(b"old wal")
        (directory / "catalog.wal.bin").write_bytes(b"old catalog")
        (directory / "unrelated.txt").write_bytes(b"user owned")
    advanced_before = advanced.read_bytes()
    result = _upgrade(repo_root, user, "v1.3.5-2-gabcdef0", advanced)
    assert result.returncode == 0, result.stdout + result.stderr
    migrated = json.loads(user.read_text(encoding="utf-8-sig"))
    expected = json.loads((repo_root / user.name).read_text(encoding="utf-8"))
    expected["cli"]["language"] = "en"
    expected["runtime"]["process_mode"] = ""
    expected["watch"].update(tray_enabled=False, toast_enabled=False, clipboard_monitor_enabled=True,
                             clipboard_builtin_max_entries=0, toast_report_retention_days=None,
                             event_log_retention_days=0)
    expected["passwords"]["clipboard_passwords_enabled"] = False
    expected["extraction"]["content_requirement"] = "allow_partial"
    expected["recursive_authorization"]["enabled"] = False
    expected["filesystem"]["scan_filters"] = []
    assert migrated == expected
    assert {p.name for p in data.iterdir()} == {user.name, roots.name, passwords.name}
    assert roots.read_text(encoding="utf-8-sig").splitlines() == [
        "# 保留注释 | output | true | true | false",
        "C:\\Downloads | D:\\输出 | true | false | false",
        "C:\\Other | | false | false | true"]
    assert [line for line in passwords.read_bytes().splitlines() if line.strip()] == good_lines
    assert all(line.strip() for line in passwords.read_bytes().splitlines())
    assert json.loads(passwords.read_text(encoding="utf-8-sig"))["passwords"][0]["value"] == " 密码\r\n "
    assert {p.name for p in custom.iterdir()} == {"unrelated.txt"}
    assert (custom / "unrelated.txt").read_bytes() == b"user owned"
    assert advanced.read_bytes() == advanced_before
    before = {name: value[0] for name, value in _snapshot(data).items()}
    result = _upgrade(repo_root, user, "v1.3.5-2-gabcdef0", advanced)
    assert result.returncode == 0, result.stdout + result.stderr
    assert {name: value[0] for name, value in _snapshot(data).items()} == before


def test_version_gate_and_failed_preflight_leave_all_data_untouched(tmp_path, repo_root):
    # No runtime test can detect a destructive unknown-version guess, a current
    # install repair, or mutation before JSON/reparse preflight. One matrix
    # covers these distinct entry conditions without separate fine-grained tests.
    for index, (version, broken, success) in enumerate([
        ("1.4.0", False, True), ("v1.4.0-2-gabcdef0", True, False),
        ("1.10.0", False, True), ("", False, False), ("invalid", False, False),
        ("1.3.5", True, False),
    ]):
        data = tmp_path / str(index)
        data.mkdir()
        user = data / "sunpack_config.json"
        user.write_text("{invalid}" if broken else '{"cli":{"language":"en"}}', encoding="utf-8")
        (data / "builtin_passwords.json").write_bytes(b'{\r\r\n\r\n"passwords": []\r\n}')
        (data / "sunpack_watch_roots.txt").write_bytes(b"C:\\input | D:\\out | true | true | false\r\n")
        (data / "state.snapshot").write_bytes(b"keep")
        before = _snapshot(data)
        result = _upgrade(repo_root, user, version)
        assert (result.returncode == 0) is success, result.stdout + result.stderr
        assert _snapshot(data) == before
    fresh = tmp_path / "fresh" / "sunpack_config.json"
    assert _upgrade(repo_root, fresh, "").returncode == 0
    assert not fresh.parent.exists()

    data, outside = tmp_path / "linked", tmp_path / "outside"
    data.mkdir()
    outside.mkdir()
    (outside / "precious.txt").write_bytes(b"never touch")
    user = data / "sunpack_config.json"
    user.write_text('{}', encoding="utf-8")
    junction = data / "state"
    subprocess.run(["cmd.exe", "/d", "/c", "mklink", "/J", str(junction), str(outside)],
                   check=True, capture_output=True)
    before = user.read_bytes(), user.stat().st_mtime_ns
    try:
        assert _upgrade(repo_root, user, "1.3.5").returncode != 0
        assert (user.read_bytes(), user.stat().st_mtime_ns) == before
        assert (outside / "precious.txt").read_bytes() == b"never touch"
        assert junction.is_dir()
    finally:
        junction.rmdir()


def test_legacy_filters_keep_only_active_sources_and_repeat_safely(tmp_path, repo_root):
    # Only the installer converts legacy modules. This four-case matrix catches
    # accidental activation of disabled rules, lost legacy matching, template
    # defaults and non-idempotent rewrites; runtime matcher tests cannot do so.
    for index, (prune, blocked) in enumerate(((True, True), (True, False), (False, True), (False, False))):
        data = tmp_path / str(index)
        data.mkdir()
        user = data / "sunpack_config.json"
        user.write_text(json.dumps({"filesystem": {"scan_filters": [
            {"name": "directory_prune", "enabled": prune, "prune_dir_globs": [".git"],
             "path_globs": ["Cache/Private/**"]},
            {"name": "blacklist", "enabled": blocked, "blocked_files": ["Thumbs.db"],
             "blocked_extensions": ["tmp", ".", "..never"]},
            {"name": "whitelist", "enabled": False, "allowed_files": ["keep.zip"],
             "path_globs": ["downloads/**"]},
            {"name": "size_range", "enabled": True, "min_bytes": 0},
        ]}}), encoding="utf-8")
        result = _upgrade(repo_root, user, "v1.3.4-7-gabcdef0")
        assert result.returncode == 0, result.stdout + result.stderr
        filters = json.loads(user.read_text(encoding="utf-8-sig"))["filesystem"]["scan_filters"]
        assert [f["name"] for f in filters] == ["blacklist", "whitelist", "size_range"]
        blacklist, whitelist, size = filters
        assert blacklist["enabled"] is (prune or blocked)
        assert blacklist["paths"] == ([{"value": ".git", "regex": False},
            {"value": r"(?:\A|/)(?:Cache/Private)(?:/|\z)", "regex": True}] if prune or not blocked else [])
        assert blacklist["full_names"] == ([{"value": "Thumbs.db", "regex": False}] if blocked or not prune else [])
        assert blacklist["extensions"] == ([{"value": "tmp", "regex": False},
            {"value": r"\A\z", "regex": True}, {"value": ".never", "regex": False}]
            if blocked or not prune else [])
        assert blacklist["files"] == []
        assert whitelist["enabled"] is False
        assert whitelist["paths"] == [{"value": "downloads", "regex": False}]
        assert whitelist["full_names"] == [{"value": "keep.zip", "regex": False}]
        assert size == {"name": "size_range", "enabled": True, "min_bytes": 0, "max_bytes": None}
        before = {name: value[0] for name, value in _snapshot(data).items()}
        assert _upgrade(repo_root, user, "v1.3.4-7-gabcdef0").returncode == 0
        assert {name: value[0] for name, value in _snapshot(data).items()} == before


def test_current_filters_merge_by_name_without_adding_modules(tmp_path, repo_root):
    # Current-format custom rule lists must not be legacy-converted, expanded
    # with absent modules, or merged positionally. The legacy matrix cannot
    # detect this boundary; one script invocation covers it.
    user = tmp_path / "sunpack_config.json"
    filters = [{"name": "size_range", "enabled": False, "min_bytes": 0},
               {"name": "blacklist", "enabled": False, "extensions": [],
                "paths": [{"value": "exact/*", "regex": True}]}]
    user.write_text(json.dumps({"filesystem": {"scan_filters": filters}}), encoding="utf-8")
    result = _upgrade(repo_root, user, "v1.3.5")
    assert result.returncode == 0, result.stdout + result.stderr
    template = json.loads((repo_root / user.name).read_text(encoding="utf-8"))
    defaults = {f["name"]: f for f in template["filesystem"]["scan_filters"]}
    expected = [dict(defaults[f["name"]], **f) for f in filters]
    assert json.loads(user.read_text(encoding="utf-8-sig"))["filesystem"]["scan_filters"] == expected


def test_current_upgrade_retires_verification_and_preserves_state(tmp_path, repo_root):
    user, advanced = tmp_path / "sunpack_config.json", tmp_path / "advanced.json"
    payload = {"extraction": {"content_requirement": "allow_partial"}, "verification": {"enabled": False}}
    user.write_text(json.dumps(payload), encoding="utf-8")
    advanced.write_text("{invalid}", encoding="utf-8")
    before = _snapshot(tmp_path)
    assert _upgrade(repo_root, user, "1.4.0", advanced).returncode != 0
    assert _snapshot(tmp_path) == before
    advanced.write_text(json.dumps({"verification": {"methods": []}, "custom": "retained"}), encoding="utf-8")
    state = tmp_path / "state.snapshot"
    state.write_bytes(b"retained runtime state")
    result = _upgrade(repo_root, user, "1.4.0", advanced)
    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(user.read_text(encoding="utf-8")) == {"extraction": payload["extraction"]}
    assert json.loads(advanced.read_text(encoding="utf-8")) == {"custom": "retained"}
    assert state.read_bytes() == b"retained runtime state"
    before = _snapshot(tmp_path)
    assert _upgrade(repo_root, user, "1.4.0", advanced).returncode == 0
    assert _snapshot(tmp_path) == before
