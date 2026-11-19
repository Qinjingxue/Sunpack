"""Coarse tests of the installer's on-disk upgrade policy, not runtime shims."""
import json
import subprocess


def _upgrade(repo_root, user, version, advanced=None, *, template=None):
    command = ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive",
               "-ExecutionPolicy", "Bypass", "-File", str(repo_root / "scripts/upgrade_config.ps1"),
               "-UserConfig", str(user), "-TemplateConfig", str(template or repo_root / "sunpack_config.json"),
               "-PreviousVersion", version]
    if advanced is not None:
        command += ["-AdvancedConfig", str(advanced)]
    return subprocess.run(command, capture_output=True)


def _snapshot(directory):
    return {str(p.relative_to(directory)): (p.read_bytes(), p.stat().st_mtime_ns)
            for p in directory.rglob("*") if p.is_file()}


def test_compatible_upgrade_retains_inputs_and_retires_state(tmp_path, repo_root):
    # Only this real script transaction covers template projection, advanced
    # promotion, lossless password formatting, intact roots and selective state deletion together.
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
                       'C:\\Other | | false | true | true\n'
                       'C:\\Disabled | | false | false | false | false\n').encode())
    passwords = data / "builtin_passwords.json"
    password_document = {
        "passwords": [{"value": ' 密码\r\n "]  ", ', "scopes": ["D:/工作"]}, {"value": "off", "enabled": False}],
        "clipboard_history": ["历史", "/Date(1)/", "  2025-01-01T00:00:00Z  "],
    }
    expanded = json.dumps(password_document, indent=2, ensure_ascii=False).replace("/", r"\/")
    passwords.write_bytes(b'\xef\xbb\xbf' + expanded.replace("\n", "\r\n").encode("utf-8"))
    for directory in (data / ".sunpack_watch", data / "unknown", custom):
        directory.mkdir(exist_ok=True)
        (directory / "state.snapshot").write_bytes(b"old continuation")
        (directory / "state.journal.00000000000000000001.wal").write_bytes(b"old wal")
        (directory / "catalog.wal.bin").write_bytes(b"old catalog")
        (directory / "unrelated.txt").write_bytes(b"user owned")
    advanced_before = advanced.read_bytes()
    roots_before = roots.read_bytes()
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
    assert roots.read_bytes() == roots_before.replace(b" | false\rC:", b" | false | true\rC:").replace(b" | true\n", b" | true | true\n")
    password_text = passwords.read_bytes()
    assert password_text.startswith(b'\xef\xbb\xbf')
    password_document["passwords"][0]["enabled"] = True
    assert json.loads(password_text) == password_document
    compact_lines = [
        f'  "{key}": ' + json.dumps(value, ensure_ascii=False, separators=(",", ":")).replace("/", r"\/")
        for key, value in password_document.items()
    ]
    assert password_text.decode("utf-8-sig") == "{\n" + ",\n".join(compact_lines) + "\n}\n"
    assert {p.name for p in custom.iterdir()} == {"unrelated.txt"}
    assert (custom / "unrelated.txt").read_bytes() == b"user owned"
    assert advanced.read_bytes() == advanced_before
    before = {name: value[0] for name, value in _snapshot(data).items()}
    password_mtime = passwords.stat().st_mtime_ns
    result = _upgrade(repo_root, user, "v1.3.5-2-gabcdef0", advanced)
    assert result.returncode == 0, result.stdout + result.stderr
    assert {name: value[0] for name, value in _snapshot(data).items()} == before
    assert passwords.stat().st_mtime_ns == password_mtime


def test_version_gate_and_failed_preflight_leave_all_data_untouched(tmp_path, repo_root):
    # Exercise current repairs and failed JSON/reparse preflight on disk.
    for index, version in enumerate([
        "1.2.5", "1.2.6", "1.4.0", "v1.4.0-2-gabcdef0", "1.10.0",
        "1.4.0rc1", "1.4.0.dev1", "20261114-020000", "dev", "",
    ]):
        data = tmp_path / str(index)
        data.mkdir()
        user = data / "sunpack_config.json"
        user.write_text("{invalid}", encoding="utf-8")
        (data / "builtin_passwords.json").write_bytes(b'{\r\r\n\r\n"passwords": []\r\n}')
        (data / "sunpack_watch_roots.txt").write_bytes(b"C:\\input | D:\\out | true | true | false\r\n")
        (data / "state.snapshot").write_bytes(b"keep")
        before = _snapshot(data)
        result = _upgrade(repo_root, user, version)
        assert result.returncode != 0, result.stdout + result.stderr
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
    template = json.loads((repo_root / "sunpack_config.json").read_text(encoding="utf-8"))
    default_extensions = next(f["extensions"] for f in template["filesystem"]["scan_filters"]
                              if f["name"] == "blacklist")
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
        migrated_extensions = ([{"value": "tmp", "regex": False},
            {"value": r"\A\z", "regex": True}, {"value": ".never", "regex": False}]
            if blocked or not prune else [])
        assert blacklist["extensions"] == migrated_extensions + [
            rule for rule in default_extensions if rule not in migrated_extensions]
        assert blacklist["files"] == []
        assert whitelist["enabled"] is False
        assert whitelist["paths"] == [{"value": "downloads", "regex": False}]
        assert whitelist["full_names"] == [{"value": "keep.zip", "regex": False}]
        assert size == {"name": "size_range", "enabled": True, "min_bytes": 0, "max_bytes": None}
        before = {name: value[0] for name, value in _snapshot(data).items()}
        assert _upgrade(repo_root, user, "v1.3.4-7-gabcdef0").returncode == 0
        assert {name: value[0] for name, value in _snapshot(data).items()} == before


def test_current_filters_append_template_rules_without_adding_modules(tmp_path, repo_root):
    # The legacy matrix does not exercise modern rule identity, custom order,
    # or defaults in the whitelist. Two upgrades also check idempotence.
    template = json.loads((repo_root / "sunpack_config.json").read_text(encoding="utf-8"))
    defaults = {f["name"]: f for f in template["filesystem"]["scan_filters"]}
    common = {"value": "tmp", "regex": False}
    local = {"value": "local", "regex": False}
    new_extension = {"value": "new", "regex": False}
    new_path = {"value": "cache/**", "regex": False}
    white_rule = {"value": "zip", "regex": False}
    white_regex = {"value": "zip", "regex": True}
    white_file = {"value": "项目包", "regex": False}
    defaults["blacklist"].update(extensions=[common, new_extension], paths=[new_path])
    defaults["whitelist"].update(extensions=[white_rule, white_regex, white_regex], full_names=[white_file])
    template_path = tmp_path / "template.json"
    template_path.write_text(json.dumps(template), encoding="utf-8")
    data = tmp_path / "data"
    data.mkdir()
    user = data / "sunpack_config.json"
    filters = [{"name": "size_range", "enabled": False, "min_bytes": 0},
               {"name": "blacklist", "enabled": False, "extensions": [local, common, local],
                "paths": [{"value": r'\A"exact  [x]"\z', "regex": True}]},
               {"name": "whitelist", "enabled": True, "extensions": [white_rule], "full_names": []}]
    user.write_text(json.dumps({"filesystem": {"scan_filters": filters}}, indent=2), encoding="utf-8")
    result = _upgrade(repo_root, user, "1.4.1", template=template_path)
    assert result.returncode == 0, result.stdout + result.stderr
    expected = [dict(defaults[f["name"]], **f) for f in filters]
    expected[1].update(extensions=[local, common, local, new_extension], paths=filters[1]["paths"] + [new_path])
    expected[2].update(extensions=[white_rule, white_regex], full_names=[white_file])
    migrated = user.read_text(encoding="utf-8-sig")
    assert json.loads(migrated)["filesystem"]["scan_filters"] == expected
    lines = {line.strip().removesuffix(",") for line in migrated.splitlines()}
    assert all(json.dumps(f, separators=(",", ":"), ensure_ascii=False) in lines for f in expected[1:])
    before = user.read_bytes()
    result = _upgrade(repo_root, user, "1.4.1", template=template_path)
    assert result.returncode == 0, result.stdout + result.stderr
    assert user.read_bytes() == before


def test_upgrade_boundary_and_current_projection(tmp_path, repo_root):
    # One matrix checks the exact retained-format boundary, modern versions,
    # fresh missing config and whole-data resets. Legacy rule tests do not cover
    # this branch choice or additions after 1.4; process cost is small.
    for index, version in enumerate(("1.2.5", "v1.2.6", "1.4.0", "1.4.1", "1.5.0", "1.10.0")):
        data = tmp_path / str(index)
        data.mkdir()
        user = data / "sunpack_config.json"
        user.write_text(json.dumps({"cli": {"language": "en"}, "watch": {"tray_enabled": False},
                                   "verification": {"enabled": False}, "obsolete": 3}), encoding="utf-8")
        roots, passwords = data / "sunpack_watch_roots.txt", data / "builtin_passwords.json"
        roots.write_bytes(b"C:\\input | D:\\out | true | true | false\r\n")
        passwords.write_bytes(b'{\n  "passwords": ["  keep  "],\n  "clipboard_history": ["old"]\n}\n')
        (data / "state.snapshot").write_bytes(b"discard")
        result = _upgrade(repo_root, user, version)
        assert result.returncode == 0, result.stdout + result.stderr
        if version == "1.2.5":
            assert list(data.iterdir()) == []
        else:
            expected = json.loads((repo_root / user.name).read_text(encoding="utf-8"))
            expected["cli"]["language"] = "en"
            expected["watch"]["tray_enabled"] = False
            assert json.loads(user.read_text(encoding="utf-8")) == expected
            assert roots.read_bytes().endswith(b" | true | false | true\r\n")
            assert json.loads(passwords.read_bytes()) == {
                "passwords": [{"value": "  keep  ", "enabled": True}],
                "clipboard_history": ["old"],
            }
            assert {p.name for p in data.iterdir()} == {user.name, roots.name, passwords.name}
    missing = tmp_path / "missing" / "sunpack_config.json"
    assert _upgrade(repo_root, missing, "1.2.6").returncode == 0
    assert json.loads(missing.read_text(encoding="utf-8")) == json.loads((repo_root / missing.name).read_text(encoding="utf-8"))


def test_failed_config_commit_does_not_clear_inputs_or_state(tmp_path, repo_root):
    # A readable config can still fail atomic publication. Lock its deletion
    # rather than its read to exercise commit, not the parse preflight above.
    from tests.helpers.marker_utils import open_shared_file

    user = tmp_path / "sunpack_config.json"
    user.write_text('{"cli":{"language":"en"}}', encoding="utf-8")
    (tmp_path / "builtin_passwords.json").write_bytes(b'{"passwords": []}')
    (tmp_path / "sunpack_watch_roots.txt").write_bytes(b'C:/input | | false | true | true')
    (tmp_path / "state.snapshot").write_bytes(b"keep until commit")
    before = _snapshot(tmp_path)
    with open_shared_file(user, "rb", share=0x1 | 0x2):
        assert _upgrade(repo_root, user, "1.4.1").returncode != 0
    assert _snapshot(tmp_path) == before
    assert _upgrade(repo_root, user, "1.4.1").returncode == 0
    assert not (tmp_path / "state.snapshot").exists()
