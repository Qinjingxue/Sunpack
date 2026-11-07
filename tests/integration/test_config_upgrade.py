import json
import subprocess

from sunpack.core.config.loader import apply_config_overrides
from sunpack.core.config.schema import normalize_config
from sunpack.pipeline.discovery.filesystem.directory_scanner import DirectoryScanner


def test_installer_resets_old_input_recovery_once_and_preserves_user_files(tmp_path, repo_root):
    # Configuration migration does not exercise checkpoint/WAL retirement. One
    # real upgrade and repeat prove old continuations cannot enter the new model
    # and current recovery survives later installations, without any runtime shim.
    state = tmp_path / "custom ' [watch]"
    state.mkdir()
    snapshot = state / "state.snapshot"
    wal = state / "state.journal.00000000000000000001.wal"
    kept = state / "events.json"
    for path in (snapshot, wal, kept):
        path.write_text("preserved or reset", encoding="utf-8")
    user = tmp_path / "sunpack_config.json"
    user.write_text('{"cli":{"language":"en"}}', encoding="utf-8")
    advanced = tmp_path / "advanced.json"
    advanced.write_text(json.dumps({"watch": {"state_dir": str(state)},
                                          "extraction": {"content_requirement": "allow_partial"}}), encoding="utf-8")
    command = ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
               "-File", str(repo_root / "scripts/upgrade_config.ps1"), "-UserConfig", str(user),
               "-AdvancedConfig", str(advanced)]
    subprocess.run(command, check=True, capture_output=True)
    default = tmp_path / ".sunpack_watch"
    assert snapshot.exists() and wal.exists()  # Original state remains available for rollback.
    assert not (default / snapshot.name).exists() and not (default / wal.name).exists()
    assert json.loads(user.read_text(encoding="utf-8"))["extraction"]["content_requirement"] == "allow_partial"
    assert kept.read_text(encoding="utf-8") == "preserved or reset"
    assert (default / kept.name).read_text(encoding="utf-8") == "preserved or reset"
    snapshot = default / snapshot.name
    snapshot.write_text("current recovery", encoding="utf-8")
    subprocess.run(command, check=True, capture_output=True)
    assert snapshot.read_text(encoding="utf-8") == "current recovery"


def test_installer_promotes_controls_and_migrates_current_state_without_overwrite(tmp_path, repo_root):
    # One real installer transaction covers promotion precedence, recoverable
    # custom-state relocation, retry safety and retired-key removal. Runtime
    # loader tests cannot catch lost on-disk values or stale migration copies.
    old_state = tmp_path / "custom state"
    old_state.mkdir()
    (old_state / "logical-input-recovery").touch()
    (old_state / "state.snapshot").write_text("current recovery", encoding="utf-8")
    (old_state / "catalog.wal.bin").write_bytes(b"catalog")
    display = old_state / "events.json.store"
    display.mkdir()
    (display / "block.data").write_bytes(b"history")
    (old_state / "unrelated.txt").write_text("user-owned", encoding="utf-8")
    advanced = tmp_path / "previous-advanced.json"
    advanced.write_text(json.dumps({
        "watch": {"state_dir": str(old_state), "clipboard_monitor_enabled": False,
                  "clipboard_builtin_max_entries": 17, "toast_report_retention_days": 61},
        "passwords": {"clipboard_passwords_enabled": False},
        "input_planning": {"enabled": False, "cache_size": 8},
        "analysis": {"shared_cache_mb": 4, "thresholds": {"extractable_confidence": 0.99}},
        "performance": {"worker": {"job_buffer_budget_bytes": 1024}},
    }), encoding="utf-8")
    advanced_before = advanced.read_bytes()
    user = tmp_path / "sunpack_config.json"
    original = {"watch": {"state_dir": str(old_state), "clipboard_monitor_enabled": True,
                          "toast_report_max_files": 3,
                          "toast_report_max_bytes": 1024, "runtime_cache_cleanup_enabled": False},
                "performance": {"worker": {"thread_capacity": 2, "stage_thread_capacity": 3,
                    "max_pending_stage_jobs": 4, "max_queue_jobs": 5, "space_gate_enabled": False,
                    "memory_reserve_bytes": 1024, "writer_threads": 6, "job_buffer_budget_bytes": 2048}},
                "input_planning": {"enabled": False, "cache_size": 0, "unknown": "retire whole section"},
                "analysis": {"shared_cache_mb": 0, "max_concurrent_reads": 3,
                             "thresholds": {"extractable_confidence": 0.5},
                             "prepass": {"enabled": False, "head_bytes": 1, "tail_bytes": 1}, "unknown": "keep"},
                "detection": {"enabled": False},
                "unknown": "keep"}
    user.write_text(json.dumps(original), encoding="utf-8")
    command = ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
               "-File", str(repo_root / "scripts/upgrade_config.ps1"), "-UserConfig", str(user),
               "-AdvancedConfig", str(advanced)]
    subprocess.run(command, check=True, capture_output=True)
    migrated = json.loads(user.read_text(encoding="utf-8"))
    assert migrated["watch"] == {"clipboard_monitor_enabled": True, "clipboard_builtin_max_entries": 17,
                                 "toast_report_retention_days": 61}
    assert migrated["passwords"]["clipboard_passwords_enabled"] is False
    assert migrated["performance"]["worker"] == {"writer_threads": 6}
    assert "input_planning" not in migrated
    assert "detection" not in migrated
    assert migrated["analysis"] == {"max_concurrent_reads": 3, "unknown": "keep"}
    # The old advanced snapshot is read-only; deployment replaces the installed
    # template instead of migrating it through a second compatibility chain.
    assert advanced.read_bytes() == advanced_before
    assert migrated["unknown"] == "keep"
    default = tmp_path / ".sunpack_watch"
    assert (default / "state.snapshot").read_text(encoding="utf-8") == "current recovery"
    assert (default / "catalog.wal.bin").read_bytes() == b"catalog"
    assert (default / "events.json.store" / "block.data").read_bytes() == b"history"
    assert not (default / "unrelated.txt").exists()
    assert (old_state / "unrelated.txt").exists() and (old_state / "state.snapshot").exists()
    before = user.read_bytes(), user.stat().st_mtime_ns
    subprocess.run(command, check=True, capture_output=True)
    assert (user.read_bytes(), user.stat().st_mtime_ns) == before

    # After a later installer rollback, the old version may write its original
    # state again. A retry must not silently select the now-stale default copy.
    user.write_text(json.dumps(original), encoding="utf-8")
    (old_state / "state.snapshot").write_text("newer recovery after rollback", encoding="utf-8")
    result = subprocess.run(command, capture_output=True)
    assert result.returncode != 0
    assert json.loads(user.read_text(encoding="utf-8")) == original
    assert (default / "state.snapshot").read_text(encoding="utf-8") == "current recovery"
    assert (old_state / "state.snapshot").read_text(encoding="utf-8") == "newer recovery after rollback"

    # An existing fixed directory without our migration receipt is also never
    # overwritten, even if it happens to have similarly named state files.
    (default / "fixed-state-directory").unlink()
    result = subprocess.run(command, capture_output=True)
    assert result.returncode != 0
    assert json.loads(user.read_text(encoding="utf-8")) == original
    assert (default / "state.snapshot").read_text(encoding="utf-8") == "current recovery"


def test_installer_unifies_path_rules_ors_switches_and_is_idempotent(tmp_path, repo_root):
    """Only the real upgrade script can catch lost rules, switch activation or repeated rewrites.

    One subprocess per shape exercises the installer boundary without building
    an installer or duplicating runtime matcher cases.
    """
    for index, (prune_enabled, blacklist_enabled, whitelist_enabled) in enumerate(
        ((True, True, False), (True, False, True), (False, True, False), (False, False, True))
    ):
        user = tmp_path / f"user ' [{index}].json"
        payload = {
            "cli": {"language": "en"},
            "verification": {},
            "filesystem": {
                "scan_filters_enabled": index != 2,
                "scan_filters": [
                    {"name": "directory_prune", "enabled": prune_enabled,
                     "prune_dir_globs": [".git", "node_*"],
                     "path_globs": [".git/**", "Cache/Private/**"]},
                    {"name": "whitelist", "enabled": whitelist_enabled,
                     "path_globs": ["downloads/**"], "prune_dir_globs": ["downloads", "archives"],
                     "allowed_files": ["keep_01.zip"], "allowed_extensions": ["zip"]},
                    {"name": "blacklist", "enabled": blacklist_enabled,
                     "blocked_files": ["Thumbs.db"], "blocked_extensions": ["tmp", "TMP", ".", "..never"]},
                    {"name": "size_range", "enabled": True, "min_bytes": 1},
                ],
            },
        }
        if index == 0:
            payload["extraction"] = {"content_requirement": "allow_partial"}
        user.write_text(json.dumps(payload), encoding="utf-8")
        command = ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive",
                   "-ExecutionPolicy", "Bypass", "-File", str(repo_root / "scripts/upgrade_config.ps1"),
                   "-UserConfig", str(user)]
        subprocess.run(command, check=True, capture_output=True)
        migrated = json.loads(user.read_text(encoding="utf-8"))
        assert migrated["extraction"]["content_requirement"] == ("allow_partial" if index == 0 else "complete")
        assert migrated["cli"] == payload["cli"]
        assert migrated["filesystem"]["scan_filters_enabled"] is (index != 2)
        filters = migrated["filesystem"]["scan_filters"]
        assert all(item["name"] != "directory_prune" and "prune_dir_globs" not in item for item in filters)
        blacklists = [item for item in filters if item["name"] == "blacklist"]
        assert len(blacklists) == 1
        blacklist = blacklists[0]
        assert blacklist["enabled"] is (prune_enabled or blacklist_enabled)
        assert blacklist["paths"] == [{"value": ".git", "regex": False},
                                      {"value": "node_*", "regex": False},
                                      {"value": r"(?:\A|/)(?:Cache/Private)(?:/|\z)", "regex": True}]
        assert blacklist["files"] == []
        assert blacklist["full_names"] == [{"value": "Thumbs.db", "regex": False}]
        assert blacklist["extensions"] == [{"value": "tmp", "regex": False},
                                            {"value": "TMP", "regex": False},
                                            {"value": r"\A\z", "regex": True},
                                            {"value": ".never", "regex": False}]
        whitelists = [item for item in filters if item["name"] == "whitelist"]
        assert len(whitelists) == 1 and whitelists[0]["enabled"] is whitelist_enabled
        # The two legacy path groups become a single OR list. Filenames and
        # extensions still use separate fields in the same whitelist module.
        assert whitelists[0]["paths"] == [{"value": "downloads", "regex": False},
                                           {"value": "archives", "regex": False}]
        assert whitelists[0]["full_names"] == [{"value": "keep_01.zip", "regex": False}]
        assert whitelists[0]["extensions"] == [{"value": "zip", "regex": False}]
        from sunpack_native import NativePathRule
        def native(item):
            return NativePathRule(*(item[field] for field in ("paths", "files", "extensions", "full_names")))
        deny = native(blacklist)
        assert deny.rejects("C:/input/a.tmp", "C:/input", False, False)
        assert deny.rejects("C:/input/a.TMP", "C:/input", False, False)
        assert deny.rejects("C:/input/Thumbs.db", "C:/input", False, False)
        assert not deny.rejects("C:/input/thumbs.db", "C:/input", False, False)
        assert deny.rejects("C:/input/a.", "C:/input", False, False)
        assert deny.rejects("C:/input/.tmp", "C:/input", False, False)
        assert not deny.rejects("C:/input/a.never", "C:/input", False, False)
        directory_deny = native(blacklist)
        assert directory_deny.rejects("C:/input/Cache/Private/a.zip", "C:/input", False, False)
        assert not directory_deny.rejects("C:/input/cache/private/a.zip", "C:/input", False, False)
        allow = [native(item) for item in whitelists]
        def accepted(path):
            return all(not rule.rejects(path, "C:/input", False, True) for rule in allow)
        assert accepted("C:/input/downloads/keep_01.zip")
        assert not accepted("C:/input/downloads/keep_01.rar")
        assert not accepted("C:/input/downloads/other.zip")
        assert accepted("C:/input/elsewhere/downloads/keep_01.zip")
        assert accepted("C:/input/archives/keep_01.zip")
        assert filters[-1] == payload["filesystem"]["scan_filters"][-1]
        # Exercise the actual advanced-default/user-config merge, not just the
        # isolated migrated payload (same-name filters are merged by name).
        advanced = json.loads((repo_root / "sunpack_advanced_config.json").read_text(encoding="utf-8"))
        effective = normalize_config(apply_config_overrides(advanced, migrated))
        effective_filters = effective["filesystem"]["scan_filters"]
        assert [item for item in effective_filters if item["name"] == "blacklist"] == [blacklist]
        assert [item for item in effective_filters if item["name"] == "whitelist"] == whitelists
        DirectoryScanner.compile_scan_options(effective)
        # A second upgrade must not touch an already-migrated configuration.
        before, stamp = user.read_bytes(), user.stat().st_mtime_ns
        subprocess.run(command, check=True, capture_output=True)
        assert user.read_bytes() == before and user.stat().st_mtime_ns == stamp
