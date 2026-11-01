import json
import subprocess

from sunpack.core.config.schema import normalize_config
from sunpack.pipeline.discovery.filesystem.directory_scanner import DirectoryScanner


def test_installer_merges_path_rules_preserves_switches_and_is_idempotent(tmp_path, repo_root):
    """Only the real upgrade script can catch lost rules, switch activation or repeated rewrites.

    One subprocess per shape exercises the installer boundary without building
    an installer or duplicating runtime matcher cases.
    """
    old = tmp_path / "old.json"
    old.write_text("{}", encoding="utf-8")
    for index, (prune_enabled, blacklist_enabled) in enumerate(((True, True), (True, False), (False, True))):
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
                    {"name": "whitelist", "enabled": False,
                     "path_globs": ["downloads/**"], "prune_dir_globs": ["archives"],
                     "allowed_files": ["keep_??.zip"], "allowed_extensions": ["zip"]},
                    {"name": "blacklist", "enabled": blacklist_enabled,
                     "blocked_files": ["Thumbs.db"], "blocked_extensions": ["tmp", ".", "..never"]},
                    {"name": "size_range", "enabled": True, "min_bytes": 1},
                ],
            },
        }
        user.write_text(json.dumps(payload), encoding="utf-8")
        command = ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive",
                   "-ExecutionPolicy", "Bypass", "-File", str(repo_root / "scripts/upgrade_config.ps1"),
                   "-OldAdvanced", str(old), "-NewAdvanced", str(repo_root / "sunpack_advanced_config.json"),
                   "-Template", str(repo_root / "sunpack_config.json"), "-UserConfig", str(user)]
        subprocess.run(command, check=True, capture_output=True)
        migrated = json.loads(user.read_text(encoding="utf-8"))
        assert migrated["cli"] == payload["cli"]
        assert migrated["filesystem"]["scan_filters_enabled"] is (index != 2)
        filters = migrated["filesystem"]["scan_filters"]
        assert all(item["name"] != "directory_prune" and "prune_dir_globs" not in item for item in filters)
        blacklists = [item for item in filters if item["name"] == "blacklist"]
        assert len(blacklists) == (1 if prune_enabled == blacklist_enabled else 2)
        paths = next(item for item in blacklists if item.get("paths"))
        assert paths["enabled"] is prune_enabled
        assert len(paths["paths"]) == 3
        assert {item["value"] for item in paths["paths"]} == {".git", r"(?:\A|/)(?:node_[^/]*)(?:/|\z)", "Cache/Private"}
        files = next(item for item in blacklists if item.get("files"))
        assert files["enabled"] is blacklist_enabled
        assert files["files"] == [{"value": "Thumbs.db", "regex": False}, {"value": r"(?s:.)\.(?:tmp|)\z", "regex": True}]
        whitelists = [item for item in filters if item["name"] == "whitelist"]
        assert len(whitelists) == 2 and all(not item["enabled"] for item in whitelists)
        assert whitelists[0]["paths"] == [{"value": "archives", "regex": False}, {"value": r"\A(?:downloads)\z", "regex": True}]
        assert whitelists[0]["files"] == [{"value": r"\A(?:keep_[^/][^/]\.zip)\z", "regex": True}]
        assert whitelists[1]["files"] == [{"value": r"(?s:.)\.(?:zip)\z", "regex": True}]
        # Assert actual AND semantics and root anchoring, not just the shape.
        from sunpack_native import NativePathRule
        deny = NativePathRule(files["paths"], files["files"])
        assert deny.rejects("C:/input/a.tmp", "C:/input", False, False)
        assert deny.rejects("C:/input/a.", "C:/input", False, False)
        assert not deny.rejects("C:/input/.tmp", "C:/input", False, False)
        assert not deny.rejects("C:/input/a.never", "C:/input", False, False)
        allow = [NativePathRule(item["paths"], item["files"]) for item in whitelists]
        def accepted(path):
            return all(not rule.rejects(path, "C:/input", False, True) for rule in allow)
        assert accepted("C:/input/downloads/keep_01.zip")
        assert not accepted("C:/input/downloads/keep_01.rar")
        assert not accepted("C:/input/downloads/other.zip")
        assert not accepted("C:/input/elsewhere/downloads/keep_01.zip")
        assert filters[-1] == payload["filesystem"]["scan_filters"][-1]
        DirectoryScanner.compile_scan_options(normalize_config(migrated))
        # A second upgrade must not touch an already-migrated configuration.
        before, stamp = user.read_bytes(), user.stat().st_mtime_ns
        subprocess.run(command, check=True, capture_output=True)
        assert user.read_bytes() == before and user.stat().st_mtime_ns == stamp
