from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest
import sunpack.core.passwords.internal.builtin as builtin
from sunpack.core.passwords.internal.store import PasswordStore, EMPTY_PASSWORD_SNAPSHOT


def seed(path, values=(), scopes=()):
    path.write_text(json.dumps({"passwords": [
        *({"value": v} for v in values),
        *({"value": v, "scopes": dirs} for v, dirs in scopes),
    ], "clipboard_history": []}, ensure_ascii=False), encoding="utf-8")


def test_snapshot_literal_values_scopes_and_semantic_reuse(tmp_path):
    # Unique coverage: literal JSON values, Windows ancestry, immutable sharing.
    path = tmp_path / "passwords.json"
    special = ' #a|b \t"c" \n'
    seed(path, [special, "global"], [("secret", ["D:/Work", "//server/share/Files"]), ("near", ["D:/Work/Child"])])
    first = builtin.read_builtin_password_file(path)
    store = PasswordStore.from_sources(password_snapshot=first, cli_passwords=["cli", "global"], clipboard_passwords=["clip"])
    store.remember_success("secret")
    assert store.candidates("d:/work/child/deep") == ["secret", "near", "cli", "global", "clip", special]
    assert "secret" not in store.candidates("D:/Workspace")
    assert "secret" in store.candidates("//SERVER/share/files/child")
    assert "secret" not in store.candidates("//server/share/FilesOther")
    assert copy.deepcopy(first) is first
    with pytest.raises(TypeError):
        first.scoped_index["new"] = ()
    path.write_text(json.dumps(json.loads(path.read_text(encoding="utf-8")), indent=4), encoding="utf-8")
    assert builtin.read_builtin_password_file(path, first) is first
    assert builtin.read_builtin_password_file(path).signature == first.signature
    seed(path, [special, "changed"], [("secret", ["D:/Work", "//server/share/Files"]), ("near", ["D:/Work/Child"])])
    second = builtin.read_builtin_password_file(path, first)
    assert second.signature != first.signature
    assert all(second.scoped_index[key] is values for key, values in first.scoped_index.items())
    assert store.snapshot is first
    assert store.candidates("E:/Private") == ["cli", "global", "clip", special]
    store = PasswordStore.from_sources(recent_passwords=store.recent_passwords, password_snapshot=EMPTY_PASSWORD_SNAPSHOT)
    assert "secret" not in store.candidates("D:/Work")
    root = builtin._parse_document('{"passwords":[{"value":"root","scopes":["//server/share"]}]}')[0]
    assert PasswordStore.from_sources(password_snapshot=root).candidates("//server/share/child") == ["root"]
    assert root.scope_signature("//SERVER/share/child") != EMPTY_PASSWORD_SNAPSHOT.scope_signature("//server/share/child")
    seed(path, [special, "global"], [("secret", ["D:/Work", "//server/share/Files"]), ("new-near", ["D:/Work/Child"])])
    scoped_edit = builtin.read_builtin_password_file(path, first)
    for scope in ("D:/Work", "D:/Workspace", "//SERVER/share/files/child", "//server/share/FilesOther"):
        assert scoped_edit.scope_signature(scope) == first.scope_signature(scope)
    assert scoped_edit.scope_signature("d:/WORK/CHILD/deep") != first.scope_signature("D:/Work/Child/deep")
    assert second.scope_signature("E:/Private") != first.scope_signature("E:/Private")


def test_file_events_keep_last_valid_snapshot_clear_deletion_and_never_restore_defaults(tmp_path, monkeypatch):
    # Unique coverage: invalid updates, real deletion, explicit empty configuration.
    path = tmp_path / "builtin_passwords.json"
    seed(path, ["secret"])
    monkeypatch.setattr(builtin, "builtin_password_path", lambda: path)
    source = builtin.PasswordFileSource()
    good = source.snapshot
    invalid = [
        '{"passwords":[{"value":"x","scopes":[]}]}',
        '{"passwords":[{"value":"x","scopes":["relative"]}]}',
        '{"passwords":[{"value":"x","scopes":["C:relative"]}]}',
        '{"passwords":[{"value":"x","scopes":[42]}]}',
        '{"passwords":[{"value":"x\\u0000"}]}',
        '{"passwords":[],"unexpected":1}',
        '{"passwords":[],"passwords":[]}',
        '{"passwords":[],}',
        '{"passwords":[{"value":"x"},]}',
        '{"passwords":['
    ]
    for text in invalid:
        path.write_text(text, encoding="utf-8")
        assert source.reload() is good
    path.unlink()
    assert source.reload() is EMPTY_PASSWORD_SNAPSHOT
    assert not path.exists()
    seed(path)
    assert source.reload().global_passwords == ()
    assert builtin.PasswordFileSource().snapshot.global_passwords == ()
    assert good.global_passwords == ("secret",)


def test_first_creation_publishes_complete_json_between_processes(tmp_path, monkeypatch):
    # Only this test exposes partial first writes to another process and races publication.
    path = tmp_path / "builtin_passwords.json"
    child = """
import json
import sys
from pathlib import Path
from sunpack.core.passwords.internal import builtin
builtin.builtin_password_path = lambda: Path(sys.argv[1])
dump = builtin.json.dump
def paused_dump(document, handle, **kwargs):
    handle.write('{"passwords":')
    handle.flush()
    print('writing', flush=True)
    sys.stdin.read(1)
    handle.seek(0)
    handle.truncate()
    dump(document, handle, **kwargs)
builtin.json.dump = paused_dump
path = builtin.ensure_builtin_password_file()
print(json.dumps(json.loads(path.read_text(encoding='utf-8'))), flush=True)
"""
    processes = [subprocess.Popen(
        [sys.executable, "-c", child, str(path)],
        cwd=Path(__file__).resolve().parents[2], stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    ) for _ in range(2)]
    try:
        for process in processes:
            assert process.stdout.readline().strip() == "writing"
        assert not path.exists()
        first, second = processes
        output, error = first.communicate(input="g", timeout=10)
        assert first.returncode == 0, error
        assert json.loads(output) == {
            "passwords": [{"value": v} for v in builtin.DEFAULT_BUILTIN_PASSWORDS],
            "clipboard_history": [],
        }
        seed(path, ["winner-updated"])
        output, error = second.communicate(input="g", timeout=10)
        assert second.returncode == 0, error
        assert json.loads(output) == {"passwords": [{"value": "winner-updated"}], "clipboard_history": []}
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
                process.communicate()
    assert list(tmp_path.iterdir()) == [path]
    monkeypatch.setattr(builtin, "builtin_password_path", lambda: path)
    seed(path, ["existing"])
    before = path.stat().st_mtime_ns
    assert builtin.ensure_builtin_password_file() == path
    assert path.stat().st_mtime_ns == before
    assert builtin.read_builtin_password_file(path).global_passwords == ("existing",)


@pytest.mark.parametrize("stage", ["write", "publish"])
def test_first_creation_cleans_failed_writes_and_publication(tmp_path, monkeypatch, stage):
    # The concurrent success test cannot detect orphaned files after failed IO.
    path = tmp_path / "builtin_passwords.json"
    monkeypatch.setattr(builtin, "builtin_password_path", lambda: path)
    def fail_write(document, handle, **kwargs):
        handle.write('{"passwords":')
        raise OSError("write failed")
    def fail_publish(temp, target):
        raise OSError("publish failed")
    if stage == "write":
        monkeypatch.setattr(builtin.json, "dump", fail_write)
    else:
        monkeypatch.setattr(Path, "rename", fail_publish)
    with pytest.raises(OSError, match=f"{stage} failed"):
        builtin.ensure_builtin_password_file()
    assert not list(tmp_path.iterdir())


def test_clipboard_merge_preserves_manual_records_with_concurrent_writers(tmp_path, monkeypatch):
    # Unique coverage: cross-process history merges, bounds and no-op writes.
    path = tmp_path / "builtin_passwords.json"
    seed(path, [" manual "] , [("scoped", ["D:/Work"])])
    monkeypatch.setattr(builtin, "builtin_password_path", lambda: path)
    original_records = json.loads(path.read_text(encoding="utf-8"))["passwords"]
    child = """
import sys
from pathlib import Path
from sunpack.core.passwords.internal import builtin
builtin.builtin_password_path = lambda: Path(sys.argv[1])
print('ready', flush=True)
sys.stdin.read(1)
sys.exit(0 if builtin.merge_watch_clipboard_passwords([sys.argv[2]], max_entries=4) else 1)
"""
    processes = [subprocess.Popen(
        [sys.executable, "-c", child, str(path), f"clip-{i}"],
        cwd=Path(__file__).resolve().parents[2], stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    ) for i in range(4)]
    try:
        for process in processes:
            assert process.stdout.readline().strip() == "ready"
        for process in processes:
            process.stdin.write("g")
            process.stdin.flush()
        for process in processes:
            _, error = process.communicate(timeout=10)
            assert process.returncode == 0, error
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
                process.communicate()
    doc = json.loads(path.read_text(encoding="utf-8"))
    assert doc["passwords"] == original_records
    assert set(doc["clipboard_history"]) == {f"clip-{i}" for i in range(4)}
    reads = []
    read = builtin.read_shared_utf8_text
    def count_read(*args, **kwargs):
        reads.append(args[0])
        return read(*args, **kwargs)
    monkeypatch.setattr(builtin, "read_shared_utf8_text", count_read)
    assert builtin.merge_watch_clipboard_passwords(["last", "last"], max_entries=2)
    assert reads == [path]
    doc = json.loads(path.read_text(encoding="utf-8"))
    assert doc["passwords"] == original_records
    assert len(doc["clipboard_history"]) == 2
    assert doc["clipboard_history"][-1] == "last"
    before = path.stat().st_mtime_ns
    assert not builtin.merge_watch_clipboard_passwords(["last"], max_entries=2)
    assert path.stat().st_mtime_ns == before
    assert not list(tmp_path.glob(".*.tmp"))
