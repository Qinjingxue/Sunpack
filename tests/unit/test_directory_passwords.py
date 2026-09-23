from types import SimpleNamespace

from sunpack.core.passwords.directory_context import DirectoryPasswordContextStore
from sunpack.core.passwords.internal.clipboard import _plausible_passwords
from sunpack.core.passwords.internal.local_files import (
    DIRECTORY_PASSWORD_CONTEXT_KEY,
    discover_directory_passwords_for_archive,
    is_directory_password_file,
)


def test_discovers_same_directory_sunpack_passwords(tmp_path):
    archive = tmp_path / "archive.zip"
    archive.write_bytes(b"not really an archive")
    (tmp_path / "sunpack-passwords.txt").write_text("#secret\nouter-secret\n password \n\n", encoding="utf-8")

    assert discover_directory_passwords_for_archive(str(archive), {}) == ["#secret", "outer-secret", " password "]


def test_ignores_other_same_directory_txt_files(tmp_path):
    archive = tmp_path / "archive.zip"
    archive.write_bytes(b"not really an archive")
    (tmp_path / "passwords.txt").write_text("wrong-source\n", encoding="utf-8")
    (tmp_path / "notes.txt").write_text("also-wrong\n", encoding="utf-8")

    assert discover_directory_passwords_for_archive(str(archive), {}) == []
    assert is_directory_password_file(str(tmp_path / "sunpack-passwords.txt"), {})
    assert not is_directory_password_file(str(tmp_path / "passwords.txt"), {})


def test_directory_password_context_inherits_and_extends(tmp_path):
    parent = tmp_path / "parent"
    parent.mkdir()
    child = parent / "child"
    child.mkdir()
    archive = child / "nested.zip"
    archive.write_bytes(b"not really an archive")
    (child / "sunpack-passwords.txt").write_text("inner-secret\nouter-secret\n", encoding="utf-8")

    store = DirectoryPasswordContextStore({})
    parent_task = SimpleNamespace(runtime={
        DIRECTORY_PASSWORD_CONTEXT_KEY: ["outer-secret"],
    })
    store.remember(str(parent), parent_task)
    task = SimpleNamespace(main_path=str(archive), runtime={})

    store.annotate([task])

    assert task.runtime[DIRECTORY_PASSWORD_CONTEXT_KEY] == ["outer-secret", "inner-secret"]


def test_clipboard_password_filter_rejects_obvious_non_text_payloads():
    assert _plausible_passwords(["ok", "bad\x00value", "x" * 600], max_password_length=512) == ["ok"]
