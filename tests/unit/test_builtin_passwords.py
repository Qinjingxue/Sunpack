from __future__ import annotations

import sunpack.passwords.internal.builtin as builtin_module


def _seed_builtin_file(path, *passwords: str) -> None:
    path.write_text(
        "# Built-in common password list. You can edit this file; use one password per line.\n"
        + "".join(f"{password}\n" for password in passwords)
        + "\n# The following section is managed automatically by SunPack Watch.\n"
        + f"{builtin_module.WATCH_CLIPBOARD_BLOCK_BEGIN}\n"
        + f"{builtin_module.WATCH_CLIPBOARD_BLOCK_END}\n",
        encoding="utf-8",
    )


def test_watch_clipboard_passwords_are_persisted_only_inside_managed_block(tmp_path, monkeypatch):
    builtin_path = tmp_path / "builtin_passwords.txt"
    _seed_builtin_file(builtin_path, "user-secret")
    monkeypatch.setattr(builtin_module, "builtin_password_path", lambda: builtin_path)

    changed = builtin_module.merge_watch_clipboard_passwords(["clip-a", "clip-b"], max_entries=10)

    text = builtin_path.read_text(encoding="utf-8")
    assert changed is True
    assert "user-secret" in text
    assert builtin_module.WATCH_CLIPBOARD_BLOCK_BEGIN in text
    assert "clip-a" in text
    assert "clip-b" in text
    assert builtin_module.get_builtin_passwords() == ["user-secret", "clip-a", "clip-b"]


def test_watch_clipboard_password_block_keeps_most_recent_entries(tmp_path, monkeypatch):
    builtin_path = tmp_path / "builtin_passwords.txt"
    _seed_builtin_file(builtin_path, "user-secret")
    monkeypatch.setattr(builtin_module, "builtin_password_path", lambda: builtin_path)

    builtin_module.merge_watch_clipboard_passwords(["a", "b"], max_entries=2)
    changed = builtin_module.merge_watch_clipboard_passwords(["c"], max_entries=2)

    text = builtin_path.read_text(encoding="utf-8")
    assert changed is True
    assert "\na\n" not in text
    assert "\nb\n" in text
    assert "\nc\n" in text


def test_watch_clipboard_password_markers_do_not_change_with_cli_language(tmp_path, monkeypatch):
    builtin_path = tmp_path / "builtin_passwords.txt"
    _seed_builtin_file(builtin_path, "user-secret")
    monkeypatch.setattr(builtin_module, "builtin_password_path", lambda: builtin_path)
    monkeypatch.setattr(builtin_module, "load_cli_language_from_config", lambda: "zh")

    assert builtin_module.merge_watch_clipboard_passwords(["剪贴板密码"], max_entries=10) is True

    text = builtin_path.read_text(encoding="utf-8")
    assert builtin_module.WATCH_CLIPBOARD_BLOCK_BEGIN in text
    assert builtin_module.WATCH_CLIPBOARD_BLOCK_END in text
    assert "# 开始 SUNPACK 监控剪贴板密码" not in text
    assert builtin_module.get_builtin_passwords() == ["user-secret", "剪贴板密码"]


def test_watch_clipboard_writer_refuses_to_invent_missing_managed_block(tmp_path, monkeypatch):
    builtin_path = tmp_path / "builtin_passwords.txt"
    original = "#legacy-password\nuser-secret\n"
    builtin_path.write_text(original, encoding="utf-8")
    monkeypatch.setattr(builtin_module, "builtin_password_path", lambda: builtin_path)

    assert builtin_module.merge_watch_clipboard_passwords(["new-clip"], max_entries=10) is False
    assert builtin_path.read_text(encoding="utf-8") == original


def test_builtin_parser_preserves_hash_prefixed_and_surrounding_space_passwords(tmp_path, monkeypatch):
    builtin_path = tmp_path / "builtin_passwords.txt"
    _seed_builtin_file(builtin_path, "#secret", " password ", "   ")
    monkeypatch.setattr(builtin_module, "builtin_password_path", lambda: builtin_path)

    assert builtin_module.get_builtin_passwords() == ["#secret", " password ", "   "]
