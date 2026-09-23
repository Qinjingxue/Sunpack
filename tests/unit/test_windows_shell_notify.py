from __future__ import annotations

import sunpack.core.platform.windows.shell_notify as shell_notify


def test_unique_directories_include_parent_of_files_and_output_dirs(tmp_path):
    watch_root = tmp_path / "downloads"
    output_dir = watch_root / "sample"
    archive = watch_root / "sample.zip"
    watch_root.mkdir()
    output_dir.mkdir()
    archive.write_bytes(b"zip")

    directories = shell_notify._unique_existing_directories(
        [str(archive), str(output_dir), str(archive), ""]
    )

    assert directories == [str(watch_root.resolve()), str(output_dir.resolve())]


def test_missing_file_still_resolves_parent_directory(tmp_path):
    watch_root = tmp_path / "downloads"
    watch_root.mkdir()
    missing_archive = watch_root / "gone.zip"

    directories = shell_notify._unique_existing_directories([str(missing_archive)])

    assert directories == [str(watch_root.resolve())]


def test_notify_shell_directories_updated_calls_change_notify_once_per_dir(tmp_path, monkeypatch):
    watch_root = tmp_path / "downloads"
    output_dir = watch_root / "sample"
    watch_root.mkdir()
    output_dir.mkdir()
    calls = []

    monkeypatch.setattr(shell_notify.sys, "platform", "win32")
    monkeypatch.setattr(
        shell_notify,
        "_sh_change_notify_updatedir",
        lambda directories: calls.append(list(directories)),
    )

    notified = shell_notify.notify_shell_directories_updated(
        [str(watch_root / "sample.zip"), str(output_dir)]
    )

    assert notified == [str(watch_root.resolve()), str(output_dir.resolve())]
    assert calls == [[str(watch_root.resolve()), str(output_dir.resolve())]]


def test_notify_shell_directories_updated_is_noop_off_windows(tmp_path, monkeypatch):
    watch_root = tmp_path / "downloads"
    watch_root.mkdir()
    called = []

    monkeypatch.setattr(shell_notify.sys, "platform", "linux")
    monkeypatch.setattr(
        shell_notify,
        "_sh_change_notify_updatedir",
        lambda directories: called.append(list(directories)),
    )

    notified = shell_notify.notify_shell_directories_updated([str(watch_root / "a.zip")])

    assert notified == [str(watch_root.resolve())]
    assert called == []
