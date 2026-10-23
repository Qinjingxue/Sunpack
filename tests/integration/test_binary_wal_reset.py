import json
import subprocess

import pytest

from sunpack.runtime.watch.state import WatchStateJournalError, WatchStateStore


def test_installer_reset_removes_only_old_persistence_and_portable_refuses_it(tmp_path, repo_root):
    """Other recovery tests cannot catch deletion of custom-dir config/new WAL.

    Removing this loses reset scope, repeat-upgrade preservation and portable
    refusal coverage. Two short PowerShell runs avoid a full installer launch.
    """
    data = tmp_path / 'data'
    custom = data / 'custom'
    default = data / '.sunpack_watch'
    old_files = ('state.json', 'state.journal.00000000000000000001.jsonl',
                 'catalog.snapshot', 'catalog.snapshot.tmp', 'catalog.wal',
                 '.state.json.' + 'a' * 32 + '.tmp')
    keep_files = ('sunpack_config.json', 'builtin_passwords.json', 'events.jsonl',
                  'state.journal.notes.jsonl', '.state.json.notes.tmp',
                  'catalog.snapshot.bin', 'catalog.wal.bin', 'catalog.lock')
    for directory in (default, custom):
        directory.mkdir(parents=True)
        for name in old_files + keep_files:
            (directory / name).write_bytes(b'preserve bytes')
        (directory / 'catalog.snapshot.tmp.directory').mkdir()
        # A live new snapshot must survive an upgrade even when old files remain.
        store = WatchStateStore(str(directory / 'new.snapshot'))
        store.save()
        store.close()
    advanced = tmp_path / 'advanced.json'
    advanced.write_text(json.dumps({'watch': {'state_dir': ''}}), encoding='utf-8')
    config = data / 'sunpack_config.json'
    config.write_text(json.dumps({'watch': {'state_dir': 'custom'}}), encoding='utf-8')
    with pytest.raises(WatchStateJournalError, match='must be reset'):
        WatchStateStore(str(custom / 'state.snapshot'))
    command = ['powershell.exe', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
               '-File', str(repo_root / 'scripts/reset_legacy_watch_state.ps1'),
               '-DataRoot', str(data), '-AdvancedConfig', str(advanced), '-UserConfig', str(config)]
    result = subprocess.run(command, capture_output=True, text=True, timeout=20)
    assert result.returncode == 10, result.stderr
    for directory in (default, custom):
        assert all(not (directory / name).exists() for name in old_files)
        assert all((directory / name).read_bytes() == b'preserve bytes' for name in keep_files)
        assert (directory / 'catalog.snapshot.tmp.directory').is_dir()
        state = WatchStateStore(str(directory / 'state.snapshot'))
        state.save()
        state.close()
    snapshots = {directory: (directory / 'state.snapshot').read_bytes() for directory in (default, custom)}
    result = subprocess.run(command, capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
    assert all((directory / 'state.snapshot').read_bytes() == content for directory, content in snapshots.items())
    assert json.loads(config.read_text(encoding='utf-8')) == {'watch': {'state_dir': 'custom'}}
