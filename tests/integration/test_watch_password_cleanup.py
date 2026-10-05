from __future__ import annotations

import asyncio
import subprocess
import time
import uuid

import pytest
import sunpack_native

import sunpack.core.passwords.internal.builtin as builtin
import sunpack.core.passwords.internal.clipboard_monitor as clipboard
from sunpack.core.config.loader import load_config
from sunpack.pipeline.coordinator.engine import PipelineEngine
from sunpack.runtime.watch.scheduler import WatchScheduler
from tests.helpers.tool_config import get_test_tools


pytestmark = pytest.mark.requires_watch_broker


def test_concurrent_header_encrypted_rar_retry_cleans_single_and_disguised_volumes(tmp_path, monkeypatch):
    rar = get_test_tools()['rar_exe']
    if rar is None or not rar.is_file():
        pytest.skip('RAR fixture generator is required')
    root = tmp_path / 'watch'
    root.mkdir()
    source = tmp_path / 'source'
    source.mkdir()
    payload = 'password-cleanup-regression\n' * 8000
    (source / 'payload.txt').write_text(payload, encoding='utf-8')
    password = 'retry-' + uuid.uuid4().hex
    for name, options in [('single.rar', []), ('split.rar', ['-v80k'])]:
        generated = subprocess.run(
            [str(rar), 'a', '-ma5', '-m0', '-hp' + password, '-y', *options,
             str(root / name), 'payload.txt'],
            cwd=source, capture_output=True, timeout=15,
        )
        assert generated.returncode == 0, generated.stderr
    volumes = list(root.glob('split.part*.rar'))
    assert len(volumes) >= 2
    for path in volumes:
        path.rename(path.with_name(path.name + '.jpg'))
    archives = list(root.iterdir())
    builtin_path = tmp_path / 'builtin_passwords.txt'
    builtin_path.write_text(
        'wrong\n' + builtin.WATCH_CLIPBOARD_BLOCK_BEGIN + '\n'
        + builtin.WATCH_CLIPBOARD_BLOCK_END + '\n', encoding='utf-8',
    )
    monkeypatch.setattr(builtin, 'builtin_password_path', lambda: builtin_path)
    monkeypatch.setattr(clipboard, 'read_clipboard_passwords', lambda: [password])
    config = load_config()
    config['user_passwords'] = []
    config['builtin_passwords'] = ['wrong']
    config['cli']['quiet'] = True
    config['post_extract']['archive_cleanup_mode'] = 'delete'
    config['watch']['clipboard_monitor_enabled'] = False

    async def settle(watcher):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            await watcher.run_once()
            if not watcher.pending_count and not watcher._inflight_requests and not watcher._password_dirty_dirs:
                return
            await asyncio.sleep(0.01)
        pytest.fail('password retry/cleanup did not settle before the barrier timeout')

    async def scenario():
        async with PipelineEngine(config) as engine:
            responses = []
            original_run = engine.run
            async def run(*args, **kwargs):
                response = await original_run(*args, **kwargs)
                responses.append(response)
                return response
            monkeypatch.setattr(engine, 'run', run)
            watcher = WatchScheduler(
                config, [str(root)], out_dir='.', state_path=str(tmp_path / '.sunpack_watch' / 'state.json'),
                cold_start_seconds=0, initial_scan=False, pipeline_engine=engine,
            )
            await watcher.start()
            try:
                for path in archives:
                    watcher.enqueue(str(path))
                await settle(watcher)
                assert all(path.exists() for path in archives)
                entries = list(watcher.state.entries.values())
                assert len(entries) == 2
                assert all(entry.status == 'failed_password' for entry in entries)
                responses.clear()
                watcher._clipboard_monitor._handle_clipboard_update()
                await settle(watcher)
                assert sum(response.summary.success_count for response in responses) == 2
                assert not any(response.summary.cleanup_results for response in responses)
                assert not any(path.exists() for path in archives)
                extracted = list(root.rglob('payload.txt'))
                assert len(extracted) == 2
                assert all(path.read_text(encoding='utf-8') == payload for path in extracted)
            finally:
                await watcher.stop()
                await watcher.drain()

    sunpack_native.watch_broker_acquire()
    try:
        asyncio.run(scenario())
    finally:
        sunpack_native.watch_broker_release()
