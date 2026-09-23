import math
import struct
import pytest
from sunpack.core.platform.windows.toast_protocol import (
    MAX_SNAPSHOT_BYTES, ToastAction, ToastActionKind, ToastProgressMode,
    ToastSnapshot, ToastSnapshotKind, encode_snapshot,
)


@pytest.mark.parametrize('progress, expected', [(2., 1.), (-1., 0.), (math.nan, 0.), (math.inf, 0.), (.25, .25)])
def test_snapshot_clamps_progress_and_limits_actions(progress, expected):
    actions = tuple(ToastAction(ToastActionKind.OPEN_LOG, f'log-{i}', f'C:\\logs\\{i}.txt') for i in range(3))
    payload = encode_snapshot(ToastSnapshot(
        kind=ToastSnapshotKind.FAILURE, batch_id='batch', title='失败 & 完成',
        progress_mode=ToastProgressMode.DETERMINATE, progress_value=progress,
        actions=actions, ttl_ms=1234,
    ))
    assert struct.unpack_from('<BBBBdI', payload) == (3, 1, 2, 0, expected, 1234)
    assert '失败 & 完成'.encode() in payload
    assert b'log-2' not in payload


@pytest.mark.parametrize('ttl, expected', [(-1, 0), (0, 0), (2**40, 0xFFFFFFFF)])
def test_snapshot_clamps_ttl(ttl, expected):
    snapshot = ToastSnapshot(ToastSnapshotKind.SUCCESS, 'batch', 'done', ttl_ms=ttl)
    assert struct.unpack_from('<I', encode_snapshot(snapshot), 12)[0] == expected


def test_snapshot_preserves_size_limit():
    snapshot = ToastSnapshot(ToastSnapshotKind.SUCCESS, '', 'x' * (MAX_SNAPSHOT_BYTES - 40))
    assert len(encode_snapshot(snapshot)) == MAX_SNAPSHOT_BYTES
    with pytest.raises(ValueError, match='64 KiB'):
        encode_snapshot(ToastSnapshot(ToastSnapshotKind.SUCCESS, '', snapshot.title + 'x'))
