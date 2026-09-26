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
        actions=actions,
    ))
    assert struct.unpack_from('<BBBBd', payload) == (3, 1, 2, 0, expected)
    assert '失败 & 完成'.encode() in payload
    assert b'log-2' not in payload


def test_snapshot_preserves_size_limit():
    snapshot = ToastSnapshot(ToastSnapshotKind.SUCCESS, '', 'x' * (MAX_SNAPSHOT_BYTES - 36))
    assert len(encode_snapshot(snapshot)) == MAX_SNAPSHOT_BYTES
    with pytest.raises(ValueError, match='64 KiB'):
        encode_snapshot(ToastSnapshot(ToastSnapshotKind.SUCCESS, '', snapshot.title + 'x'))
