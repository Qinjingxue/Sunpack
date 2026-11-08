import io
import zipfile
import gzip

import pytest

from sunpack.pipeline.coordinator.task_provider import ArchiveTaskProvider
from tests.helpers.config_factory import make_config


def _zip_bytes() -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_STORED) as archive:
        archive.writestr("inside.txt", "hello")
    return output.getvalue()


def test_disguised_zip_is_resolved_by_relations(tmp_path):
    path = tmp_path / "movie.dat"
    path.write_bytes(_zip_bytes())
    result = ArchiveTaskProvider(make_config({})).discover_targets([str(path)])
    assert len(result.tasks) == 1
    assert result.tasks[0].discovery_source == "relations"


def test_embedded_carrier_with_prefix_and_suffix_is_discovered(tmp_path):
    path = tmp_path / "carrier.bin"
    path.write_bytes(b"prefix" + _zip_bytes() + b"suffix")
    result = ArchiveTaskProvider(make_config({"embedded_scan": {"enabled": True}})).discover_targets([str(path)])
    assert len(result.tasks) == 1
    assert result.tasks[0].discovery_source == "embedded"
    assert result.tasks[0].archive_input().open_mode == "file_range"


def test_embedded_switch_prevents_carrier_scan(tmp_path):
    path = tmp_path / "carrier.bin"
    path.write_bytes(b"prefix" + _zip_bytes() + b"suffix")
    result = ArchiveTaskProvider(make_config({"embedded_scan": {"enabled": False}})).discover_targets([str(path)])
    assert result.tasks == []


def test_recursive_embedded_ratio_uses_individual_candidate_share(tmp_path):
    paths = [tmp_path / name for name in ("large", "medium", "small")]
    carrier = b"prefix" + gzip.compress(b"payload")
    for path, size in zip(paths, (7000, 2500, 500)):
        path.write_bytes(carrier.ljust(size, b"x"))

    for ratio, expected in ((0.3, paths[:1]), (0.05, paths), (0, [])):
        config = make_config({"embedded_scan": {"recursive_candidate_ratio": ratio}})
        result = ArchiveTaskProvider(config).discover_targets([str(tmp_path)], is_recursive_scan=True)
        assert {task.carrier_path for task in result.tasks} == {str(path) for path in expected}


@pytest.mark.parametrize("force", [False, True])
def test_shared_recursive_scan_keeps_root_policy_and_candidate_page_identity(tmp_path, force):
    """Multi-root scheduling must preserve local selection and row ownership.

    Single-root cases cannot catch a combined size denominator or a batch-local
    row applied to a different table. One sparse root crosses the old raw page
    boundary, and force mode crosses the selected-job page boundary as well.
    """
    from sunpack.pipeline.discovery.embedded.options import EmbeddedOptions

    roots = [tmp_path / name for name in ("large", "sparse", "small")]
    for root in roots:
        root.mkdir()
        (root / "zz_carrier.bin").write_bytes(b"prefix" * 64 + gzip.compress(b"payload") + b"suffix")
    (roots[0] / "noise.bin").write_bytes(b"x" * 10000)
    for index in range(260):
        (roots[1] / f"noise_{index:03}.bin").write_bytes(b"x")
    config = make_config({"embedded_scan": {"enabled": True, "recursive_candidate_ratio": 0.3}})
    provider = ArchiveTaskProvider(config, EmbeddedOptions(force_scan=force))
    serial = [task for root in roots for task in provider.discover_targets(
        [str(root)], is_recursive_scan=True,
    ).tasks]
    shared = provider.discover_targets([str(root) for root in roots], is_recursive_scan=True)

    expected = [str(root / "zz_carrier.bin") for root in (roots if force else roots[1:])]
    assert [task.main_path for task in serial] == expected
    assert [task.main_path for task in shared.tasks] == expected
    assert [task.archive_input().to_dict() for task in shared.tasks] == [
        task.archive_input().to_dict() for task in serial
    ]
    assert not shared.blocked_paths
