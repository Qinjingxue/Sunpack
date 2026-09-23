import os
from pathlib import Path

import pytest

from sunpack.config.loader import clear_config_cache, load_config
from sunpack.coordinator.output_scan_policy import NestedOutputScanPolicy
from sunpack.coordinator.recursive_authorization import RecursiveAuthorization
from sunpack.coordinator.task_provider import ArchiveTaskProvider


GAME_TREE_ROOT = Path(os.environ.get("SUNPACK_GAME_TREE_ROOT", r"D:\game"))

pytestmark = pytest.mark.skipif(
    os.environ.get("SUNPACK_RUN_GAME_TREE_TEST") != "1",
    reason="set SUNPACK_RUN_GAME_TREE_TEST=1 to scan the local game tree",
)


def test_game_tree_resources_are_not_authorized_for_recursive_extraction(monkeypatch):
    if not GAME_TREE_ROOT.is_dir():
        pytest.skip(f"game tree is not available: {GAME_TREE_ROOT}")
    output_dirs = [str(path) for path in GAME_TREE_ROOT.iterdir() if path.is_dir()]
    if not output_dirs:
        pytest.skip("game tree has no child directories")
    monkeypatch.delenv("SUNPACK_CONFIG_OVERRIDES", raising=False)
    clear_config_cache()
    try:
        config = load_config()
        output_scan = NestedOutputScanPolicy(config)
        roots = output_scan.scan_roots_from_outputs(output_dirs)
        session = output_scan.take_scan_session(roots)
        assert session is not None
        provider = ArchiveTaskProvider(config)
        inputs = provider.discover_targets(
            roots, scan_session=session, is_recursive_scan=True,
        ).resolved_inputs
        result = RecursiveAuthorization(config).authorize_batch(
            inputs, roots, session, round_index=2,
        )
        assert len(result.allowed_inputs) <= len(inputs)
        assert all(item.entry_path for item in result.allowed_inputs)
    finally:
        clear_config_cache()
