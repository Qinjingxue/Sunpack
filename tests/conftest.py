import os
from pathlib import Path

import pytest


DEFAULT_TEST_CONFIG_OVERRIDES = (
    '{"filesystem": {"scan_filters": [{"name": "size_range", "enabled": false}]}}'
)


@pytest.fixture(scope="session", autouse=True)
def apply_default_test_config_overrides():
    """Let pytest runs use small fixtures by disabling the size_range filter.

    The value is only installed when the caller did not already set
    SUNPACK_CONFIG_OVERRIDES, so custom overrides keep working.
    """
    if "SUNPACK_CONFIG_OVERRIDES" not in os.environ:
        os.environ["SUNPACK_CONFIG_OVERRIDES"] = DEFAULT_TEST_CONFIG_OVERRIDES
    try:
        from sunpack.config.loader import clear_config_cache
    except Exception:
        pass
    else:
        clear_config_cache()
    yield
    if os.environ.get("SUNPACK_CONFIG_OVERRIDES") == DEFAULT_TEST_CONFIG_OVERRIDES:
        os.environ.pop("SUNPACK_CONFIG_OVERRIDES", None)


@pytest.fixture(scope="session", autouse=True)
def isolate_builtin_password_file(tmp_path_factory):
    """Prevent watch tests from persisting clipboard contents into the checkout."""
    import sunpack.passwords.internal.builtin as builtin_module

    builtin_path = tmp_path_factory.mktemp("sunpack-resources") / "builtin_passwords.txt"
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(builtin_module, "builtin_password_path", lambda: builtin_path)
    yield
    monkeypatch.undo()

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def repo_root() -> Path:
    return REPO_ROOT


def pytest_addoption(parser):
    parser.addoption(
        "--run-performance",
        action="store_true",
        default=False,
        help="Run opt-in performance and memory-stability assertions.",
    )
    parser.addoption(
        "--run-large-archive-performance",
        action="store_true",
        default=False,
        help="Run opt-in large archive performance tests that generate multi-GB fixtures.",
    )
    parser.addoption(
        "--large-archive-count",
        action="store",
        type=int,
        default=10,
        help="Number of large archives to generate for --run-large-archive-performance.",
    )
    parser.addoption(
        "--large-archive-size-mb",
        action="store",
        type=int,
        default=300,
        help="Payload size in MiB for each generated large archive.",
    )
def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "performance: opt-in timing or resource stability assertion; run with --run-performance",
    )
    config.addinivalue_line(
        "markers",
        "large_archive_performance: opt-in large archive performance tests that generate multi-GB fixtures",
    )
    config.addinivalue_line(
        "markers",
        "requires_watch_broker: requires the isolated, ephemeral Watch Broker test service",
    )


def pytest_collection_modifyitems(config, items):
    skip_performance = None
    if not config.getoption("--run-performance"):
        skip_performance = pytest.mark.skip(reason="use --run-performance to run performance assertions")
    skip_large = None
    if not config.getoption("--run-large-archive-performance"):
        skip_large = pytest.mark.skip(
            reason="use --run-large-archive-performance to run multi-GB performance tests"
        )
    isolated_broker = (
        os.environ.get("SUNPACK_WATCH_BROKER_SERVICE_NAME", "").startswith("SunPackWatchBrokerTest_")
        and os.environ.get("SUNPACK_WATCH_BROKER_PIPE_NAME", "").startswith(
            r"\\.\pipe\SunPack.WatchBroker.Test."
        )
    )
    skip_broker = pytest.mark.skip(
        reason="requires an isolated, ephemeral Watch Broker test service"
    )
    for item in items:
        item_path = Path(str(item.path)).as_posix()
        if "/tests/real/plan7_watch_downloads/" in f"/{item_path}":
            item.add_marker(pytest.mark.requires_watch_broker)
        if "requires_watch_broker" in item.keywords and not isolated_broker:
            item.add_marker(skip_broker)
        if skip_performance and "performance" in item.keywords and "large_archive_performance" not in item.keywords:
            item.add_marker(skip_performance)
        if skip_large and "large_archive_performance" in item.keywords:
            item.add_marker(skip_large)
