import os
from pathlib import Path

import pytest

from tests.helpers.package import package


REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def repo_root() -> Path:
    return REPO_ROOT


def pytest_addoption(parser):
    parser.addoption("--diagnostics-dir", default=None, help="Persist acceptance test progress")


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "requires_watch_broker: requires a configured Watch Broker service and pipe",
    )
    diagnostic_dir = config.getoption("--diagnostics-dir")
    if diagnostic_dir:
        directory = Path(diagnostic_dir)
        directory.mkdir(parents=True, exist_ok=True)
        worker = os.environ.get("PYTEST_XDIST_WORKER", "controller")
        log = (directory / f"{worker}-{os.getpid()}.log").open("w", encoding="utf-8", buffering=1)
        config.pluginmanager.register(_AcceptanceDiagnostics(log))
        config.add_cleanup(log.close)


class _AcceptanceDiagnostics:
    def __init__(self, log):
        self.log = log
        self.log.write("session configured\n")

    def pytest_sessionstart(self, session):
        self.log.write("session started\n")

    def pytest_collection_finish(self, session):
        self.log.write(f"collected {len(session.items)} tests\n")

    @pytest.hookimpl(tryfirst=True)
    def pytest_runtest_setup(self, item):
        self.log.write(f"setup {item.nodeid}\n")

    @pytest.hookimpl(tryfirst=True)
    def pytest_runtest_call(self, item):
        self.log.write(f"call {item.nodeid}\n")

    @pytest.hookimpl(tryfirst=True)
    def pytest_runtest_teardown(self, item):
        self.log.write(f"teardown {item.nodeid}\n")

    def pytest_sessionfinish(self, session, exitstatus):
        self.log.write(f"session finished {exitstatus}\n")


def pytest_collection_modifyitems(items):
    if all(os.environ.get(name) for name in (
        "SUNPACK_WATCH_BROKER_SERVICE_NAME", "SUNPACK_WATCH_BROKER_PIPE_NAME",
    )):
        return
    skip = pytest.mark.skip(reason="requires a configured Watch Broker service and pipe")
    for item in items:
        if item.get_closest_marker("requires_watch_broker"):
            item.add_marker(skip)
