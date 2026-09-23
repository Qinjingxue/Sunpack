from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def bypass_installed_watch_broker_for_scheduler_unit_tests(monkeypatch):
    """Scheduler unit tests isolate policy logic from the installed SCM service."""
    import sunpack.runtime.watch.scheduler as scheduler_module

    monkeypatch.setattr(scheduler_module, "validate_ntfs_watch_roots", lambda _roots: None)
