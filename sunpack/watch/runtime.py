from __future__ import annotations

async def run_watch_service(
    *,
    tray_enabled: bool = True,
    once: bool = False,
    initial_scan: bool = False,
) -> int:
    from sunpack.cli.runtime_state import require_runtime_host

    host = require_runtime_host()
    if once:
        return await host.run_watch_once(initial_scan=initial_scan)
    await host.start_watch(tray_enabled=tray_enabled, initial_scan=initial_scan)
    return 0
