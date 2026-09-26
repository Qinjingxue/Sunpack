from __future__ import annotations


from sunpack.runtime.cli.cli_aliases import COMMAND_ALIASES
from sunpack.runtime.cli.cli_constants import EXIT_TASK_FAILED, EXIT_USAGE
from sunpack.runtime.cli.cli_parsers import CliHelpFormatter, build_common_parser, localize_help_action
from sunpack.runtime.cli.cli_types import CliCommandResult
from sunpack.runtime.cli.persistent_runtime import load_request_config
from sunpack.runtime.watch.service import (
    add_watch_roots,
    list_watch_roots,
    remove_watch_roots,
    service_state_dir,
)


COMMAND = "watch"
ORDER = 15


def register(subparsers, ctx):
    common = build_common_parser(ctx)
    parser = subparsers.add_parser(
        COMMAND,
        aliases=COMMAND_ALIASES[COMMAND],
        parents=[common],
        help=ctx.t("cli.watch.help"),
        usage="sunpack watch <add|remove|list|start|stop|reload|status|startup> [options]",
        formatter_class=CliHelpFormatter,
    )
    parser.set_defaults(command=COMMAND)
    localize_help_action(parser, ctx)
    actions = parser.add_subparsers(dest="watch_action", required=True)

    start_parser = actions.add_parser("start", parents=[common], help=ctx.t("cli.watch.start"), formatter_class=CliHelpFormatter)
    start_parser.add_argument("--once", action="store_true", help=ctx.t("cli.watch.once"))
    start_parser.add_argument("--no-tray", action="store_true", help=ctx.t("cli.watch.no_tray"))
    start_parser.add_argument("-i", "--initial-scan", dest="initial_scan", action="store_true", help=ctx.t("cli.watch.initial_scan"))

    add_parser = actions.add_parser("add", parents=[common], help=ctx.t("cli.watch.add"), formatter_class=CliHelpFormatter)
    add_parser.add_argument("paths", nargs="+", help=ctx.t("cli.watch.paths"))
    add_parser.add_argument("-o", "--out-dir", dest="output_dir", help=ctx.t("cli.watch.output_dir"))
    add_parser.add_argument("-s", "--start", dest="start", action="store_true", help=ctx.t("cli.watch.start_after_add"))
    add_parser.add_argument("-i", "--initial-scan", dest="initial_scan", action="store_true", help=ctx.t("cli.watch.initial_scan"))
    add_parser.add_argument("-d", "--deep-detect", dest="deep_detect", action="store_true", default=None, help=ctx.t("cli.watch.deep_detect"))

    remove_parser = actions.add_parser("remove", aliases=["rm"], parents=[common], help=ctx.t("cli.watch.remove"), formatter_class=CliHelpFormatter)
    remove_parser.set_defaults(watch_action="remove")
    remove_parser.add_argument("paths", nargs="+", help=ctx.t("cli.watch.paths"))

    list_parser = actions.add_parser("list", aliases=["ls"], parents=[common], help=ctx.t("cli.watch.list"), formatter_class=CliHelpFormatter)
    list_parser.set_defaults(watch_action="list")
    actions.add_parser("reload", parents=[common], help=ctx.t("cli.watch.reload"), formatter_class=CliHelpFormatter)
    actions.add_parser("stop", parents=[common], help=ctx.t("cli.watch.stop"), formatter_class=CliHelpFormatter)
    status_parser = actions.add_parser("status", aliases=["st"], parents=[common], help=ctx.t("cli.watch.status"), formatter_class=CliHelpFormatter)
    status_parser.set_defaults(watch_action="status")

    startup_parser = actions.add_parser("startup", parents=[common], help=ctx.t("cli.watch.startup"), formatter_class=CliHelpFormatter)
    startup_parser.add_argument("startup_action", choices=["enable", "disable", "status"])


async def handle(args, ctx):
    try:
        action = args.watch_action
        if action == "start":
            return await _handle_start(args, ctx)
        if action == "add":
            return await _handle_add(args, ctx)
        if action == "remove":
            return await _handle_remove(args, ctx)
        if action == "list":
            return _handle_list()
        if action == "reload":
            return await _handle_reload(ctx)
        if action == "stop":
            return await _handle_stop(ctx)
        if action == "status":
            return _handle_status(ctx)
        if action == "startup":
            return _handle_startup(args)
    except Exception as exc:
        return EXIT_TASK_FAILED, CliCommandResult(command=COMMAND, inputs={}, summary={}, errors=[ctx.t("cli.operation_failed", error=exc)])
    return EXIT_USAGE, CliCommandResult(command=COMMAND, inputs={}, summary={}, errors=[ctx.t("cli.watch.unknown_action", action=action)])


async def _handle_start(args, ctx):
    from sunpack.runtime.cli.runtime_state import require_runtime_host

    host = require_runtime_host()
    if bool(getattr(args, "once", False)):
        code = await host.run_watch_once(initial_scan=bool(getattr(args, "initial_scan", False)))
        return code, CliCommandResult(command=COMMAND, inputs={"action": "start", "once": True}, summary={"exit_code": code})
    summary = await host.start_watch(
        tray_enabled=not bool(getattr(args, "no_tray", False)),
        initial_scan=bool(getattr(args, "initial_scan", False)),
    )
    return 0, CliCommandResult(command=COMMAND, inputs={"action": "start"}, summary=summary)


async def _handle_add(args, ctx):
    from sunpack.runtime.cli.runtime_state import require_runtime_host

    start_requested = bool(getattr(args, "start", False))
    initial_scan_requested = bool(getattr(args, "initial_scan", False))
    paths = list(args.paths or [])
    output_dir = getattr(args, "output_dir", None)
    deep_detect = getattr(args, "deep_detect", None)
    if output_dir is not None and len(paths) != 1:
        return EXIT_USAGE, CliCommandResult(
            command=COMMAND,
            inputs={"action": "add", "paths": paths, "output_dir": output_dir},
            summary={},
            errors=[ctx.t("cli.watch.output_dir_single_path")],
        )
    host = require_runtime_host()
    apply_summary = None
    if host.watch_enabled:
        apply_summary = await host.add_watch_roots(
            paths,
            output_dir=output_dir,
            deep_detect=deep_detect,
            initial_scan=initial_scan_requested,
        )
        roots_path = apply_summary["roots_path"]
        added = list(apply_summary["added"])
        updated = list(apply_summary["updated"])
    else:
        roots_path_obj, added, updated = add_watch_roots(paths, output_dir=output_dir, deep_detect=deep_detect)
        roots_path = str(roots_path_obj)
    start_summary = None
    if start_requested and not host.watch_enabled:
        start_summary = await host.start_watch(
            initial_scan_roots=added + updated if initial_scan_requested else None,
        )
    return 0, CliCommandResult(
        command=COMMAND,
        inputs={"action": "add", "paths": paths, "output_dir": output_dir, "deep_detect": deep_detect},
        summary={
            "roots_path": str(roots_path),
            "added": added,
            "updated": updated,
            "apply": apply_summary,
            "start": start_summary,
            "start_requested": start_requested,
            "initial_scan_requested": initial_scan_requested,
        },
        items=added,
    )


async def _handle_remove(args, ctx):
    from sunpack.runtime.cli.runtime_state import require_runtime_host

    paths = list(args.paths or [])
    host = require_runtime_host()
    apply_summary = None
    if host.watch_enabled:
        apply_summary = await host.remove_watch_roots(paths)
        roots_path = apply_summary["roots_path"]
        removed = list(apply_summary["removed"])
    else:
        roots_path_obj, removed = remove_watch_roots(paths)
        roots_path = str(roots_path_obj)
    return 0, CliCommandResult(
        command=COMMAND,
        inputs={"action": "remove", "paths": paths},
        summary={"roots_path": str(roots_path), "removed": removed, "apply": apply_summary},
        items=removed,
    )


def _handle_list():
    roots_path, roots = list_watch_roots()
    return 0, CliCommandResult(
        command=COMMAND,
        inputs={"action": "list"},
        summary={"roots_path": str(roots_path), "count": len(roots)},
        items=roots,
    )


async def _handle_reload(ctx):
    from sunpack.runtime.cli.runtime_state import require_runtime_host

    summary = await require_runtime_host().reload_watch()
    return 0, CliCommandResult(command=COMMAND, inputs={"action": "reload"}, summary=summary)


async def _handle_stop(ctx):
    from sunpack.runtime.cli.runtime_state import require_runtime_host

    summary = await require_runtime_host().stop_watch()
    return 0, CliCommandResult(command=COMMAND, inputs={"action": "stop"}, summary=summary)


def _handle_status(ctx):
    from sunpack.runtime.cli.runtime_state import require_runtime_host

    config = load_request_config(ctx.cwd)
    _, roots = list_watch_roots()
    host_status = require_runtime_host().watch_status()
    return 0, CliCommandResult(
        command=COMMAND,
        inputs={"action": "status"},
        summary={**host_status, "count": len(roots), "state_dir": service_state_dir(config)},
        items=roots,
    )


def _handle_startup(args):
    from sunpack.runtime.watch.startup import disable_startup, enable_startup, startup_status

    if args.startup_action == "enable":
        command = enable_startup()
        return 0, CliCommandResult(command=COMMAND, inputs={"action": "startup", "startup_action": "enable"}, summary={"enabled": True, "command": command})
    if args.startup_action == "disable":
        changed = disable_startup()
        return 0, CliCommandResult(command=COMMAND, inputs={"action": "startup", "startup_action": "disable"}, summary={"enabled": False, "changed": changed})
    enabled, command = startup_status()
    return 0, CliCommandResult(command=COMMAND, inputs={"action": "startup", "startup_action": "status"}, summary={"enabled": enabled, "command": command})
