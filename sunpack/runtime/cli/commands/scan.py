from sunpack.runtime.cli.cli_parsers import CliHelpFormatter, build_common_parser, build_detection_parser, build_process_mode_parser, localize_help_action
from sunpack.runtime.cli.cli_runtime import (
    resolve_common_root,
    resolve_target_paths,
    result_for_missing,
    scan_result_to_item,
)
from sunpack.runtime.cli.cli_types import CliCommandResult
from sunpack.runtime.cli.persistent_runtime import load_request_config
from sunpack.pipeline.coordinator.scanner import ScanOrchestrator
from sunpack.pipeline.discovery.embedded.options import EmbeddedOptions

COMMAND = "scan"
ORDER = 20


def register(subparsers, ctx):
    parser = subparsers.add_parser(
        COMMAND,
        parents=[build_common_parser(ctx), build_detection_parser(ctx), build_process_mode_parser(ctx)],
        help=ctx.t("cli.scan.help"),
        usage="sunpack scan [options] <paths...>",
        formatter_class=CliHelpFormatter,
    )
    localize_help_action(parser, ctx)
    parser.add_argument("paths", nargs="+", help=ctx.t("cli.scan.paths"))


def handle(args, ctx):
    reporter = ctx.reporter
    target_paths, missing_paths = resolve_target_paths(args.paths, base_dir=ctx.cwd)
    if missing_paths:
        return result_for_missing(COMMAND, args, missing_paths, ctx)

    config = load_request_config(ctx.cwd)
    orchestrator = ScanOrchestrator(config, EmbeddedOptions(force_scan=bool(args.deep_detect)))
    task_items = [scan_result_to_item(res) for res in orchestrator.scan_targets(target_paths)]
    task_items.sort(key=lambda item: item["main_path"].lower())

    summary = {
        "task_count": len(task_items),
        "split_task_count": sum(1 for item in task_items if len(item["all_parts"]) > 1),
    }
    if not args.json:
        reporter.info(ctx.t("cli.scan.identified", count=summary["task_count"]))
        for item in task_items:
            reporter.info(ctx.t("cli.item_path", path=item["main_path"]))
            reporter.info(ctx.t(
                "cli.scan.details",
                source=item["discovery_source"] or "-",
                format=item["format"] or "-",
                parts=len(item["all_parts"]),
            ))
            if reporter.verbose and item["discovery_reason"]:
                reporter.info(ctx.t("cli.scan.reason", reason=item["discovery_reason"]))

    return 0, CliCommandResult(
        command=COMMAND,
        inputs={"paths": target_paths, "common_root": resolve_common_root(target_paths), "config_overrides": {}, "deep_detect": bool(args.deep_detect)},
        summary=summary,
        tasks=task_items,
    )
