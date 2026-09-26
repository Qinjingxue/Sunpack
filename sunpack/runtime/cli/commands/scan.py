from sunpack.runtime.cli.cli_aliases import COMMAND_ALIASES
from sunpack.runtime.cli.cli_parsers import CliHelpFormatter, build_common_parser, build_detection_parser, build_process_mode_parser, localize_help_action
from sunpack.runtime.cli.cli_runtime import (
    resolve_common_root,
    resolve_target_paths,
    result_for_missing,
    scan_finding_to_item,
    scan_result_to_item,
)
from sunpack.runtime.cli.cli_types import CliCommandResult
from sunpack.runtime.cli.persistent_runtime import load_request_config
from sunpack.pipeline.coordinator.scanner import ScanOrchestrator
from sunpack.pipeline.discovery.embedded.options import EmbeddedOptions

COMMAND = "scan"
ORDER = 20

_REASON_KEYS = {
    "embedded_password_required": "failure.password_required",
    "embedded_wrong_password": "failure.wrong_password",
    "embedded_truncated": "failure.damaged",
    "embedded_carrier_blocked": "cli.scan.carrier_blocked",
}

_SOURCE_KEYS = {
    "embedded": "cli.scan.source.embedded",
    "relations": "cli.scan.source.relations",
    "detection": "cli.scan.source.detection",
}

_STATUS_KEYS = {
    "resolved": "cli.scan.status.resolved",
    "blocked": "cli.scan.status.blocked",
}


def register(subparsers, ctx):
    parser = subparsers.add_parser(
        COMMAND,
        aliases=COMMAND_ALIASES[COMMAND],
        parents=[build_common_parser(ctx), build_detection_parser(ctx), build_process_mode_parser(ctx)],
        help=ctx.t("cli.scan.help"),
        usage="sunpack scan [options] <paths...>",
        formatter_class=CliHelpFormatter,
    )
    parser.set_defaults(command=COMMAND)
    localize_help_action(parser, ctx)
    parser.add_argument("paths", nargs="+", help=ctx.t("cli.scan.paths"))


def handle(args, ctx):
    reporter = ctx.reporter
    target_paths, missing_paths = resolve_target_paths(args.paths, base_dir=ctx.cwd)
    if missing_paths:
        return result_for_missing(COMMAND, args, missing_paths, ctx)

    config = load_request_config(ctx.cwd)
    orchestrator = ScanOrchestrator(config, EmbeddedOptions(force_scan=bool(args.deep_detect)))
    report = orchestrator.scan_report(target_paths)

    task_items = [scan_result_to_item(res) for res in report.tasks]
    task_items.sort(key=lambda item: item["main_path"].lower())

    finding_items = [scan_finding_to_item(finding) for finding in report.findings]
    finding_items.sort(key=lambda item: (
        item["main_path"].lower(),
        item["offset"] if item["offset"] is not None else -1,
        item["format"],
    ))

    summary = {
        "task_count": len(task_items),
        "split_task_count": sum(1 for item in task_items if len(item["all_parts"]) > 1),
        "finding_count": len(finding_items),
        "blocked_finding_count": sum(1 for item in finding_items if item["status"] == "blocked"),
    }
    if not args.json:
        reporter.info(ctx.t(
            "cli.scan.identified",
            count=summary["finding_count"],
            resolved=sum(1 for item in finding_items if item["status"] == "resolved"),
            blocked=summary["blocked_finding_count"],
        ))
        for item in finding_items:
            source_key = _SOURCE_KEYS.get(item["discovery_source"])
            status_key = _STATUS_KEYS.get(item["status"])
            reporter.info(ctx.t("cli.item_path", path=item["main_path"]))
            reporter.info(ctx.t(
                "cli.scan.details",
                source=ctx.t(source_key) if source_key else item["discovery_source"] or "-",
                format=item["format"] or "-",
                status=ctx.t(status_key) if status_key else item["status"] or "-",
                parts=len(item["all_parts"]),
            ))
            if item["offset"] is not None:
                reporter.info(ctx.t(
                    "cli.scan.range",
                    start=item["offset"],
                    end=item["end_offset"] if item["end_offset"] is not None else "?",
                ))
            if item["discovery_reason"] and (
                reporter.verbose or item["status"] != "resolved"
            ):
                reason_key = _REASON_KEYS.get(item["discovery_reason"])
                reason = ctx.t(reason_key) if reason_key else item["discovery_reason"]
                reporter.info(ctx.t("cli.scan.reason", reason=reason))

    return 0, CliCommandResult(
        command=COMMAND,
        inputs={"paths": target_paths, "common_root": resolve_common_root(target_paths), "config_overrides": {}, "deep_detect": bool(args.deep_detect)},
        summary=summary,
        items=finding_items,
        tasks=task_items,
    )
