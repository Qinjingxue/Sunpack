import os
from itertools import groupby

from sunpack.core.contracts.failures import FailureKind, PASSWORD_FAILURE_KINDS
from sunpack.core.support.path_keys import path_key
from sunpack.runtime.cli.cli_aliases import COMMAND_ALIASES
from sunpack.runtime.cli.cli_parsers import (
    build_common_parser, build_detection_parser, build_password_parser, build_process_mode_parser,
)
from sunpack.runtime.cli.cli_types import CliCommandResult
from sunpack.runtime.cli.cli_constants import EXIT_TASK_FAILED

COMMAND = "scan"
ORDER = 20


def register(subparsers, ctx):
    parser = subparsers.add_parser(
        COMMAND, aliases=COMMAND_ALIASES[COMMAND],
        parents=[build_common_parser(ctx), build_detection_parser(ctx), build_password_parser(ctx), build_process_mode_parser(ctx)],
        help=ctx.t("cli.scan.help"), usage="sunpack scan [options] <paths...>",
    )
    parser.set_defaults(command=COMMAND)
    parser.add_argument("paths", nargs="+", help=ctx.t("cli.scan.paths"))


async def handle(args, ctx):
    from sunpack.runtime.cli.commands.extract import handle as execute
    return await execute(args, ctx, operation="scan")


def command_result(args, ctx, paths, summary):
    rows = [(path_key(item["main_path"]), item)
            for result in summary.target_results for item in result.scan_items]
    rows.sort(key=lambda row: (row[0], row[1].get("offset", -1), row[1].get("format", "")))
    items = [item for _, item in rows]
    if not args.verbose:
        for item in items:
            item.pop("discovery_source", None)
            item.pop("damage_flags", None)
    if not args.json:
        for _, group in groupby(rows, key=lambda row: row[0]):
            entries = [item for _, item in group]
            path = entries[0]["main_path"]
            ctx.reporter.info(path)
            multiple = len(entries) > 1
            for index, item in enumerate(entries, 1):
                prefix = ("   " if index == len(entries) else "│  ") if multiple else "  "
                if multiple:
                    branch = "└─ " if index == len(entries) else "├─ "
                    ctx.reporter.info(branch + ctx.t("cli.scan.segment", index=index) + _range(item))
                elif "offset" in item:
                    ctx.reporter.info(prefix + ctx.t("cli.scan.range", start=item["offset"], end=item.get("end_offset") if item.get("end_offset") is not None else "?"))
                # Omit errors already explained by visible fact fields. Quiet
                # mode has no headings or fields, so retain standalone errors.
                if item.get("error") and (ctx.reporter.quiet or not (
                    (item.get("error_kind") in PASSWORD_FAILURE_KINDS
                     and item.get("password_used", "") is None)
                    or (item.get("error_kind") == FailureKind.MISSING_VOLUME
                        and item.get("volume_completeness") == "missing")
                )):
                    error_prefix = f"{path}{_range(item)}: " if ctx.reporter.quiet else prefix
                    ctx.reporter.error(error_prefix + ctx.t("cli.scan.error", error=item["error"]))
                for text in _details(item, ctx):
                    ctx.reporter.info(prefix + text)
        for failure in summary.scan_failures:
            ctx.reporter.error(ctx.t("report.scan_error", task=failure.display_message))
        if summary.scan_error_count:
            ctx.reporter.error(ctx.t("report.scan_incomplete"))
        for result in summary.target_results:
            if not result.scan_items and result.error:
                ctx.reporter.error(f"{result.input_path}: {result.error}")
    result = CliCommandResult(
        command=COMMAND, inputs={"paths": paths, "deep_detect": bool(args.deep_detect)},
        summary={"archive_count": len(items), "failed_count": summary.failed_count,
                 "scan_error_count": summary.scan_error_count, "input_error_count": summary.input_error_count},
        items=items, errors=summary.failed_tasks,
    )
    return (EXIT_TASK_FAILED if summary.failed_tasks else 0), result


def _range(item):
    if "offset" not in item:
        return ""
    end = item.get("end_offset")
    return f": [{item['offset']}, {end if end is not None else '?'})"


def _details(item, ctx):
    if item.get("format"):
        yield ctx.t("cli.scan.format", format=item["format"])
    plan = item.get("volume_attempts")
    if plan:
        domains = []
        for domain in plan["domains"]:
            names = [_source_name(plan["sources"][i]) for i in domain["choices"]]
            domains.append(names[0] if len(names) == 1 else "(" + ", ".join(names) + ")")
        for layout in plan["layouts"]:
            yield ctx.t("cli.scan.parts", parts=", ".join(domains[slot["domain"]] for slot in layout["slots"]))
            if layout.get("minimum_slots"):
                yield ctx.t("cli.scan.volume_count", minimum=layout["minimum_slots"], maximum=len(layout["slots"]))
        yield ctx.t("cli.scan.constraints")
    elif "all_parts" in item:
        others = [os.path.basename(path) for path in item["all_parts"] if path != item["main_path"]]
        if others:
            yield ctx.t("cli.scan.parts", parts=", ".join(others))
    if "volume_completeness" in item:
        yield ctx.t("cli.scan.volumes", state=ctx.t("cli.scan.volumes." + item["volume_completeness"]))
    if "password_used" in item:
        password = item["password_used"]
        yield ctx.t("cli.scan.password", password=ctx.t("cli.scan.password_unknown") if password is None else repr(password) if password == "" else password)
    if item.get("discovery_source"):
        yield ctx.t("cli.scan.source", source=item["discovery_source"])
    if item.get("damage_flags"):
        yield ctx.t("cli.scan.damage", flags=", ".join(item["damage_flags"]))


def _source_name(source):
    name = os.path.basename(source["path"])
    if source.get("start") or source.get("end") is not None:
        end = source.get("end")
        name += f"[{source.get('start', 0)}, {end if end is not None else '?'})"
    return name
