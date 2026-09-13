from sunpack.cli.cli_parsers import CliHelpFormatter, build_common_parser, build_detection_parser, localize_help_action
from sunpack.cli.cli_runtime import (
    build_effective_config,
    inspect_result_to_item,
    resolve_common_root,
    resolve_target_paths,
    result_for_missing,
)
from sunpack.cli.cli_types import CliCommandResult
from sunpack.contracts.detection import FactBag
from sunpack.contracts.tasks import ArchiveTask
from sunpack.cli.persistent_runtime import load_request_config
from sunpack.analysis import ArchiveAnalyzer
from sunpack.analysis.request import AnalysisRequest
from sunpack.analysis.source import analysis_source_for_descriptor
from sunpack.coordinator.detection_diagnostics import DetectionDiagnostics
from sunpack.support.json_format import to_json_text
from sunpack.detection.options import DetectionOptions

COMMAND = "inspect"
ORDER = 30


def register(subparsers, ctx):
    parser = subparsers.add_parser(
        COMMAND,
        parents=[build_common_parser(ctx), build_detection_parser(ctx)],
        help=ctx.t("cli.inspect.help"),
        usage="sunpack inspect [options] <paths...>",
        formatter_class=CliHelpFormatter,
    )
    localize_help_action(parser, ctx)
    parser.add_argument("--archives-only", action="store_true", help=ctx.t("cli.inspect.archives_only"))
    parser.add_argument("--analyze", action="store_true", help=ctx.t("cli.inspect.analyze"))
    parser.add_argument("paths", nargs="+", help=ctx.t("cli.inspect.paths"))


def handle(args, ctx):
    reporter = ctx.reporter
    target_paths, missing_paths = resolve_target_paths(args.paths, base_dir=ctx.cwd)
    if missing_paths:
        return result_for_missing(COMMAND, args, missing_paths, ctx)

    config = load_request_config(ctx.cwd)
    effective_config = build_effective_config(config)
    detection_options = DetectionOptions(deep_scan=bool(args.deep_detect))
    results = DetectionDiagnostics(config, detection_options).collect(target_paths)
    all_items = [inspect_result_to_item(res) for res in results]
    if args.analyze:
        analyses = _analysis_preview_by_path(results, config)
        for item in all_items:
            item["analysis"] = analyses.get(item["path"])
    all_items.sort(key=lambda item: item["path"].lower())
    items = [item for item in all_items if item["should_extract"]] if args.archives_only else all_items
    summary = {
        "total_items": len(all_items),
        "displayed_items": len(items),
        "archive_items": sum(1 for item in all_items if item["decision"] == "archive"),
        "maybe_archive_items": sum(1 for item in all_items if item["decision"] == "maybe_archive"),
        "not_archive_items": sum(1 for item in all_items if item["decision"] == "not_archive"),
        "extractable_items": sum(1 for item in all_items if item["should_extract"]),
        "encrypted_items": 0,
        "archives_only": bool(args.archives_only),
        "analyze": bool(args.analyze),
        "analyzed_items": sum(1 for item in all_items if item.get("analysis")),
        "analysis_extractable_items": sum(1 for item in all_items if (item.get("analysis") or {}).get("has_extractable")),
    }
    if not args.json:
        reporter.info(
            ctx.t(
                "cli.inspect.complete",
                total=summary["total_items"],
                archive=summary["archive_items"],
                maybe=summary["maybe_archive_items"],
                not_archive=summary["not_archive_items"],
            )
        )
        if reporter.verbose:
            reporter.info(ctx.t("cli.inspect.effective_config"))
            reporter.info(to_json_text(effective_config))
        for item in items:
            reporter.info(ctx.t("cli.item_path", path=item["path"]))
            reporter.info(ctx.t(
                "cli.inspect.details",
                decision=item["decision"],
                extract=ctx.t("common.yes" if item["should_extract"] else "common.no"),
                detected=item["detected_ext"] or "-",
            ))
            reporter.info(ctx.t("cli.inspect.decision_trace",
                stage=item.get("decision_stage") or "-",
                discarded_at=item.get("discarded_at") or "-",
                rule=item.get("deciding_rule") or "-",
            ))
            if item.get("stop_reason"):
                reporter.info(ctx.t("cli.inspect.stop_reason", reason=item["stop_reason"]))
            if args.analyze and item.get("analysis"):
                analysis = item["analysis"]
                reporter.info(ctx.t("cli.inspect.analysis",
                    status=analysis.get("status") or "-",
                    selected=analysis.get("selected_format") or "-",
                    confidence=_confidence_label(analysis.get("selected_confidence")),
                    segment=_segment_label(analysis.get("primary_segment")),
                    damage=", ".join(analysis.get("damage_flags") or []) or "-",
                ))
                candidates = _candidate_label(analysis.get("candidates") or [])
                if candidates:
                    reporter.info(ctx.t("cli.inspect.analysis_candidates", candidates=candidates))
            if reporter.verbose and item["reasons"]:
                reporter.info(ctx.t("cli.inspect.matched_rules", rules=", ".join(item["reasons"])))
            if reporter.verbose and item.get("fact_errors"):
                reporter.info(ctx.t("cli.inspect.fact_errors", errors=to_json_text(item["fact_errors"], pretty=False)))

    return 0, CliCommandResult(
        command=COMMAND,
        inputs={
            "paths": target_paths,
            "common_root": resolve_common_root(target_paths),
            "config_overrides": {},
            "archives_only": bool(args.archives_only),
            "analyze": bool(args.analyze),
            "effective_config": effective_config,
            "detection": effective_config["detection"],
            "deep_detect": bool(args.deep_detect),
        },
        summary=summary,
        items=items,
    )


def _analysis_preview_by_path(results, config: dict) -> dict[str, dict]:
    analyzer = ArchiveAnalyzer(config)
    output = {}
    for result in results:
        if not _should_analyze_result(result):
            continue
        task = _task_from_inspect_result(result)
        try:
            state = task.archive_state()
            source = analysis_source_for_descriptor(
                state.to_archive_input_descriptor(),
                report_path=task.main_path,
            )
            prepass = task.fact_bag.get("analysis.signature_prepass")
            report = analyzer.analyze(
                source,
                AnalysisRequest(
                    initial_prepass=(
                        dict(prepass)
                        if isinstance(prepass, dict) and prepass.get("full_scan_complete")
                        else None
                    )
                ),
            )
            output[result.path] = _analysis_summary(task, report)
        except Exception as exc:
            output[result.path] = {
                "status": "error",
                "error": str(exc),
                "has_extractable": False,
                "selected_format": "",
                "selected_confidence": 0.0,
                "primary_segment": None,
                "damage_flags": [],
                "candidates": [],
            }
    return output


def _should_analyze_result(result) -> bool:
    return bool(getattr(result, "should_extract", False) or getattr(result, "decision", "") == "maybe_archive")


def _task_from_inspect_result(result) -> ArchiveTask:
    bag = _clone_fact_bag(result.fact_bag)
    return ArchiveTask.from_fact_bag(bag)


def _clone_fact_bag(source) -> FactBag:
    cloned = FactBag()
    if source is not None and hasattr(source, "to_dict"):
        for key, value in source.to_dict().items():
            cloned.set(key, value)
    return cloned


def _analysis_summary(task: ArchiveTask, report) -> dict:
    if report is None:
        return {
            "status": "error",
            "error": task.fact_bag.get("inspection.error") or "",
            "has_extractable": False,
            "selected_format": "",
            "selected_confidence": 0.0,
            "primary_segment": None,
            "damage_flags": [],
            "candidates": [],
        }
    selected = list(report.selected or [])
    primary = selected[0] if selected else None
    segment = primary.segments[0] if primary and primary.segments else None
    candidates = [
        _evidence_summary(evidence)
        for evidence in sorted(report.evidences, key=lambda item: item.confidence, reverse=True)[:3]
    ]
    damage_flags = _dedupe([
        flag
        for evidence in selected[:2]
        for segment_item in evidence.segments[:2]
        for flag in segment_item.damage_flags
    ])
    return {
        "status": "extractable" if report.has_extractable else "not_extractable",
        "has_extractable": bool(report.has_extractable),
        "selected_format": getattr(primary, "format", "") if primary else "",
        "selected_confidence": float(getattr(primary, "confidence", 0.0) or 0.0) if primary else 0.0,
        "selected_status": getattr(primary, "status", "") if primary else "",
        "primary_segment": _segment_summary(segment),
        "damage_flags": damage_flags,
        "candidate_count": len(report.evidences),
        "candidates": candidates,
        "read_bytes": int(report.read_bytes or 0),
        "cache_hits": int(report.cache_hits or 0),
    }


def _evidence_summary(evidence) -> dict:
    damage_flags = _dedupe([
        flag
        for segment in evidence.segments[:2]
        for flag in segment.damage_flags
    ])
    return {
        "format": evidence.format,
        "status": evidence.status,
        "confidence": float(evidence.confidence or 0.0),
        "segments": len(evidence.segments or []),
        "damage_flags": damage_flags,
        "warnings": list(evidence.warnings[:3]),
    }


def _segment_summary(segment) -> dict | None:
    if segment is None:
        return None
    end = segment.end_offset
    length = None if end is None else max(0, int(end) - int(segment.start_offset))
    return {
        "start": int(segment.start_offset),
        "end": int(end) if end is not None else None,
        "length": length,
        "confidence": float(segment.confidence or 0.0),
        "role": segment.role,
    }


def _segment_label(segment: dict | None) -> str:
    if not segment:
        return "-"
    end = segment.get("end")
    end_text = "?" if end is None else str(end)
    length = segment.get("length")
    length_text = "" if length is None else f" len={length}"
    return f"{segment.get('start', 0)}-{end_text}{length_text}"


def _candidate_label(candidates: list[dict]) -> str:
    parts = []
    for candidate in candidates:
        parts.append(
            f"{candidate.get('format') or '?'}:{candidate.get('status') or '?'}@{_confidence_label(candidate.get('confidence'))}"
        )
    return ", ".join(parts)


def _confidence_label(value) -> str:
    try:
        return f"{float(value or 0.0):.2f}"
    except (TypeError, ValueError):
        return "0.00"


def _dedupe(values: list[str]) -> list[str]:
    result = []
    seen = set()
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result
