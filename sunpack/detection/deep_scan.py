from __future__ import annotations

from sunpack.contracts.detection import FactBag
from sunpack.contracts.rules import RuleDecision
from sunpack.coordinator.nested_extraction_policy import EMBEDDED_SCAN_ALLOWED_FACT
from sunpack.support.global_cache_manager import file_identity


DEEP_SCAN_RULE = "deep_full_stream_scan"


def evaluate_deep_bag(fact_bag: FactBag) -> RuleDecision:
    from sunpack.analysis import scan_embedded_archives

    if not bool(fact_bag.get(EMBEDDED_SCAN_ALLOWED_FACT)):
        return _decision(False, "Embedded scan is not authorized by the recursive scan policy")

    path = str(fact_bag.get("file.path") or fact_bag.get("candidate.entry_path") or "")
    if not path:
        return _decision(False, "Deep full-stream scan has no input path")

    try:
        identity = file_identity(path)
        file_size = int(identity[1])
        result = scan_embedded_archives(path, expected_size=file_size, identity=identity)
    except OSError as exc:
        return _decision(False, f"Deep full-stream scan failed: {exc}")

    fact_bag.set("file.path", path)
    fact_bag.set("file.size", file_size)
    fact_bag.set("embedded_archive.analysis", result.to_dict())
    fact_bag.set("analysis.signature_prepass", result.to_prepass())
    if not result.candidates:
        return _decision(False, "Deep full-stream scan found no structurally valid archive candidates")

    primary = result.candidates[0]
    fact_bag.set("file.probe_detected_archive", True)
    fact_bag.set("file.probe_offset", primary.offset)
    fact_bag.set("file.detected_ext", primary.detected_ext)
    fact_bag.set("file.embedded_archive_found", any(item.offset > 0 for item in result.candidates))
    count = len(result.candidates)
    return _decision(True, f"Deep full-stream scan found {count} structurally valid archive candidate(s)")


def _decision(should_extract: bool, reason: str) -> RuleDecision:
    return RuleDecision(
        should_extract=should_extract,
        matched_rules=[DEEP_SCAN_RULE] if should_extract else [],
        stop_reason=reason,
        decision="archive" if should_extract else "not_archive",
        decision_stage="deep_detection",
        discarded_at=None if should_extract else "deep_detection",
        deciding_rule=DEEP_SCAN_RULE,
    )
