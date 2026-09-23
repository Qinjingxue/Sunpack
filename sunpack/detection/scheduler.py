"""Single-file TAR and compression-stream confirmation."""

from dataclasses import dataclass
from typing import Any

from sunpack.analysis import ArchiveAnalyzer
from sunpack.contracts.detection import FactBag
from sunpack.contracts.rules import RuleDecision
from sunpack.detection.formats import CONFIRMERS


@dataclass(frozen=True)
class DetectionResult:
    fact_bag: FactBag
    decision: RuleDecision


class DetectionScheduler:
    def __init__(self, config: dict[str, Any]):
        self.config = config
        self.analyzer = ArchiveAnalyzer(config)

    def validate_config(self) -> list[str]:
        return []

    def evaluate_bag(self, fact_bag: FactBag, fact_provider=None) -> RuleDecision:
        if fact_provider is not None and not fact_bag.has("file.path"):
            fact_bag.set("file.path", fact_provider.base_path)
        return self.evaluate_pool([fact_bag])[fact_bag]

    def evaluate(self, fact_bag: FactBag, fact_provider=None) -> RuleDecision:
        return self.evaluate_bag(fact_bag, fact_provider)

    def evaluate_pool(self, fact_bags: list[FactBag], scan_session=None) -> dict[FactBag, RuleDecision]:
        return {bag: self._confirm(bag) for bag in fact_bags}

    def evaluate_bags(self, fact_bags: list[FactBag], scan_session=None) -> list[DetectionResult]:
        return [DetectionResult(bag, decision) for bag, decision in self.evaluate_pool(fact_bags, scan_session).items()]

    def evaluate_extractable_bags(self, fact_bags: list[FactBag], scan_session=None) -> list[DetectionResult]:
        return [result for result in self.evaluate_bags(fact_bags, scan_session) if result.decision.should_extract]

    def _confirm(self, bag: FactBag) -> RuleDecision:
        archive_format = str(bag.get("filesystem.format_hint") or "").lower()
        path = str(bag.get("candidate.entry_path") or bag.get("file.path") or "")
        confirmer = CONFIRMERS.get(archive_format)
        if not path or confirmer is None:
            return _not_archive()
        try:
            accepted = confirmer.confirm(path, self.analyzer)
        except (OSError, ValueError):
            return _not_archive()
        if not accepted:
            return _not_archive()
        bag.set("file.detected_ext", confirmer.EXTENSION)
        bag.set("file.probe_detected_archive", True)
        bag.set("file.probe_offset", 0)
        return RuleDecision(
            should_extract=True, matched_rules=["single_file_format"],
            stop_reason=f"Confirmed {archive_format} structure", decision="archive",
            decision_stage="detection", deciding_rule="single_file_format",
        )


def _not_archive() -> RuleDecision:
    return RuleDecision(False, [], decision="not_archive", decision_stage="detection")
