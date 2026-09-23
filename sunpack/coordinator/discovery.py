"""Compose the filesystem, relation, format, and embedded stages."""

from sunpack.contracts.discovery import StageResult, candidate_paths
from sunpack.contracts.detection import FactBag
from sunpack.detection.confirmation import FormatConfirmation
from sunpack.detection.scheduler import DetectionScheduler
from sunpack.embedded.discovery import EmbeddedDiscovery
from sunpack.embedded.options import EmbeddedOptions
from sunpack.relations.resolver import RelationResolver


class ArchiveDiscoveryPipeline:
    def __init__(self, config: dict, detector: DetectionScheduler, options: EmbeddedOptions):
        self.config = config
        self.relations = RelationResolver()
        self.detection = FormatConfirmation(detector)
        self.embedded = EmbeddedDiscovery(config, options)

    def discover(
        self, bags: list[FactBag], *, scan_session=None, is_recursive_scan: bool = False,
    ) -> tuple[StageResult, list]:
        relations = [bag for bag in bags if bag.get("filesystem.route") == "relations"]
        formats = [bag for bag in bags if bag.get("filesystem.route") == "detection"]
        residual = [bag for bag in bags if bag.get("filesystem.route") == "residual"]

        relation_result, relation_decisions = self.relations.resolve(relations)
        claimed = set(relation_result.claimed_paths)
        blocked = set(relation_result.blocked_paths)

        if self.config.get("detection", {}).get("enabled", True):
            eligible = [bag for bag in formats if not candidate_paths(bag) & (claimed | blocked)]
            format_result, format_decisions = self.detection.confirm(eligible, scan_session=scan_session)
        else:
            format_result, format_decisions = StageResult(), []
            residual.extend(formats)

        claimed.update(format_result.claimed_paths)
        blocked.update(format_result.blocked_paths)
        residual.extend(bag for bag in relations if candidate_paths(bag) & relation_result.residual_paths)
        residual.extend(bag for bag in formats if candidate_paths(bag) & format_result.residual_paths)
        unclaimed = []
        seen_ids = set()
        for bag in residual:
            if id(bag) not in seen_ids and not candidate_paths(bag) & (claimed | blocked):
                unclaimed.append(bag)
                seen_ids.add(id(bag))
        embedded_result, embedded_decisions = self.embedded.discover(
            unclaimed, is_recursive_scan=is_recursive_scan,
        )
        result = StageResult(
            resolved_inputs=[
                *relation_result.resolved_inputs,
                *format_result.resolved_inputs,
                *embedded_result.resolved_inputs,
            ],
            claimed_paths=claimed | embedded_result.claimed_paths,
            blocked_paths=blocked | embedded_result.blocked_paths,
            residual_paths=embedded_result.residual_paths,
        )
        result.validate()
        return result, [*relation_decisions, *format_decisions, *embedded_decisions]
