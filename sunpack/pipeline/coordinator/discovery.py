"""Compose filesystem routing, Relations, format confirmation, and embedded discovery."""

from sunpack.core.contracts.discovery import DiscoveryCandidate, StageResult
from sunpack.pipeline.discovery.detection.confirmation import FormatConfirmation
from sunpack.pipeline.discovery.detection.scheduler import DetectionScheduler
from sunpack.pipeline.discovery.embedded.discovery import EmbeddedDiscovery
from sunpack.pipeline.discovery.embedded.options import EmbeddedOptions
from sunpack.pipeline.discovery.relations.resolver import RelationResolver


class ArchiveDiscoveryPipeline:
    def __init__(self, config: dict, detector: DetectionScheduler, options: EmbeddedOptions):
        self.config = config
        self.relations = RelationResolver()
        self.detection = FormatConfirmation(detector)
        self.embedded = EmbeddedDiscovery(config, options)

    def discover(
        self,
        candidates: list[DiscoveryCandidate],
        *,
        is_recursive_scan: bool = False,
    ) -> StageResult:
        relations = [item for item in candidates if item.route == "relations"]
        formats = [item for item in candidates if item.route == "detection"]
        residual = [item for item in candidates if item.route == "residual"]

        relation_result = self.relations.resolve(relations)
        claimed = set(relation_result.claimed_paths)
        blocked = set(relation_result.blocked_paths)

        if self.config.get("detection", {}).get("enabled", True):
            eligible = [
                item
                for item in formats
                if not item.path_keys & (claimed | blocked)
            ]
            format_result = self.detection.confirm(eligible)
        else:
            format_result = StageResult()
            for item in formats:
                format_result.add_residual(
                    item,
                    source="detection",
                    reason="detection_disabled",
                )

        claimed.update(format_result.claimed_paths)
        blocked.update(format_result.blocked_paths)

        residual.extend(
            item
            for item in relations
            if item.path_keys & relation_result.residual_paths
        )
        residual.extend(
            item
            for item in formats
            if item.path_keys & format_result.residual_paths
        )

        unclaimed: list[DiscoveryCandidate] = []
        seen: set[int] = set()
        for item in residual:
            if id(item) in seen or item.path_keys & (claimed | blocked):
                continue
            seen.add(id(item))
            unclaimed.append(item)

        embedded_result = self.embedded.discover(
            unclaimed,
            is_recursive_scan=is_recursive_scan,
        )
        result = StageResult(
            resolved_tasks=[
                *relation_result.resolved_tasks,
                *format_result.resolved_tasks,
                *embedded_result.resolved_tasks,
            ],
            claimed_paths=claimed | embedded_result.claimed_paths,
            blocked_paths=blocked | embedded_result.blocked_paths,
            residual_paths=set(embedded_result.residual_paths),
            traces=[
                *relation_result.traces,
                *format_result.traces,
                *embedded_result.traces,
            ],
        )
        result.validate()
        return result
