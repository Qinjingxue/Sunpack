"""Compose the filesystem, relation, format, and embedded stages."""

from sunpack.contracts.discovery import DiscoveryCandidate, StageResult, candidate_paths
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
        self,
        candidates: list[DiscoveryCandidate],
        *,
        scan_session=None,
        is_recursive_scan: bool = False,
    ) -> tuple[StageResult, list]:
        relations = [item for item in candidates if item.route == "relations"]
        formats = [item for item in candidates if item.route == "detection"]
        residual = [item for item in candidates if item.route == "residual"]

        relation_result, relation_decisions = self.relations.resolve(relations)
        claimed = set(relation_result.claimed_paths)
        blocked = set(relation_result.blocked_paths)

        if self.config.get("detection", {}).get("enabled", True):
            eligible = [
                item
                for item in formats
                if not candidate_paths(item) & (claimed | blocked)
            ]
            format_result, format_decisions = self.detection.confirm(
                eligible,
                scan_session=scan_session,
            )
        else:
            format_result, format_decisions = StageResult(), []
            residual.extend(formats)

        claimed.update(format_result.claimed_paths)
        blocked.update(format_result.blocked_paths)
        residual.extend(
            item
            for item in relations
            if candidate_paths(item) & relation_result.residual_paths
        )
        residual.extend(
            item
            for item in formats
            if candidate_paths(item) & format_result.residual_paths
        )

        unclaimed: list[DiscoveryCandidate] = []
        seen_ids: set[int] = set()
        for item in residual:
            if id(item) in seen_ids or candidate_paths(item) & (claimed | blocked):
                continue
            unclaimed.append(item)
            seen_ids.add(id(item))

        embedded_result, embedded_decisions = self.embedded.discover(
            unclaimed,
            is_recursive_scan=is_recursive_scan,
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
        return result, [
            *relation_decisions,
            *format_decisions,
            *embedded_decisions,
        ]
