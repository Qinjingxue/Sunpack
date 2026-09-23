"""Resolve RAR, 7z and ZIP physical families into logical inputs."""

from sunpack.contracts.discovery import ResolvedArchiveInput, StageResult, candidate_paths
from sunpack.contracts.detection import FactBag
from sunpack.contracts.rules import RuleDecision
from sunpack.detection.scheduler import DetectionResult


_FORMATS = {"rar": ".rar", "7z": ".7z", "zip": ".zip"}


class RelationResolver:
    def resolve(self, bags: list[FactBag]) -> tuple[StageResult, list[DetectionResult]]:
        result = StageResult()
        decisions = []
        for bag in bags:
            anchor = bag.get("relation.volume_anchor") or {}
            archive_format = str(anchor.get("format") or "").lower().lstrip(".")
            paths = candidate_paths(bag)
            if not anchor.get("relation_confirmed") and (
                anchor.get("needs_password") or anchor.get("multivolume")
            ):
                result.blocked_paths.update(paths)
                continue
            if anchor.get("relation_confirmed") and archive_format in _FORMATS:
                offset = int(anchor.get("structure_offset") or 0)
                bag.set("file.detected_ext", _FORMATS[archive_format])
                bag.set("file.probe_detected_archive", True)
                bag.set("file.probe_offset", offset)
                bag.set("file.magic_matched", offset == 0)
                bag.set("file.embedded_archive_found", offset > 0)
                if anchor.get("sfx") and anchor.get("pe_structure"):
                    bag.set("file.container_type", "pe")
                result.add_resolved(ResolvedArchiveInput.from_bag(bag, "relations", dict(anchor)))
                decisions.append(DetectionResult(bag, RuleDecision(
                    should_extract=True, matched_rules=["relations"],
                    decision="archive", stop_reason="Relations confirmed native archive identity",
                )))
            else:
                result.residual_paths.update(paths)
        result.residual_paths.difference_update(result.claimed_paths | result.blocked_paths)
        result.validate()
        return result, decisions
