"""Resolve RAR, 7z and ZIP physical families into logical inputs."""

from sunpack.contracts.discovery import (
    DiscoveryCandidate,
    ResolvedArchiveInput,
    StageResult,
    candidate_paths,
)
from sunpack.contracts.rules import RuleDecision
from sunpack.detection.scheduler import DetectionResult


_FORMATS = {"rar", "7z", "zip"}


class RelationResolver:
    def resolve(
        self,
        candidates: list[DiscoveryCandidate],
    ) -> tuple[StageResult, list[DetectionResult]]:
        result = StageResult()
        decisions: list[DetectionResult] = []
        for candidate in candidates:
            anchor = candidate.relation_anchor
            archive_format = str(anchor.get("format") or candidate.format_hint or "").lower().lstrip(".")
            paths = candidate_paths(candidate)
            if not anchor.get("relation_confirmed") and (
                anchor.get("needs_password") or anchor.get("multivolume")
            ):
                result.blocked_paths.update(paths)
                continue
            if (
                anchor.get("relation_confirmed")
                and archive_format in _FORMATS
                and candidate.archive_input is not None
            ):
                reason = "Relations confirmed native archive identity"
                resolved = ResolvedArchiveInput.from_candidate(
                    candidate,
                    "relations",
                    dict(anchor),
                    archive_input=candidate.archive_input,
                    confidence=1.0 if str(anchor.get("confidence") or "") == "strong" else 0.8,
                    reasons=(reason,),
                )
                result.add_resolved(resolved)
                decisions.append(DetectionResult(
                    candidate,
                    RuleDecision(
                        should_extract=True,
                        matched_rules=["relations"],
                        decision="archive",
                        stop_reason=reason,
                        decision_stage="relations",
                        deciding_rule="relations",
                    ),
                    archive_format,
                    resolved,
                ))
            else:
                result.residual_paths.update(paths)
        result.residual_paths.difference_update(result.claimed_paths | result.blocked_paths)
        result.validate()
        return result, decisions
