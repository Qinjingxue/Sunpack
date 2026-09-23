"""Resolve RAR, 7z and ZIP physical families into logical inputs."""

from sunpack.core.contracts.discovery import (
    DiscoveryCandidate,
    ResolvedArchiveInput,
    StageResult,
)


_FORMATS = {"rar", "7z", "zip"}


class RelationResolver:
    def resolve(self, candidates: list[DiscoveryCandidate]) -> StageResult:
        result = StageResult()
        for candidate in candidates:
            anchor = candidate.relation_anchor
            archive_format = str(anchor.get("format") or candidate.format_hint or "").lower().lstrip(".")
            if not anchor.get("relation_confirmed") and (
                anchor.get("needs_password") or anchor.get("multivolume")
            ):
                result.add_blocked(
                    candidate,
                    source="relations",
                    reason="Relations requires password or additional volume evidence",
                )
                continue

            if (
                anchor.get("relation_confirmed")
                and archive_format in _FORMATS
                and candidate.archive_input is not None
            ):
                result.add_resolved(
                    ResolvedArchiveInput(
                        archive_input=candidate.archive_input,
                        source="relations",
                        carrier_path=candidate.carrier_path,
                        cleanup_paths=candidate.cleanup_paths,
                        evidence=dict(anchor),
                    ),
                    reason="Relations confirmed native archive identity",
                )
                continue

            result.add_residual(candidate, source="relations")

        result.residual_paths.difference_update(result.claimed_paths | result.blocked_paths)
        result.validate()
        return result
