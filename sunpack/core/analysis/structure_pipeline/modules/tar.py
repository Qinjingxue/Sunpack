from sunpack.core.analysis.structure_pipeline.module import AnalysisModuleSpec
from sunpack.core.analysis.structure_pipeline.modules._read_fault import read_fault_damage_flags
from sunpack.core.analysis.structure_pipeline.registry import register_analysis_module
from sunpack.core.analysis.result import ArchiveFormatEvidence, ArchiveSegment
from sunpack.core.analysis.structure_pipeline.modules._combine import combine_format_candidates
from sunpack.core.analysis.probes.tar import TarProbeOptions, probe_tar_view


class TarAnalysisModule:
    spec = AnalysisModuleSpec(name="tar", formats=("tar",), signatures=(b"ustar",), io_profile="head_heavy")

    def analyze(self, view, prepass: dict, config: dict) -> ArchiveFormatEvidence:
        embedded = [
            item for item in prepass.get("embedded_candidates", [])
            if item.get("format") == "tar"
            and item["candidate_kind"] == "logical_archive"
        ]
        if embedded:
            candidates = []
            for item in embedded:
                start = int(item.get("offset") or 0)
                end = item.get("end_offset")
                exact = (
                    end is not None
                    and item["boundary_kind"] == "exact"
                    and item["extractable"]
                )
                confidence = float(item.get("confidence") or 0.0)
                candidates.append(ArchiveFormatEvidence(
                    format="tar",
                    confidence=confidence if exact else min(confidence, 0.80),
                    status="extractable" if exact else "damaged",
                    segments=[ArchiveSegment(
                        start_offset=start,
                        end_offset=int(end) if end is not None else None,
                        confidence=confidence if exact else min(confidence, 0.80),
                        damage_flags=[] if exact else ["tar_boundary_unresolved"],
                        evidence=[f"tar:{item.get('validation') or 'validated_structure'}"],
                    )],
                    details={
                        "source": "embedded_scan",
                        "candidate": item,
                        "boundary_kind": item["boundary_kind"],
                    },
                ))
            return combine_format_candidates("tar", candidates, preserve_multiple=True)
        max_entries = int(config.get("max_entries_to_walk", 64) or 64)
        hit_starts = sorted(set(
            max(0, int(hit.get("offset") or 0) - 257)
            for hit in prepass.get("hits", [])
            if hit.get("name") == "tar_ustar"
        ))
        evidences: list[ArchiveFormatEvidence] = []

        # A valid archive at offset zero owns its member headers.  Treating
        # every member's ustar marker as another embedded archive was the root
        # cause of suffix-only extraction for archives larger than the walk
        # sample budget.
        primary = self._candidate(view, prepass, 0, max_entries)
        if primary is not None and primary.status == "extractable":
            return combine_format_candidates("tar", [primary], preserve_multiple=False)

        covered_until = 0
        if primary is not None:
            evidences.append(primary)
        for start in hit_starts:
            if start <= 0 or start < covered_until:
                continue
            candidate = self._candidate(view, prepass, start, max_entries)
            if candidate is None:
                continue
            evidences.append(candidate)
            segment = candidate.segments[0] if candidate.segments else None
            if segment is not None and segment.end_offset is not None:
                covered_until = max(covered_until, int(segment.end_offset))
            elif candidate.status == "extractable":
                # Without a proven end boundary, later ustar hits may simply be
                # members of this archive and cannot be emitted independently.
                break
        return combine_format_candidates("tar", evidences, preserve_multiple=prepass.get("source") == "embedded_scan")

    @staticmethod
    def _candidate(view, prepass: dict, start: int, max_entries: int) -> ArchiveFormatEvidence | None:
            result = probe_tar_view(
                view,
                TarProbeOptions(start_offset=start, max_entries_to_walk=max_entries),
            ).to_raw_dict()
            if result and result.get("plausible"):
                confidence = 0.94 if result.get("end_zero_blocks") else (0.90 if result.get("walk_complete") else 0.86)
                details = dict(result)
                evidence = list(result.get("evidence") or [])
                damage_flags = read_fault_damage_flags(result)
                return ArchiveFormatEvidence(
                    format="tar",
                    confidence=confidence,
                    status="extractable",
                    segments=[ArchiveSegment(start_offset=start, end_offset=result.get("segment_end"), confidence=confidence, damage_flags=damage_flags, evidence=evidence)],
                    details=details,
                )
            if result and result.get("magic_matched"):
                details = dict(result)
                damage_flags = read_fault_damage_flags(result) or ["tar_metadata_bad"]
                return ArchiveFormatEvidence(
                    format="tar", confidence=0.72, status="damaged",
                    segments=[ArchiveSegment(start_offset=start, end_offset=None, confidence=0.72,
                                             damage_flags=damage_flags, evidence=list(result.get("evidence") or ["tar:header"]))],
                    details={**details, "route_evidence_flags": damage_flags},
                )
            return None
register_analysis_module(TarAnalysisModule())
