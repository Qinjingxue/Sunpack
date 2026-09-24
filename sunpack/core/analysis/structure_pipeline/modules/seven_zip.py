from sunpack.core.analysis.structure_pipeline.module import AnalysisModuleSpec
from sunpack.core.analysis.structure_pipeline.registry import register_analysis_module
from sunpack.core.analysis.structure_pipeline.modules._read_fault import read_fault_damage_flags
from sunpack.core.analysis.result import ArchiveFormatEvidence, ArchiveSegment
from sunpack.core.analysis.structure_pipeline.modules._combine import combine_format_candidates
from sunpack.core.analysis.probes.seven_zip import SevenZipProbeOptions, probe_seven_zip_view


class SevenZipAnalysisModule:
    spec = AnalysisModuleSpec(name="seven_zip", formats=("7z",), signatures=(b"7z\xbc\xaf\x27\x1c",))

    def analyze(self, view, prepass: dict, config: dict) -> ArchiveFormatEvidence:
        embedded = [
            item for item in prepass.get("embedded_candidates", [])
            if item.get("format") == "7z"
            and item.get("candidate_kind") == "logical_archive"
        ]
        exact = [
            item for item in embedded
            if item.get("boundary_kind") == "exact"
            and item.get("end_offset") is not None
            and item.get("extractable")
        ]
        if exact:
            candidates = [self._from_embedded(item) for item in exact]
            return combine_format_candidates("7z", candidates, preserve_multiple=True)

        hits = [hit for hit in prepass.get("hits", []) if hit.get("name") == "7z"]
        if not hits:
            return ArchiveFormatEvidence(format="7z", confidence=0.0, status="not_found")
        candidates = []
        for start in sorted({int(hit["offset"]) for hit in hits}):
            observation = probe_seven_zip_view(
                view,
                SevenZipProbeOptions(
                    start_offset=start,
                    max_next_header_check_bytes=int(
                        config.get("max_next_header_check_bytes", 1024 * 1024)
                        or 1024 * 1024
                    ),
                ),
            )
            candidates.append(self._from_native(observation.to_raw_dict(), start))
        return combine_format_candidates(
            "7z",
            candidates,
            preserve_multiple=prepass.get("source") == "embedded_scan",
        )

    @staticmethod
    def _from_embedded(item: dict) -> ArchiveFormatEvidence:
        start = int(item.get("offset") or 0)
        end = int(item["end_offset"])
        confidence = float(item.get("confidence") or 0.0)
        validation = str(item.get("validation") or "start_header_crc_and_declared_end")
        return ArchiveFormatEvidence(
            format="7z",
            confidence=confidence,
            status="extractable",
            segments=[
                ArchiveSegment(
                    start_offset=start,
                    end_offset=end,
                    confidence=confidence,
                    evidence=[f"7z:{validation}", "embedded_scan:exact_boundary"],
                )
            ],
            details={
                "source": "embedded_scan",
                "validation": validation,
                "candidate_kind": "logical_archive",
                "boundary_kind": "exact",
                "boundary_confidence": "high",
                "integrity_confidence": "deferred",
            },
        )

    @staticmethod
    def _from_native(native: dict, start: int) -> ArchiveFormatEvidence:
        if not native.get("magic_matched"):
            return ArchiveFormatEvidence(
                format="7z",
                confidence=0.0,
                status="not_found",
                details=native,
            )
        evidence = list(native.get("evidence") or ["7z:signature"])
        strong = bool(native.get("strong_accept"))
        plausible = bool(native.get("plausible"))
        if strong:
            status = "extractable"
            confidence = 0.97
        elif plausible:
            status = "damaged"
            confidence = 0.65
        else:
            status = "weak"
            confidence = 0.35

        damage_flags = read_fault_damage_flags(native)
        error = str(native.get("error") or "")
        if error:
            damage_flags.append(error)
        boundary_unreliable = error in {
            "start_header_crc_mismatch",
            "next_header_out_of_range",
            "invalid_next_header_range",
        }
        if boundary_unreliable:
            damage_flags.append("boundary_unreliable")
            native["boundary_confidence"] = "none"
        elif native.get("next_header_crc_checked") and not native.get("next_header_crc_ok"):
            damage_flags.append("directory_integrity_bad_or_unknown")
            native["boundary_confidence"] = "medium"
            native["integrity_confidence"] = "low"
        else:
            native.setdefault("boundary_confidence", "high" if strong else "medium")
            native.setdefault("integrity_confidence", "medium" if strong else "unknown")

        next_header_offset = int(native.get("next_header_offset") or 0)
        next_header_size = int(native.get("next_header_size") or 0)
        end_offset = int(native.get("segment_end") or 0) or (
            start + 32 + next_header_offset + next_header_size
            if next_header_size
            else None
        )
        if boundary_unreliable:
            end_offset = None
        return ArchiveFormatEvidence(
            format="7z",
            confidence=confidence,
            status=status,
            segments=[
                ArchiveSegment(
                    start_offset=start,
                    end_offset=end_offset,
                    confidence=confidence,
                    damage_flags=damage_flags,
                    evidence=evidence,
                )
            ],
            warnings=[] if end_offset else ["7z archive structure does not prove an exact end for this segment"],
            details=native,
        )


register_analysis_module(SevenZipAnalysisModule())
