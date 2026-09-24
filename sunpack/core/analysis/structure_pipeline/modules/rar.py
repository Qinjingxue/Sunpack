from sunpack.core.analysis.structure_pipeline.module import AnalysisModuleSpec
from sunpack.core.analysis.structure_pipeline.registry import register_analysis_module
from sunpack.core.analysis.structure_pipeline.modules._read_fault import read_fault_damage_flags
from sunpack.core.analysis.result import ArchiveFormatEvidence, ArchiveSegment
from sunpack.core.analysis.structure_pipeline.modules._combine import combine_format_candidates
from sunpack.core.analysis.probes.rar import RarProbeOptions, probe_rar_view


class RarAnalysisModule:
    spec = AnalysisModuleSpec(
        name="rar",
        formats=("rar",),
        signatures=(b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01\x00"),
    )

    def analyze(self, view, prepass: dict, config: dict) -> ArchiveFormatEvidence:
        hits = [
            hit
            for hit in prepass.get("hits", [])
            if str(hit.get("name", "")).startswith("rar")
        ]
        embedded = [
            item
            for item in prepass.get("embedded_candidates", [])
            if item.get("format") == "rar"
            and item.get("candidate_kind") == "logical_archive"
        ]
        if not hits and not embedded:
            return ArchiveFormatEvidence(format="rar", confidence=0.0, status="not_found")

        candidates = []
        exact_starts = set()
        for item in embedded:
            start = int(item.get("offset") or 0)
            end = item.get("end_offset")
            if (
                end is None
                or item.get("boundary_kind") != "exact"
                or not item.get("extractable")
            ):
                continue
            exact_starts.add(start)
            confidence = float(item.get("confidence") or 0.0)
            candidates.append(ArchiveFormatEvidence(
                format="rar",
                confidence=confidence,
                status="extractable",
                segments=[ArchiveSegment(
                    start_offset=start,
                    end_offset=int(end),
                    confidence=confidence,
                    evidence=[f"rar:{item.get('validation') or 'complete_header_walk'}"],
                )],
                details={
                    "source": "embedded_scan",
                    "candidate": item,
                    "boundary_kind": "exact",
                    "boundary_confidence": "high",
                    "integrity_confidence": "deferred",
                },
            ))

        starts = {
            int(item.get("offset") or 0)
            for item in embedded
        } or {int(hit["offset"]) for hit in hits}
        for start in sorted(starts - exact_starts):
            observation = probe_rar_view(
                view,
                RarProbeOptions(
                    start_offset=start,
                    max_blocks_to_walk=int(
                        config.get("max_blocks_to_walk", 4096) or 4096
                    ),
                ),
            )
            candidates.append(self._from_native(
                observation.to_raw_dict(),
                start,
            ))
        return combine_format_candidates(
            "rar",
            candidates,
            preserve_multiple=prepass.get("source") == "embedded_scan",
        )

    def _from_native(self, native: dict, start: int) -> ArchiveFormatEvidence:
        if not native.get("magic_matched"):
            return ArchiveFormatEvidence(
                format="rar",
                confidence=0.0,
                status="not_found",
                details=native,
            )
        evidence = list(native.get("evidence") or ["rar:signature"])
        strong = bool(native.get("strong_accept"))
        plausible = bool(native.get("plausible"))
        error = str(native.get("error") or "")
        taxonomy = self._classify_damage(native)
        segment_end = int(native.get("segment_end") or 0) or None

        if strong and segment_end is not None:
            status = "extractable"
            confidence = 0.97
        elif taxonomy == "probably_truncated":
            status = "damaged"
            confidence = 0.82
            segment_end = None
        elif taxonomy == "valid_encrypted_but_unwalkable":
            status = "damaged"
            confidence = 0.72
            segment_end = None
        elif plausible:
            status = "damaged"
            confidence = 0.65
            segment_end = None
        else:
            status = "weak"
            confidence = 0.35
            segment_end = None

        damage_flags = read_fault_damage_flags(native)
        if error:
            damage_flags.append(error)
        if taxonomy:
            damage_flags.append(taxonomy)
        native.setdefault(
            "boundary_confidence",
            "high" if strong and segment_end is not None else "none",
        )
        native.setdefault("integrity_confidence", "unknown")
        if taxonomy == "valid_encrypted_but_unwalkable":
            native["password_required"] = True
            native["header_encrypted"] = True

        return ArchiveFormatEvidence(
            format="rar",
            confidence=confidence,
            status=status,
            segments=[ArchiveSegment(
                start_offset=start,
                end_offset=segment_end,
                confidence=confidence,
                damage_flags=damage_flags,
                evidence=evidence,
            )],
            warnings=[] if status == "extractable" else self._warnings_for_taxonomy(taxonomy),
            details=native,
        )

    @staticmethod
    def _classify_damage(native: dict) -> str:
        error = str(native.get("error") or "")
        blocks_checked = int(native.get("blocks_checked") or 0)
        if "probably_truncated" in (native.get("damage_flags") or []) and blocks_checked > 0:
            return "probably_truncated"
        if error in {"rar5_main_header_missing", "rar4_main_header_missing"}:
            return "valid_encrypted_but_unwalkable"
        return ""

    @staticmethod
    def _warnings_for_taxonomy(taxonomy: str) -> list[str]:
        if taxonomy == "probably_truncated":
            return ["rar block chain is incomplete; archive is probably truncated"]
        if taxonomy == "valid_encrypted_but_unwalkable":
            return ["rar header is encrypted; password is required before exact boundary resolution"]
        return ["rar archive structure does not prove an exact end for this segment"]


register_analysis_module(RarAnalysisModule())
