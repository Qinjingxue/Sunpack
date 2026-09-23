from sunpack.analysis.structure_pipeline.module import AnalysisModuleSpec
from sunpack.analysis.structure_pipeline.registry import register_analysis_module
from sunpack.analysis.structure_pipeline.modules._read_fault import read_fault_damage_flags
from sunpack.analysis.result import ArchiveFormatEvidence, ArchiveSegment
from sunpack.analysis.structure_pipeline.modules._combine import combine_format_candidates
from sunpack.analysis.probes.rar import RarProbeOptions, probe_rar_view


class RarAnalysisModule:
    spec = AnalysisModuleSpec(name="rar", formats=("rar",), signatures=(b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01\x00"))

    def analyze(self, view, prepass: dict, config: dict) -> ArchiveFormatEvidence:
        hits = [hit for hit in prepass.get("hits", []) if str(hit.get("name", "")).startswith("rar")]
        embedded = [
            item for item in prepass.get("embedded_candidates", [])
            if item.get("format") == "rar"
            and item["candidate_kind"] == "logical_archive"
        ]
        if not hits and not embedded:
            return ArchiveFormatEvidence(format="rar", confidence=0.0, status="not_found")
        candidates = []
        exact_starts = set()
        bounded_ends: dict[int, int] = {}
        for item in embedded:
            start = int(item.get("offset") or 0)
            end = item.get("end_offset")
            # A validated logical candidate whose own end is unknowable still carries the
            # scanner-resolved upper bound for its bytes.  That bound comes from verified
            # logical archive starts (or EOF), so it is the only admissible fallback when
            # the archive structure cannot prove its own exact end.
            bounded_end = int(item.get("range_end_offset") or 0)
            if bounded_end > start:
                bounded_ends[start] = bounded_end
            if end is None or item["boundary_kind"] != "exact":
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
                    evidence=[f"rar:{item.get('validation') or 'complete_block_walk'}"],
                )],
                details={
                    "source": "embedded_scan",
                    "candidate": item,
                    "boundary_kind": "exact",
                    "boundary_confidence": "high",
                },
            ))
        starts = {
            int(item.get("offset") or 0) for item in embedded
        } or {int(hit["offset"]) for hit in hits}
        for start in sorted(starts - exact_starts):
            observation = probe_rar_view(
                view,
                RarProbeOptions(
                    start_offset=start,
                    max_blocks_to_walk=int(config.get("max_blocks_to_walk", 4096) or 4096),
                ),
            )
            candidates.append(self._from_native(
                observation.to_raw_dict(),
                start,
                bounded_ends.get(start, view.size),
                prepass,
                view.size,
            ))
        return combine_format_candidates("rar", candidates, preserve_multiple=prepass.get("source") == "embedded_scan")

    def _from_native(self, native: dict, start: int, fallback_end: int, prepass: dict, file_size: int) -> ArchiveFormatEvidence:
        if not native.get("magic_matched"):
            return ArchiveFormatEvidence(format="rar", confidence=0.0, status="not_found", details=native)
        evidence = list(native.get("evidence") or ["rar:signature"])
        strong = bool(native.get("strong_accept"))
        plausible = bool(native.get("plausible"))
        error = str(native.get("error") or "")
        taxonomy = self._classify_damage(native)
        segment_end = int(native.get("segment_end") or 0) or fallback_end
        if strong:
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
        else:
            status = "weak"
            confidence = 0.35
        damage_flags = read_fault_damage_flags(native)
        if error:
            damage_flags.append(str(error))
        if taxonomy:
            damage_flags.append(taxonomy)
        native.setdefault("boundary_confidence", "high" if strong else ("low" if taxonomy else "unknown"))
        native.setdefault("integrity_confidence", "unknown")
        if taxonomy == "probably_truncated":
            native["boundary_confidence"] = "low"
        elif taxonomy == "valid_encrypted_but_unwalkable":
            native["boundary_confidence"] = "low"
            native["password_required"] = True
            native["header_encrypted"] = True
        return ArchiveFormatEvidence(
            format="rar",
            confidence=confidence,
            status=status,
            segments=[ArchiveSegment(start_offset=start, end_offset=segment_end, confidence=confidence, damage_flags=damage_flags, evidence=evidence)],
            warnings=[] if strong else self._warnings_for_taxonomy(taxonomy),
            details=native,
        )

    def _classify_damage(self, native: dict) -> str:
        error = str(native.get("error") or "")
        blocks_checked = int(native.get("blocks_checked") or 0)
        if "probably_truncated" in (native.get("damage_flags") or []) and blocks_checked > 0:
            return "probably_truncated"
        if error in {"rar5_main_header_missing", "rar4_main_header_missing"}:
            return "valid_encrypted_but_unwalkable"
        return ""

    def _warnings_for_taxonomy(self, taxonomy: str) -> list[str]:
        if taxonomy == "probably_truncated":
            return ["rar block chain is incomplete; archive is probably truncated"]
        if taxonomy == "valid_encrypted_but_unwalkable":
            return ["rar header appears encrypted or unreadable; password is required before boundary walk"]
        return ["rar archive structure does not prove an exact end; segment is bounded by the enclosing input"]


register_analysis_module(RarAnalysisModule())
