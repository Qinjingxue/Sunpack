from sunpack.analysis.structure_pipeline.module import AnalysisModuleSpec
from sunpack.analysis.structure_pipeline.registry import register_analysis_module
from sunpack.analysis.structure_pipeline.modules._read_fault import read_fault_damage_flags
from sunpack.analysis.result import ArchiveFormatEvidence, ArchiveSegment
from sunpack.analysis.structure_pipeline.modules._combine import combine_format_candidates
from sunpack.analysis.probes.zip import ZipEocdProbeOptions, probe_zip_eocd_view


class ZipAnalysisModule:
    spec = AnalysisModuleSpec(name="zip", formats=("zip",), signatures=(b"PK\x03\x04", b"PK\x05\x06"), io_profile="tail_heavy")

    def analyze(self, view, prepass: dict, config: dict) -> ArchiveFormatEvidence:
        hits = [hit for hit in prepass.get("hits", []) if str(hit.get("name", "")).startswith("zip_")]
        embedded = [
            item for item in prepass.get("embedded_candidates", [])
            if item.get("format") == "zip"
        ]
        if not hits and not embedded:
            return ArchiveFormatEvidence(format="zip", confidence=0.0, status="not_found")

        logical = [item for item in embedded if item["candidate_kind"] == "logical_archive"]
        evidences = [self._from_embedded_candidate(view, item, logical) for item in logical]
        if evidences:
            return combine_format_candidates("zip", evidences, preserve_multiple=True)
        max_entries = int(config.get("max_cd_entries_to_walk", 64) or 64)
        eocd_hits = [int(hit["offset"]) for hit in hits if hit.get("name") == "zip_eocd"]
        for eocd_offset in sorted(eocd_hits, reverse=True):
            native = probe_zip_eocd_view(
                view,
                ZipEocdProbeOptions(
                    max_cd_entries_to_walk=max_entries,
                    eocd_offset=eocd_offset,
                ),
            ).to_raw_dict()
            if not native or not (native.get("magic_matched") or native.get("plausible")):
                continue
            native = dict(native)
            recovered = self._local_header_recovery(view, native, hits, prepass)
            if recovered:
                evidences.append(recovered)
            else:
                evidences.append(self._from_native(view, native, hits, prepass))
        known_starts = {segment.start_offset for evidence in evidences for segment in evidence.segments}
        for item in embedded:
            if item.get("format") == "zip" and "local_header" in str(item.get("validation") or ""):
                start = int(item.get("offset") or 0)
                if start in known_starts:
                    continue
                evidences.append(ArchiveFormatEvidence(
                    format="zip", confidence=0.70, status="damaged",
                    segments=[ArchiveSegment(start_offset=start, end_offset=None, confidence=0.70,
                                             damage_flags=["central_directory_unavailable"],
                                             evidence=["zip:validated_local_header"])],
                    details={"boundary_confidence": "low"},
                ))
        return combine_format_candidates("zip", evidences, preserve_multiple=prepass.get("source") == "embedded_scan")

    def _from_embedded_candidate(self, view, item: dict, candidates: list[dict]) -> ArchiveFormatEvidence:
        start = int(item.get("offset") or 0)
        del candidates
        explicit_end = item.get("end_offset")
        range_end = item.get("range_end_offset")
        end = int(explicit_end) if explicit_end is not None else (
            int(range_end) if range_end is not None else None
        )
        confidence = float(item.get("confidence") or 0.0)
        validation = str(item.get("validation") or "validated_structure")
        boundary_kind = str(item["boundary_kind"])
        extractable = bool(item["extractable"]) and end is not None and end > start
        status = "extractable" if confidence >= 0.85 and extractable else "damaged"
        return ArchiveFormatEvidence(
            format="zip",
            confidence=confidence,
            status=status,
            segments=[ArchiveSegment(
                start_offset=start,
                end_offset=end if end is not None and end > start else None,
                confidence=confidence,
                evidence=[f"zip:{validation}", "embedded_scan:validated_candidate"],
            )],
            details={
                "source": "embedded_scan",
                "validation": validation,
                "boundary_kind": boundary_kind,
                "boundary_confidence": "high" if boundary_kind == "exact" else "bounded_or_unresolved",
            },
        )

    def _from_native(self, view, native: dict, hits: list[dict], prepass: dict) -> ArchiveFormatEvidence:
        if not native.get("magic_matched") and not hits:
            return ArchiveFormatEvidence(format="zip", confidence=0.0, status="not_found", details=native)

        archive_offset = int(native.get("archive_offset") or 0)
        eocd_offset = int(native.get("eocd_offset") or 0)
        comment_length = int(native.get("comment_length") or 0)
        end_offset = eocd_offset + 22 + comment_length if eocd_offset else None
        evidence = list(native.get("evidence") or [])
        if native.get("central_directory_present"):
            evidence.append("zip:central_directory")
        if native.get("central_directory_walk_ok"):
            evidence.append("zip:central_directory_walk")
        if native.get("local_header_links_ok"):
            evidence.append("zip:local_header_links")

        plausible = bool(native.get("plausible"))
        walk_ok = bool(native.get("central_directory_walk_ok")) and bool(native.get("local_header_links_ok"))
        if plausible and walk_ok:
            status = "extractable"
            confidence = 0.99
        elif plausible:
            status = "damaged"
            confidence = 0.65
        else:
            status = "weak"
            confidence = 0.35 if hits else 0.0

        damage_flags = read_fault_damage_flags(native)
        error = native.get("error") or ""
        if error:
            damage_flags.append(str(error))
        crc_warning = str(native.get("content_integrity_warning") or "")
        if crc_warning:
            damage_flags.append("content_integrity_bad_or_unknown")
            native["integrity_confidence"] = "low"
            native["content_damage_reason"] = crc_warning
            confidence = min(confidence, 0.90)
        else:
            native.setdefault("integrity_confidence", "unknown" if not plausible else "medium")
        native.setdefault("boundary_confidence", "high" if plausible and walk_ok else "low")
        segment_end = min(end_offset, int(view.size)) if end_offset is not None else None
        return ArchiveFormatEvidence(
            format="zip",
            confidence=confidence,
            status=status,
            segments=[
                ArchiveSegment(
                    start_offset=archive_offset,
                    end_offset=segment_end,
                    confidence=confidence,
                    damage_flags=damage_flags,
                    evidence=evidence or ["zip:eocd" if native.get("magic_matched") else "zip:signature"],
                )
            ] if confidence > 0 else [],
            warnings=[],
            details=native,
        )

    def _local_header_recovery(self, view, native: dict, hits: list[dict], prepass: dict) -> ArchiveFormatEvidence | None:
        error = str(native.get("error") or "")
        if error not in {"bad_central_directory_signature", "archive_offset_underflow", "central_directory_size_out_of_range"}:
            return None
        local_hits = [int(hit["offset"]) for hit in hits if hit.get("name") == "zip_local"]
        if not local_hits:
            return None
        start = min(local_hits)
        details = {
            **native,
            "boundary_confidence": "low",
            "integrity_confidence": "unknown",
            "directory_confidence": "low",
        }
        evidence = ["zip:local_header"]
        damage_flags = ["central_directory_unreliable", "local_header_recovery"]
        return ArchiveFormatEvidence(
            format="zip",
            confidence=0.70,
            status="damaged",
            segments=[
                ArchiveSegment(
                    start_offset=start,
                    end_offset=None,
                    confidence=0.70,
                    damage_flags=damage_flags,
                    evidence=evidence,
                )
            ],
            warnings=["zip central directory is damaged; recovered candidate from local headers"],
            details=details,
        )



register_analysis_module(ZipAnalysisModule())
