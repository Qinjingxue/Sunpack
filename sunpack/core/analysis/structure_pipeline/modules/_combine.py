from sunpack.core.analysis.result import ArchiveFormatEvidence


_STATUS_RANK = {"not_found": 0, "error": 1, "weak": 2, "damaged": 3, "extractable": 4}


def combine_format_candidates(
    fmt: str,
    candidates: list[ArchiveFormatEvidence],
    *,
    preserve_multiple: bool = True,
) -> ArchiveFormatEvidence:
    """Preserve every distinct segment while retaining one evidence per format."""
    usable = [item for item in candidates if item.confidence > 0 or item.segments]
    if not usable:
        return ArchiveFormatEvidence(format=fmt, confidence=0.0, status="not_found")
    reliable = [item for item in usable if item.status in {"damaged", "extractable"}]
    if reliable:
        usable = reliable
    best = max(usable, key=lambda item: (_STATUS_RANK.get(item.status, 0), item.confidence))
    if not preserve_multiple:
        return best
    segments = []
    seen = set()
    for item in usable:
        for segment in item.segments:
            key = (segment.start_offset, segment.end_offset, segment.role)
            if key not in seen:
                seen.add(key)
                segments.append(segment)
    segments.sort(key=lambda item: (item.start_offset, item.end_offset is None, item.end_offset or 0))
    return ArchiveFormatEvidence(
        format=fmt,
        confidence=best.confidence,
        status=best.status,
        segments=segments,
        warnings=list(dict.fromkeys(warning for item in usable for warning in item.warnings)),
        details={
            **best.details,
            "candidate_count": len(usable),
            "candidate_details": [item.details for item in usable],
        },
    )
