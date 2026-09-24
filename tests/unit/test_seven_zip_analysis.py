from sunpack.core.analysis.structure_pipeline.modules.seven_zip import SevenZipAnalysisModule


def test_damaged_seven_zip_reuses_bounded_embedded_candidate_range():
    module = SevenZipAnalysisModule()
    start = 128
    end = 4096
    native = {
        "magic_matched": True,
        "strong_accept": False,
        "plausible": True,
        "error": "next_header_out_of_range",
        "next_header_offset": 8192,
        "next_header_size": 256,
        "evidence": ["7z:start_header_crc"],
    }
    prepass = {
        "source": "embedded_scan",
        "embedded_candidates": [
            {
                "format": "7z",
                "offset": start,
                "end_offset": None,
                "confidence": 0.90,
                "validation": "start_header_crc_truncated_next_header",
                "candidate_kind": "logical_archive",
                "boundary_kind": "bounded",
                "range_end_offset": end,
                "extractable": True,
                "contained_anchor_count": 0,
            }
        ],
    }

    evidence = module._from_native(native, start, prepass, end)

    assert evidence.status == "extractable"
    assert evidence.confidence == 0.90
    assert evidence.segments[0].end_offset == end
    assert evidence.details["source"] == "embedded_scan"
    assert evidence.details["candidate_kind"] == "logical_archive"
    assert evidence.details["boundary_kind"] == "bounded"
