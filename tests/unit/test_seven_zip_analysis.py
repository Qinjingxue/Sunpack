from sunpack.core.analysis.structure_pipeline.modules.seven_zip import SevenZipAnalysisModule


def test_damaged_seven_zip_never_reuses_guessed_embedded_end():
    module = SevenZipAnalysisModule()
    start = 128
    native = {
        "magic_matched": True,
        "strong_accept": False,
        "plausible": True,
        "error": "next_header_out_of_range",
        "next_header_offset": 8192,
        "next_header_size": 256,
        "evidence": ["7z:start_header_crc"],
    }

    evidence = module._from_native(native, start)

    assert evidence.status == "damaged"
    assert evidence.segments[0].end_offset is None
    assert "boundary_unreliable" in evidence.segments[0].damage_flags
    assert evidence.details["boundary_confidence"] == "none"


def test_exact_embedded_seven_zip_boundary_skips_next_header_revalidation():
    module = SevenZipAnalysisModule()
    item = {
        "format": "7z",
        "offset": 128,
        "end_offset": 4096,
        "confidence": 1.0,
        "validation": "start_header_crc_and_declared_end",
        "candidate_kind": "logical_archive",
        "boundary_kind": "exact",
        "extractable": True,
    }

    evidence = module._from_embedded(item)

    assert evidence.status == "extractable"
    assert evidence.segments[0].end_offset == 4096
    assert evidence.details["source"] == "embedded_scan"
    assert evidence.details["boundary_kind"] == "exact"
    assert evidence.details["integrity_confidence"] == "deferred"
