from sunpack.pipeline.verification.error_classification import classify_verification_error


def test_payload_failures_are_not_confused_with_container_damage():
    for kind in ("checksum_error", "crc_error", "data_error", "corrupted_data", "hash_mismatch"):
        classified = classify_verification_error(kind)
        assert classified.content_integrity == "payload_damaged"
        assert classified.container_integrity == "unknown"
        assert classified.category == "payload_damage"


def test_truncation_and_missing_volume_prove_partial_content():
    for kind in ("unexpected_end", "input_truncated", "stream_truncated", "missing_volume"):
        classified = classify_verification_error(kind)
        assert classified.content_integrity == "verified_partial"
        assert classified.container_integrity == "structurally_damaged"
        assert classified.category == "incomplete_archive"


def test_header_and_recognition_failures_do_not_claim_payload_damage():
    for kind in ("headers_error", "not_archive", "structure_recognition", "central_directory_bad"):
        classified = classify_verification_error(kind)
        assert classified.content_integrity == "unknown"
        assert classified.container_integrity == "structurally_damaged"
        assert classified.category == "container_structure"


def test_password_and_execution_failures_leave_integrity_unknown():
    for kind in ("wrong_password", "backend_unavailable", "output_filesystem", "unsupported_method"):
        classified = classify_verification_error(kind)
        assert classified.content_integrity == "unknown"
        assert classified.container_integrity == "unknown"


def test_unknown_item_extraction_failure_is_payload_damage_but_password_is_not():
    assert classify_verification_error("unknown", "item_extract").content_integrity == "payload_damaged"
    assert classify_verification_error("wrong_password", "item_extract").content_integrity == "unknown"
