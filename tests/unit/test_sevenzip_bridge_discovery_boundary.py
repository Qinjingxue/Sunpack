from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BRIDGE = ROOT / "native" / "sevenzip_bridge"
INTERNAL = BRIDGE / "src" / "internal"


def test_sevenzip_bridge_has_no_embedded_detector():
    assert not (INTERNAL / "embedded_7z.cpp").exists()
    assert not (INTERNAL / "embedded_7z.hpp").exists()

    cmake = (BRIDGE / "CMakeLists.txt").read_text(encoding="utf-8")
    open_plan = (INTERNAL / "archive_open_plan.cpp").read_text(encoding="utf-8")
    open_plan_header = (INTERNAL / "archive_open_plan.hpp").read_text(encoding="utf-8")

    forbidden = (
        "embedded_7z",
        "find_embedded_archive_candidates",
        "find_embedded_seven_zip_candidates",
        "embedded_archive_open_plans",
        "embedded_seven_zip_open_plans",
    )
    for token in forbidden:
        assert token not in cmake
        assert token not in open_plan
        assert token not in open_plan_header


def test_password_open_plan_only_consumes_canonical_input():
    source = (INTERNAL / "archive_open_plan.cpp").read_text(encoding="utf-8")

    assert 'plan.source = input_ranges.empty() ? "whole_file" : "provided_ranges";' in source
    assert "input_ranges.front().start" in source
    assert "format_hint.empty() ? archive_type_for_path(archive_path) : format_hint" in source
    assert "return {plan};" in source

    # Full-file/chunk signature scans belong to the Rust embedded scanner.
    assert "ReadFile(" not in source
    assert "kChunkSize" not in source
    assert "signature" not in source
