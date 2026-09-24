from sunpack.pipeline.coordinator.target_scan import build_candidates_for_targets
from tests.helpers.detection_config import with_detection_pipeline


def test_filename_only_scan_does_not_absorb_unmarked_fuzzy_parts(tmp_path):
    first = tmp_path / "sample123456.7z.001"
    normal_2 = tmp_path / "sample123456"
    normal_3 = tmp_path / "sample123456.7z"
    fuzzy_4 = tmp_path / "56.7z.005"
    fuzzy_5 = tmp_path / "sample1234.7"

    for path in (first, normal_2, normal_3, fuzzy_4, fuzzy_5):
        path.write_bytes(b"7z\xbc\xaf\x27\x1c" + b"x" * (1024 * 1024))

    config = with_detection_pipeline({
        "thresholds": {"archive_score_threshold": 1, "maybe_archive_threshold": 1},
    })

    candidates = build_candidates_for_targets([str(tmp_path)], config=config)
    grouped = next(candidate for candidate in candidates if candidate.entry_path == str(first))

    assert grouped.archive_input.part_paths() == [str(first)]
    assert grouped.archive_input is None or grouped.archive_input.open_mode == "file"
    assert not grouped.is_split
    assert all(
        str(path) not in grouped.archive_input.part_paths()
        for path in (normal_2, normal_3, fuzzy_4, fuzzy_5)
    )
