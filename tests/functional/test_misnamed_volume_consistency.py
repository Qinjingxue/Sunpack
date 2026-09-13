from sunpack.coordinator.target_scan import build_fact_bags_for_targets
from tests.helpers.detection_config import with_detection_pipeline


def test_filename_only_scan_does_not_absorb_unmarked_fuzzy_parts(tmp_path):
    first = tmp_path / "rj081295.7z.001"
    normal_2 = tmp_path / "rj081295"
    normal_3 = tmp_path / "rj081295.7z"
    fuzzy_4 = tmp_path / "95.7z.005"
    fuzzy_5 = tmp_path / "rj0815.7"

    for path in (first, normal_2, normal_3, fuzzy_4, fuzzy_5):
        path.write_bytes(b"7z\xbc\xaf\x27\x1c" + b"x" * (1024 * 1024))

    config = with_detection_pipeline({
        "thresholds": {"archive_score_threshold": 1, "maybe_archive_threshold": 1},
    })

    bags = build_fact_bags_for_targets([str(tmp_path)], config=config)
    grouped = next(bag for bag in bags if bag.get("file.path") == str(first))

    assert grouped.get("candidate.member_paths") == [str(first)]
    assert [
        (item["path"], item["number"], item["source"])
        for item in grouped.get("relation.split_volumes")
    ] == [
        (str(first), 1, "standard"),
    ]
    assert all(
        str(path) not in grouped.get("candidate.member_paths")
        for path in (normal_2, normal_3, fuzzy_4, fuzzy_5)
    )
