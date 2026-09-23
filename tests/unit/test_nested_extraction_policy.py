from pathlib import Path

import pytest

from sunpack.config.fields.coordinator import normalize_recursive_authorization
from sunpack.contracts.filesystem import DirectorySnapshot, FileEntry
from sunpack.coordinator.recursive_authorization import RecursiveAuthorization
from sunpack.coordinator.scan_session import DiscoveryScanSession
from sunpack.coordinator.task_scan import direct_file_task


def _config(**overrides):
    return {
        "recursive_authorization": {
            "enabled": True,
            "byte_ratio_exponent": 1,
            "project_ratio_exponent": 1,
            "authorization_bias": 0,
            "minimum_authorization_score": 0.85,
            "minimum_archive_byte_ratio": 0.1,
            "hard_maximum_other_projects": 1000,
            **overrides,
        }
    }


def _authorize(root: Path, entries: list[FileEntry], archives: list[Path], *, round_index=2):
    snapshot = DirectorySnapshot.from_entries(root, entries, raw_entries=entries)
    session = DiscoveryScanSession(config=_config())
    session.prime_snapshot(str(root), snapshot)
    tasks = [direct_file_task(str(path)) for path in archives]
    return RecursiveAuthorization(_config()).authorize_batch(
        tasks,
        [str(root)],
        session,
        round_index=round_index,
    )


def test_first_round_bypasses_policy_for_the_user_requested_scope(tmp_path):
    wrapper = tmp_path / "game"
    archive = wrapper / "wanted.rar"
    task = direct_file_task(str(archive))
    result = RecursiveAuthorization(_config()).authorize_batch(
        [task],
        [str(tmp_path)],
        None,
        round_index=1,
    )

    assert [task.main_path for task in result.allowed_inputs] == [str(archive)]
    assert result.skipped == []


def test_removed_initial_root_setting_is_rejected():
    with pytest.raises(ValueError, match="allow_initial_root_archives"):
        normalize_recursive_authorization({"allow_initial_root_archives": True})


def test_removed_or_rule_setting_is_rejected():
    with pytest.raises(ValueError, match="maximum_other_projects"):
        normalize_recursive_authorization({"maximum_other_projects": 2})


def test_removed_cleanliness_model_settings_are_rejected():
    with pytest.raises(ValueError, match="other_project_tolerance"):
        normalize_recursive_authorization({"other_project_tolerance": 2})


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("byte_ratio_exponent", 0),
        ("byte_ratio_exponent", float("inf")),
        ("project_ratio_exponent", -1),
        ("project_ratio_exponent", float("nan")),
        ("authorization_bias", float("inf")),
        ("minimum_authorization_score", float("nan")),
    ],
)
def test_odds_fusion_settings_must_be_finite_and_in_range(field, value):
    with pytest.raises(ValueError, match=field):
        normalize_recursive_authorization({field: value})


def test_normal_detection_session_retains_raw_snapshots_for_relation_evidence():
    assert DiscoveryScanSession(config=_config()).include_raw_snapshots is True


def test_second_round_root_child_has_no_special_privilege(tmp_path):
    archive = tmp_path / "nested.zip"
    entries = [
        FileEntry(archive, False, 10),
        *[FileEntry(tmp_path / f"asset_{index}", False, 100) for index in range(10)],
    ]

    result = _authorize(tmp_path, entries, [archive], round_index=2)

    assert result.allowed_inputs == []
    assert result.skipped[0]["reason"] == "archive_byte_ratio_below_floor"


def test_recursive_policy_rejects_game_dlc_payload_shape(tmp_path):
    """Metadata-only regression for the private DLC archive fixture."""
    wrapper = tmp_path / "dlc_pack"
    gfx = wrapper / "gfx"
    sound = wrapper / "sound"
    archive = wrapper / "payload.zip"
    other_file_sizes = [
        315,
        275,
        27_178,
        1_574,
        2_036_265,
        59_247,
        11_834,
        8_755,
        1_074_194,
        39_223,
        6_349,
        10_722,
        1_901_566,
        53_815,
        9_459,
        7_392,
        467_889,
        21_133,
        11_163,
        8_008,
        1_455,
        3_267,
        3_288,
        659_760,
        687_840,
        414_904,
        1_328,
        43_510,
    ]
    entries = [
        FileEntry(wrapper, True),
        FileEntry(gfx, True),
        FileEntry(sound, True),
        FileEntry(archive, False, 2_461_198),
    ]
    entries.extend(
        FileEntry(
            (gfx if index < 21 else sound) / f"resource_{index}.bin",
            False,
            size,
        )
        for index, size in enumerate(other_file_sizes)
    )

    result = _authorize(tmp_path, entries, [archive])

    assert result.allowed_inputs == []
    assert result.skipped[0]["reason"] == "authorization_score_below_threshold"
    assert result.skipped[0]["local_other_file_count"] == 28
    assert result.skipped[0]["local_foreign_branch_count"] == 2
    assert result.skipped[0]["local_other_project_count"] == 30
    assert result.skipped[0]["local_candidate_byte_ratio"] == pytest.approx(
        0.24531257444253937
    )
    assert result.skipped[0]["local_candidate_project_ratio"] == pytest.approx(1 / 31)
    assert result.skipped[0]["authorization_score"] == pytest.approx(
        0.010718922813754538
    )


def test_recursive_policy_allows_dominant_release_archive_shape(tmp_path):
    """Metadata-only regression for the private encrypted release fixture."""
    notes = tmp_path / "release_notes"
    archive = tmp_path / "inner.zip"
    archive_size = 988_855_997
    note_sizes = [1_664, 245, 1_653, 614, 39]
    entries = [
        FileEntry(notes, True),
        FileEntry(notes / "note_0.txt", False, note_sizes[0]),
        FileEntry(notes / "note_1.txt", False, note_sizes[1]),
        FileEntry(notes / "note_2.txt", False, note_sizes[2]),
        FileEntry(notes / "note_3.txt", False, note_sizes[3]),
        FileEntry(tmp_path / "note_4.txt", False, note_sizes[4]),
        FileEntry(archive, False, archive_size),
    ]

    assert archive_size / (archive_size + sum(note_sizes)) == pytest.approx(
        0.9999957375168412
    )
    assert 1 / (1 + len(note_sizes) + 1) == pytest.approx(1 / 7)

    result = _authorize(tmp_path, entries, [archive])

    assert [task.main_path for task in result.allowed_inputs] == [str(archive)]
    assert result.skipped == []


def test_nested_archive_dominating_its_semantic_subtree_is_allowed(tmp_path):
    wrapper = tmp_path / "wrapper"
    archive = wrapper / "inner.zip"
    entries = [
        FileEntry(wrapper, True),
        FileEntry(archive, False, 900),
        FileEntry(wrapper / "readme.txt", False, 100),
    ]

    result = _authorize(tmp_path, entries, [archive])

    assert [task.main_path for task in result.allowed_inputs] == [str(archive)]
    assert result.skipped == []


def test_candidates_in_same_scope_are_aggregated_once(tmp_path):
    wrapper = tmp_path / "archives"
    first = wrapper / "one.zip"
    second = wrapper / "two.zip"
    entries = [
        FileEntry(wrapper, True),
        FileEntry(first, False, 450),
        FileEntry(second, False, 450),
        FileEntry(wrapper / "payload.dat", False, 100),
    ]

    result = _authorize(tmp_path, entries, [first, second])

    assert [task.main_path for task in result.allowed_inputs] == [str(first), str(second)]
    assert result.skipped == []


def test_large_game_resource_is_rejected_despite_dominating_bytes(tmp_path):
    archive = tmp_path / "resource.zip"
    entries = [FileEntry(archive, False, 90_000)]
    entries.extend(
        FileEntry(tmp_path / f"asset_{index}.bin", False, 100)
        for index in range(100)
    )

    result = _authorize(tmp_path, entries, [archive])

    assert result.allowed_inputs == []
    row = result.skipped[0]
    assert row["local_candidate_byte_ratio"] == pytest.approx(0.9)
    assert row["local_other_project_count"] == 100
    assert row["local_candidate_project_ratio"] == pytest.approx(1 / 101)
    assert row["reason"] == "authorization_score_below_threshold"


def test_repository_root_can_veto_clean_release_subdirectory(tmp_path):
    release = tmp_path / "release"
    source = tmp_path / "src"
    archive = release / "build.zip"
    entries = [
        FileEntry(release, True),
        FileEntry(source, True),
        FileEntry(archive, False, 90_000),
    ]
    entries.extend(
        FileEntry(source / f"module_{index}.py", False, 10)
        for index in range(100)
    )

    result = _authorize(tmp_path, entries, [archive])

    assert result.allowed_inputs == []
    row = result.skipped[0]
    assert row["local_authorization_score"] == pytest.approx(1.0)
    assert row["limiting_context"] == "root"
    assert row["root_foreign_branch_count"] == 1
    assert row["root_other_project_count"] == 101
    assert row["root_candidate_project_ratio"] == pytest.approx(1 / 102)
    assert row["reason"] == "authorization_score_below_threshold"


def test_deep_single_directory_wrapper_does_not_add_project_burden(tmp_path):
    wrapper = tmp_path / "B"
    middle = wrapper / "C"
    deepest = middle / "D"
    archive = deepest / "large.zip"
    entries = [
        FileEntry(wrapper, True),
        FileEntry(middle, True),
        FileEntry(deepest, True),
        FileEntry(archive, False, 990),
        FileEntry(tmp_path / "readme.txt", False, 10),
    ]

    result = _authorize(tmp_path, entries, [archive])

    assert [task.main_path for task in result.allowed_inputs] == [str(archive)]
    assert result.skipped == []


def test_extreme_byte_ratio_overcomes_a_few_other_files(tmp_path):
    archive = tmp_path / "large.zip"
    entries = [FileEntry(archive, False, 9_970)]
    entries.extend(
        FileEntry(tmp_path / f"note_{index}.txt", False, 10)
        for index in range(3)
    )

    result = _authorize(tmp_path, entries, [archive])

    assert [task.main_path for task in result.allowed_inputs] == [str(archive)]
    assert result.skipped == []


@pytest.mark.parametrize(
    ("other_projects", "allowed"),
    [(17, True), (18, False)],
)
def test_ninety_nine_percent_bytes_has_five_percent_project_boundary(
    tmp_path,
    other_projects,
    allowed,
):
    archive = tmp_path / "large.zip"
    entries = [FileEntry(archive, False, 9_900)]
    each_size, remainder = divmod(100, other_projects)
    entries.extend(
        FileEntry(
            tmp_path / f"note_{index}.txt",
            False,
            each_size + (1 if index < remainder else 0),
        )
        for index in range(other_projects)
    )

    result = _authorize(tmp_path, entries, [archive])

    if allowed:
        assert [task.main_path for task in result.allowed_inputs] == [str(archive)]
        assert result.skipped == []
    else:
        assert result.allowed_inputs == []
        row = result.skipped[0]
        assert row["reason"] == "authorization_score_below_threshold"
        assert row["local_candidate_byte_ratio"] == pytest.approx(0.99)
        assert row["local_candidate_project_ratio"] == pytest.approx(1 / 19)
