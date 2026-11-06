from __future__ import annotations

import pytest

from tests.helpers.real_archives import ArchiveFixtureFactory
from tests.helpers.tool_config import get_optional_rar
from tests.real.plan4_missing_volumes.plan4_support import (
    SCENARIOS,
    apply_missing_volume_scenario,
    assert_missing_volume_or_ignored,
)


FACTORY = ArchiveFixtureFactory()
RAR_AVAILABLE = get_optional_rar() is not None


@pytest.mark.parametrize("archive_format", ["zip", "rar", "7z"])
@pytest.mark.parametrize("scenario", SCENARIOS)
@pytest.mark.parametrize("sfx", [False, True], ids=["archive", "sfx"])
def test_plan4_encrypted_split_missing_volumes(
    tmp_path, archive_format, scenario, sfx, plan4_error
):
    if archive_format == "rar" and not RAR_AVAILABLE:
        pytest.skip("RAR generator is not configured")
    case_id = f"{'sfx_' if sfx else ''}split_{archive_format}_{scenario}"
    password = f"correct-{case_id}"
    plan4_error["case_id"] = case_id
    plan4_error["archive_format"] = archive_format
    plan4_error["scenario"] = scenario
    plan4_error["split"] = True
    plan4_error["sfx"] = sfx
    case = FACTORY.create(
        tmp_path,
        f"enc_{case_id}",
        archive_format,
        password=password,
        split=True,
        sfx=sfx,
        payload_size=620 * 1024,
    )
    plan4_error["part_count_before"] = len(
        [path for path in case.archive_dir.iterdir() if path.is_file()]
    )
    apply_missing_volume_scenario(case, scenario)
    plan4_error["part_count_after"] = len(
        [path for path in case.archive_dir.iterdir() if path.is_file()]
    )

    assert_missing_volume_or_ignored(
        case, [password], error_info=plan4_error,
        allow_scan_ignore=scenario in {"missing_head", "only_middle", "only_tail"},
    )
