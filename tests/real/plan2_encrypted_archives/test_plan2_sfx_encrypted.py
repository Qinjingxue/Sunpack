from __future__ import annotations

import pytest

from tests.helpers.real_archives import ArchiveFixtureFactory
from tests.helpers.tool_config import get_optional_rar
from tests.real.plan2_encrypted_archives.plan2_support import (
    assert_plan2_success,
    encrypted_password_list,
)
from tests.real.encrypted_cases import SFX_FORMATS


FACTORY = ArchiveFixtureFactory()
RAR_AVAILABLE = get_optional_rar() is not None


@pytest.mark.parametrize("archive_format", SFX_FORMATS)
@pytest.mark.parametrize("split", [False, True], ids=["single", "split"])
def test_plan2_encrypted_sfx_find_correct_password(tmp_path, archive_format, split, plan2_error):
    if archive_format == "rar" and not RAR_AVAILABLE:
        pytest.skip("RAR generator is not configured")
    case_id = f"sfx_{'split_' if split else ''}{archive_format}"
    password = f"correct-{case_id}"
    plan2_error["case_id"] = case_id
    plan2_error["archive_format"] = archive_format
    plan2_error["sfx"] = True
    plan2_error["split"] = split
    plan2_error["password_list_size"] = 100
    case = FACTORY.create(
        tmp_path,
        case_id,
        archive_format,
        password=password,
        sfx=True,
        split=split,
        payload_size=(420 if split else 16) * 1024,
    )

    assert_plan2_success(
        case,
        f".{archive_format}",
        expected_container="pe",
        passwords=encrypted_password_list(password),
        error_info=plan2_error,
    )
