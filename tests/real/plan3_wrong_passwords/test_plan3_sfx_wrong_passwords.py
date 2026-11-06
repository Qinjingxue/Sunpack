from __future__ import annotations

import pytest

from tests.helpers.real_archives import ArchiveFixtureFactory
from tests.helpers.tool_config import get_optional_rar
from tests.real.encrypted_cases import SFX_FORMATS
from tests.real.plan3_wrong_passwords.plan3_support import assert_password_error


FACTORY = ArchiveFixtureFactory()
RAR_AVAILABLE = get_optional_rar() is not None


@pytest.mark.parametrize("archive_format", SFX_FORMATS)
@pytest.mark.parametrize("split", [False, True], ids=["single", "split"])
def test_plan3_encrypted_sfx_reports_password_error(tmp_path, archive_format, split, plan3_error):
    if archive_format == "rar" and not RAR_AVAILABLE:
        pytest.skip("RAR generator is not configured")
    case_id = f"sfx_{'split_' if split else ''}{archive_format}"
    plan3_error["case_id"] = case_id
    plan3_error["archive_format"] = archive_format
    plan3_error["sfx"] = True
    plan3_error["split"] = split
    case = FACTORY.create(
        tmp_path,
        case_id,
        archive_format,
        password="correct-password-not-in-list",
        sfx=True,
        split=split,
        payload_size=(420 if split else 16) * 1024,
    )

    assert_password_error(case, error_info=plan3_error)
