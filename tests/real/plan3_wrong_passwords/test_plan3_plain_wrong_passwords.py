from __future__ import annotations

import pytest

from tests.helpers.tool_config import get_optional_rar
from tests.real.encrypted_cases import ENCRYPTED_CASES
from tests.real.plan3_wrong_passwords.plan3_support import assert_password_error


RAR_AVAILABLE = get_optional_rar() is not None


@pytest.mark.parametrize(("archive_format", "case_id", "create_archive", "options"), ENCRYPTED_CASES)
def test_plan3_encrypted_archive_reports_password_error(
    tmp_path, archive_format, case_id, create_archive, options, plan3_error,
):
    if archive_format == "rar" and not RAR_AVAILABLE:
        pytest.skip("RAR generator is not configured")
    password = "correct-password-not-in-list"
    case_id = f"{archive_format}_{case_id}"
    plan3_error.update({"case_id": case_id, "archive_format": archive_format, **options})
    case = create_archive(tmp_path, case_id, password=password, **options)

    assert_password_error(case, error_info=plan3_error)
