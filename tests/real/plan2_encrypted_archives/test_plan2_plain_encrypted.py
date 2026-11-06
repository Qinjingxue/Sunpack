from __future__ import annotations

import pytest

from tests.helpers.tool_config import get_optional_rar
from tests.real.encrypted_cases import ENCRYPTED_CASES
from tests.real.plan2_encrypted_archives.plan2_support import (
    assert_plan2_success, encrypted_password_list,
)


RAR_AVAILABLE = get_optional_rar() is not None


@pytest.mark.parametrize(("archive_format", "case_id", "create_archive", "options"), ENCRYPTED_CASES)
def test_plan2_encrypted_archive_find_correct_password(
    tmp_path, archive_format, case_id, create_archive, options, plan2_error,
):
    if archive_format == "rar" and not RAR_AVAILABLE:
        pytest.skip("RAR generator is not configured")
    password = f"correct-{case_id}"
    case_id = f"{archive_format}_{case_id}"
    plan2_error.update({"case_id": case_id, "archive_format": archive_format, **options})
    case = create_archive(tmp_path, case_id, password=password, **options)

    plan2_error["password_list_size"] = 100
    assert_plan2_success(
        case, f".{archive_format}",
        passwords=encrypted_password_list(password), error_info=plan2_error,
    )
