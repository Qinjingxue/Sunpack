from __future__ import annotations

from tests.real.enc_support import create_enc_case
from tests.real.plan3_wrong_passwords.plan3_support import assert_password_error


def test_plan3_enc_reports_password_error_when_candidate_is_wrong(tmp_path, plan3_error):
    case = create_enc_case(tmp_path, "official_enc_v4_wrong_password")
    plan3_error.update(
        {
            "case_id": "official_enc_v4_wrong_password",
            "archive_format": "enc",
            "password_list_size": 1,
        }
    )

    assert_password_error(case, error_info=plan3_error, passwords=["definitely-wrong"])
