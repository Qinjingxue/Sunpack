from __future__ import annotations

from tests.real.enc_support import ENC_PASSWORD, create_enc_case
from tests.real.plan2_encrypted_archives.plan2_support import (
    assert_plan2_success,
    encrypted_password_list,
)


def test_plan2_enc_finds_password_and_decrypts_inner_archive(tmp_path, plan2_error):
    case = create_enc_case(tmp_path, "official_enc_v4", input_suffix=".mov")
    passwords = encrypted_password_list(ENC_PASSWORD, count=3, correct_index=1)
    plan2_error.update(
        {
            "case_id": "official_enc_v4_disguised_as_mov",
            "archive_format": "enc",
            "password_list_size": len(passwords),
        }
    )

    # The .mov name checks signature-based ENC discovery before password search.
    assert_plan2_success(
        case,
        ".enc",
        passwords=passwords,
        error_info=plan2_error,
    )
