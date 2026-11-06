from __future__ import annotations

import pytest

from tests.helpers.real_archives import (
    create_encrypted_7z_archive,
    create_encrypted_rar_archive,
    create_encrypted_zip_archive,
)


# Success and wrong-password tests must exercise the same format variants.
ENCRYPTED_CASES = [
    *[
        pytest.param("zip", case_id, create_encrypted_zip_archive,
                     {"encryption": encryption, "method": method}, id=f"zip-{case_id}")
        for case_id, encryption, method in (
            ("zipcrypto", "ZipCrypto", None),
            ("aes128", "AES128", None),
            ("aes256", "AES256", None),
            ("deflate64", "ZipCrypto", "Deflate64"),
            ("bzip2", "ZipCrypto", "BZip2"),
            ("lzma", "ZipCrypto", "LZMA"),
            ("ppmd", "ZipCrypto", "PPMd"),
        )
    ],
    *[
        pytest.param("rar", case_id, create_encrypted_rar_archive,
                     {"rar4": rar4, "header_encrypt": header_encrypt}, id=case_id)
        for case_id, rar4, header_encrypt in (
            ("rar5-header", False, True),
            ("rar5-data", False, False),
            ("rar4-header", True, True),
            ("rar4-data", True, False),
        )
    ],
    *[
        pytest.param("7z", case_id, create_encrypted_7z_archive,
                     {"header_encrypt": header_encrypt, "solid": solid, "method": method},
                     id=f"7z-{case_id}")
        for case_id, header_encrypt, solid, method in (
            ("header-on", True, True, None),
            ("header-off", False, True, None),
            ("nonsolid", True, False, None),
            ("lzma", True, True, "LZMA"),
            ("ppmd", True, True, "PPMd"),
            ("bzip2", True, True, "BZip2"),
            ("deflate", True, True, "Deflate"),
        )
    ],
]

SFX_FORMATS = ["7z", "zip", "rar"]
