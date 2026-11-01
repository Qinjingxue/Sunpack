from typing import List

from sunpack_native import read_password_file


def parse_password_lines(text: str) -> List[str]:
    """Treat every non-empty line as a literal password.

    Password sources do not have a generic comment syntax. In particular,
    leading # characters and surrounding whitespace may be part of a
    password and must not be discarded.
    """
    return [line for line in (text or "").splitlines() if line != ""]


def dedupe_passwords(passwords: List[str]) -> List[str]:
    deduped_passwords = []
    seen = set()
    for password in passwords:
        if password not in seen:
            seen.add(password)
            deduped_passwords.append(password)
    return deduped_passwords
