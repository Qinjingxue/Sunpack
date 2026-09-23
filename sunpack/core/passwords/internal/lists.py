from typing import List

from sunpack.core.support.resource_lifecycle import open_task_file


def parse_password_lines(text: str) -> List[str]:
    """Treat every non-empty line as a literal password.

    Password sources do not have a generic comment syntax. In particular,
    leading # characters and surrounding whitespace may be part of a
    password and must not be discarded.
    """
    return [line for line in (text or "").splitlines() if line != ""]


def read_password_file(password_file: str) -> List[str]:
    with open_task_file(password_file, "r", encoding="utf-8") as handle:
        return parse_password_lines(handle.read())


def dedupe_passwords(passwords: List[str]) -> List[str]:
    deduped_passwords = []
    seen = set()
    for password in passwords:
        if password not in seen:
            seen.add(password)
            deduped_passwords.append(password)
    return deduped_passwords
