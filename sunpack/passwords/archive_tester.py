from typing import List

from sunpack.passwords.internal.store import PasswordStore
from sunpack.passwords.scheduler import PasswordScheduler


class ArchivePasswordTester:
    """Own the password store and bounded Rust verifier scheduler.

    Full-payload confirmation belongs to the extraction worker. The Python
    password layer only performs bounded ZIP/RAR/7z verification and hands any
    inconclusive candidates to extraction.
    """

    def __init__(
        self,
        cli_passwords: List[str] = None,
        builtin_passwords_file: str = None,
        builtin_passwords: List[str] = None,
        password_store: PasswordStore | None = None,
    ):
        self.password_store = password_store or PasswordStore.from_sources(
            cli_passwords=cli_passwords or [],
            builtin_passwords=builtin_passwords,
            builtin_passwords_file=builtin_passwords_file,
        )
        self.password_scheduler = PasswordScheduler.with_fast_verifiers()

    @property
    def recent_passwords(self) -> List[str]:
        return list(self.password_store.recent_passwords)

    @property
    def passwords(self) -> List[str]:
        return self.password_store.candidates()

    def get_passwords_to_try(self) -> List[str]:
        return self.password_store.candidates()

    def add_recent_password(self, pwd: str):
        self.password_store.remember_success(pwd)


PasswordManager = ArchivePasswordTester
