from dataclasses import dataclass, field
from typing import Any
from sunpack.core.passwords.internal.store import PasswordSnapshot, EMPTY_PASSWORD_SNAPSHOT


@dataclass
class CliCommandResult:
    command: str
    inputs: dict[str, Any]
    summary: dict[str, Any]
    errors: list[str] = field(default_factory=list)
    items: list[dict[str, Any]] = field(default_factory=list)
    tasks: list[dict[str, Any]] = field(default_factory=list)
    logs: list[str] = field(default_factory=list)


@dataclass
class CliPasswordSummary:
    user_passwords: list[str]
    clipboard_passwords: list[str]
    recent_passwords: list[str]
    builtin_passwords: tuple[str, ...]
    use_builtin_passwords: bool
    password_snapshot: PasswordSnapshot = EMPTY_PASSWORD_SNAPSHOT


    @property
    def combined_passwords(self) -> list[str]:
        from sunpack.core.passwords.internal.store import PasswordStore
        return PasswordStore.from_sources(
            cli_passwords=self.user_passwords, clipboard_passwords=self.clipboard_passwords,
            recent_passwords=self.recent_passwords, password_snapshot=self.password_snapshot,
        ).candidates()
