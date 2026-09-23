from dataclasses import dataclass, field
from typing import Any


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
    builtin_passwords: list[str]
    combined_passwords: list[str]
    use_builtin_passwords: bool

