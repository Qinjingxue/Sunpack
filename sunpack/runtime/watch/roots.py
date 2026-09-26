"""Input-root policy shared by Watch configuration and task admission."""

from dataclasses import dataclass


@dataclass(frozen=True)
class WatchRootEntry:
    input_root: str
    output_root: str | None = None
    deep_detect: bool = False
