from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class EmbeddedOptions:
    force_scan: bool = False
