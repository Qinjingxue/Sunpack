from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Iterable

from sunpack.core.passwords.candidates import PasswordCandidate, PasswordCandidatePipeline
from sunpack.core.passwords.fingerprint import ArchiveFingerprint
from sunpack.core.passwords.verifier.input import PasswordProbeInput


@dataclass(frozen=True)
class PasswordJob:
    archive_path: str
    part_paths: list[str] | None = None
    archive_input: dict | None = None
    archive_key: str = ""
    fingerprint: ArchiveFingerprint | None = None
    candidates: Iterable[PasswordCandidate | str] | None = None
    batch_size: int | None = None
    progress_callback: Callable[[object], None] | None = None
    metadata: dict[str, object] = field(default_factory=dict)
    probe_input: PasswordProbeInput | None = field(default=None, repr=False, compare=False)

    def candidate_pipeline(self) -> Iterable[PasswordCandidate | str]:
        return self.candidates or PasswordCandidatePipeline()
