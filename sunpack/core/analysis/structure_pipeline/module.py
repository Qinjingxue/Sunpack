from dataclasses import dataclass
from typing import Protocol

from sunpack.core.analysis.result import ArchiveFormatEvidence
from sunpack.core.analysis.view import SharedBinaryView


@dataclass(frozen=True)
class AnalysisModuleSpec:
    name: str
    formats: tuple[str, ...]
    signatures: tuple[bytes, ...] = ()
    io_profile: str = "balanced"
    parallel_safe: bool = True


class AnalysisModule(Protocol):
    spec: AnalysisModuleSpec

    def analyze(self, view: SharedBinaryView, prepass: dict, config: dict) -> ArchiveFormatEvidence:
        ...
